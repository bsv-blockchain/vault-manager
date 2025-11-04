import React, { FC, useState, useMemo, useCallback, useEffect } from 'react'
import Vault from '../../Vault'
import { Notification, OutgoingOutputSpec, CoinRecord, AttestationFn } from '../../types'
import {
  validateAddressOrScript,
  validateSatoshis,
  validateMemo,
  parseInteger
} from '../../validators'
import { getTxFromStore } from '../../utils'
import { useDialog } from '../dialogs/DialogProvider'
import { Utils } from '@bsv/sdk'
import QRScanner from '../common/QRScanner'
import QRDisplay from '../common/QRDisplay'

interface OutgoingWizardProps {
  vault: Vault
  onUpdate: () => void
  notify: (t: Notification['type'], m: string) => void
}

const COLORS = {
  red: 'var(--color-error)',
  green: 'var(--color-success)',
  blue: 'var(--color-info)',
  accent: 'var(--color-accent-gold)',
  gray600: 'var(--color-text-tertiary)',
  border: 'var(--color-border-secondary)',
  text: 'var(--color-text-primary)',
  textSecondary: 'var(--color-text-secondary)'
}

const OutgoingWizard: FC<OutgoingWizardProps> = ({ vault, onUpdate, notify }) => {
  const dialog = useDialog()
  type Step = 1 | 2 | 3 | 4 | 5
  const [step, setStep] = useState<Step>(1)

  // State for the new multi-output UI
  const [outputs, setOutputs] = useState([
    { destinationAddressOrScript: '', satoshis: '', memo: '' }
  ])

  const [parsedOutputs, setParsedOutputs] = useState<OutgoingOutputSpec[]>([])
  const [manualInputs, setManualInputs] = useState<Record<string, boolean>>({})
  const [changeSerials, setChangeSerials] = useState<Record<string, boolean>>({})
  const [txMemo, setTxMemo] = useState<string>('')
  const [requirePerUtxoAttestation, setRequirePerUtxoAttestation] = useState<boolean>(false)

  const [beefHex, setBeefHex] = useState<string | null>(null)
  const [beefTxid, setBeefTxid] = useState<string | null>(null)
  const [rawTxHex, setRawTxHex] = useState<string | null>(null)
  const [isBuilding, setIsBuilding] = useState(false)
  const [scanningForOutput, setScanningForOutput] = useState<number | null>(null)
  const [showBeefQR, setShowBeefQR] = useState(false)

  // Handlers for the multi-output UI
  const handleOutputChange = (
    index: number,
    field: keyof typeof outputs[0],
    value: string
  ) => {
    const newOutputs = [...outputs]
    newOutputs[index] = { ...newOutputs[index], [field]: value }
    setOutputs(newOutputs)
  }

  const addOutput = () => {
    setOutputs([...outputs, { destinationAddressOrScript: '', satoshis: '', memo: '' }])
  }

  const removeOutput = (index: number) => {
    if (outputs.length > 1) {
      setOutputs(outputs.filter((_, i) => i !== index))
    }
  }

  const resetWizard = () => {
    setStep(1)
    setOutputs([{ destinationAddressOrScript: '', satoshis: '', memo: '' }])
    setParsedOutputs([])
    setManualInputs({})
    setChangeSerials({})
    setTxMemo('')
    setRequirePerUtxoAttestation(false)
    setBeefHex(null)
    setBeefTxid(null)
    setRawTxHex(null)
    setScanningForOutput(null)
    setShowBeefQR(false)
  }

  const handleQRScan = (index: number, data: string) => {
    // Trim and validate the scanned data
    const trimmedData = data.trim()
    handleOutputChange(index, 'destinationAddressOrScript', trimmedData)
    setScanningForOutput(null)
    notify('success', 'Address scanned from QR code')
  }

  const totalOutputSats = useMemo(() => {
    return parsedOutputs.reduce((sum, o) => sum + o.satoshis, 0)
  }, [parsedOutputs])

  const totalInputSats = useMemo(() => {
    const selectedIds = Object.keys(manualInputs).filter((id) => manualInputs[id])
    let sum = 0
    for (const id of selectedIds) {
      const [txid, voutStr] = id.split(':')
      const coin = vault.coins.find((c) => c.txid === txid && c.outputIndex === Number(voutStr))
      if (coin) {
        try {
          const tx = getTxFromStore(vault.beefStore, coin.txid)
          sum += tx.outputs[coin.outputIndex].satoshis as number
        } catch {}
      }
    }
    return sum
  }, [manualInputs, vault.coins, vault.beefStore])

  const coinTimestamp = useCallback(
    (coin: CoinRecord) => {
      const entry = vault.transactionLog.find((t) => t.txid === coin.txid)
      return entry ? entry.at : 0
    },
    [vault.transactionLog]
  )

  useEffect(() => {
    if (step !== 2) return
    if (Object.keys(manualInputs).some((id) => manualInputs[id])) return
    const required = totalOutputSats
    if (required <= 0) return
    const selection: Record<string, boolean> = {}
    let accumulated = 0
    const coinsSorted = [...vault.coins].sort((a, b) => coinTimestamp(a) - coinTimestamp(b))
    for (const coin of coinsSorted) {
      try {
        const tx = getTxFromStore(vault.beefStore, coin.txid)
        const sat = tx.outputs[coin.outputIndex].satoshis as number
        const id = `${coin.txid}:${coin.outputIndex}`
        selection[id] = true
        accumulated += sat
        if (accumulated >= required) break
      } catch {}
    }
    if (Object.keys(selection).length) {
      setManualInputs(selection)
    }
  }, [step, manualInputs, vault.coins, vault.beefStore, totalOutputSats, coinTimestamp])

  useEffect(() => {
    if (step !== 3) return
    if (Object.values(changeSerials).some(Boolean)) return
    let cancelled = false
    const ensureChangeKey = async () => {
      let fresh = [...vault.keys].find((k) => !k.usedOnChain)
      if (!fresh) {
        try {
          const newKey = await vault.generateKey('change')
          onUpdate()
          fresh = newKey
          if (!cancelled && fresh) {
            notify('info', `New change key ${fresh.serial} generated automatically.`)
          }
        } catch (err: any) {
          if (!cancelled)
            notify('error', err?.message || 'Failed to generate change key automatically.')
          return
        }
      }
      if (cancelled || !fresh) return
      setChangeSerials({ [fresh.serial]: true })
    }
    ensureChangeKey()
    return () => {
      cancelled = true
    }
  }, [step, changeSerials, vault.keys, vault, onUpdate, notify])

  function nextFromOutputs() {
    try {
      const specs: OutgoingOutputSpec[] = []
      for (const output of outputs) {
        const dest = output.destinationAddressOrScript.trim()
        const satStr = output.satoshis.trim()
        const memo = output.memo.trim()

        // Skip completely empty rows silently
        if (!dest && !satStr && !memo) continue

        if (!dest) {
          throw new Error('An output is missing a destination address or script.')
        }
        const destOk = validateAddressOrScript(dest)
        if (destOk !== true) throw new Error(destOk)
        const satOk = validateSatoshis(satStr)
        if (satOk !== true)
          throw new Error(typeof satOk === 'string' ? satOk : 'Invalid satoshi amount.')
        const sat = Number(satStr)
        const memoOk = validateMemo(memo, 'Memo', 256)
        if (memoOk !== true) throw new Error(memoOk)

        specs.push({ destinationAddressOrScript: dest, satoshis: sat, memo: memo || undefined })
      }

      if (specs.length === 0) {
        throw new Error('You must define at least one valid output.')
      }

      setParsedOutputs(specs)
      setStep(2)
    } catch (e: any) {
      notify('error', e.message || 'Invalid outputs.')
    }
  }

  function nextFromInputs() {
    const selectedIds = Object.keys(manualInputs).filter((id) => manualInputs[id])
    if (!selectedIds.length) {
      notify('error', 'Select at least one input UTXO.')
      return
    }
    if (totalInputSats < totalOutputSats) {
      notify(
        'error',
        `Selected inputs (${totalInputSats.toLocaleString()} sats) do not cover the required output amount (${totalOutputSats.toLocaleString()} sats).`
      )
      return
    }

    // Warn if any selected inputs are from unprocessed transactions
    const unprocessedParents: string[] = []
    for (const id of selectedIds) {
      const [txid] = id.split(':')
      const t = vault.transactionLog.find((tl) => tl.txid === txid)
      if (t && !t.processed) unprocessedParents.push(id)
    }
    if (unprocessedParents.length > 0) {
      dialog
        .confirm(
          `WARNING: You are consuming inputs from transactions not yet marked as "processed":\n\n${unprocessedParents.join('\n')}\n\nProceed anyway?`,
          {
            title: 'Unprocessed Inputs Warning',
            confirmText: 'Proceed Anyway',
            cancelText: 'Review Inputs'
          }
        )
        .then((ok) => {
          if (ok) setStep(3)
        })
      return
    }

    setStep(3)
  }

  function nextFromChange() {
    const change = Object.keys(changeSerials).filter((s) => changeSerials[s])
    if (!change.length) {
      notify('error', 'Select at least one change key.')
      return
    }

    // Privacy warning if change key(s) already used
    const usedSelected = change
      .map((s) => vault.keys.find((k) => k.serial === s))
      .filter((k) => k?.usedOnChain)
      .map((k) => `${k!.serial}${k!.memo ? ` (${k!.memo})` : ''}`)
    if (usedSelected.length > 0) {
      dialog
        .confirm(
          `PRIVACY WARNING: You selected change key(s) that are already used on-chain:\n\n${usedSelected.join('\n')}\n\nReusing addresses harms privacy and may leak linkage. Proceed anyway?`,
          {
            title: 'Change Key Reuse',
            confirmText: 'Proceed Anyway',
            cancelText: 'Pick Different Keys'
          }
        )
        .then((ok) => {
          if (ok) setStep(4)
        })
      return
    }

    setStep(4)
  }

  async function handleGenerateNewChangeKey() {
    const memo = await dialog.prompt('Enter a memo for the new change key:', {
      title: 'New Key',
      maxLength: 256,
      validate: (v) => validateMemo(v, 'Memo', 256)
    })
    if (memo === null) return // User cancelled
    await vault.generateKey(memo || '')
    onUpdate() // This will cause the component to get the new key list
    notify('success', 'New key generated and added to the list.')
  }

  async function buildAndSign() {
    setIsBuilding(true)
    try {
      const selectedIds = Object.keys(manualInputs).filter((id) => manualInputs[id])
      const change = Object.keys(changeSerials).filter((s) => changeSerials[s])

      const attestationFn: AttestationFn | undefined =
        vault.confirmOutgoingCoins && requirePerUtxoAttestation
          ? async (coin) => {
              const id = `${coin.txid}:${coin.outputIndex}`
              return await dialog.confirm(
                `ATTESTATION REQUIRED:\n\nConfirm this UTXO is unspent on the HONEST chain:\n\n${id}`,
                {
                  title: 'Per-UTXO Attestation',
                  confirmText: 'I Certify',
                  cancelText: 'Abort Signing'
                }
              )
            }
          : undefined

      const { tx, atomicBEEFHex } = await vault.buildAndSignOutgoing({
        outputs: parsedOutputs,
        inputIds: selectedIds,
        changeKeySerials: change,
        perUtxoAttestation: requirePerUtxoAttestation,
        attestationFn,
        txMemo
      })

      setBeefHex(atomicBEEFHex)
      setBeefTxid(tx.id('hex') as string)
      try {
        const rawHex =
          typeof (tx as any).toHex === 'function'
            ? (tx as any).toHex()
            : Utils.toHex((tx.toBinary ? tx.toBinary() : []) as number[])
        setRawTxHex(rawHex || null)
      } catch {
        setRawTxHex(null)
      }

      onUpdate()
      notify(
        'success',
        'Transaction built & signed. Download the Atomic BEEF or raw hex below, then SAVE the vault to persist changes.'
      )
      setStep(5)
    } catch (e: any) {
      notify('error', e.message || String(e))
    } finally {
      setIsBuilding(false)
    }
  }

  const btnRemoveStyle: React.CSSProperties = {
    background: COLORS.red,
    color: 'white',
    padding: '8px 12px',
    lineHeight: 1,
    minWidth: 'auto',
    fontWeight: 'bold',
    maxWidth: 120
  }

  const StepIndicator = () => (
    <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
      {[1, 2, 3, 4, 5].map((n) => (
        <div
          key={n}
          style={{
            padding: '8px 14px',
            borderRadius: 4,
            background: step === n
              ? 'linear-gradient(135deg, var(--color-accent-gold) 0%, #b89650 100%)'
              : 'var(--color-bg-elevated)',
            border: step === n
              ? '1px solid rgba(201, 169, 97, 0.3)'
              : '1px solid var(--color-border-primary)',
            color: step === n ? '#0f1216' : 'var(--color-text-secondary)',
            fontSize: 11,
            fontWeight: step === n ? 600 : 500,
            letterSpacing: '0.04em',
            textTransform: 'uppercase',
            boxShadow: step === n
              ? '0 2px 8px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1)'
              : 'none',
            transition: 'all 0.2s ease'
          }}
        >
          {n}.{' '}
          {n === 1
            ? 'Outputs'
            : n === 2
            ? 'Inputs'
            : n === 3
            ? 'Change'
            : n === 4
            ? 'Review & Sign'
            : 'Result'}
        </div>
      ))}
    </div>
  )

  const downloadTextFile = useCallback(
    (content: string, fileName: string) => {
      try {
        const blob = new Blob([content], { type: 'text/plain' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = fileName
        a.click()
        URL.revokeObjectURL(url)
      } catch (err: any) {
        notify('error', err?.message || 'Download failed.')
      }
    },
    [notify]
  )

  const handleDownloadBeef = useCallback(() => {
    if (!beefHex || !beefTxid) return
    downloadTextFile(beefHex, `tx_${beefTxid}.atomic-beef.txt`)
    notify('info', 'Atomic BEEF downloaded.')
  }, [beefHex, beefTxid, downloadTextFile, notify])

  const handleCopyBeef = useCallback(async () => {
    if (!beefHex) return
    try {
      await navigator.clipboard.writeText(beefHex)
      notify('success', 'Atomic BEEF copied to clipboard.')
    } catch (err: any) {
      notify('error', err?.message || 'Clipboard copy failed.')
    }
  }, [beefHex, notify])

  const handleCopyRaw = useCallback(async () => {
    if (!rawTxHex) return
    try {
      await navigator.clipboard.writeText(rawTxHex)
      notify('success', 'Raw transaction hex copied.')
    } catch (err: any) {
      notify('error', err?.message || 'Clipboard copy failed.')
    }
  }, [rawTxHex, notify])

  const handleDownloadRaw = useCallback(() => {
    if (!rawTxHex || !beefTxid) return
    downloadTextFile(rawTxHex, `tx_${beefTxid}.raw-tx.txt`)
    notify('info', 'Raw transaction hex downloaded.')
  }, [rawTxHex, beefTxid, downloadTextFile, notify])

  // Helpers: Select/Deselect all inputs; "all funds available" flow
  const selectAllInputs = () => {
    const next: Record<string, boolean> = {}
    vault.coins.forEach((c) => {
      next[`${c.txid}:${c.outputIndex}`] = true
    })
    setManualInputs(next)
  }
  const clearAllInputs = () => setManualInputs({})

  return (
    <section className="section">
      <h2 style={{
        marginTop: 0,
        marginBottom: 8,
        fontSize: 14,
        fontWeight: 600,
        letterSpacing: '0.08em',
        textTransform: 'uppercase',
        color: COLORS.textSecondary
      }}>
        Build Outgoing Transaction
      </h2>
      <StepIndicator />

      {scanningForOutput !== null && (
        <QRScanner
          onScan={(data) => handleQRScan(scanningForOutput, data)}
          onError={(err) => {
            notify('error', err)
            setScanningForOutput(null)
          }}
          onClose={() => setScanningForOutput(null)}
        />
      )}

      {step === 1 && (
        <div>
          <div style={{ marginBottom: 8, color: COLORS.gray600, fontSize: 12, lineHeight: 1.6 }}>
            Add one or more outputs for the transaction.
          </div>
          <div style={{ display: 'grid', gap: 12 }}>
            {outputs.map((output, index) => (
              <div
                key={index}
                style={{
                  display: 'grid',
                  gap: 8,
                  gridTemplateColumns: '1fr',
                  padding: 12,
                  background: 'var(--color-bg-secondary)',
                  border: '1px solid var(--color-border-secondary)',
                  borderRadius: 6
                }}
              >
                <div style={{
                  fontSize: 11,
                  fontWeight: 600,
                  letterSpacing: '0.04em',
                  textTransform: 'uppercase',
                  color: COLORS.textSecondary
                }}>
                  Output {index + 1}
                </div>
                <div style={{ display: 'grid', gap: 4 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label style={{
                      fontSize: 12,
                      fontWeight: 600,
                      letterSpacing: '0.03em',
                      color: COLORS.textSecondary
                    }}>
                      Address or Script Hex
                    </label>
                    <button
                      onClick={() => setScanningForOutput(index)}
                      className="btn-ghost"
                      style={{ fontSize: 11, padding: '4px 8px', height: 'auto' }}
                    >
                      📷 Scan QR
                    </button>
                  </div>
                  <input
                    placeholder="Address or Script Hex"
                    value={output.destinationAddressOrScript}
                    onChange={(e) =>
                      handleOutputChange(index, 'destinationAddressOrScript', e.target.value)
                    }
                    className="input"
                    autoComplete="off"
                  />
                </div>
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  placeholder="Satoshis"
                  value={output.satoshis}
                  onChange={(e) => handleOutputChange(index, 'satoshis', e.target.value)}
                  className="input"
                  autoComplete="off"
                  maxLength={16}
                />
                <input
                  placeholder="Memo (optional)"
                  value={output.memo}
                  onChange={(e) => handleOutputChange(index, 'memo', e.target.value)}
                  className="input"
                  autoComplete="off"
                  maxLength={256}
                />
                <button
                  onClick={() => removeOutput(index)}
                  disabled={outputs.length <= 1}
                  className="btn-remove"
                  style={{ width: '100%' }}
                >
                  Remove Output
                </button>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 12, display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr' }}>
            <button
              onClick={addOutput}
              className="btn-ghost"
            >
              + Add Output
            </button>
            <button onClick={nextFromOutputs} className="btn">
              Next: Select Inputs
            </button>
          </div>
        </div>
      )}

      {step === 2 && (
        <div>
          <b>Input Selection</b>
          <div
            style={{
              background: 'var(--color-bg-elevated)',
              padding: '8px 12px',
              borderRadius: 8,
              marginTop: 8,
              border: `1px solid var(--color-border-secondary)`,
              borderLeft: `4px solid ${totalInputSats >= totalOutputSats ? COLORS.green : COLORS.red}`
            }}
          >
            <div>
              Required for outputs: <b>{totalOutputSats.toLocaleString()} sats</b>
            </div>
            <div>
              Selected from inputs:{' '}
              <b
                style={{
                  color: totalInputSats >= totalOutputSats ? COLORS.green : COLORS.red
                }}
              >
                {totalInputSats.toLocaleString()} sats
              </b>
            </div>
            {totalInputSats < totalOutputSats && (
              <div style={{ fontSize: 12, color: COLORS.red, marginTop: 4 }}>
                You need to select at least{' '}
                {(totalOutputSats - totalInputSats).toLocaleString()} more sats.
              </div>
            )}
          </div>

          <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
            <button onClick={selectAllInputs} className="btn-ghost">
              Select All UTXOs
            </button>
            <button onClick={clearAllInputs} className="btn-ghost">
              Clear All
            </button>
          </div>

          {vault.coins.length === 0 && <div style={{ marginTop: 8 }}>No spendable UTXOs</div>}
          {vault.coins.map((c) => {
            const id = `${c.txid}:${c.outputIndex}`
            let sats = 0
            try {
              const tx = getTxFromStore(vault.beefStore, c.txid)
              sats = tx.outputs[c.outputIndex].satoshis as number
            } catch {}
            return (
              <div key={id} style={{ padding: '6px 0', wordBreak: 'break-all' }}>
                <label>
                  <input
                    type="checkbox"
                    checked={!!manualInputs[id]}
                    onChange={(e) =>
                      setManualInputs((prev) => ({ ...prev, [id]: e.target.checked }))
                    }
                  />{' '}
                  {id} — {sats.toLocaleString()} sats ({(sats / 100000000).toFixed(8)} BSV)
                </label>
              </div>
            )
          })}
          <div style={{ marginTop: 10, display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr' }}>
            <button onClick={() => setStep(1)} className="btn-ghost">
              Back
            </button>
            <button onClick={nextFromInputs} className="btn">
              Next: Choose Change
            </button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 8 }}>
            <div>
              <b>Change Keys</b>
              <div style={{ marginTop: 6, color: COLORS.gray600, fontSize: 12 }}>
                Select at least one key to receive change.
              </div>
            </div>
            <button
              onClick={handleGenerateNewChangeKey}
              className="btn-ghost"
              style={{ background: COLORS.green }}
            >
              Generate New Key
            </button>
          </div>

          {vault.keys.map((k) => (
            <div key={k.serial} style={{ padding: '6px 0' }}>
              <label>
                <input
                  type="checkbox"
                  checked={!!changeSerials[k.serial]}
                  onChange={(e) =>
                    setChangeSerials((prev) => ({ ...prev, [k.serial]: e.target.checked }))
                  }
                />{' '}
                {k.serial} {k.memo && `— ${k.memo}`}{' '}
                {k.usedOnChain ? (
                  <span style={{ color: '#b36' }}> (used)</span>
                ) : (
                  <span style={{ color: COLORS.green }}>(unused)</span>
                )}
              </label>
            </div>
          ))}
          <div style={{ marginTop: 12, display: 'grid', alignItems: 'center', gap: 8 }}>
            {vault.confirmOutgoingCoins && (
              <label style={{ display: 'grid', gap: 4 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <input
                    type="checkbox"
                    checked={requirePerUtxoAttestation}
                    onChange={(e) => setRequirePerUtxoAttestation(e.target.checked)}
                  />
                  <span>Require per-UTXO attestation while signing</span>
                </span>
                <span style={{ fontSize: 12, color: COLORS.gray600, marginLeft: 26 }}>
                  When enabled, each input prompts the operator to confirm it against their
                  independent HONEST chain view before the signature is applied.
                </span>
              </label>
            )}
            <input
              placeholder="Transaction Memo (optional)"
              value={txMemo}
              onChange={(e) => setTxMemo(e.target.value)}
              className="input"
              autoComplete="off"
            />
          </div>
          <div style={{ marginTop: 10, display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr' }}>
            <button onClick={() => setStep(2)} className="btn-ghost">
              Back
            </button>
            <button onClick={nextFromChange} className="btn">
              Next: Review & Sign
            </button>
          </div>
        </div>
      )}

      {step === 4 && (
        <div>
          <b>Review</b>
          <div style={{ display: 'grid', gap: 12, marginTop: 8 }}>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>Outputs</div>
              <div
                style={{
                  border: `1px solid ${COLORS.border}`,
                  borderRadius: 8,
                  padding: 8,
                  marginTop: 6,
                  fontFamily: 'monospace',
                  whiteSpace: 'pre-wrap',
                  fontSize: 12,
                  overflowX: 'auto'
                }}
              >
                {parsedOutputs
                  .map(
                    (o, i) =>
                      `${i + 1}. ${o.destinationAddressOrScript} ${o.satoshis}${o.memo ? ` (${o.memo})` : ''}`
                  )
                  .join('\n')}
              </div>
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>Inputs</div>
              <div
                style={{
                  border: `1px solid ${COLORS.border}`,
                  borderRadius: 8,
                  padding: 8,
                  marginTop: 6,
                  fontFamily: 'monospace',
                  whiteSpace: 'pre-wrap',
                  fontSize: 12
                }}
              >
                {Object.keys(manualInputs)
                  .filter((id) => manualInputs[id])
                  .join('\n') || '—'}
              </div>
              <div style={{ marginTop: 8, fontSize: 12 }}>
                Change Keys:{' '}
                <b>
                  {Object.keys(changeSerials)
                    .filter((s) => changeSerials[s])
                    .join(', ') || '—'}
                </b>
              </div>
              <div style={{ marginTop: 4, fontSize: 12 }}>
                Per-UTXO Attestation:{' '}
                <b>
                  {vault.confirmOutgoingCoins
                    ? requirePerUtxoAttestation
                      ? 'Enabled'
                      : 'Disabled'
                    : 'Policy off'}
                </b>
              </div>
              {txMemo && (
                <div style={{ marginTop: 4, fontSize: 12 }}>
                  Tx Memo: <b>{txMemo}</b>
                </div>
              )}
            </div>
          </div>

          <div style={{ marginTop: 12, display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr' }}>
            <button onClick={() => setStep(3)} className="btn-ghost">
              Back
            </button>
            <button onClick={buildAndSign} disabled={isBuilding} className="btn">
              {isBuilding ? 'Building...' : 'Finalize & Sign'}
            </button>
          </div>
        </div>
      )}

      {step === 5 && (
        <div>
          <h3 style={{
            marginTop: 0,
            fontSize: 14,
            fontWeight: 600,
            letterSpacing: '0.05em',
            textTransform: 'uppercase',
            color: COLORS.textSecondary
          }}>
            Transaction Result
          </h3>
          {beefHex && beefTxid ? (
            <div
              style={{
                border: `1px solid ${COLORS.border}`,
                borderRadius: 6,
                padding: 16,
                marginTop: 8,
                display: 'grid',
                gap: 16
              }}
            >
              <div style={{
                fontSize: 12,
                fontFamily: '"SF Mono", "Monaco", monospace',
                wordBreak: 'break-all',
                background: 'var(--color-bg-primary)',
                padding: 10,
                borderRadius: 4,
                border: '1px solid var(--color-border-secondary)'
              }}>
                <span style={{ color: COLORS.gray600 }}>TXID:</span>{' '}
                <span style={{ color: COLORS.accent }}>{beefTxid}</span>
              </div>

              <div style={{ display: 'grid', gap: 10 }}>
                <div style={{
                  fontWeight: 600,
                  fontSize: 13,
                  letterSpacing: '0.03em',
                  color: COLORS.text
                }}>
                  Atomic BEEF Transaction
                </div>

                {showBeefQR ? (
                  <div style={{ display: 'grid', gap: 10 }}>
                    <QRDisplay
                      data={beefHex}
                      size={350}
                      label="Atomic BEEF QR"
                      onError={(err) => notify('error', err)}
                    />
                    <button
                      onClick={() => setShowBeefQR(false)}
                      className="btn-ghost"
                    >
                      Hide QR Code
                    </button>
                  </div>
                ) : (
                  <>
                    <div
                      style={{
                        border: `1px solid ${COLORS.border}`,
                        borderRadius: 4,
                        padding: 10,
                        fontFamily: '"SF Mono", "Monaco", monospace',
                        fontSize: 11,
                        maxHeight: 160,
                        overflowY: 'auto',
                        wordBreak: 'break-all',
                        background: 'var(--color-bg-primary)',
                        color: COLORS.textSecondary
                      }}
                    >
                      {beefHex}
                    </div>
                    <div style={{ display: 'grid', gap: 8, gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
                      <button onClick={() => setShowBeefQR(true)} className="btn">
                        Show as QR Code
                      </button>
                      <button onClick={() => handleCopyBeef()} className="btn-ghost">
                        Copy to Clipboard
                      </button>
                      <button onClick={handleDownloadBeef} className="btn-ghost">
                        Download (.txt)
                      </button>
                    </div>
                  </>
                )}
              </div>

              <div style={{ display: 'grid', gap: 10 }}>
                <div style={{
                  fontWeight: 600,
                  fontSize: 13,
                  letterSpacing: '0.03em',
                  color: COLORS.text
                }}>
                  Raw Transaction Hex
                </div>
                {rawTxHex ? (
                  <>
                    <div
                      style={{
                        border: `1px solid ${COLORS.border}`,
                        borderRadius: 4,
                        padding: 10,
                        fontFamily: '"SF Mono", "Monaco", monospace',
                        fontSize: 11,
                        maxHeight: 160,
                        overflowY: 'auto',
                        wordBreak: 'break-all',
                        background: 'var(--color-bg-primary)',
                        color: COLORS.textSecondary
                      }}
                    >
                      {rawTxHex}
                    </div>
                    <div style={{ display: 'grid', gap: 8, gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))' }}>
                      <button onClick={() => handleCopyRaw()} className="btn-ghost">
                        Copy Raw Hex
                      </button>
                      <button onClick={handleDownloadRaw} className="btn-ghost">
                        Download (.txt)
                      </button>
                    </div>
                  </>
                ) : (
                  <div style={{
                    fontSize: 12,
                    color: COLORS.gray600,
                    fontStyle: 'italic',
                    padding: 10,
                    background: 'var(--color-bg-primary)',
                    borderRadius: 4
                  }}>
                    Raw hex export unavailable. Use the Atomic BEEF file for broadcasting.
                  </div>
                )}
              </div>

              <div style={{
                fontSize: 12,
                color: COLORS.gray600,
                lineHeight: 1.6,
                padding: 12,
                background: 'rgba(201, 169, 97, 0.05)',
                border: '1px solid var(--color-border-accent)',
                borderRadius: 4
              }}>
                <strong style={{ color: COLORS.accent }}>Next Steps:</strong> Share the Atomic BEEF (via QR or file) with your broadcast operator.
                Then <strong>SAVE the vault</strong> to persist changes. Use your preferred broadcaster (WhatsOnChain, ARC, etc.) with the raw hex. Keep the BEEF for recovery.
              </div>
            </div>
          ) : (
            <div style={{ marginTop: 8 }}>No result to show.</div>
          )}
          <div style={{ marginTop: 12, display: 'grid', justifyContent: 'end' }}>
            <button onClick={resetWizard} className="btn">
              Create Another
            </button>
          </div>
        </div>
      )}
    </section>
  )
}

export default OutgoingWizard
