import { useState } from 'react'
import { P2PKH, Utils } from '@bsv/sdk'
import QRScanner from '../common/QRScanner'
import { useWallet } from '../../context/wallet'
import { useTransactions } from '../../context/transactions'

interface Output {
  destinationAddressOrScript: string
  satoshis: string
  memo: string
}

const COLORS = {
  textSecondary: '#9da3ae',
  border: '#3a3f49'
}

interface SendCreateProps {
  onTransactionCreated: () => void
}

export default function SendCreate({ onTransactionCreated }: SendCreateProps) {
  const wallet = useWallet()
  const { addTransaction } = useTransactions()
  const [outputs, setOutputs] = useState<Output[]>([{ destinationAddressOrScript: '', satoshis: '', memo: '' }])
  const [scanningForOutput, setScanningForOutput] = useState<number | null>(null)
  const [isCreating, setIsCreating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const addOutput = () => {
    setOutputs([...outputs, { destinationAddressOrScript: '', satoshis: '', memo: '' }])
  }

  const removeOutput = (index: number) => {
    if (outputs.length > 1) {
      setOutputs(outputs.filter((_, i) => i !== index))
    }
  }

  const handleOutputChange = (index: number, field: keyof Output, value: string) => {
    const newOutputs = [...outputs]
    newOutputs[index][field] = value
    setOutputs(newOutputs)
  }

  const handleQRScan = (data: string) => {
    if (scanningForOutput !== null) {
      handleOutputChange(scanningForOutput, 'destinationAddressOrScript', data)
      setScanningForOutput(null)
    }
  }

  const validateOutputs = (): boolean => {
    for (const output of outputs) {
      if (!output.destinationAddressOrScript.trim()) {
        setError('All outputs must have an address or script')
        return false
      }
      const sats = parseInt(output.satoshis)
      if (isNaN(sats) || sats <= 0) {
        setError('All outputs must have a valid amount > 0')
        return false
      }
    }
    return true
  }

  const handleCreateTransaction = async () => {
    setError(null)
    if (!validateOutputs()) return

    try {
      setIsCreating(true)
      const actionOutputs = outputs.map(output => {
        let lockingScript: string
        if (output.destinationAddressOrScript.match(/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/)) {
          lockingScript = new P2PKH().lock(output.destinationAddressOrScript).toHex()
        } else {
          lockingScript = output.destinationAddressOrScript
        }
        return {
          lockingScript,
          satoshis: parseInt(output.satoshis),
          outputDescription: output.memo || 'BSV Transfer',
          basket: 'vault'
        }
      })

      const result = await wallet.createAction({
        description: 'BSV Transfer Transaction',
        outputs: actionOutputs,
        labels: ['transfer', 'outbound']
      })

      if (result?.txid && result?.tx) {
        // Store transaction in pending queue
        addTransaction({
          txid: result.txid,
          beefHex: Utils.toHex(result.tx),
          outputs: outputs.map(o => ({ ...o }))
        })

        // Reset form
        setOutputs([{ destinationAddressOrScript: '', satoshis: '', memo: '' }])

        // Notify parent to switch to queue view
        onTransactionCreated()
      } else {
        setError('Failed to create transaction')
      }
    } catch (e: any) {
      setError(e.message || 'Failed to create transaction')
    } finally {
      setIsCreating(false)
    }
  }

  return (
    <>
      {error && (
        <div style={{
          background: 'rgba(196, 92, 92, 0.15)',
          border: '1px solid var(--color-error)',
          color: 'var(--color-error)',
          padding: 14,
          marginBottom: 16,
          borderRadius: 4,
          fontSize: 13
        }}>
          {error}
        </div>
      )}

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
          Define Outputs
        </h2>

        <div style={{ display: 'grid', gap: 20 }}>
          {outputs.map((output, index) => (
            <div
              key={index}
              style={{
                border: `1px solid ${COLORS.border}`,
                borderRadius: 4,
                padding: 16,
                background: 'var(--color-bg-elevated)',
                display: 'grid',
                gap: 12
              }}
            >
              <div style={{
                fontSize: 12,
                fontWeight: 600,
                letterSpacing: '0.05em',
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
                  onChange={(e) => handleOutputChange(index, 'destinationAddressOrScript', e.target.value)}
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

        <div style={{ marginTop: 16, display: 'grid', gap: 8 }}>
          <button onClick={addOutput} className="btn-ghost">
            + Add Output
          </button>
          <button
            onClick={handleCreateTransaction}
            disabled={isCreating}
            className="btn"
          >
            {isCreating ? 'Creating Transaction...' : 'Sign Transaction'}
          </button>
        </div>
      </section>

      {/* QR Scanner */}
      {scanningForOutput !== null && (
        <QRScanner
          onScan={handleQRScan}
          onClose={() => setScanningForOutput(null)}
        />
      )}
    </>
  )
}
