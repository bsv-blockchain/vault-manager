import { useState } from 'react'
import { P2PKH, PrivateKey, WalletClient } from '@bsv/sdk'
import QRDisplay from './components/common/QRDisplay'
import QRScanner from './components/common/QRScanner'
import './styles/index.css'

type Mode = 'send' | 'receive'

interface Output {
  destinationAddressOrScript: string
  satoshis: string
  memo: string
}

const COLORS = {
  gray600: '#9da3ae',
  textSecondary: '#9da3ae',
  border: '#3a3f49'
}

export default function App() {
  const [mode, setMode] = useState<Mode>('send')
  const [outputs, setOutputs] = useState<Output[]>([{ destinationAddressOrScript: '', satoshis: '', memo: '' }])
  const [scanningForOutput, setScanningForOutput] = useState<number | null>(null)
  const [isCreating] = useState(false)
  const [beefHex, setBeefHex] = useState<string | null>(null)
  const [beefTxid, setBeefTxid] = useState<string | null>(null)
  const [showBeefQR, setShowBeefQR] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Receive mode state
  const [receiveAddress, setReceiveAddress] = useState<string | null>(null)
  const [showReceiveScanner, setShowReceiveScanner] = useState(false)
  const [isGeneratingAddress, setIsGeneratingAddress] = useState(false)

  // For real implementation: derive prefix from date
  // const getCurrentDate = () => new Date().toISOString().split('T')[0]
  // const derivationPrefix = Utils.toBase64(Utils.toArray(getCurrentDate(), 'utf8'))

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
      const wallet = new WalletClient()

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
          outputDescription: output.memo || 'BSV Transfer'
        }
      })

      const result = await wallet.createAction({
        description: 'BSV Transfer Transaction',
        outputs: actionOutputs,
        labels: ['transfer', 'outbound']
      })

      if (result?.txid) {
        setBeefTxid(result?.txid)
      } else {
        setError('Failed to create transaction')
      }
    } catch (e: any) {
      setError(e.message || 'Failed to create transaction')
    }
  }

  const handleGenerateReceiveAddress = async () => {
    setIsGeneratingAddress(true)
    setError(null)

    try {
      // This is a demo implementation - replace with real WalletClient.getPublicKey
      const privKey = new PrivateKey(1)
      const publicKey = privKey.toPublicKey()
      const address = publicKey.toAddress()

      setReceiveAddress(address)

      // Real implementation would be:
      /*
      const wallet = new WalletClient(yourWalletInterface, 'transfer.app')
      const { publicKey } = await wallet.getPublicKey({
        protocolID: brc29ProtocolID,
        keyID: derivationPrefix + ' ' + derivationSuffix,
        counterparty: 'anyone',
        forSelf: true
      })
      const address = PublicKey.fromString(publicKey).toAddress()
      setReceiveAddress(address)
      */
    } catch (e: any) {
      setError(e.message || 'Failed to generate address')
    } finally {
      setIsGeneratingAddress(false)
    }
  }

  const handleReceiveQRScan = async (_data: string) => {
    setShowReceiveScanner(false)
    setError(null)

    try {
      // This is a placeholder - in production you'd use WalletClient.internalizeAction
      setError('To use this feature, configure a WalletInterface. See the code for integration instructions.')

      // Real implementation would be:
      /*
      const wallet = new WalletClient(yourWalletInterface, 'transfer.app')
      const derivationSuffix = Utils.toBase64(Utils.toArray('transfer', 'utf8'))

      await wallet.internalizeAction({
        tx: data, // Atomic BEEF hex
        description: 'Received BSV via Transfer',
        outputs: [{
          outputIndex: 0,
          protocol: 'wallet payment',
          paymentRemittance: {
            senderIdentityKey: new PrivateKey(1).toPublicKey().toString(),
            derivationPrefix,
            derivationSuffix
          }
        }],
        labels: ['transfer', 'inbound']
      })

      alert('Transaction received successfully!')
      */
    } catch (e: any) {
      setError(e.message || 'Failed to process received transaction')
    }
  }

  const resetSend = () => {
    setOutputs([{ destinationAddressOrScript: '', satoshis: '', memo: '' }])
    setBeefHex(null)
    setBeefTxid(null)
    setShowBeefQR(false)
    setError(null)
  }

  return (
    <div className="app-shell">
      <div className="container">
        <div className="panel" style={{ padding: 24 }}>
          <h1 style={{
            marginTop: 0,
            fontSize: 22,
            fontWeight: 300,
            letterSpacing: '0.02em',
            color: 'var(--color-text-primary)',
            borderBottom: '1px solid var(--color-border-accent)',
            paddingBottom: 16,
            marginBottom: 24,
            background: 'linear-gradient(90deg, var(--color-accent-gold) 0%, var(--color-text-primary) 40%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text'
          }}>
            VAULT TRANSFER
          </h1>

          {/* Mode Selector */}
          <div style={{
            display: 'flex',
            gap: 8,
            marginBottom: 24,
            borderBottom: '1px solid var(--color-border-primary)',
            paddingBottom: 8
          }}>
            <button
              onClick={() => setMode('send')}
              className={mode === 'send' ? 'tab tab-active' : 'tab'}
            >
              Send
            </button>
            <button
              onClick={() => setMode('receive')}
              className={mode === 'receive' ? 'tab tab-active' : 'tab'}
            >
              Receive
            </button>
          </div>

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

          {/* SEND MODE */}
          {mode === 'send' && (
            <>
              {!beefHex ? (
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
                      {isCreating ? 'Creating Transaction...' : 'Create Transaction'}
                    </button>
                  </div>
                </section>
              ) : (
                <section className="section">
                  <h2 style={{
                    marginTop: 0,
                    fontSize: 14,
                    fontWeight: 600,
                    letterSpacing: '0.08em',
                    textTransform: 'uppercase',
                    color: COLORS.textSecondary
                  }}>
                    Transaction Created
                  </h2>

                  <div style={{
                    background: 'var(--color-bg-elevated)',
                    border: '1px solid var(--color-border-accent)',
                    borderRadius: 4,
                    padding: 16,
                    marginBottom: 16
                  }}>
                    <div style={{
                      fontSize: 12,
                      color: COLORS.textSecondary,
                      marginBottom: 8
                    }}>
                      Transaction ID:
                    </div>
                    <div style={{
                      fontFamily: 'monospace',
                      fontSize: 11,
                      color: 'var(--color-accent-gold)',
                      wordBreak: 'break-all'
                    }}>
                      {beefTxid}
                    </div>
                  </div>

                  {showBeefQR ? (
                    <div style={{ marginBottom: 16 }}>
                      <QRDisplay
                        data={beefHex}
                        size={350}
                        label="Atomic BEEF Transaction"
                      />
                      <button
                        onClick={() => setShowBeefQR(false)}
                        className="btn-ghost"
                        style={{ width: '100%', marginTop: 12 }}
                      >
                        Hide QR Code
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setShowBeefQR(true)}
                      className="btn"
                      style={{ width: '100%', marginBottom: 16 }}
                    >
                      Show as QR Code
                    </button>
                  )}

                  <button
                    onClick={resetSend}
                    className="btn-ghost"
                    style={{ width: '100%' }}
                  >
                    Create Another Transaction
                  </button>
                </section>
              )}
            </>
          )}

          {/* RECEIVE MODE */}
          {mode === 'receive' && (
            <section className="section">
              <h2 style={{
                marginTop: 0,
                fontSize: 14,
                fontWeight: 600,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                color: COLORS.textSecondary
              }}>
                Receive BSV
              </h2>

              {!receiveAddress ? (
                <button
                  onClick={handleGenerateReceiveAddress}
                  disabled={isGeneratingAddress}
                  className="btn"
                  style={{ width: '100%' }}
                >
                  {isGeneratingAddress ? 'Generating Address...' : 'Generate Receive Address'}
                </button>
              ) : (
                <>
                  <div style={{
                    background: 'var(--color-bg-elevated)',
                    border: '1px solid var(--color-border-accent)',
                    borderRadius: 4,
                    padding: 16,
                    marginBottom: 16
                  }}>
                    <div style={{
                      fontSize: 12,
                      color: COLORS.textSecondary,
                      marginBottom: 8
                    }}>
                      Your Receive Address:
                    </div>
                    <div style={{
                      fontFamily: 'monospace',
                      fontSize: 13,
                      color: 'var(--color-accent-gold)',
                      wordBreak: 'break-all'
                    }}>
                      {receiveAddress}
                    </div>
                  </div>

                  <div style={{ marginBottom: 16 }}>
                    <QRDisplay
                      data={receiveAddress}
                      size={280}
                      label="Receive Address"
                    />
                  </div>

                  <button
                    onClick={() => setShowReceiveScanner(true)}
                    className="btn"
                    style={{ width: '100%' }}
                  >
                    📷 Scan Transaction QR
                  </button>
                </>
              )}
            </section>
          )}

          {/* QR Scanners */}
          {scanningForOutput !== null && (
            <QRScanner
              onScan={handleQRScan}
              onClose={() => setScanningForOutput(null)}
            />
          )}

          {showReceiveScanner && (
            <QRScanner
              onScan={handleReceiveQRScan}
              onClose={() => setShowReceiveScanner(false)}
            />
          )}
        </div>
      </div>
    </div>
  )
}
