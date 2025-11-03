import { useState } from 'react'
import { PublicKey, Utils, PrivateKey } from '@bsv/sdk'
import QRDisplay from '../common/QRDisplay'
import QRScanner from '../common/QRScanner'
import { useWallet } from '../../context/wallet'
import { brc29ProtocolID } from '@bsv/wallet-toolbox-client'

const COLORS = {
  textSecondary: '#9da3ae'
}

const getCurrentDate = (daysOffset: number) => {
  const today = new Date()
  today.setDate(today.getDate() - daysOffset)
  return today.toISOString().split('T')[0]
}

interface ReceiveProps {
  onError: (error: string) => void
}

export default function Receive({ onError }: ReceiveProps) {
  const wallet = useWallet()
  const [receiveAddress, setReceiveAddress] = useState<string | null>(null)
  const [showReceiveScanner, setShowReceiveScanner] = useState(false)
  const [isGeneratingAddress, setIsGeneratingAddress] = useState(false)

  const derivationPrefix = Utils.toBase64(Utils.toArray(getCurrentDate(0), 'utf8'))
  const derivationSuffix = Utils.toBase64(Utils.toArray('transfer', 'utf8'))

  const handleGenerateReceiveAddress = async () => {
    setIsGeneratingAddress(true)

    try {
      const { publicKey } = await wallet.getPublicKey({
        protocolID: brc29ProtocolID,
        keyID: derivationPrefix + ' ' + derivationSuffix,
        counterparty: 'anyone',
        forSelf: true
      })
      const address = PublicKey.fromString(publicKey).toAddress()
      setReceiveAddress(address)
    } catch (e: any) {
      onError(e.message || 'Failed to generate address')
    } finally {
      setIsGeneratingAddress(false)
    }
  }

  const handleReceiveQRScan = async (data: string) => {
    setShowReceiveScanner(false)

    try {

      const tx = Utils.toArray(data, 'hex')

      await wallet.internalizeAction({
        tx, // Atomic BEEF hex
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
    } catch (e: any) {
      onError(e.message || 'Failed to process received transaction')
    }
  }

  return (
    <>
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

      {/* QR Scanner */}
      {showReceiveScanner && (
        <QRScanner
          onScan={handleReceiveQRScan}
          onClose={() => setShowReceiveScanner(false)}
        />
      )}
    </>
  )
}
