import { useState } from 'react'
import QRDisplay from '../common/QRDisplay'
import { useTransactions } from '../../context/transactions'

const COLORS = {
  textSecondary: '#9da3ae',
  textMuted: '#6b7280',
  border: '#3a3f49'
}

interface SendQueueProps {
  onError: (error: string) => void
}

export default function SendQueue({ onError }: SendQueueProps) {
  const { pendingTransactions, removeTransaction, markAsConfirmed, isLoading } = useTransactions()
  const [selectedTxId, setSelectedTxId] = useState<string | null>(null)

  if (isLoading) {
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
          Outbound Transaction Queue
        </h2>
        <div style={{
          padding: 40,
          textAlign: 'center',
          color: COLORS.textSecondary,
          fontSize: 14
        }}>
          Loading transactions from wallet...
        </div>
      </section>
    )
  }

  if (pendingTransactions.length === 0) {
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
          Outbound Transaction Queue
        </h2>
        <div style={{
          padding: 40,
          textAlign: 'center',
          color: COLORS.textSecondary,
          fontSize: 14
        }}>
          No pending transactions. Create a transaction to add it to the queue.
        </div>
      </section>
    )
  }

  const selectedTx = selectedTxId ? pendingTransactions.find(tx => tx.id === selectedTxId) : null

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
        Outbound Transaction Queue
      </h2>

      {selectedTx ? (
        // Transaction Detail View
        <div>
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
              wordBreak: 'break-all',
              marginBottom: 16
            }}>
              {selectedTx.txid}
            </div>

            <div style={{
              fontSize: 12,
              color: COLORS.textSecondary,
              marginBottom: 8
            }}>
              Outputs:
            </div>
            {selectedTx.outputs.map((output, idx) => (
              <div key={idx} style={{
                fontSize: 11,
                padding: 8,
                marginBottom: 8,
                background: 'var(--color-bg-primary)',
                borderRadius: 4
              }}>
                <div style={{ marginBottom: 4 }}>
                  <span style={{ color: COLORS.textSecondary }}>To:</span>{' '}
                  <span style={{ fontFamily: 'monospace', fontSize: 10 }}>
                    {output.destinationAddressOrScript.substring(0, 20)}...
                  </span>
                </div>
                <div>
                  <span style={{ color: COLORS.textSecondary }}>Amount:</span>{' '}
                  <span style={{ color: 'var(--color-accent-gold)' }}>
                    {output.satoshis} sats
                  </span>
                  {output.memo && (
                    <>
                      {' - '}
                      <span style={{ fontStyle: 'italic' }}>{output.memo}</span>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* BEEF Hex Display */}
          <div style={{
            background: 'var(--color-bg-primary)',
            border: '1px solid var(--color-border-secondary)',
            borderRadius: 4,
            padding: 16,
            marginBottom: 16
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: 8
            }}>
              <div style={{
                fontSize: 12,
                color: COLORS.textSecondary,
                fontWeight: 600,
                letterSpacing: '0.05em',
                textTransform: 'uppercase'
              }}>
                Atomic BEEF (Hex)
              </div>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(selectedTx.beefHex)
                    .then(() => {
                      console.log('BEEF hex copied to clipboard')
                    })
                    .catch(err => {
                      console.error('Failed to copy:', err)
                      onError('Failed to copy to clipboard')
                    })
                }}
                className="btn-ghost"
                style={{
                  fontSize: 11,
                  padding: '4px 12px',
                  height: 'auto'
                }}
              >
                Copy
              </button>
            </div>
            <div style={{
              fontFamily: 'monospace',
              fontSize: 10,
              color: 'var(--color-accent-gold)',
              wordBreak: 'break-all',
              lineHeight: 1.6,
              maxHeight: 120,
              overflowY: 'auto',
              padding: 8,
              background: 'var(--color-bg-secondary)',
              borderRadius: 3,
              border: '1px solid var(--color-border-primary)'
            }}>
              {selectedTx.beefHex}
            </div>
            <div style={{
              fontSize: 10,
              color: COLORS.textMuted,
              marginTop: 8,
              fontStyle: 'italic'
            }}>
              {selectedTx.beefHex.length / 2} bytes • {selectedTx.beefHex.length} hex characters
            </div>
          </div>

          <div style={{ marginBottom: 16 }}>
            <QRDisplay
              data={selectedTx.beefHex}
              size={350}
              label="Scan to Transmit Transaction"
            />
          </div>

          <div style={{ display: 'grid', gap: 8 }}>
            <button
              onClick={() => {
                markAsConfirmed(selectedTxId)
                setSelectedTxId(null)
              }}
              className="btn"
              style={{ width: '100%' }}
            >
              Mark as Delivered
            </button>
            <button
              onClick={() => setSelectedTxId(null)}
              className="btn-ghost"
              style={{ width: '100%' }}
            >
              Back to Queue
            </button>
            <button
              onClick={() => {
                if (confirm('Are you sure you want to remove this transaction?')) {
                  removeTransaction(selectedTxId)
                  setSelectedTxId(null)
                }
              }}
              className="btn-remove"
              style={{ width: '100%' }}
            >
              Remove Transaction
            </button>
          </div>
        </div>
      ) : (
        // Transaction List View
        <div style={{ display: 'grid', gap: 12 }}>
          {pendingTransactions.map((tx) => (
            <div
              key={tx.id}
              style={{
                border: `1px solid ${tx.confirmed ? 'var(--color-success)' : COLORS.border}`,
                borderRadius: 4,
                padding: 16,
                background: 'var(--color-bg-elevated)',
                cursor: 'pointer',
                transition: 'all 0.2s',
                opacity: tx.confirmed ? 0.6 : 1
              }}
              onClick={() => setSelectedTxId(tx.id)}
            >
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
                marginBottom: 8
              }}>
                <div style={{
                  fontSize: 11,
                  fontWeight: 600,
                  letterSpacing: '0.05em',
                  textTransform: 'uppercase',
                  color: tx.confirmed ? 'var(--color-success)' : COLORS.textSecondary
                }}>
                  {tx.confirmed ? '✓ Delivered' : 'Pending'}
                </div>
                <div style={{
                  fontSize: 10,
                  color: COLORS.textMuted
                }}>
                  {new Date(tx.createdAt).toLocaleString()}
                </div>
              </div>

              <div style={{
                fontFamily: 'monospace',
                fontSize: 11,
                color: 'var(--color-accent-gold)',
                marginBottom: 8,
                wordBreak: 'break-all'
              }}>
                {tx.txid.substring(0, 16)}...{tx.txid.substring(tx.txid.length - 16)}
              </div>

              <div style={{
                fontSize: 12,
                color: COLORS.textSecondary
              }}>
                {tx.outputs.length} output{tx.outputs.length !== 1 ? 's' : ''} •{' '}
                {tx.outputs.reduce((sum, o) => sum + parseInt(o.satoshis), 0)} sats total
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
