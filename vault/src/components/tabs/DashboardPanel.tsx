import React, { FC } from 'react'
import Vault from '../../Vault'
import { getTxFromStore } from '../../utils'

interface DashboardPanelProps {
  vault: Vault
  balance: number
  triggerRerender: () => void
}

const COLORS = {
  green: '#5a9367',
  red: '#c45c5c',
  border: '#3a3f49',
  label: '#6b7280',
  value: '#e4e6eb'
}

const DashboardPanel: FC<DashboardPanelProps> = ({ vault, balance, triggerRerender }) => {
  return (
    <section className="section">
      <h2 style={{
        marginTop: 0,
        fontSize: 14,
        fontWeight: 600,
        letterSpacing: '0.08em',
        textTransform: 'uppercase',
        color: '#9da3ae'
      }}>
        Dashboard
      </h2>
      <div style={{
        fontSize: 15,
        padding: '12px 0',
        borderBottom: `1px solid ${COLORS.border}`,
        marginBottom: 16
      }}>
        <span style={{ color: COLORS.label, fontSize: 13, letterSpacing: '0.02em' }}>
          TOTAL BALANCE
        </span>
        <div style={{ marginTop: 6, fontSize: 18, fontWeight: 600, color: COLORS.value }}>
          {balance.toLocaleString()} <span style={{ fontSize: 14, color: COLORS.label }}>sats</span>
          <span style={{ margin: '0 8px', color: COLORS.border }}>•</span>
          {(balance / 100000000).toFixed(8)} <span style={{ fontSize: 14, color: COLORS.label }}>BSV</span>
        </div>
      </div>
      <div
        style={{
          display: 'grid',
          gap: 16,
          marginTop: 12,
          gridTemplateColumns: '1fr'
        }}
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          <h3 style={{
            fontSize: 13,
            fontWeight: 600,
            letterSpacing: '0.05em',
            textTransform: 'uppercase',
            color: '#9da3ae',
            marginBottom: 12
          }}>
            Current UTXOs ({vault.coins.length})
          </h3>
          {vault.coins.length === 0 && (
            <div style={{
              color: COLORS.label,
              fontSize: 13,
              fontStyle: 'italic',
              padding: '16px 0'
            }}>
              No spendable coins
            </div>
          )}
          {vault.coins.map((c) => {
            const id = `${c.txid}:${c.outputIndex}`
            let sats = 0
            try {
              const tx = getTxFromStore(vault.beefStore, c.txid)
              sats = tx.outputs[c.outputIndex].satoshis as number
            } catch {}
            return (
              <div
                key={id}
                style={{
                  borderTop: `1px solid ${COLORS.border}`,
                  padding: '12px 0',
                  fontSize: 12,
                  wordBreak: 'break-all'
                }}
              >
                <div style={{
                  fontFamily: '"SF Mono", "Monaco", monospace',
                  color: COLORS.value,
                  marginBottom: 6,
                  fontSize: 11
                }}>
                  {id}
                </div>
                <div style={{ color: COLORS.label, fontSize: 13 }}>
                  {sats.toLocaleString()} sats
                  <span style={{ margin: '0 6px', color: COLORS.border }}>•</span>
                  <span style={{ color: COLORS.value, fontWeight: 600 }}>
                    {(sats / 100000000).toFixed(8)}
                  </span> BSV
                </div>
                {c.memo && (
                  <div style={{
                    marginTop: 6,
                    color: '#c9a961',
                    fontSize: 12,
                    fontStyle: 'italic'
                  }}>
                    {c.memo}
                  </div>
                )}
              </div>
            )
          })}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <h3 style={{
            fontSize: 13,
            fontWeight: 600,
            letterSpacing: '0.05em',
            textTransform: 'uppercase',
            color: '#9da3ae',
            marginBottom: 12
          }}>
            Transaction Log ({vault.transactionLog.length})
          </h3>
          {[...vault.transactionLog].reverse().map((t) => (
            <div
              key={t.at + t.txid}
              style={{
                borderTop: `1px solid ${COLORS.border}`,
                padding: '12px 0',
                fontSize: 12,
                wordBreak: 'break-all'
              }}
            >
              <div style={{
                fontFamily: '"SF Mono", "Monaco", monospace',
                color: COLORS.value,
                marginBottom: 6,
                fontSize: 11
              }}>
                {t.txid}
              </div>
              {t.memo && (
                <div style={{
                  marginBottom: 6,
                  color: '#c9a961',
                  fontSize: 12,
                  fontStyle: 'italic'
                }}>
                  {t.memo}
                </div>
              )}
              <div style={{
                color: t.net >= 0 ? COLORS.green : COLORS.red,
                fontSize: 13,
                fontWeight: 600,
                marginBottom: 8
              }}>
                {t.net >= 0 ? '+' : ''}{t.net.toLocaleString()} sats
                <span style={{ margin: '0 6px', color: COLORS.border }}>•</span>
                {t.net >= 0 ? '+' : ''}{(t.net / 100000000).toFixed(8)} BSV
              </div>
              <label style={{
                display: 'inline-flex',
                gap: 10,
                alignItems: 'center',
                cursor: 'pointer',
                fontSize: 12,
                color: COLORS.label
              }}>
                <input
                  type="checkbox"
                  checked={t.processed}
                  onChange={(e) => {
                    vault.markProcessed(t.txid, e.target.checked)
                    triggerRerender()
                  }}
                />
                <span style={{ letterSpacing: '0.02em' }}>MARK PROCESSED</span>
              </label>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

export default DashboardPanel
