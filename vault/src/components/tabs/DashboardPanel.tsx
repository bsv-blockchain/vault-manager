import React, { FC } from 'react'
import Vault from '../../Vault'
import { getTxFromStore } from '../../utils'

interface DashboardPanelProps {
  vault: Vault
  balance: number
  triggerRerender: () => void
}

const COLORS = {
  green: '#0a7b22',
  red: '#8b0000',
  border: '#ddd'
}

const DashboardPanel: FC<DashboardPanelProps> = ({ vault, balance, triggerRerender }) => {
  return (
    <section className="section">
      <h2 style={{ marginTop: 0 }}>Dashboard</h2>
      <div>
        Total balance: <b>{balance.toLocaleString()}</b> sats (
        <b>{(balance / 100000000).toFixed(8)}</b> BSV)
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
          <h3>Current UTXOs ({vault.coins.length})</h3>
          {vault.coins.length === 0 && <div>No spendable coins</div>}
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
                  padding: '8px 0',
                  fontSize: '12px',
                  wordBreak: 'break-all'
                }}
              >
                <div>
                  <b>{id}</b> — {sats.toLocaleString()} sats (
                  <b>{(sats / 100000000).toFixed(8)}</b> BSV)
                </div>
                {c.memo && <div>Memo: {c.memo}</div>}
              </div>
            )
          })}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <h3>Transaction Log ({vault.transactionLog.length})</h3>
          {[...vault.transactionLog].reverse().map((t) => (
            <div
              key={t.at + t.txid}
              style={{
                borderTop: `1px solid ${COLORS.border}`,
                padding: '8px 0',
                fontSize: '12px',
                wordBreak: 'break-all'
              }}
            >
              <div>
                <b>{t.txid}</b>
              </div>
              {t.memo && <div>Memo: {t.memo}</div>}
              <div style={{ color: t.net >= 0 ? COLORS.green : COLORS.red }}>
                Net: {t.net.toLocaleString()} sats (<b>{(t.net / 100000000).toFixed(8)}</b> BSV)
              </div>
              <label style={{ display: 'inline-flex', gap: 8, alignItems: 'center', marginTop: 4 }}>
                <input
                  type="checkbox"
                  checked={t.processed}
                  onChange={(e) => {
                    vault.markProcessed(t.txid, e.target.checked)
                    triggerRerender()
                  }}
                />
                Mark processed
              </label>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

export default DashboardPanel
