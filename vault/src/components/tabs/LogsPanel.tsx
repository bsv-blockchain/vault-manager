import React, { FC, useState } from 'react'
import Vault from '../../Vault'
import { AuditEvent } from '../../types'
import { useDialog } from '../dialogs/DialogProvider'

interface LogsPanelProps {
  vault: Vault
  onUpdate: () => void
}

const COLORS = {
  border: '#3a3f49',
  logBg: '#0f1216',
  logText: '#9da3ae',
  timestamp: '#6b7280'
}

const LogViewer: FC<{ log: AuditEvent[] }> = ({ log }) => (
  <div
    style={{
      height: 220,
      overflowY: 'auto',
      border: `1px solid ${COLORS.border}`,
      borderRadius: 4,
      padding: 12,
      background: COLORS.logBg,
      fontFamily: '"SF Mono", "Monaco", "Cascadia Code", "Roboto Mono", monospace',
      fontSize: 12,
      lineHeight: 1.6,
      boxShadow: 'inset 0 1px 3px rgba(0, 0, 0, 0.4)'
    }}
  >
    {[...log].reverse().map((e) => (
      <div
        key={e.at + e.event}
        style={{
          wordBreak: 'break-all',
          color: COLORS.logText,
          marginBottom: 4
        }}
      >
        <span style={{ color: COLORS.timestamp, fontWeight: 500 }}>
          [{new Date(e.at).toISOString()}]
        </span>{' '}
        {e.event}
        {e.data ? <span style={{ color: '#c9a961' }}>: {e.data}</span> : ''}
      </div>
    ))}
  </div>
)

const LogsPanel: FC<LogsPanelProps> = ({ vault, onUpdate }) => {
  const [customLogEntry, setCustomLogEntry] = useState('')
  const dialog = useDialog()

  const addCustomLog = async () => {
    if (!customLogEntry.trim()) return
    const ok = await dialog.confirm(
      'Are you sure you want to add this custom entry to the permanent vault log? This action cannot be undone.',
      {
        title: 'Confirm Log Entry',
        confirmText: 'Add Entry',
        cancelText: 'Keep Editing'
      }
    )
    if (ok) {
      vault.logVault('custom.entry', customLogEntry)
      setCustomLogEntry('')
      onUpdate()
    }
  }

  return (
    <section className="section">
      <h2 style={{ marginTop: 0 }}>Logs</h2>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
        <div>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: 8,
              gap: 8
            }}
          >
            <h3 style={{ margin: 0 }}>Vault Log (Permanent)</h3>
            <button onClick={() => vault.exportVaultLog()} className="btn-ghost">
              Download
            </button>
          </div>
          <LogViewer log={vault.vaultLog} />
          <div style={{ marginTop: 8, display: 'grid', gap: 8 }}>
            <input
              placeholder="Add custom vault log entry..."
              value={customLogEntry}
              onChange={(e) => setCustomLogEntry(e.target.value)}
              className="input"
            />
            <button onClick={addCustomLog} className="btn">
              Add Entry
            </button>
          </div>
        </div>
        <div>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: 8,
              gap: 8
            }}
          >
            <h3 style={{ margin: 0 }}>Session Log (Temporary)</h3>
            <button onClick={() => vault.exportSessionLog()} className="btn-ghost">
              Download
            </button>
          </div>
          <LogViewer log={vault.sessionLog} />
        </div>
      </div>
    </section>
  )
}

export default LogsPanel
