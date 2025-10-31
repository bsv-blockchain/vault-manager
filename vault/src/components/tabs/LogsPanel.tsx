import React, { FC, useState } from 'react'
import Vault from '../../Vault'
import { AuditEvent } from '../../types'
import { useDialog } from '../dialogs/DialogProvider'

interface LogsPanelProps {
  vault: Vault
  onUpdate: () => void
}

const COLORS = {
  border: '#ddd'
}

const LogViewer: FC<{ log: AuditEvent[] }> = ({ log }) => (
  <div
    style={{
      height: 200,
      overflowY: 'auto',
      border: `1px solid ${COLORS.border}`,
      borderRadius: 8,
      padding: 8,
      background: '#fcfcfc',
      fontFamily: 'monospace',
      fontSize: 12
    }}
  >
    {[...log].reverse().map((e) => (
      <div key={e.at + e.event} style={{ wordBreak: 'break-all' }}>
        {`[${new Date(e.at).toISOString()}] ${e.event}${e.data ? `: ${e.data}` : ''}`}
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
            <h3 style={{ margin: 0 }}>Session Log (Ephemeral)</h3>
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
