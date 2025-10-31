import React, { FC, useState } from 'react'
import Vault from '../../Vault'
import { Notification } from '../../types'
import { useDialog } from '../dialogs/DialogProvider'

interface KeyManagerProps {
  vault: Vault
  onUpdate: () => void
  notify: (type: Notification['type'], msg: string) => void
}

const COLORS = {
  green: '#0a7b22',
  gray600: '#555',
  border: '#ddd'
}

const KeyManager: FC<KeyManagerProps> = ({ vault, onUpdate, notify }) => {
  const dialog = useDialog()
  const [hoverMap, setHoverMap] = useState<Record<string, boolean>>({})
  const [editingSerial, setEditingSerial] = useState<string | null>(null)
  const [memoDraft, setMemoDraft] = useState('')
  const [savingMemo, setSavingMemo] = useState(false)

  const beginEdit = (serial: string, currentMemo: string) => {
    setEditingSerial(serial)
    setMemoDraft(currentMemo || '')
  }

  const cancelEdit = () => {
    setEditingSerial(null)
    setMemoDraft('')
    setSavingMemo(false)
  }

  const saveMemo = async () => {
    if (!editingSerial) return
    setSavingMemo(true)
    try {
      await vault.updateKeyMemo(editingSerial, memoDraft)
      notify('success', `Memo updated for ${editingSerial}.`)
      onUpdate()
      cancelEdit()
    } catch (e: any) {
      notify('error', e?.message || 'Failed to update memo.')
      setSavingMemo(false)
    }
  }

  return (
    <section className="section">
      <h2 style={{ marginTop: 0 }}>Keys ({vault.keys.length})</h2>
      <p style={{ fontSize: 12, color: COLORS.gray600, margin: '0 0 8px 0' }}>
        Generate as many fresh keys as you need. Deposit slips bundle the address, script, and
        metadata you can hand to counterparties.
      </p>
      <button
        onClick={async () => {
          await vault.generateKey('')
          onUpdate()
          notify('success', 'New key generated.')
        }}
        className="btn"
      >
        Generate New Key
      </button>
      <div style={{ marginTop: 12 }}>
        {[...vault.keys].reverse().map((k) => (
          <div
            key={k.serial}
            style={{
              borderTop: `1px solid ${COLORS.border}`,
              padding: '8px 0',
              display: 'grid',
              gridTemplateColumns: '1fr',
              gap: 8
            }}
          >
            <div>
              <b>{k.serial}</b> {k.memo && editingSerial !== k.serial && `— ${k.memo}`}{' '}
              {k.usedOnChain ? (
                <span style={{ color: '#b36' }}> (used)</span>
              ) : (
                <span style={{ color: COLORS.green }}>(unused)</span>
              )}
              <div
                style={{
                  fontSize: 12,
                  color: COLORS.gray600,
                  fontFamily: 'monospace',
                  wordBreak: 'break-all'
                }}
              >
                {k.public.toAddress()}
              </div>
            </div>
            <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr' }}>
              <button
                onClick={async () => {
                  await vault.downloadDepositSlipTxt(k.serial)
                  notify('info', `Deposit slip generated for ${k.serial}`)
                }}
                className="btn-ghost"
                title="Creates a text file with the address, script, and metadata you can hand to counterparties as a receipt."
              >
                Deposit Slip (.txt)
              </button>
              <button
                onMouseEnter={() => setHoverMap((m) => ({ ...m, [k.serial]: true }))}
                onMouseLeave={() => setHoverMap((m) => ({ ...m, [k.serial]: false }))}
                onClick={async () => {
                  await navigator.clipboard.writeText(k.public.toAddress())
                  await dialog.alert(
                    `Address copied.\n\nFor your security, paste the address into a trusted editor and verify it EXACTLY matches:\n\n${k.public.toAddress()}\n\nMalware can rewrite clipboard contents. Always compare before broadcasting or sending.`,
                    'Verify Copied Address'
                  )
                }}
                className="btn-ghost"
                style={{ background: hoverMap[k.serial] ? '#555' : '#777' }}
              >
                Copy Address
              </button>
              {editingSerial === k.serial ? (
                <button className="btn-ghost" style={{ gridColumn: 'span 2', background: '#999' }} disabled>
                  Editing…
                </button>
              ) : (
                <button
                  onClick={() => beginEdit(k.serial, k.memo)}
                  className="btn-ghost"
                  style={{ gridColumn: 'span 2' }}
                >
                  Edit Memo
                </button>
              )}
            </div>
            {editingSerial === k.serial && (
              <div style={{ display: 'grid', gap: 8 }}>
                <input
                  value={memoDraft}
                  onChange={(e) => setMemoDraft(e.target.value)}
                  className="input"
                  placeholder="Optional memo (visible in this vault only)"
                  maxLength={256}
                />
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button onClick={saveMemo} className="btn" disabled={savingMemo}>
                    {savingMemo ? 'Saving…' : 'Save Memo'}
                  </button>
                  <button onClick={cancelEdit} className="btn-ghost">
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </section>
  )
}

export default KeyManager
