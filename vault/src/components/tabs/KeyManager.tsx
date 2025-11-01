import React, { FC, useState } from 'react'
import Vault from '../../Vault'
import { Notification } from '../../types'
import { useDialog } from '../dialogs/DialogProvider'
import QRDisplay from '../common/QRDisplay'

interface KeyManagerProps {
  vault: Vault
  onUpdate: () => void
  notify: (type: Notification['type'], msg: string) => void
}

const COLORS = {
  green: '#5a9367',
  gray600: '#6b7280',
  border: '#3a3f49',
  text: '#e4e6eb',
  textSecondary: '#9da3ae'
}

const KeyManager: FC<KeyManagerProps> = ({ vault, onUpdate, notify }) => {
  const dialog = useDialog()
  const [hoverMap, setHoverMap] = useState<Record<string, boolean>>({})
  const [editingSerial, setEditingSerial] = useState<string | null>(null)
  const [memoDraft, setMemoDraft] = useState('')
  const [savingMemo, setSavingMemo] = useState(false)
  const [showQRSerial, setShowQRSerial] = useState<string | null>(null)

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
      <h2 style={{
        marginTop: 0,
        fontSize: 14,
        fontWeight: 600,
        letterSpacing: '0.08em',
        textTransform: 'uppercase',
        color: COLORS.textSecondary
      }}>
        Keys ({vault.keys.length})
      </h2>
      <p style={{
        fontSize: 12,
        color: COLORS.gray600,
        margin: '0 0 12px 0',
        lineHeight: 1.6
      }}>
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
            {showQRSerial === k.serial && (
              <div style={{ marginTop: 12 }}>
                <QRDisplay
                  data={k.public.toAddress()}
                  size={280}
                  label={`Address QR - ${k.serial}`}
                />
                <button
                  onClick={() => setShowQRSerial(null)}
                  className="btn-ghost"
                  style={{ width: '100%', marginTop: 12 }}
                >
                  Hide QR Code
                </button>
              </div>
            )}
            <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr' }}>
              <button
                onClick={() => setShowQRSerial(showQRSerial === k.serial ? null : k.serial)}
                className="btn"
              >
                {showQRSerial === k.serial ? 'Hide QR' : 'Show QR Code'}
              </button>
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
