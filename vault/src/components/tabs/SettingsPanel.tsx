import React, { FC, useState } from 'react'
import Vault from '../../Vault'
import { HashRecord, BackupRecord, LoadedFileMeta } from '../../types'
import {
  validateVaultName,
  requireIntegerString,
  parseInteger
} from '../../validators'
import { useDialog } from '../dialogs/DialogProvider'

interface SettingsPanelProps {
  vault: Vault
  onUpdate: () => void
  setLastSavedPlainHash: (h: string | null) => void
  plainHash: string | null
  expectedHash?: HashRecord
  backups: BackupRecord[]
  onDownloadBackup: (entry: BackupRecord) => void
  loadedFileMeta: LoadedFileMeta | null
}

const COLORS = {
  gray600: '#6b7280',
  border: '#3a3f49',
  label: '#9da3ae',
  value: '#e4e6eb'
}

const SettingsPanel: FC<SettingsPanelProps> = ({
  vault,
  onUpdate,
  setLastSavedPlainHash,
  plainHash,
  expectedHash,
  backups,
  onDownloadBackup,
  loadedFileMeta
}) => {
  const [incoming, setIncoming] = useState(vault.confirmIncomingCoins)
  const [outgoing, setOutgoing] = useState(vault.confirmOutgoingCoins)
  const [phOld, setPhOld] = useState(String(vault.persistHeadersOlderThanBlocks))
  const [rvRecent, setRvRecent] = useState(String(vault.reverifyRecentHeadersAfterSeconds))
  const [rvHeight, setRvHeight] = useState(String(vault.reverifyCurrentBlockHeightAfterSeconds))
  const [useUserEntropy, setUseUserEntropy] = useState(vault.useUserEntropyForRandom)

  const [newName, setNewName] = useState(vault.vaultName)

  const dialog = useDialog()

  async function save() {
    // Validate inputs first
    const nameOk = validateVaultName(newName)
    if (nameOk !== true) {
      await dialog.alert(
        typeof nameOk === 'string' ? nameOk : 'Invalid vault name.',
        'Invalid Name'
      )
      return
    }
    const phOk = requireIntegerString(phOld, 'Persist headers (blocks)', { min: 0 })
    if (phOk !== true) {
      await dialog.alert(typeof phOk === 'string' ? phOk : 'Invalid number.', 'Invalid Setting')
      return
    }
    const rvROk = requireIntegerString(rvRecent, 'Re-verify recent headers (seconds)', { min: 1 })
    if (rvROk !== true) {
      await dialog.alert(typeof rvROk === 'string' ? rvROk : 'Invalid number.', 'Invalid Setting')
      return
    }
    const rvHOk = requireIntegerString(rvHeight, 'Re-verify height (seconds)', { min: 1 })
    if (rvHOk !== true) {
      await dialog.alert(typeof rvHOk === 'string' ? rvHOk : 'Invalid number.', 'Invalid Setting')
      return
    }

    const ok = await dialog.confirm(
      'Are you sure you want to apply these settings? This will mark the vault as having unsaved changes.',
      {
        title: 'Confirm Settings',
        confirmText: 'Apply Settings',
        cancelText: 'Keep Editing'
      }
    )
    if (!ok) return
    vault.confirmIncomingCoins = !!incoming
    vault.confirmOutgoingCoins = !!outgoing
    vault.persistHeadersOlderThanBlocks = parseInteger(phOld)
    vault.reverifyRecentHeadersAfterSeconds = parseInteger(rvRecent)
    vault.reverifyCurrentBlockHeightAfterSeconds = parseInteger(rvHeight)
    vault.useUserEntropyForRandom = !!useUserEntropy
    if (newName.trim() !== vault.vaultName) {
      await vault.renameVault(newName.trim())
    }
    onUpdate()
  }

  async function doChangePassword() {
    try {
      await vault.changePassword()
      onUpdate()
      // Changing password changes plaintext (salt & settings), update dirty hash baseline? No: we want to show unsaved.
      await dialog.alert(
        'Password updated. You must SAVE the vault file to persist the change.',
        'Password Changed'
      )
    } catch (e: any) {
      await dialog.alert(e.message || 'Failed to change password.', 'Error')
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
        color: '#9da3ae'
      }}>
        Settings
      </h2>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 12 }}>
          <div>
            <div style={{
              fontSize: 11,
              color: COLORS.gray600,
              marginBottom: 6,
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              fontWeight: 600
            }}>
              Vault Display Name
            </div>
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              className="input"
              autoComplete="off"
              maxLength={64}
            />
          </div>
          
          <button style={{ flex: 1 }} onClick={doChangePassword} className="btn-ghost">
            Change Password
          </button>

          <label style={{
            display: 'flex',
            gap: 10,
            alignItems: 'center',
            cursor: 'pointer',
            padding: '8px 0'
          }}>
            <input
              type="checkbox"
              checked={incoming}
              onChange={(e) => setIncoming(e.target.checked)}
            />
            <span style={{ fontSize: 13, letterSpacing: '0.01em' }}>
              Require attestation for incoming UTXOs
            </span>
          </label>
          <div style={{
            fontSize: 12,
            color: COLORS.gray600,
            marginLeft: 28,
            lineHeight: 1.5,
            marginTop: -4
          }}>
            When enabled, new incoming UTXOs pause for explicit operator confirmation before being
            admitted.
          </div>
          <label style={{
            display: 'flex',
            gap: 10,
            alignItems: 'center',
            cursor: 'pointer',
            padding: '8px 0'
          }}>
            <input
              type="checkbox"
              checked={outgoing}
              onChange={(e) => setOutgoing(e.target.checked)}
            />
            <span style={{ fontSize: 13, letterSpacing: '0.01em' }}>
              Require attestation for outgoing UTXOs
            </span>
          </label>
          <div style={{
            fontSize: 12,
            color: COLORS.gray600,
            marginLeft: 28,
            lineHeight: 1.5,
            marginTop: -4
          }}>
            Adds a per-input confirmation during signing so the operator attests each UTXO was
            verified independently.
          </div>
          <label style={{
            display: 'flex',
            gap: 10,
            alignItems: 'center',
            cursor: 'pointer',
            padding: '8px 0'
          }}>
            <input
              type="checkbox"
              checked={useUserEntropy}
              onChange={(e) => setUseUserEntropy(e.target.checked)}
            />
            <span style={{ fontSize: 13, letterSpacing: '0.01em' }}>
              Require user-provided entropy for randomness (keys & salts)
            </span>
          </label>
          <div style={{
            fontSize: 12,
            color: COLORS.gray600,
            marginLeft: 28,
            lineHeight: 1.5,
            marginTop: -4
          }}>
            Collect additional keyboard/mouse noise when randomness is needed. Useful on devices
            with questionable RNG.
          </div>

          <div>
            <div style={{
              fontSize: 11,
              color: COLORS.gray600,
              marginBottom: 6,
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              fontWeight: 600
            }}>
              Persist headers older than N blocks
            </div>
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              value={phOld}
              onChange={(e) => setPhOld(e.target.value)}
              className="input"
              autoComplete="off"
              maxLength={10}
            />
          </div>
          <div>
            <div style={{
              fontSize: 11,
              color: COLORS.gray600,
              marginBottom: 6,
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              fontWeight: 600
            }}>
              Re-verify recent headers after (seconds)
            </div>
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              value={rvRecent}
              onChange={(e) => setRvRecent(e.target.value)}
              className="input"
              autoComplete="off"
              maxLength={10}
            />
          </div>
          <div>
            <div style={{
              fontSize: 11,
              color: COLORS.gray600,
              marginBottom: 6,
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              fontWeight: 600
            }}>
              Re-verify current block height after (seconds)
            </div>
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              value={rvHeight}
              onChange={(e) => setRvHeight(e.target.value)}
              className="input"
              autoComplete="off"
              maxLength={10}
            />
          </div>
          <div style={{ display: 'grid', width: '100%', alignItems: 'center', gap: 8, justifyItems: 'right', gridTemplateColumns: '1fr' }}>
            <button style={{ flex: 1 }} onClick={save} className="btn">
              Apply Changes
            </button>
          </div>
        </div>

        <div
          style={{
            borderTop: `1px solid ${COLORS.border}`,
            paddingTop: 12,
            display: 'grid',
            gap: 8
          }}
        >
          <div style={{
            fontWeight: 600,
            fontSize: 13,
            letterSpacing: '0.05em',
            textTransform: 'uppercase',
            color: COLORS.label
          }}>
            Automatic Backups
          </div>
          {plainHash ? (
            backups.length ? (
              backups.map((b) => (
                <div
                  key={b.id}
                  style={{
                    border: `1px solid ${COLORS.border}`,
                    borderRadius: 8,
                    padding: 8,
                    display: 'grid',
                    gap: 4
                  }}
                >
                  <div style={{ fontSize: 13 }}>
                    <b>Stored:</b> {new Date(b.storedAt).toLocaleString()} &nbsp;·&nbsp;{' '}
                    <b>SHA-256:</b>{' '}
                    <code style={{ wordBreak: 'break-all' }}>{b.fileHash}</code>
                  </div>
                  <div style={{ fontSize: 12, color: COLORS.gray600 }}>
                    {b.fileName ? `Source file: ${b.fileName}` : 'Source file name unavailable'}
                  </div>
                  <div>
                    <button onClick={() => onDownloadBackup(b)} className="btn-ghost" style={{ maxWidth: 200 }}>
                      Download Backup Copy
                    </button>
                  </div>
                </div>
              ))
            ) : (
              <div style={{ fontSize: 13, color: COLORS.gray600 }}>
                Backups are created automatically the first time you load a vault file. None
                recorded yet.
              </div>
            )
          ) : (
            <div style={{ fontSize: 13, color: COLORS.gray600 }}>
              Load or save a vault to populate automatic backups.
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

export default SettingsPanel
