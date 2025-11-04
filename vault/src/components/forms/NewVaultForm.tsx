import React, { FC, useState } from 'react'
import { CreateVaultOptions } from '../../types'
import {
  validateVaultName,
  validatePassword,
  validatePBKDF2Rounds,
  requireIntegerString
} from '../../validators'

interface NewVaultFormProps {
  onSubmit: (opts: CreateVaultOptions) => Promise<void>
  onCancel: () => void
  submitting: boolean
}

const COLORS = {
  red: 'var(--color-error)',
  green: 'var(--color-success)',
  gray600: 'var(--color-text-tertiary)',
  border: 'var(--color-border-secondary)'
}

const NewVaultForm: FC<NewVaultFormProps> = ({ onSubmit, onCancel, submitting }) => {
  const [name, setName] = useState('Vault')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [blockHeight, setBlockHeight] = useState('')
  const [rounds, setRounds] = useState(String(80000))
  const [persistHeaders, setPersistHeaders] = useState(String(144))
  const [reverifyRecent, setReverifyRecent] = useState(String(60))
  const [reverifyHeight, setReverifyHeight] = useState(String(600))
  const [requireIncomingReview, setRequireIncomingReview] = useState(true)
  const [requireOutgoingReview, setRequireOutgoingReview] = useState(false)
  const [requireEntropy, setRequireEntropy] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (submitting) return

    const nameOk = validateVaultName(name)
    if (nameOk !== true) {
      setError(typeof nameOk === 'string' ? nameOk : 'Invalid vault name.')
      return
    }

    const pwOk = validatePassword(password)
    if (pwOk !== true) {
      setError(typeof pwOk === 'string' ? pwOk : 'Invalid password.')
      return
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.')
      return
    }

    const roundsOk = validatePBKDF2Rounds(rounds)
    if (roundsOk !== true) {
      setError(typeof roundsOk === 'string' ? roundsOk : 'Invalid PBKDF2 rounds.')
      return
    }

    const heightOk = requireIntegerString(blockHeight, 'Block height', { min: 1 })
    if (heightOk !== true) {
      setError(typeof heightOk === 'string' ? heightOk : 'Invalid block height.')
      return
    }

    const persistOk = requireIntegerString(persistHeaders, 'Persist headers (blocks)', { min: 0 })
    if (persistOk !== true) {
      setError(typeof persistOk === 'string' ? persistOk : 'Invalid header retention.')
      return
    }

    const recentOk = requireIntegerString(reverifyRecent, 'Re-verify recent headers (seconds)', {
      min: 1
    })
    if (recentOk !== true) {
      setError(typeof recentOk === 'string' ? recentOk : 'Invalid re-verify window.')
      return
    }

    const heightWindowOk = requireIntegerString(
      reverifyHeight,
      'Re-verify height (seconds)',
      { min: 1 }
    )
    if (heightWindowOk !== true) {
      setError(typeof heightWindowOk === 'string' ? heightWindowOk : 'Invalid height re-verify window.')
      return
    }

    setError(null)
    await onSubmit({
      name: name.trim(),
      password,
      passwordRounds: Number(rounds),
      useUserEntropyForRandom: requireEntropy,
      confirmIncomingCoins: requireIncomingReview,
      confirmOutgoingCoins: requireOutgoingReview,
      persistHeadersOlderThanBlocks: Number(persistHeaders),
      reverifyRecentHeadersAfterSeconds: Number(reverifyRecent),
      reverifyCurrentBlockHeightAfterSeconds: Number(reverifyHeight),
      initialBlockHeight: Number(blockHeight)
    })
  }

  const toggleHelpStyle: React.CSSProperties = {
    fontSize: 12,
    color: COLORS.gray600,
    marginTop: 4,
    lineHeight: 1.4
  }

  const toggleRowStyle: React.CSSProperties = {
    display: 'grid',
    gridTemplateColumns: 'auto 1fr',
    gap: 12,
    alignItems: 'flex-start',
    padding: '8px 0',
    borderBottom: `1px solid ${COLORS.border}`
  }

  const advancedBoxStyle: React.CSSProperties = {
    border: `1px dashed var(--color-border-secondary)`,
    borderRadius: 4,
    padding: 16,
    marginTop: 14,
    background: 'rgba(26, 29, 36, 0.5)',
    display: 'grid',
    gap: 8
  }

  return (
    <section className="section">
      <form onSubmit={handleSubmit} autoComplete="off" style={{ display: 'grid', gap: 12 }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: 12
          }}
        >
          <h2 style={{ margin: 0 }}>New Vault Setup</h2>
          <button type="button" onClick={onCancel} className="btn-ghost">
            Cancel
          </button>
        </div>
        <p style={{ margin: 0, fontSize: 13, color: COLORS.gray600 }}>
          Fill out the essentials once. You can revisit all settings in the <b>Settings</b> tab
          after creation.
        </p>
        <label style={{ display: 'grid', gap: 4 }}>
          <span>Vault name</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="input"
            maxLength={64}
            autoFocus
          />
        </label>
        <label style={{ display: 'grid', gap: 4 }}>
          <span>Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="input"
            maxLength={1024}
          />
        </label>
        <label style={{ display: 'grid', gap: 4 }}>
          <span>Confirm password</span>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            className="input"
            maxLength={1024}
          />
        </label>
        <div style={{ fontSize: 12, color: COLORS.gray600 }}>
          Use a memorable passphrase (12+ characters). Symbols and digits are optional.
        </div>
        <label style={{ display: 'grid', gap: 4 }}>
          <span>Current HONEST chain block height</span>
          <input
            value={blockHeight}
            onChange={(e) => setBlockHeight(e.target.value)}
            className="input"
            inputMode="numeric"
            pattern="[0-9]*"
            placeholder="e.g. 820000"
          />
          <div style={toggleHelpStyle}>
            The vault records when you confirmed this value so you can be reminded to refresh it
            later.
          </div>
        </label>

        <div
          style={{
            borderTop: `1px solid ${COLORS.border}`,
            paddingTop: 8,
            display: 'grid',
            gap: 8
          }}
        >
          <div style={{ fontWeight: 600 }}>Policy quick toggles</div>

          <label style={toggleRowStyle}>
            <input
              type="checkbox"
              checked={requireIncomingReview}
              onChange={(e) => setRequireIncomingReview(e.target.checked)}
            />
            <div>
              <div>Require manual review before adding incoming UTXOs</div>
              <div style={toggleHelpStyle}>
                When enabled, the review modal calls out each matched UTXO before it is added to
                the vault.
              </div>
            </div>
          </label>

          <label style={toggleRowStyle}>
            <input
              type="checkbox"
              checked={requireOutgoingReview}
              onChange={(e) => setRequireOutgoingReview(e.target.checked)}
            />
            <div>
              <div>Require per-UTXO attestation when spending</div>
              <div style={toggleHelpStyle}>
                Adds an extra confirmation for every input you sign so operators can attest they
                verified it on the HONEST chain.
              </div>
            </div>
          </label>

          <label style={{ ...toggleRowStyle, borderBottom: 'none' }}>
            <input
              type="checkbox"
              checked={requireEntropy}
              onChange={(e) => setRequireEntropy(e.target.checked)}
            />
            <div>
              <div>Collect extra keyboard/mouse entropy</div>
              <div style={toggleHelpStyle}>
                Recommended if you do not trust the device RNG. You&apos;ll mash keys once and the
                app records randomness automatically.
              </div>
            </div>
          </label>
        </div>

        <div>
          <button
            type="button"
            onClick={() => setShowAdvanced((s) => !s)}
            className="btn-ghost"
          >
            {showAdvanced ? 'Hide Advanced Options' : 'Show Advanced Options'}
          </button>
        </div>

        {showAdvanced && (
          <div style={advancedBoxStyle}>
            <label style={{ display: 'grid', gap: 4 }}>
              <span>PBKDF2 rounds</span>
              <input
                value={rounds}
                onChange={(e) => setRounds(e.target.value)}
                className="input"
                inputMode="numeric"
                pattern="[0-9]*"
              />
              <div style={toggleHelpStyle}>
                Default is 80,000. Higher values increase password derivation cost when unlocking.
              </div>
            </label>
            <label style={{ display: 'grid', gap: 4 }}>
              <span>Persist headers older than (blocks)</span>
              <input
                value={persistHeaders}
                onChange={(e) => setPersistHeaders(e.target.value)}
                className="input"
                inputMode="numeric"
                pattern="[0-9]*"
              />
            </label>
            <label style={{ display: 'grid', gap: 4 }}>
              <span>Re-verify recent headers every (seconds)</span>
              <input
                value={reverifyRecent}
                onChange={(e) => setReverifyRecent(e.target.value)}
                className="input"
                inputMode="numeric"
                pattern="[0-9]*"
              />
            </label>
            <label style={{ display: 'grid', gap: 4 }}>
              <span>Re-verify block height every (seconds)</span>
              <input
                value={reverifyHeight}
                onChange={(e) => setReverifyHeight(e.target.value)}
                className="input"
                inputMode="numeric"
                pattern="[0-9]*"
              />
            </label>
          </div>
        )}

        {error && <div style={{ color: COLORS.red, fontSize: 12 }}>{error}</div>}

        <button type="submit" className="btn" disabled={submitting}>
          {submitting ? 'Creating…' : 'Create Vault'}
        </button>
      </form>
    </section>
  )
}

export default NewVaultForm
