import React, { FC, useState, useEffect, useMemo } from 'react'
import Modal from './Modal'

const COLORS = {
  red: '#c45c5c',
  gray600: '#6b7280',
  textSecondary: '#9da3ae'
}

export interface PromptDialogRequest {
  kind: 'prompt'
  title?: string
  message: string
  password?: boolean
  defaultValue?: string
  placeholder?: string
  maxLength?: number
  validate?: (val: string) => true | string
  resolve: (val: string | null) => void
}

interface PromptDialogProps {
  req: PromptDialogRequest
  onResolve: (val: string | null) => void
}

const PromptDialog: FC<PromptDialogProps> = ({ req, onResolve }) => {
  const [val, setVal] = useState(req.defaultValue || '')
  const [error, setError] = useState<string | null>(null)

  // Reset the value if the request changes, ensuring the input is fresh
  useEffect(() => {
    setVal(req.defaultValue || '')
    setError(null)
  }, [req])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // Run optional validation; if invalid, show error and keep dialog open
    if (req.validate) {
      const res = req.validate(val)
      if (res !== true) {
        setError(typeof res === 'string' ? res : 'Invalid input.')
        return
      }
    }
    onResolve(val)
  }

  // Randomize a name attribute to further avoid password-manager heuristics
  const randomName = useMemo(() => `fld_${Math.random().toString(36).slice(2)}`, [])

  return (
    <Modal title={req.title || 'Input Required'} onClose={() => onResolve(null)}>
      <form onSubmit={handleSubmit} autoComplete="off">
        <p style={{
          whiteSpace: 'pre-wrap',
          fontSize: 14,
          lineHeight: 1.6,
          color: COLORS.textSecondary,
          margin: '0 0 16px 0'
        }}>
          {req.message}
        </p>
        <input
          type={req.password ? 'password' : 'text'}
          name={randomName}
          autoComplete="off"
          value={val}
          onChange={(e) => setVal(e.target.value)}
          placeholder={req.placeholder}
          maxLength={req.maxLength}
          className="input"
          style={{ marginBottom: 8 }}
          autoFocus
        />
        {req.password && (
          <div style={{
            marginBottom: 8,
            fontSize: 11,
            color: COLORS.gray600,
            lineHeight: 1.5,
            fontStyle: 'italic'
          }}>
            Minimum 12 characters. Long passphrases are encouraged; no special character requirements.
          </div>
        )}
        {!!error && (
          <div style={{
            marginBottom: 12,
            fontSize: 12,
            color: COLORS.red,
            fontWeight: 600,
            padding: 10,
            background: 'rgba(196, 92, 92, 0.1)',
            border: '1px solid rgba(196, 92, 92, 0.3)',
            borderRadius: 4
          }}>
            {error}
          </div>
        )}
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            marginTop: 16,
            gap: 10,
            flexWrap: 'wrap'
          }}
        >
          <button type="button" onClick={() => onResolve(null)} className="btn-ghost">
            Cancel
          </button>
          <button type="submit" className="btn">
            Submit
          </button>
        </div>
      </form>
    </Modal>
  )
}

export default PromptDialog
