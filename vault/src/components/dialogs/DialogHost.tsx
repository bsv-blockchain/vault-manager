import React, { FC, useEffect } from 'react'
import Modal from './Modal'
import PromptDialog from './PromptDialog'

export type DialogRequest =
  | { kind: 'alert'; title?: string; message: string; resolve: () => void }
  | {
      kind: 'confirm'
      title?: string
      message: string
      confirmText?: string
      cancelText?: string
      resolve: (ok: boolean) => void
    }
  | {
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

interface DialogHostProps {
  queue: DialogRequest[]
  setQueue: React.Dispatch<React.SetStateAction<DialogRequest[]>>
}

const DialogHost: FC<DialogHostProps> = ({ queue, setQueue }) => {
  if (!queue.length) return null
  const req = queue[0]
  const close = () => setQueue((q) => q.slice(1))

  // Keypress handler for the simple 'alert' dialog
  useEffect(() => {
    if (req.kind !== 'alert') return

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Enter') {
        event.preventDefault()
        req.resolve()
        close()
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [req, close])

  if (req.kind === 'alert') {
    return (
      <Modal
        title={req.title || 'Notice'}
        onClose={() => {
          req.resolve()
          close()
        }}
      >
        <p style={{ whiteSpace: 'pre-wrap' }}>{req.message}</p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12 }}>
          <button
            onClick={() => {
              req.resolve()
              close()
            }}
            className="btn"
            autoFocus
          >
            OK
          </button>
        </div>
      </Modal>
    )
  }

  if (req.kind === 'confirm') {
    return (
      <Modal
        title={req.title || 'Confirm'}
        onClose={() => {
          req.resolve(false)
          close()
        }}
      >
        <p style={{ whiteSpace: 'pre-wrap' }}>{req.message}</p>
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            marginTop: 12,
            gap: 8,
            flexWrap: 'wrap'
          }}
        >
          <button
            onClick={() => {
              req.resolve(false)
              close()
            }}
            className="btn-ghost"
          >
            {req.cancelText || 'No'}
          </button>
          <button
            onClick={() => {
              req.resolve(true)
              close()
            }}
            className="btn"
            autoFocus
          >
            {req.confirmText || 'Yes'}
          </button>
        </div>
      </Modal>
    )
  }

  if (req.kind === 'prompt') {
    return (
      <PromptDialog
        req={req}
        onResolve={(val) => {
          req.resolve(val)
          close()
        }}
      />
    )
  }

  return null
}

export default DialogHost
