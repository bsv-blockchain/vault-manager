import React, { FC, useState } from 'react'
import Vault from '../../Vault'
import { IncomingPreview } from '../../types'
import Modal from '../dialogs/Modal'

interface ProcessIncomingModalProps {
  vault: Vault
  preview: IncomingPreview
  onClose: () => void
  onSuccess: (txid: string) => void
  onError: (msg: string) => void
}

const COLORS = {
  gray600: 'var(--color-text-tertiary)',
  border: 'var(--color-border-secondary)'
}

const ProcessIncomingModal: FC<ProcessIncomingModalProps> = ({
  vault,
  preview,
  onClose,
  onSuccess,
  onError
}) => {
  const [memos, setMemos] = useState<Record<number, string>>({})
  const [txMemo, setTxMemo] = useState('')
  const [isFinalizing, setIsFinalizing] = useState(false)
  const [processed, setProcessed] = useState(false)

  const handleFinalize = async () => {
    setIsFinalizing(true)
    try {
      const res = await vault.processIncoming(preview.tx, { txMemo, perUtxoMemo: memos, processed })
      onSuccess(res.txid)
    } catch (e: any) {
      onError(e.message || 'An error occurred during finalization.')
      onClose()
    } finally {
      setIsFinalizing(false)
    }
  }

  return (
    <Modal title="Review Incoming Transaction" onClose={onClose}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <p style={{ fontSize: 13, margin: 0, wordBreak: 'break-all' }}>
          TXID: <code>{preview.txid}</code>
        </p>
        <button
          onClick={() => navigator.clipboard.writeText(preview.txid)}
          className="btn-ghost"
          style={{ padding: '6px 10px', fontSize: 12, maxWidth: 140 }}
        >
          Copy TXID
        </button>
      </div>
      <p style={{ fontSize: 13, color: 'green', fontWeight: 'bold' }}>SPV Verified Successfully</p>
      <hr style={{ margin: '12px 0' }} />
      <p>
        The following outputs in this transaction are spendable by your vault's keys. All matched
        UTXOs will be admitted automatically; add memos if helpful.
      </p>
      <div style={{ fontSize: 12, color: COLORS.gray600, marginTop: -4 }}>
        Tip: open your trusted SPV explorer with this TXID and confirm the merkle root matches your
        independently retrieved headers before admitting funds.
      </div>

      {preview.matches.map((m) => (
        <div
          key={m.outputIndex}
          style={{
            border: `1px solid ${COLORS.border}`,
            padding: 8,
            margin: '8px 0',
            borderRadius: 8
          }}
        >
          <strong>Output #{m.outputIndex}</strong>: {m.satoshis.toLocaleString()} sats (
          <b>{(m.satoshis / 100000000).toFixed(8)}</b> BSV), to Key <strong>{m.serial}</strong>
          <input
            type="text"
            placeholder="UTXO Memo (optional)"
            className="input"
            style={{ marginTop: 6 }}
            value={memos[m.outputIndex] || ''}
            onChange={(e) =>
              setMemos((prev) => ({ ...prev, [m.outputIndex]: e.target.value }))
            }
            maxLength={256}
          />
        </div>
      ))}

      <button
        onClick={() => {
          const ids = preview.matches.map((m) => `${preview.txid}:${m.outputIndex}`).join('\n')
          navigator.clipboard.writeText(ids)
        }}
        className="btn-ghost"
        style={{ marginTop: 6, fontSize: 12, maxWidth: 220 }}
      >
        Copy All Matched UTXO IDs
      </button>

      <input
        type="text"
        placeholder="Transaction Memo (optional)"
        className="input"
        style={{ marginTop: 12 }}
        value={txMemo}
        onChange={(e) => setTxMemo(e.target.value)}
        maxLength={256}
      />
      <label style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 12 }}>
        <input
          type="checkbox"
          checked={processed}
          onChange={(e) => setProcessed(e.target.checked)}
        />
        <span style={{ fontSize: 13 }}>
          Mark as processed on-chain (check after your independent confirmation).
        </span>
      </label>

      <div
        style={{
          marginTop: 12,
          display: 'flex',
          justifyContent: 'flex-end',
          gap: 8,
          flexWrap: 'wrap'
        }}
      >
        <button onClick={onClose} className="btn-ghost">
          Cancel
        </button>
        <button onClick={handleFinalize} disabled={isFinalizing} className="btn">
          {isFinalizing ? 'Saving...' : `Admit ${preview.matches.length} UTXO(s)`}
        </button>
      </div>
    </Modal>
  )
}

export default ProcessIncomingModal
