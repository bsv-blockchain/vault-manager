import React, { FC, useState } from 'react'
import Vault from '../../Vault'
import { IncomingPreview } from '../../types'
import { validateBeefHex } from '../../validators'
import QRScanner from '../common/QRScanner'

interface IncomingManagerProps {
  vault: Vault
  onPreview: (p: IncomingPreview) => void
  onError: (msg: string) => void
}

const COLORS = {
  gray600: 'var(--color-text-tertiary)'
}

const IncomingManager: FC<IncomingManagerProps> = ({ vault, onPreview, onError }) => {
  const [hex, setHex] = useState('')
  const [isProcessing, setIsProcessing] = useState(false)
  const [showScanner, setShowScanner] = useState(false)

  function handleQRScan(data: string) {
    setHex(data)
    setShowScanner(false)
  }

  async function handlePreview() {
    if (!hex.trim()) {
      onError('BEEF hex cannot be empty.')
      return
    }
    const v = validateBeefHex(hex)
    if (v !== true) {
      onError(typeof v === 'string' ? v : 'Invalid Atomic BEEF hex.')
      return
    }
    setIsProcessing(true)
    try {
      const previewData = await vault.previewIncoming(hex)
      onPreview(previewData)
    } catch (e: any) {
      onError(e.message || 'Failed to process BEEF.')
    } finally {
      setIsProcessing(false)
    }
  }

  return (
    <section className="section">
      <h2 style={{ marginTop: 0 }}>Process Incoming Atomic BEEF</h2>
      <p style={{ fontSize: 12, color: COLORS.gray600 }}>
        Paste an SPV-valid Atomic BEEF transaction to add new UTXOs to your vault.
      </p>
      <textarea
        placeholder="Paste Atomic BEEF hex..."
        rows={4}
        className="input"
        style={{ width: '100%', fontFamily: 'monospace' }}
        value={hex}
        onChange={(e) => setHex(e.target.value)}
      />
      <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
        <button onClick={handlePreview} disabled={isProcessing} className="btn">
          {isProcessing ? 'Verifying...' : 'Review & Process'}
        </button>
        <button onClick={() => setShowScanner(true)} className="btn-ghost">
          📷 Scan BEEF QR
        </button>
      </div>

      {showScanner && (
        <QRScanner
          onScan={handleQRScan}
          onClose={() => setShowScanner(false)}
          title="Scan Atomic BEEF QR Code"
        />
      )}
    </section>
  )
}

export default IncomingManager
