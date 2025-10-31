import React, { FC, useState, useCallback, useEffect, useRef } from 'react'
import { Utils } from '@bsv/sdk'
import Modal from '../dialogs/Modal'

interface EntropyCaptureModalProps {
  bytesNeeded: number
  onComplete: (bytes: number[]) => void
  onCancel: () => void
}

const COLORS = {
  green: '#0a7b22',
  gray600: '#555'
}

const EntropyCaptureModal: FC<EntropyCaptureModalProps> = ({
  bytesNeeded,
  onComplete,
  onCancel
}) => {
  const [samples, setSamples] = useState<number[]>([])
  const [keypresses, setKeypresses] = useState(0)
  const doneRef = useRef(false)
  const target = Math.max(64, bytesNeeded)

  const appendSamples = useCallback(
    (vals: number[]) => {
      setSamples((prev) => {
        if (prev.length >= target) return prev
        const next = prev.concat(vals).slice(0, target)
        return next
      })
    },
    [target]
  )

  useEffect(() => {
    const handleKey = (event: KeyboardEvent) => {
      const base = event.key.length === 1 ? event.key.charCodeAt(0) : event.keyCode
      const mix = (base + Math.floor(event.timeStamp)) & 0xff
      appendSamples([mix, (event.location * 73) & 0xff, (Math.random() * 256) | 0])
      setKeypresses((k) => k + 1)
    }
    const handleMouse = (event: MouseEvent) => {
      const delta = (Math.abs(event.movementX) + Math.abs(event.movementY)) & 0xff
      appendSamples([
        delta,
        (event.screenX ^ event.screenY) & 0xff,
        (Math.random() * 256) | 0
      ])
    }
    const handleTouch = (event: TouchEvent) => {
      const touch = event.touches[0]
      if (!touch) return
      appendSamples([
        (touch.screenX + touch.screenY) & 0xff,
        event.timeStamp & 0xff,
        (Math.random() * 256) | 0
      ])
    }
    const handlePaste = (event: ClipboardEvent) => {
      const text = event.clipboardData?.getData('text') || ''
      const utf = Utils.toArray(text, 'utf8')
      appendSamples(utf.slice(0, 16))
    }

    window.addEventListener('keydown', handleKey)
    window.addEventListener('mousemove', handleMouse)
    window.addEventListener('touchmove', handleTouch)
    window.addEventListener('paste', handlePaste)
    return () => {
      window.removeEventListener('keydown', handleKey)
      window.removeEventListener('mousemove', handleMouse)
      window.removeEventListener('touchmove', handleTouch)
      window.removeEventListener('paste', handlePaste)
    }
  }, [appendSamples])

  useEffect(() => {
    if (!doneRef.current && samples.length >= target) {
      doneRef.current = true
      onComplete(samples.slice(0, target))
    }
  }, [samples, target, onComplete])

  const progress = Math.min(1, samples.length / target)

  return (
    <Modal title="Collect Entropy" onClose={onCancel}>
      <div style={{ display: 'grid', gap: 12 }}>
        <p style={{ margin: 0 }}>
          Wiggle the mouse or trackpad, mash random keys, and paste anything unpredictable.
          We'll capture enough noise automatically.
        </p>
        <div style={{ height: 14, borderRadius: 999, background: '#eee', overflow: 'hidden' }}>
          <div
            style={{
              width: `${progress * 100}%`,
              background: COLORS.green,
              height: '100%',
              transition: 'width 120ms linear'
            }}
          />
        </div>
        <div style={{ fontSize: 13, color: COLORS.gray600 }}>
          Progress: {(progress * 100).toFixed(0)}% · Key presses recorded: {keypresses}
        </div>
        <button type="button" onClick={onCancel} className="btn-ghost" style={{ maxWidth: 200 }}>
          Cancel (use device RNG)
        </button>
      </div>
    </Modal>
  )
}

export default EntropyCaptureModal
