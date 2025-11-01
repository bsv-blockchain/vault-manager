/**
 * QRDisplay Component
 *
 * Displays QR codes with support for animated chunked data.
 * For large data (>100 chars), automatically chunks and animates through QR codes.
 */

import React, { FC, useEffect, useRef, useState } from 'react'
import { chunkData, type ChunkedData } from '../../utils/qrChunking'
import { generatePublicKeyQR } from '../../utils/qrCodeUtils'

interface QRDisplayProps {
  data: string
  size?: number
  label?: string
  onError?: (error: string) => void
}

const COLORS = {
  bg: '#1a1d24',
  border: '#3a3f49',
  accent: '#c9a961',
  text: '#e4e6eb',
  textSecondary: '#9da3ae',
  textMuted: '#6b7280'
}

const QRDisplay: FC<QRDisplayProps> = ({ data, size = 300, label, onError }) => {
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState<string>('')
  const [chunkedData, setChunkedData] = useState<ChunkedData | null>(null)
  const [currentChunkIndex, setCurrentChunkIndex] = useState(0)
  const [isGeneratingQR, setIsGeneratingQR] = useState(false)
  const [isAnimating, setIsAnimating] = useState(false)

  const animationRef = useRef(false)
  const intervalRef = useRef<NodeJS.Timeout | null>(null)

  // Initialize chunking and generate first QR code
  useEffect(() => {
    const initializeQR = async () => {
      try {
        setIsGeneratingQR(true)

        // Chunk the data
        const chunks = chunkData(data)
        setChunkedData(chunks)

        // Generate QR for first chunk
        const firstQR = await generatePublicKeyQR(chunks.chunks[0].data, {
          size: size * 2, // 2x for retina display
          errorCorrectionLevel: 'M',
          margin: 1
        })

        setQrCodeDataUrl(firstQR)
        setCurrentChunkIndex(0)

        // Start animation if chunked
        if (chunks.isChunked && chunks.chunks.length > 1) {
          setIsAnimating(true)
          animationRef.current = true
          startQRAnimation(chunks)
        }
      } catch (error) {
        console.error('Failed to generate QR code:', error)
        if (onError) {
          onError(error instanceof Error ? error.message : 'Failed to generate QR code')
        }
      } finally {
        setIsGeneratingQR(false)
      }
    }

    initializeQR()

    // Cleanup on unmount
    return () => {
      animationRef.current = false
      if (intervalRef.current) {
        clearTimeout(intervalRef.current)
        intervalRef.current = null
      }
    }
  }, [data, size, onError])

  const startQRAnimation = async (chunks: ChunkedData) => {
    let chunkIndex = 1 // Start from second chunk (first already displayed)

    const animateNextChunk = async () => {
      if (!animationRef.current) return

      try {
        setIsGeneratingQR(true)
        const currentChunk = chunks.chunks[chunkIndex]

        // Generate QR for current chunk
        const qrDataUrl = await generatePublicKeyQR(currentChunk.data, {
          size: size * 2,
          errorCorrectionLevel: 'M',
          margin: 1
        })

        // Only update if animation is still active
        if (animationRef.current) {
          setQrCodeDataUrl(qrDataUrl)
          setCurrentChunkIndex(chunkIndex)
        }

        // Move to next chunk (cycles through)
        chunkIndex = (chunkIndex + 1) % chunks.chunks.length
      } catch (error) {
        console.error('Failed to generate QR chunk:', error)
        if (onError && animationRef.current) {
          onError('Failed to generate QR chunk')
        }
      } finally {
        setIsGeneratingQR(false)
      }

      // Schedule next animation frame if still active
      if (animationRef.current) {
        intervalRef.current = setTimeout(animateNextChunk, 200)
      }
    }

    // Start the animation loop
    intervalRef.current = setTimeout(animateNextChunk, 200)
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 16,
        padding: 20,
        background: COLORS.bg,
        border: `1px solid ${COLORS.border}`,
        borderRadius: 6,
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.4)'
      }}
    >
      {label && (
        <div
          style={{
            fontSize: 13,
            fontWeight: 600,
            letterSpacing: '0.05em',
            textTransform: 'uppercase',
            color: COLORS.textSecondary,
            textAlign: 'center'
          }}
        >
          {label}
        </div>
      )}

      <div
        style={{
          position: 'relative',
          width: size,
          height: size,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: '#ffffff',
          borderRadius: 4,
          padding: 8,
          boxShadow: `0 0 0 2px ${COLORS.border}, 0 4px 12px rgba(0, 0, 0, 0.3)`
        }}
      >
        {qrCodeDataUrl ? (
          <img
            src={qrCodeDataUrl}
            alt="QR Code"
            style={{
              width: '100%',
              height: '100%',
              imageRendering: 'crisp-edges'
            }}
          />
        ) : (
          <div
            style={{
              color: COLORS.textMuted,
              fontSize: 13,
              textAlign: 'center'
            }}
          >
            Generating QR...
          </div>
        )}

        {isGeneratingQR && (
          <div
            style={{
              position: 'absolute',
              top: 8,
              right: 8,
              width: 24,
              height: 24,
              border: `3px solid ${COLORS.border}`,
              borderTop: `3px solid ${COLORS.accent}`,
              borderRadius: '50%',
              animation: 'spin 0.6s linear infinite'
            }}
          />
        )}
      </div>

      {chunkedData && chunkedData.isChunked && (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 8,
            width: '100%'
          }}
        >
          <div
            style={{
              fontSize: 12,
              color: COLORS.textSecondary,
              letterSpacing: '0.02em',
              textAlign: 'center'
            }}
          >
            {isAnimating && (
              <span style={{ color: COLORS.accent, fontWeight: 600 }}>
                ANIMATING
              </span>
            )}{' '}
            Chunk {currentChunkIndex + 1} of {chunkedData.chunks.length}
          </div>

          <div
            style={{
              width: '100%',
              height: 4,
              background: COLORS.border,
              borderRadius: 2,
              overflow: 'hidden'
            }}
          >
            <div
              style={{
                height: '100%',
                width: `${((currentChunkIndex + 1) / chunkedData.chunks.length) * 100}%`,
                background: `linear-gradient(90deg, ${COLORS.accent} 0%, #b89650 100%)`,
                transition: 'width 0.2s ease',
                boxShadow: `0 0 8px ${COLORS.accent}`
              }}
            />
          </div>

          <div
            style={{
              fontSize: 11,
              color: COLORS.textMuted,
              textAlign: 'center',
              fontStyle: 'italic',
              lineHeight: 1.5
            }}
          >
            Large data automatically chunked for reliability.
            <br />
            Scan each frame sequentially (200ms cycle).
          </div>
        </div>
      )}

      {/* Add keyframes for spinner animation */}
      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  )
}

export default QRDisplay
