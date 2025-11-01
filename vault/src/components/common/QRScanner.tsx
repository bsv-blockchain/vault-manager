/**
 * QRScanner Component
 *
 * Scans QR codes from camera with support for chunked data reassembly.
 * Automatically handles multi-chunk QR sequences and reconstructs complete data.
 */

import React, { FC, useEffect, useRef, useState } from 'react'
import QrScanner from 'qr-scanner'
import { ChunkCollector, parseQRChunk } from '../../utils/qrChunking'

interface QRScannerProps {
  onScan: (data: string) => void
  onError?: (error: string) => void
  onClose: () => void
}

const COLORS = {
  bg: '#1a1d24',
  bgPrimary: '#0f1216',
  border: '#3a3f49',
  accent: '#c9a961',
  text: '#e4e6eb',
  textSecondary: '#9da3ae',
  textMuted: '#6b7280',
  success: '#5a9367'
}

interface ChunkProgress {
  collected: number
  total: number
  id: string
}

const QRScanner: FC<QRScannerProps> = ({ onScan, onError, onClose }) => {
  const videoRef = useRef<HTMLVideoElement>(null)
  const scannerRef = useRef<QrScanner | null>(null)
  const chunkCollectorRef = useRef<ChunkCollector>(new ChunkCollector())
  const [isScanning, setIsScanning] = useState(false)
  const [chunkProgress, setChunkProgress] = useState<ChunkProgress | null>(null)
  const [hasCamera, setHasCamera] = useState(true)

  useEffect(() => {
    let isMounted = true

    const initScanner = async () => {
      if (!videoRef.current) return

      try {
        // Check if camera is available
        const hasCamera = await QrScanner.hasCamera()
        if (!hasCamera) {
          setHasCamera(false)
          if (onError) {
            onError('No camera available')
          }
          return
        }

        const scanner = new QrScanner(
          videoRef.current,
          (result) => {
            if (!isMounted) return

            const qrData = result.data

            // Check if this is a chunked QR code
            const chunk = parseQRChunk(qrData)

            if (chunk) {
              // This is a chunked QR code
              const completeData = chunkCollectorRef.current.addChunk(chunk)

              // Update progress
              const progress = chunkCollectorRef.current.getProgress(chunk.id)
              if (progress) {
                setChunkProgress({
                  collected: progress.collected,
                  total: progress.total,
                  id: chunk.id
                })
              }

              if (completeData) {
                // All chunks collected, return complete data
                scanner.stop()
                onScan(completeData)
              }
              // Continue scanning for more chunks
            } else {
              // Regular QR code, return immediately
              scanner.stop()
              onScan(qrData)
            }
          },
          {
            highlightScanRegion: true,
            highlightCodeOutline: true,
            maxScansPerSecond: 5
          }
        )

        scannerRef.current = scanner

        // Start scanning
        await scanner.start()
        if (isMounted) {
          setIsScanning(true)
        }
      } catch (error) {
        console.error('Failed to start QR scanner:', error)
        if (isMounted && onError) {
          onError(error instanceof Error ? error.message : 'Failed to start camera')
        }
      }
    }

    initScanner()

    // Cleanup
    return () => {
      isMounted = false
      if (scannerRef.current) {
        scannerRef.current.stop()
        scannerRef.current.destroy()
        scannerRef.current = null
      }
    }
  }, [onScan, onError])

  const handleClose = () => {
    if (scannerRef.current) {
      scannerRef.current.stop()
      scannerRef.current.destroy()
      scannerRef.current = null
    }
    onClose()
  }

  if (!hasCamera) {
    return (
      <div
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(15, 18, 22, 0.95)',
          backdropFilter: 'blur(10px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}
      >
        <div
          style={{
            background: COLORS.bg,
            border: `1px solid ${COLORS.border}`,
            borderRadius: 6,
            padding: 30,
            maxWidth: 400,
            textAlign: 'center',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.6)'
          }}
        >
          <div style={{ fontSize: 16, color: COLORS.text, marginBottom: 12 }}>
            No Camera Available
          </div>
          <div
            style={{
              fontSize: 13,
              color: COLORS.textSecondary,
              marginBottom: 20,
              lineHeight: 1.6
            }}
          >
            Unable to access camera. Please check your device permissions and try again.
          </div>
          <button onClick={handleClose} className="btn" style={{ width: '100%' }}>
            Close
          </button>
        </div>
      </div>
    )
  }

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'rgba(15, 18, 22, 0.95)',
        backdropFilter: 'blur(10px)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: 20
      }}
    >
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
          maxWidth: 600,
          width: '100%'
        }}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}
        >
          <div
            style={{
              fontSize: 14,
              fontWeight: 600,
              letterSpacing: '0.05em',
              textTransform: 'uppercase',
              color: COLORS.textSecondary
            }}
          >
            Scan QR Code
          </div>
          <button
            onClick={handleClose}
            style={{
              background: 'transparent',
              border: `1px solid ${COLORS.border}`,
              borderRadius: 4,
              padding: '8px 16px',
              color: COLORS.text,
              cursor: 'pointer',
              fontSize: 13,
              fontWeight: 500,
              letterSpacing: '0.02em',
              transition: 'all 0.2s ease'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = COLORS.accent
              e.currentTarget.style.color = COLORS.accent
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = COLORS.border
              e.currentTarget.style.color = COLORS.text
            }}
          >
            CLOSE
          </button>
        </div>

        {/* Video Container */}
        <div
          style={{
            position: 'relative',
            width: '100%',
            aspectRatio: '1',
            borderRadius: 6,
            overflow: 'hidden',
            border: `2px solid ${COLORS.border}`,
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.6)'
          }}
        >
          <video
            ref={videoRef}
            style={{
              width: '100%',
              height: '100%',
              objectFit: 'cover'
            }}
          />

          {!isScanning && (
            <div
              style={{
                position: 'absolute',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: COLORS.bgPrimary,
                color: COLORS.textMuted,
                fontSize: 13
              }}
            >
              Initializing camera...
            </div>
          )}
        </div>

        {/* Chunk Progress */}
        {chunkProgress && (
          <div
            style={{
              background: COLORS.bg,
              border: `1px solid ${COLORS.border}`,
              borderRadius: 6,
              padding: 16,
              display: 'flex',
              flexDirection: 'column',
              gap: 12
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}
            >
              <div
                style={{
                  fontSize: 12,
                  color: COLORS.textSecondary,
                  letterSpacing: '0.03em',
                  textTransform: 'uppercase'
                }}
              >
                Collecting Chunks
              </div>
              <div
                style={{
                  fontSize: 13,
                  color: COLORS.accent,
                  fontWeight: 600
                }}
              >
                {chunkProgress.collected} / {chunkProgress.total}
              </div>
            </div>

            <div
              style={{
                width: '100%',
                height: 6,
                background: COLORS.bgPrimary,
                borderRadius: 3,
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  height: '100%',
                  width: `${(chunkProgress.collected / chunkProgress.total) * 100}%`,
                  background: `linear-gradient(90deg, ${COLORS.accent} 0%, #b89650 100%)`,
                  transition: 'width 0.3s ease',
                  boxShadow: `0 0 12px ${COLORS.accent}`
                }}
              />
            </div>

            <div
              style={{
                fontSize: 11,
                color: COLORS.textMuted,
                fontStyle: 'italic',
                textAlign: 'center'
              }}
            >
              Continue scanning to collect all chunks
            </div>
          </div>
        )}

        {/* Instructions */}
        <div
          style={{
            background: COLORS.bg,
            border: `1px solid ${COLORS.border}`,
            borderRadius: 6,
            padding: 16,
            fontSize: 12,
            color: COLORS.textSecondary,
            lineHeight: 1.6,
            textAlign: 'center'
          }}
        >
          Position the QR code within the camera frame.
          <br />
          For animated QR codes, hold steady and wait for all chunks to be scanned.
        </div>
      </div>
    </div>
  )
}

export default QRScanner
