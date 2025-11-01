/**
 * QR Code Data Chunking Utility
 *
 * Handles splitting large data into multiple QR codes for animated display
 * and reassembling scanned chunks back into complete data.
 *
 * Compatible with Pay-QuickR chunking format.
 */

export interface QRChunk {
  id: string
  index: number
  total: number
  data: string
}

export interface ChunkedData {
  chunks: QRChunk[]
  isChunked: boolean
}

/**
 * Generate a unique chunk collection ID (9-character random string)
 */
function generateChunkId(): string {
  return Math.random().toString(36).substring(2, 11)
}

/**
 * Split data into chunks for QR code display
 *
 * @param data - The data to chunk (typically base64 encoded)
 * @param maxChunkSize - Maximum characters per chunk (default: 80)
 * @returns ChunkedData object with chunks array and isChunked flag
 */
export function chunkData(data: string, maxChunkSize: number = 80): ChunkedData {
  // For small data, don't chunk
  if (data.length <= 100) {
    return {
      chunks: [{
        id: generateChunkId(),
        index: 0,
        total: 1,
        data
      }],
      isChunked: false
    }
  }

  const chunks: QRChunk[] = []
  const chunkId = generateChunkId()

  // Calculate how many chunks we need
  const totalChunks = Math.ceil(data.length / maxChunkSize)

  for (let i = 0; i < totalChunks; i++) {
    const start = i * maxChunkSize
    const end = Math.min(start + maxChunkSize, data.length)
    const chunkData = data.slice(start, end)

    // Format: CHUNK:id:index:total:data
    const formattedChunk = `CHUNK:${chunkId}:${i}:${totalChunks}:${chunkData}`

    chunks.push({
      id: chunkId,
      index: i,
      total: totalChunks,
      data: formattedChunk
    })
  }

  return {
    chunks,
    isChunked: true
  }
}

/**
 * Parse a QR code string to extract chunk metadata
 *
 * @param qrData - The scanned QR code data
 * @returns QRChunk object or null if not a valid chunk
 */
export function parseQRChunk(qrData: string): QRChunk | null {
  if (!qrData.startsWith('CHUNK:')) {
    return null
  }

  const parts = qrData.split(':')
  if (parts.length < 5) {
    return null
  }

  const [, id, indexStr, totalStr, ...dataParts] = parts
  const index = parseInt(indexStr, 10)
  const total = parseInt(totalStr, 10)
  const data = dataParts.join(':') // Rejoin in case original data had colons

  if (isNaN(index) || isNaN(total)) {
    return null
  }

  return {
    id,
    index,
    total,
    data
  }
}

/**
 * Collects and reassembles chunked QR code data
 *
 * Usage:
 * ```typescript
 * const collector = new ChunkCollector()
 *
 * // For each scanned QR code:
 * const chunk = parseQRChunk(scannedData)
 * if (chunk) {
 *   const completeData = collector.addChunk(chunk)
 *   if (completeData) {
 *     // All chunks received, use completeData
 *   } else {
 *     // Still waiting for more chunks
 *     const progress = collector.getProgress(chunk.id)
 *   }
 * }
 * ```
 */
export class ChunkCollector {
  private chunks: Map<string, Map<number, string>> = new Map()
  private chunkTotals: Map<string, number> = new Map()

  /**
   * Add a chunk to the collector
   *
   * @param chunk - The parsed QR chunk
   * @returns Complete data string if all chunks received, null otherwise
   */
  addChunk(chunk: QRChunk): string | null {
    if (!this.chunks.has(chunk.id)) {
      this.chunks.set(chunk.id, new Map())
      this.chunkTotals.set(chunk.id, chunk.total)
    }

    const chunkMap = this.chunks.get(chunk.id)!
    chunkMap.set(chunk.index, chunk.data)

    // Check if we have all chunks
    const expectedTotal = this.chunkTotals.get(chunk.id)!
    if (chunkMap.size === expectedTotal) {
      // Reconstruct the original data
      const sortedChunks: string[] = []
      for (let i = 0; i < expectedTotal; i++) {
        const chunkData = chunkMap.get(i)
        if (!chunkData) {
          return null // Missing chunk
        }
        sortedChunks.push(chunkData)
      }

      // Clean up
      this.chunks.delete(chunk.id)
      this.chunkTotals.delete(chunk.id)

      return sortedChunks.join('')
    }

    return null
  }

  /**
   * Get collection progress for a chunk set
   *
   * @param chunkId - The chunk collection ID
   * @returns Progress object or null if not found
   */
  getProgress(chunkId: string): { collected: number; total: number } | null {
    const chunkMap = this.chunks.get(chunkId)
    const total = this.chunkTotals.get(chunkId)

    if (!chunkMap || !total) {
      return null
    }

    return {
      collected: chunkMap.size,
      total
    }
  }

  /**
   * Clear all collected chunks
   */
  clear(): void {
    this.chunks.clear()
    this.chunkTotals.clear()
  }

  /**
   * Get all active chunk collection IDs
   */
  getActiveCollections(): string[] {
    return Array.from(this.chunks.keys())
  }
}
