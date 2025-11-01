/**
 * QR Code Generation Utilities
 *
 * Provides functions for generating QR codes for various data types:
 * - BSV addresses
 * - Public keys
 * - Transaction data (BEEF)
 * - Chunked data
 */

import QRCode from 'qrcode'

export interface QRCodeOptions {
  size?: number
  errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H'
  margin?: number
  darkColor?: string
  lightColor?: string
}

const DEFAULT_OPTIONS: QRCodeOptions = {
  size: 256,
  errorCorrectionLevel: 'M',
  margin: 2,
  darkColor: '#000000',
  lightColor: '#ffffff'
}

/**
 * Generate a QR code for a BSV address
 *
 * @param address - BSV address string
 * @param options - QR code generation options
 * @returns Data URL for the generated QR code
 */
export async function generateAddressQR(
  address: string,
  options: QRCodeOptions = {}
): Promise<string> {
  const mergedOptions = { ...DEFAULT_OPTIONS, ...options }

  try {
    const qrDataUrl = await QRCode.toDataURL(address, {
      width: mergedOptions.size,
      errorCorrectionLevel: mergedOptions.errorCorrectionLevel,
      margin: mergedOptions.margin,
      color: {
        dark: mergedOptions.darkColor!,
        light: mergedOptions.lightColor!
      }
    })

    return qrDataUrl
  } catch (error) {
    console.error('Failed to generate address QR code:', error)
    throw new Error('Failed to generate QR code for address')
  }
}

/**
 * Generate a QR code for public key or generic data
 *
 * @param data - Data to encode (hex, base64, or string)
 * @param options - QR code generation options
 * @returns Data URL for the generated QR code
 */
export async function generatePublicKeyQR(
  data: string,
  options: QRCodeOptions = {}
): Promise<string> {
  const mergedOptions = { ...DEFAULT_OPTIONS, ...options }

  try {
    const qrDataUrl = await QRCode.toDataURL(data, {
      width: mergedOptions.size,
      errorCorrectionLevel: mergedOptions.errorCorrectionLevel,
      margin: mergedOptions.margin,
      color: {
        dark: mergedOptions.darkColor!,
        light: mergedOptions.lightColor!
      }
    })

    return qrDataUrl
  } catch (error) {
    console.error('Failed to generate public key QR code:', error)
    throw new Error('Failed to generate QR code for public key')
  }
}

/**
 * Generate a QR code for a BSV payment URI
 *
 * Format: bsv:address?amount=0.001&label=Payment
 *
 * @param address - BSV address
 * @param amount - Optional amount in BSV
 * @param label - Optional label for the payment
 * @param options - QR code generation options
 * @returns Data URL for the generated QR code
 */
export async function generatePaymentQR(
  address: string,
  amount?: number,
  label?: string,
  options: QRCodeOptions = {}
): Promise<string> {
  const mergedOptions = { ...DEFAULT_OPTIONS, ...options }

  // Build payment URI
  let uri = `bsv:${address}`
  const params: string[] = []

  if (amount !== undefined && amount > 0) {
    params.push(`amount=${amount}`)
  }

  if (label) {
    params.push(`label=${encodeURIComponent(label)}`)
  }

  if (params.length > 0) {
    uri += '?' + params.join('&')
  }

  try {
    const qrDataUrl = await QRCode.toDataURL(uri, {
      width: mergedOptions.size,
      errorCorrectionLevel: mergedOptions.errorCorrectionLevel,
      margin: mergedOptions.margin,
      color: {
        dark: mergedOptions.darkColor!,
        light: mergedOptions.lightColor!
      }
    })

    return qrDataUrl
  } catch (error) {
    console.error('Failed to generate payment QR code:', error)
    throw new Error('Failed to generate QR code for payment')
  }
}

/**
 * Generate a QR code for transaction BEEF data
 *
 * @param beefHex - BEEF transaction in hex format
 * @param options - QR code generation options
 * @returns Data URL for the generated QR code
 */
export async function generateBEEFQR(
  beefHex: string,
  options: QRCodeOptions = {}
): Promise<string> {
  const mergedOptions = { ...DEFAULT_OPTIONS, ...options }

  try {
    const qrDataUrl = await QRCode.toDataURL(beefHex, {
      width: mergedOptions.size,
      errorCorrectionLevel: mergedOptions.errorCorrectionLevel,
      margin: mergedOptions.margin,
      color: {
        dark: mergedOptions.darkColor!,
        light: mergedOptions.lightColor!
      }
    })

    return qrDataUrl
  } catch (error) {
    console.error('Failed to generate BEEF QR code:', error)
    throw new Error('Failed to generate QR code for BEEF transaction')
  }
}

/**
 * Estimate the number of chunks required for data
 *
 * @param data - Data to be chunked
 * @param maxChunkSize - Maximum chunk size (default: 80)
 * @returns Estimated number of chunks
 */
export function estimateChunkCount(data: string, maxChunkSize: number = 80): number {
  if (data.length <= 100) {
    return 1
  }
  return Math.ceil(data.length / maxChunkSize)
}

/**
 * Check if data will need chunking
 *
 * @param data - Data to check
 * @returns true if data will be chunked
 */
export function willBeChunked(data: string): boolean {
  return data.length > 100
}
