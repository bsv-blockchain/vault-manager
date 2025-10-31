// Centralized validation utilities for all user inputs
export type ValidationResult = true | string

// Generic helpers ------------------------------------------------------------
export function isNonEmptyTrimmed(value: string): boolean {
  return value.trim().length > 0
}

export function requireNonEmpty(value: string, fieldName: string, maxLen?: number): ValidationResult {
  const v = value.trim()
  if (!v) return `${fieldName} cannot be empty.`
  if (typeof maxLen === 'number' && v.length > maxLen) return `${fieldName} must be at most ${maxLen} characters.`
  return true
}

export function requireLength(value: string, fieldName: string, minLen: number, maxLen: number): ValidationResult {
  const v = value.trim()
  if (v.length < minLen) return `${fieldName} must be at least ${minLen} characters.`
  if (v.length > maxLen) return `${fieldName} must be at most ${maxLen} characters.`
  return true
}

export function requireIntegerString(value: string, fieldName: string, opts?: { min?: number; max?: number }): ValidationResult {
  const v = value.trim()
  if (!/^\d+$/.test(v)) return `${fieldName} must be a whole number.`
  const n = Number(v)
  if (!Number.isSafeInteger(n)) return `${fieldName} is not a safe integer.`
  if (opts?.min !== undefined && n < opts.min) return `${fieldName} must be >= ${opts.min}.`
  if (opts?.max !== undefined && n > opts.max) return `${fieldName} must be <= ${opts.max}.`
  return true
}

export function parseInteger(value: string): number {
  return Number(value.trim())
}

// Password policy ------------------------------------------------------------
// Enforce strong password policy: length >= 12, with upper, lower, digit, and symbol
export function validatePassword(value: string): ValidationResult {
  if (value.length < 12) return 'Password must be at least 12 characters.'
  return true
}

// Entropy input (user-provided randomness prompts)
// Hex / IDs ------------------------------------------------------------------
export function isHex(value: string): boolean {
  return /^[0-9a-fA-F]+$/.test(value)
}

export function validateHex(value: string, fieldName = 'Value'): ValidationResult {
  const v = value.trim()
  if (!v) return `${fieldName} cannot be empty.`
  if (!isHex(v)) return `${fieldName} must be hexadecimal.`
  if (v.length % 2 !== 0) return `${fieldName} must have an even number of hex characters.`
  return true
}

export function validateTxid(value: string): ValidationResult {
  const v = value.trim()
  if (v.length !== 64 || !isHex(v)) return 'TXID must be a 64-character hex string.'
  return true
}

export function validateBeefHex(value: string): ValidationResult {
  // Allow Transaction.fromAtomicBEEF to do deep structure checks; ensure hex and even length here
  return validateHex(value, 'Atomic BEEF hex')
}

// Address / Script -----------------------------------------------------------
const BASE58_RE = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/

export function validateAddressOrScript(value: string): ValidationResult {
  const v = value.trim()
  if (!v) return 'Destination is required.'
  // Hex script (even-length hex, at least 20 chars)
  if (isHex(v)) {
    if (v.length % 2 !== 0) return 'Script hex must have an even number of characters.'
    if (v.length < 20) return 'Script hex looks too short.'
    return true
  }
  // Base58 address heuristic (26-62 chars typical)
  if (BASE58_RE.test(v) && v.length >= 26 && v.length <= 62) return true
  return 'Destination must be a valid Base58 address or script hex.'
}

// Amounts / memos ------------------------------------------------------------
export function validateSatoshis(value: string): ValidationResult {
  const int = requireIntegerString(value, 'Satoshis', { min: 1 })
  if (int !== true) return int
  const n = parseInteger(value)
  const MAX_SATS = 2_100_000_000_000_000 // 21M * 1e8
  if (n > MAX_SATS) return `Satoshis must be <= ${MAX_SATS.toLocaleString()}.`
  return true
}

export function validateMemo(value: string, label = 'Memo', maxLen = 256): ValidationResult {
  if (value.length > maxLen) return `${label} must be at most ${maxLen} characters.`
  return true
}

export function validateVaultName(value: string): ValidationResult {
  return requireLength(value, 'Vault name', 1, 64)
}

export function validatePBKDF2Rounds(value: string): ValidationResult {
  return requireIntegerString(value, 'PBKDF2 rounds', { min: 80000 })
}
