import { Hash, Utils, Beef, Transaction } from '@bsv/sdk'
import { HashRecord, BackupRecord } from './types'

export const STORAGE_HASHES_KEY = 'bsvvault:last-hashes'
export const STORAGE_BACKUPS_KEY = 'bsvvault:backups'
export const MAX_BACKUPS_PER_VAULT = 5

export function safeReadStore<T>(key: string, fallback: T): T {
  if (typeof window === 'undefined') return fallback
  try {
    const raw = window.localStorage.getItem(key)
    if (!raw) return fallback
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

export function safeWriteStore<T>(key: string, value: T): void {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(key, JSON.stringify(value))
  } catch (err) {
    console.warn('Failed to persist vault metadata:', err)
  }
}

export function getExpectedHashRecord(plainHash: string): HashRecord | undefined {
  const store = safeReadStore<Record<string, HashRecord>>(STORAGE_HASHES_KEY, {})
  return store[plainHash]
}

export function setExpectedHashRecord(plainHash: string, record: HashRecord): void {
  const store = safeReadStore<Record<string, HashRecord>>(STORAGE_HASHES_KEY, {})
  store[plainHash] = record
  safeWriteStore(STORAGE_HASHES_KEY, store)
}

export function bytesToHex(bytes: number[]): string {
  let hex = ''
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0')
  }
  return hex
}

export function hexToBytes(hex: string): number[] {
  const clean = hex.trim()
  const out: number[] = []
  for (let i = 0; i < clean.length; i += 2) {
    const byte = clean.slice(i, i + 2)
    out.push(parseInt(byte, 16))
  }
  return out
}

export function getBackupsForPlain(plainHash: string): BackupRecord[] {
  const store = safeReadStore<Record<string, BackupRecord[]>>(STORAGE_BACKUPS_KEY, {})
  return store[plainHash] || []
}

export function addBackupForPlain(plainHash: string, entry: BackupRecord): void {
  const store = safeReadStore<Record<string, BackupRecord[]>>(STORAGE_BACKUPS_KEY, {})
  const list = store[plainHash] || []
  list.unshift(entry)
  store[plainHash] = list.slice(0, MAX_BACKUPS_PER_VAULT)
  safeWriteStore(STORAGE_BACKUPS_KEY, store)
}

export function recordVaultLoadMetadata(params: {
  plainHash: string
  fileHash: string
  fileName: string | null
  bytes: number[]
}): { expected?: HashRecord; mismatch: boolean } {
  const { plainHash, fileHash, fileName, bytes } = params
  const timestamp = Date.now()
  addBackupForPlain(plainHash, {
    id: `${timestamp}-${Math.random().toString(36).slice(2, 8)}`,
    fileHash,
    storedAt: timestamp,
    fileName: fileName || undefined,
    hex: bytesToHex(bytes)
  })
  const expected = getExpectedHashRecord(plainHash)
  const mismatch = expected ? expected.fileHash !== fileHash : false
  return { expected, mismatch }
}

export function recordVaultSaveMetadata(params: {
  plainHash: string
  fileHash: string
  fileName: string | null
  bytes: number[]
}) {
  const timestamp = Date.now()
  addBackupForPlain(params.plainHash, {
    id: `${timestamp}-${Math.random().toString(36).slice(2, 8)}`,
    fileHash: params.fileHash,
    storedAt: timestamp,
    fileName: params.fileName || undefined,
    hex: bytesToHex(params.bytes)
  })
  setExpectedHashRecord(params.plainHash, {
    fileHash: params.fileHash,
    savedAt: timestamp,
    fileName: params.fileName || undefined
  })
}

/** Format a txid:outputIndex pair */
export function coinIdStr(txid: string, outputIndex: number): string {
  return `${txid}:${outputIndex}`
}

export function assert(cond: any, msg: string): asserts cond {
  if (!cond) throw new Error(msg)
}

/** Helper to get a TX from a vault's BEEF store (throws if missing). */
export function getTxFromStore(beefStore: Beef, txid: string): Transaction {
  const bin = beefStore.toBinary()
  const tx = Transaction.fromBEEF(bin, txid) // throws if not found
  return tx
}
