import React, { useEffect, useMemo, useState, FC, ReactNode, createContext, useCallback, useContext } from 'react'
import {
  PrivateKey, P2PKH, Script, Transaction, PublicKey, ChainTracker,
  Utils, Hash, SymmetricKey, Random, TransactionOutput, Beef
} from '@bsv/sdk'

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
  const v = value
  if (v.length < 12) return 'Password must be at least 12 characters.'
  if (!/[a-z]/.test(v)) return 'Password must include at least one lowercase letter.'
  if (!/[A-Z]/.test(v)) return 'Password must include at least one uppercase letter.'
  if (!/\d/.test(v)) return 'Password must include at least one digit.'
  if (!/[~`!@#$%^&*()_\-+=\[\]{};:'",.<>/?\\|]/.test(v)) return 'Password must include at least one symbol.'
  return true
}

// Entropy input (user-provided randomness prompts)
export function validateEntropyInput(value: string): ValidationResult {
  const v = value.trim()
  if (v.length < 24) return 'Please provide at least 24 characters of random input.'
  return true
}

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

/**
 * =============================================================================
 * Lightweight UI & Dialog System (no window.* usage anywhere)
 * =============================================================================
 */

type Notification = { type: 'success' | 'error' | 'info', message: string, id: number }

const COLORS = {
  red: '#8b0000',
  green: '#0a7b22',
  blue: '#1e6bd6',
  gray600: '#555',
  gray700: '#333',
  border: '#ddd',
  light: '#f7f7f8',
  panel: '#ffffff',
}

const appShellStyle: React.CSSProperties = { fontFamily: 'Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif', background: COLORS.light, minHeight: '100vh', color: COLORS.gray700, colorScheme: 'light' }
const containerStyle: React.CSSProperties = { padding: 12, maxWidth: 1180, margin: '0 auto' }
const panelStyle: React.CSSProperties = { background: COLORS.panel, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 12, boxShadow: '0 2px 10px rgba(0,0,0,0.03)' }
const sectionStyle: React.CSSProperties = { ...panelStyle, marginBottom: 12 }
const btnStyle: React.CSSProperties = { background: COLORS.blue, color: 'white', border: 'none', padding: '12px 14px', borderRadius: 8, cursor: 'pointer', width: '100%', maxWidth: 240, touchAction: 'manipulation' }
const btnGhostStyle: React.CSSProperties = { background: '#777', color: '#fff', border: 'none', padding: '12px 14px', borderRadius: 8, cursor: 'pointer', width: '100%', maxWidth: 240, touchAction: 'manipulation' }
const inputStyle: React.CSSProperties = {
  border: `1px solid ${COLORS.border}`,
  borderRadius: 8,
  padding: '10px 12px',
  width: '100%',
  background: '#fff',
  color: '#111',
  caretColor: '#111'
}

const NotificationBanner: FC<{ notification: Notification, onDismiss: () => void }> = ({ notification, onDismiss }) => {
  const colors = { success: '#4CAF50', error: '#8b0000', info: '#2196F3' }
  useEffect(() => {
    const timer = setTimeout(onDismiss, 5000)
    return () => clearTimeout(timer)
  }, [notification.id, onDismiss])

  return (
    <div style={{
      position: 'fixed', top: 12, right: 12, background: colors[notification.type], color: 'white',
      padding: '12px 16px', borderRadius: 12, zIndex: 1000, boxShadow: '0 8px 24px rgba(0,0,0,0.2)',
      display: 'flex', alignItems: 'center', gap: 16, maxWidth: '90vw'
    }}>
      <span style={{ wordBreak: 'break-word' }}>{notification.message}</span>
      <button onClick={onDismiss} style={{ background: 'none', border: 'none', color: 'white', fontSize: 22, cursor: 'pointer', lineHeight: 1, padding: 0 }}>&times;</button>
    </div>
  )
}

const Modal: FC<{ title: string, children: ReactNode, onClose: () => void }> = ({ title, children, onClose }) => {
  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(0, 0, 0, 0.5)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
      padding: 8
    }}>
      <div style={{
        background: 'white',
        color: '#111',
        padding: 12,
        borderRadius: 12,
        minWidth: 280,
        maxWidth: 900,
        width: '95%',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: `1px solid ${COLORS.border}`, paddingBottom: 8, marginBottom: 12, gap: 8 }}>
          <h2 style={{ margin: 0, fontSize: 18 }}>{title}</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', fontSize: 28, cursor: 'pointer', lineHeight: 1 }}>&times;</button>
        </div>
        {children}
      </div>
    </div>
  )
}

/** Dialogs ------------------------------------------------------------------ */
type DialogRequest =
  | { kind: 'alert'; title?: string; message: string; resolve: () => void }
  | { kind: 'confirm'; title?: string; message: string; confirmText?: string; cancelText?: string; resolve: (ok: boolean) => void }
  | { kind: 'prompt'; title?: string; message: string; password?: boolean; defaultValue?: string; placeholder?: string; maxLength?: number; validate?: (val: string) => true | string; resolve: (val: string | null) => void }

type DialogAPI = {
  alert(msg: string, title?: string): Promise<void>
  confirm(msg: string, opts?: { title?: string; confirmText?: string; cancelText?: string }): Promise<boolean>
  prompt(msg: string, opts?: { title?: string; password?: boolean; defaultValue?: string; placeholder?: string; maxLength?: number; validate?: (val: string) => true | string }): Promise<string | null>
}

const DialogCtx = createContext<DialogAPI | null>(null)

const PromptDialog: FC<{ req: DialogRequest & { kind: 'prompt' }; onResolve: (val: string | null) => void }> = ({ req, onResolve }) => {
  const [val, setVal] = useState(req.defaultValue || '')
  const [error, setError] = useState<string | null>(null)

  // Reset the value if the request changes, ensuring the input is fresh
  useEffect(() => {
    setVal(req.defaultValue || '')
    setError(null)
  }, [req])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // Run optional validation; if invalid, show error and keep dialog open
    if (req.validate) {
      const res = req.validate(val)
      if (res !== true) {
        setError(typeof res === 'string' ? res : 'Invalid input.')
        return
      }
    }
    onResolve(val)
  }

  // Randomize a name attribute to further avoid password-manager heuristics
  const randomName = useMemo(() => `fld_${Math.random().toString(36).slice(2)}`, [])

  return (
    <Modal title={req.title || 'Input required'} onClose={() => onResolve(null)}>
      <form onSubmit={handleSubmit} autoComplete="off">
        <p style={{ whiteSpace: 'pre-wrap' }}>{req.message}</p>
        <input
          type={req.password ? 'password' : 'text'}
          name={randomName}
          autoComplete='off'
          value={val}
          onChange={e => setVal(e.target.value)}
          placeholder={req.placeholder}
          maxLength={req.maxLength}
          style={{ ...inputStyle, marginTop: 8 }}
          autoFocus
        />
        {req.password && (
          <div style={{ marginTop: 6, fontSize: 12, color: COLORS.gray600 }}>
            Minimum 12 chars with upper, lower, digit, and symbol.
          </div>
        )}
        {!!error && (
          <div style={{ marginTop: 6, fontSize: 12, color: COLORS.red }}>{error}</div>
        )}
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12, gap: 8, flexWrap: 'wrap' }}>
          <button type="button" onClick={() => onResolve(null)} style={btnGhostStyle}>Cancel</button>
          <button type="submit" style={btnStyle}>Submit</button>
        </div>
      </form>
    </Modal>
  )
}

const DialogHost: FC<{ queue: DialogRequest[]; setQueue: React.Dispatch<React.SetStateAction<DialogRequest[]>> }> = ({ queue, setQueue }) => {
  if (!queue.length) return null
  const req = queue[0]
  const close = () => setQueue(q => q.slice(1))

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
      <Modal title={req.title || 'Notice'} onClose={() => { req.resolve(); close() }}>
        <p style={{ whiteSpace: 'pre-wrap' }}>{req.message}</p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12 }}>
          <button onClick={() => { req.resolve(); close() }} style={btnStyle} autoFocus>OK</button>
        </div>
      </Modal>
    )
  }

  if (req.kind === 'confirm') {
    return (
      <Modal title={req.title || 'Confirm'} onClose={() => { req.resolve(false); close() }}>
        <p style={{ whiteSpace: 'pre-wrap' }}>{req.message}</p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12, gap: 8, flexWrap: 'wrap' }}>
          <button onClick={() => { req.resolve(false); close() }} style={btnGhostStyle}>{req.cancelText || 'No'}</button>
          <button onClick={() => { req.resolve(true); close() }} style={btnStyle} autoFocus>{req.confirmText || 'Yes'}</button>
        </div>
      </Modal>
    )
  }

  if (req.kind === 'prompt') {
    return (
      <PromptDialog req={req} onResolve={(val) => {
        req.resolve(val)
        close()
      }} />
    )
  }

  return null
}

export const DialogProvider: FC<{ children: ReactNode }> = ({ children }) => {
  const [queue, setQueue] = React.useState<DialogRequest[]>([])
  const push = useCallback(<T,>(req: Omit<DialogRequest, 'resolve'>) =>
    new Promise<T>(resolve => setQueue(q => [...q, { ...(req as any), resolve }]))
  , [])

  const api: DialogAPI = {
    alert: (message, title) => push<void>({ kind: 'alert', title, message }),
    confirm: (message, opts) => push<boolean>({
      kind: 'confirm',
      title: opts?.title,
      message,
      confirmText: opts?.confirmText,
      cancelText: opts?.cancelText
    }),
    prompt: (message, opts) => push<string | null>({ kind: 'prompt', title: opts?.title, message, password: opts?.password, defaultValue: opts?.defaultValue, placeholder: opts?.placeholder, maxLength: opts?.maxLength, validate: opts?.validate })
  }
  return (
    <DialogCtx.Provider value={api}>
      {children}
      <DialogHost queue={queue} setQueue={setQueue} />
    </DialogCtx.Provider>
  )
}

export const useDialog = () => {
  const ctx = useContext(DialogCtx)
  if (!ctx) throw new Error('useDialog must be used within DialogProvider')
  return ctx
}

/**
 * =============================================================================
 * Types & Utilities
 * =============================================================================
 */

type UnixMs = number

/** Dialog bridge for Vault business logic (no window.*) */
type UiBridge = {
  alert: (msg: string, title?: string) => Promise<void>
  confirm: (msg: string, title?: string) => Promise<boolean>
  prompt: (msg: string, opts?: { title?: string; password?: boolean; defaultValue?: string; placeholder?: string; maxLength?: number; validate?: (val: string) => true | string }) => Promise<string | null>
}

/** A serializable, sanitized session/vault event. */
type AuditEvent = {
  at: UnixMs
  event: string
  data?: string
}

type KeyRecord = {
  serial: string
  private: PrivateKey        // NEVER log
  public: PublicKey
  usedOnChain: boolean
  memo: string
}

type CoinRecord = {
  txid: string
  outputIndex: number
  memo: string
  keySerial: string
}

type TxLogRecord = {
  at: UnixMs
  txid: string
  net: number // positive=in, negative=out (includes fee)
  memo: string
  processed: boolean
}

type PersistedHeaderClaim = {
  at: UnixMs
  merkleRoot: string
  height: number
  memo: string
}

type EphemeralHeaderClaim = {
  at: UnixMs
  merkleRoot: string
  height: number
}

type OutgoingOutputSpec = {
  /** Address (Base58/BSV) OR full locking script hex */
  destinationAddressOrScript: string
  satoshis: number
  memo?: string
}

type MatchedOutput = {
  outputIndex: number
  lockingScript: string
  satoshis: number
  serial: string
}

type IncomingPreview = {
  tx: Transaction
  txid: string
  hex: string
  matches: MatchedOutput[]
  spvValid: boolean
}

type AttestationFn = (coin: CoinRecord) => Promise<boolean>

type BuildOutgoingOptions = {
  outputs: OutgoingOutputSpec[]
  inputIds?: string[]          // REQUIRED now (enforced)
  changeKeySerials?: string[]  // REQUIRED now (enforced)
  perUtxoAttestation?: boolean
  attestationFn?: AttestationFn
  txMemo?: string
}

/** Format a txid:outputIndex pair */
function coinIdStr (txid: string, outputIndex: number): string {
  return `${txid}:${outputIndex}`
}

function assert (cond: any, msg: string): asserts cond {
  if (!cond) throw new Error(msg)
}

/** Helper to get a TX from a vault's BEEF store (throws if missing). */
function getTxFromStore (beefStore: Beef, txid: string): Transaction {
  const bin = beefStore.toBinary()
  const tx = Transaction.fromBEEF(bin, txid) // throws if not found
  return tx
}

/**
 * =============================================================================
 * Vault class
 * - Implements ChainTracker.
 * - Holds derived encryption key (NOT the password).
 * - Maintains a global vault-wide BEEF store.
 * =============================================================================
 */

class Vault implements ChainTracker {
  constructor(private ui: UiBridge) {}

  /** File format / policy */
  protocolVersion = 1
  passwordRounds = 80000
  passwordSalt: number[] = new Array(32).fill(0)
  /** Cached symmetric key derived from user password (NOT the password itself) */
  private encryptionKey?: SymmetricKey

  /** Metadata */
  vaultName = 'Vault'
  vaultRevision = 1
  created: UnixMs = Date.now()
  lastUpdated: UnixMs = Date.now()

  /** Global transaction store */
  beefStore: Beef = new Beef()

  /** Keys & coins */
  keys: KeyRecord[] = []
  coins: CoinRecord[] = []

  /** Activity logs (sanitized; never log keys) */
  transactionLog: TxLogRecord[] = []
  vaultLog: AuditEvent[] = []
  sessionLog: AuditEvent[] = []

  /** ChainTracker policy & caches */
  confirmIncomingCoins = true
  confirmOutgoingCoins = false
  persistHeadersOlderThanBlocks = 144
  reverifyRecentHeadersAfterSeconds = 60
  reverifyCurrentBlockHeightAfterSeconds = 600
  persistedHeaderClaims: PersistedHeaderClaim[] = []
  ephemeralHeaderClaims: EphemeralHeaderClaim[] = []
  currentBlockHeight = 0
  currentBlockHeightAcquiredAt = 0

  /** Randomness policy */
  useUserEntropyForRandom = false

  /** UI-only flags */
  saved = false

  // -------------------------------------------------------------------------
  // Randomness Wizard & Helpers
  // -------------------------------------------------------------------------
  private async getRandomBytes(n: number): Promise<number[]> {
    // Always include device entropy
    const dev = Random(Math.max(32, n))
    if (!this.useUserEntropyForRandom) return dev.slice(0, n)

    // Ask the user for extra entropy in a simple modal flow
    const part1 = (await this.ui.prompt(
      'Type or paste a bunch of random characters (keyboard mashing, dice rolls, book numbers, etc).',
      { title: 'Entropy Input — Part 1', validate: validateEntropyInput, placeholder: 'At least 24 random characters' }
    )) || ''
    const part2 = (await this.ui.prompt(
      'Again (different source than before).',
      { title: 'Entropy Input — Part 2', validate: validateEntropyInput, placeholder: 'At least 24 random characters' }
    )) || ''

    const userSeed = Utils.toArray(part1 + '|' + part2, 'utf8')
    const userHash = Hash.sha256(userSeed) // 32 bytes

    // Expand to n bytes using iterative hashing, mixing device entropy
    const out: number[] = []
    let counter = 0
    while (out.length < n) {
      const block = Hash.sha256([
        ...dev,
        ...userHash,
        ...Utils.toArray(String(counter))
      ])
      out.push(...block)
      counter++
    }
    // Final mash: xor with device entropy (cycled) to avoid user-only or device-only weakness
    const mixed = out.slice(0, n).map((b, i) => b ^ dev[i % dev.length])
    this.logSession('random.bytes', `n=${n} userEntropy=1`)
    return mixed
  }

  private async newPrivateKey(): Promise<PrivateKey> {
    const bytes = await this.getRandomBytes(32)
    const pk = new PrivateKey(bytes)
    return pk
  }

  // -------------------------------------------------------------------------
  // Logging (forensic; strictly sanitized)
  // -------------------------------------------------------------------------
  private logSession (event: string, data?: string) {
    this.sessionLog.push({ at: Date.now(), event, data })
  }
  logVault (event: string, data?: string) {
    this.vaultLog.push({ at: Date.now(), event, data })
  }
  private logKV (scope: 'session' | 'vault', key: string, value: string) {
    const evt = `${scope}.${key}`
    ;(scope === 'session' ? this.sessionLog : this.vaultLog).push({
      at: Date.now(),
      event: evt,
      data: value
    })
  }

  // -------------------------------------------------------------------------
  // ChainTracker
  // -------------------------------------------------------------------------
  async isValidRootForHeight (root: string, height: number): Promise<boolean> {
    const persisted = this.persistedHeaderClaims.findIndex(c => c.merkleRoot === root && c.height === height)
    if (persisted !== -1) return true

    const ephemeral = this.ephemeralHeaderClaims.findIndex(c =>
      c.merkleRoot === root &&
      c.height === height &&
      (Date.now() - c.at) < (this.reverifyRecentHeadersAfterSeconds * 1000)
    )
    if (ephemeral !== -1) return true

    const accepted = await this.ui.confirm(
      `Do you accept and confirm that block #${height} of the HONEST chain has a merkle root of:\n${root}`,
      'Confirm Merkle Root'
    )
    if (!accepted) return false

    // Decide whether to persist
    if (this.currentBlockHeight !== 0 && (this.currentBlockHeight - this.persistHeadersOlderThanBlocks) < height) {
      this.ephemeralHeaderClaims.push({ at: Date.now(), merkleRoot: root, height })
      this.logVault('chain.header.ephemeral', `h=${height} root=${root}`)
      this.logSession('chain.header.ephemeral', `h=${height} root=${root}`)
    } else {
      let memo = await this.ui.prompt('Enter the source(s) used to confirm this merkle root:', { title: 'Merkle Root Memo', maxLength: 256, validate: (v) => validateMemo(v, 'Memo', 256) })
      if (!memo) memo = 'No memo provided.'
      this.persistedHeaderClaims.push({ at: Date.now(), merkleRoot: root, height, memo })
      this.logVault('chain.header.persisted', `h=${height} root=${root} memo=${memo}`)
      this.logSession('chain.header.persisted', `h=${height} root=${root} memo=${memo}`)
    }
    return true
  }

  async currentHeight (): Promise<number> {
    if (
      this.currentBlockHeight !== 0 &&
      (Date.now() - this.currentBlockHeightAcquiredAt) < (this.reverifyCurrentBlockHeightAfterSeconds * 1000)
    ) {
      return this.currentBlockHeight
    }
    let height = 0
    do {
      try {
        const input = await this.ui.prompt('Enter the current block height for the HONEST chain:', { title: 'Block Height', validate: (v) => requireIntegerString(v, 'Block height', { min: 1 }) })
        const n = Number(input)
        if (Number.isInteger(n) && n > 0) height = n
        else await this.ui.alert('Height must be a positive integer, try again.', 'Invalid Input')
      } catch (e) {
        await this.ui.alert((e as any).message || 'Error processing height, try again.', 'Error')
      }
    } while (height === 0)
    this.currentBlockHeight = height
    this.currentBlockHeightAcquiredAt = Date.now()
    this.logVault('chain.height.set', String(height))
    return height
  }

  // -------------------------------------------------------------------------
  // Creation / Loading / Saving (no re-prompt once key is set)
  // -------------------------------------------------------------------------
  static async create (ui: UiBridge): Promise<Vault> {
    const v = new Vault(ui)
    v.logSession('wizard.start', 'create')

    const name = (await ui.prompt('Enter a vault display name:', { title: 'Vault Name' })) || 'Vault'
    v.vaultName = name
    v.logVault('vault.created', name)

    const roundsIn = await ui.prompt(`PBKDF2 rounds? (default ${v.passwordRounds})`, { title: 'PBKDF2 Rounds', defaultValue: String(v.passwordRounds), validate: validatePBKDF2Rounds })
    if (roundsIn && /^\d+$/.test(roundsIn)) {
      const n = Number(roundsIn)
      if (n >= 1) v.passwordRounds = n
    }
    v.passwordSalt = await v.getRandomBytes(32)
    v.logKV('vault', 'passwordRounds', String(v.passwordRounds))
    v.logKV('vault', 'passwordSalt.len', String(v.passwordSalt.length))

    // Policy: ask whether to use user entropy for future randomness
    v.useUserEntropyForRandom = await ui.confirm('Require user-provided entropy whenever randomness is needed? (Recommended if you distrust device RNG)', 'Randomness Policy')

    // Require password once, derive and cache key
    const pw = (await ui.prompt('Set a password for this vault file (required):', { title: 'Vault Password', password: true, validate: validatePassword, maxLength: 1024 })) || ''
    if (!pw) throw new Error('Password required to create vault.')
    const keyBytes = Hash.pbkdf2(Utils.toArray(pw), v.passwordSalt, v.passwordRounds, 32)
    v.encryptionKey = new SymmetricKey(keyBytes)
    v.logVault('vault.key.derived', `klen=${keyBytes.length}`)

    // Policy toggles
    v.confirmIncomingCoins = await ui.confirm('Require attestation for incoming UTXOs? (Recommended)', 'Incoming Attestation')
    v.confirmOutgoingCoins = await ui.confirm('Require attestation for outgoing UTXOs?', 'Outgoing Attestation')
    v.logKV('vault', 'confirmIncomingCoins', String(v.confirmIncomingCoins))
    v.logKV('vault', 'confirmOutgoingCoins', String(v.confirmOutgoingCoins))

    // Header settings
    const older = await ui.prompt(`Persist headers older than how many blocks? (default ${v.persistHeadersOlderThanBlocks})`, { title: 'Header Persistence', defaultValue: String(v.persistHeadersOlderThanBlocks), validate: (val) => requireIntegerString(val, 'Persist headers', { min: 0 }) })
    if (older && /^\d+$/.test(older)) v.persistHeadersOlderThanBlocks = Number(older)
    const recentSec = await ui.prompt(`Re-verify recent headers after how many seconds? (default ${v.reverifyRecentHeadersAfterSeconds})`, { title: 'Re-verify Recent Headers', defaultValue: String(v.reverifyRecentHeadersAfterSeconds), validate: (val) => requireIntegerString(val, 'Re-verify recent headers (seconds)', { min: 1 }) })
    if (recentSec && /^\d+$/.test(recentSec)) v.reverifyRecentHeadersAfterSeconds = Number(recentSec)
    const heightSec = await ui.prompt(`Re-verify current block height after how many seconds? (default ${v.reverifyCurrentBlockHeightAfterSeconds})`, { title: 'Re-verify Height', defaultValue: String(v.reverifyCurrentBlockHeightAfterSeconds), validate: (val) => requireIntegerString(val, 'Re-verify height (seconds)', { min: 1 }) })
    if (heightSec && /^\d+$/.test(heightSec)) v.reverifyCurrentBlockHeightAfterSeconds = Number(heightSec)

    v.logSession('wizard.complete', 'create')
    await v.currentHeight() // Prompt for initial block height
    return v
  }

  static async loadFromFile (ui: UiBridge, file: number[]): Promise<Vault> {
    const v = new Vault(ui)
    v.logSession('vault.load.start', `size=${file.length}`)

    const fileHash = Utils.toHex(Hash.sha256(file))
    v.logSession('vault.load.hash', fileHash)
    const ok = await ui.confirm(`Ensure the SHA-256 hash of the vault file that you stored matches:\n${fileHash}`, 'Verify Vault File Hash')
    if (!ok) throw new Error('Vault file SHA-256 has not been verified.')

    const r = new Utils.Reader(file)
    const proto = r.readVarIntNum()
    if (proto !== 1 && proto !== v.protocolVersion) throw new Error(`Vault protocol version mismatch. File=${proto} Software=${v.protocolVersion}`)
    v.logVault('vault.proto.ok', String(proto))

    const rounds = r.readVarIntNum()
    if (rounds < 1) throw new Error('Vault password rounds must be >= 1.')
    v.passwordRounds = rounds
    const salt = r.read(32); v.passwordSalt = salt
    const encrypted = r.read()

    let decrypted: number[] = []
    do {
      const pw = await ui.prompt('Enter vault password:', { title: 'Unlock Vault', password: true })
      const kb = Hash.pbkdf2(Utils.toArray(pw || ''), salt, rounds, 32)
      const key = new SymmetricKey(kb)
      try {
        decrypted = key.decrypt(encrypted) as number[]
        v.encryptionKey = key
        v.logSession('vault.decrypt.ok', `payload=${decrypted.length}B`)
      } catch {
        v.logSession('vault.decrypt.fail')
        await ui.alert('Failed to unlock the vault.', 'Decryption Error')
      }
    } while (decrypted.length === 0)

    v.deserializePlaintext(decrypted)
    v.logSession('vault.load.ok')
    await v.currentHeight() // Prompt for block height on load
    return v
  }

  /** Deterministic plaintext hash (for “unsaved changes” banner). */
  computePlaintextHash (): string {
    const pt = this.serializePlaintext()
    return Utils.toHex(Hash.sha256(pt))
  }

  /** Save using cached encryption key; never re-prompts. */
  async saveToFileBytes (): Promise<number[]> {
    assert(this.encryptionKey, 'Encryption key not initialized; create or load the vault first.')

    this.vaultRevision++
    this.lastUpdated = Date.now()
    this.logVault('vault.saved', `rev=${this.vaultRevision}`)

    const payload = this.serializePlaintext()
    const encrypted = this.encryptionKey!.encrypt(payload) as number[]

    const writer = new Utils.Writer()
    writer.writeVarIntNum(this.protocolVersion)
    writer.writeVarIntNum(this.passwordRounds)
    writer.write(this.passwordSalt) // 32 bytes
    writer.write(encrypted)

    const bytes = writer.toArray() as number[]
    this.saved = true
    return bytes
  }

  /** Export a specific transaction's Atomic BEEF by txid (throws if not found). */
  exportAtomicBEEFHexByTxid (txid: string): string {
    const tx = getTxFromStore(this.beefStore, txid)
    return Utils.toHex(tx.toAtomicBEEF() as number[])
  }

  async downloadVaultFileAndCertify (): Promise<boolean> {
    const bytes = await this.saveToFileBytes()
    const hashHex = Utils.toHex(Hash.sha256(bytes))
    const blob = new Blob([new Uint8Array(bytes)], { type: 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${this.vaultName.replace(/\s+/g, '_')}_rev${this.vaultRevision}_${Date.now()}.vaultfile`
    a.click()
    URL.revokeObjectURL(url)

    // Performative Certification Flow
    const cert1 = await this.ui.confirm('Do you certify that the new vault has been properly saved or copied into secure long-term storage?', 'Step 1: Confirm Safe Storage')
    if (!cert1) return false

    const cert2 = await this.ui.confirm(`The SHA-256 hash of the new vault is:\n\n${hashHex}\n\nDo you certify that you will save this hash and confirm it when the vault is next loaded to ensure it has not been tampered with?`, 'Step 2: Confirm Hash Verification')
    if (!cert2) return false

    const cert3 = await this.ui.confirm(`The current revision is #${this.vaultRevision}. All old vault revisions are now invalid and will not work.\n\nDo you certify that you have securely deleted all previous revisions and will only use the new one in the future?`, 'Step 3: Confirm Deletion of Old Revisions')
    if (!cert3) return false
    
    await this.ui.alert('Vault saved and certified successfully. You will now be logged out for security.', 'Save Complete')
    location.reload()
    return true
}

  // -------------------------------------------------------------------------
  // Password & Name management
  // -------------------------------------------------------------------------
  async renameVault(newName: string): Promise<void> {
    const name = (newName || '').trim()
    assert(name.length > 0, 'Vault name cannot be empty.')
    this.vaultName = name
    this.logVault('vault.renamed', name)
  }

  async changePassword(): Promise<void> {
    assert(this.encryptionKey, 'Encryption key not initialized.')

    const newPw = await this.ui.prompt('Enter NEW password:', { title: 'Change Password', password: true, validate: validatePassword, maxLength: 1024 })
    if (!newPw) throw new Error('Password change cancelled or empty.')
    const confirmPw = await this.ui.prompt('Re-enter NEW password:', { title: 'Confirm New Password', password: true })
    if (newPw !== confirmPw) throw new Error('Passwords do not match.')

    const roundsIn = await this.ui.prompt(`PBKDF2 rounds? (default ${this.passwordRounds})`, { title: 'PBKDF2 Rounds', defaultValue: String(this.passwordRounds), validate: validatePBKDF2Rounds })
    let rounds = this.passwordRounds
    if (roundsIn && /^\d+$/.test(roundsIn)) {
      const n = Number(roundsIn)
      if (n >= 1) rounds = n
    }

    // rotate salt using current randomness policy
    const newSalt = await this.getRandomBytes(32)
    const kb = Hash.pbkdf2(Utils.toArray(newPw), newSalt, rounds, 32)
    this.encryptionKey = new SymmetricKey(kb)
    this.passwordSalt = newSalt
    this.passwordRounds = rounds
    this.logVault('vault.password.changed', `rounds=${rounds} saltlen=${newSalt.length}`)
  }

  // -------------------------------------------------------------------------
  // Serialization (plaintext only; strictly deterministic)
  // -------------------------------------------------------------------------
  private serializePlaintext (): number[] {
    const w = new Utils.Writer()
    // name
    const nameBytes = Utils.toArray(this.vaultName); w.writeVarIntNum(nameBytes.length); w.write(nameBytes)
    // rev
    w.writeVarIntNum(this.vaultRevision)
    // timestamps
    w.writeVarIntNum(this.created); w.writeVarIntNum(this.lastUpdated)

    // keys (serial, priv, used, memo)
    w.writeVarIntNum(this.keys.length)
    for (const k of this.keys) {
      const serialBytes = Utils.toArray(k.serial); w.writeVarIntNum(serialBytes.length); w.write(serialBytes)
      w.write(k.private.toArray()) // 32B; plaintext is encrypted at rest, OK
      w.writeVarIntNum(k.usedOnChain ? 1 : 0)
      const memoBytes = Utils.toArray(k.memo || ''); w.writeVarIntNum(memoBytes.length); w.write(memoBytes)
    }

    // coins (txid, vout, memo, keySerial)
    w.writeVarIntNum(this.coins.length)
    for (const c of this.coins) {
      const txidBytes = Utils.toArray(c.txid, 'hex'); w.write(txidBytes)
      w.writeVarIntNum(c.outputIndex)
      const memoBytes = Utils.toArray(c.memo || ''); w.writeVarIntNum(memoBytes.length); w.write(memoBytes)
      const serBytes = Utils.toArray(c.keySerial); w.writeVarIntNum(serBytes.length); w.write(serBytes)
    }

    // tx log
    w.writeVarIntNum(this.transactionLog.length)
    for (const t of this.transactionLog) {
      w.writeVarIntNum(t.at)
      const txidBytes = Utils.toArray(t.txid, 'hex'); w.write(txidBytes)
      w.writeVarIntNum(t.net)
      const memoBytes = Utils.toArray(t.memo || ''); w.writeVarIntNum(memoBytes.length); w.write(memoBytes)
      w.writeVarIntNum(t.processed ? 1 : 0)
    }

    // vault log (already sanitized)
    w.writeVarIntNum(this.vaultLog.length)
    for (const L of this.vaultLog) {
      w.writeVarIntNum(L.at)
      const e = Utils.toArray(L.event); w.writeVarIntNum(e.length); w.write(e)
      const d = Utils.toArray(L.data || ''); w.writeVarIntNum(d.length); w.write(d)
    }

    // settings
    w.writeVarIntNum(this.confirmIncomingCoins ? 1 : 0)
    w.writeVarIntNum(this.confirmOutgoingCoins ? 1 : 0)
    w.writeVarIntNum(this.persistHeadersOlderThanBlocks)
    w.writeVarIntNum(this.reverifyRecentHeadersAfterSeconds)
    w.writeVarIntNum(this.reverifyCurrentBlockHeightAfterSeconds)
    w.writeVarIntNum(this.useUserEntropyForRandom ? 1 : 0)

    // persisted headers
    w.writeVarIntNum(this.persistedHeaderClaims.length)
    for (const ph of this.persistedHeaderClaims) {
      w.writeVarIntNum(ph.at)
      const mr = Utils.toArray(ph.merkleRoot); w.writeVarIntNum(mr.length); w.write(mr)
      w.writeVarIntNum(ph.height)
      const memo = Utils.toArray(ph.memo || ''); w.writeVarIntNum(memo.length); w.write(memo)
    }

    // global beef store (binary)
    const beefBin = this.beefStore.toBinary()
    w.writeVarIntNum(beefBin.length)
    w.write(beefBin)

    return w.toArray() as number[]
  }

  private deserializePlaintext (decrypted: number[]) {
    const d = new Utils.Reader(decrypted)

    const nameLen = d.readVarIntNum(); this.vaultName = Utils.toUTF8(d.read(nameLen))
    this.vaultRevision = d.readVarIntNum()
    this.created = d.readVarIntNum()
    this.lastUpdated = d.readVarIntNum()

    // keys
    const nKeys = d.readVarIntNum(); this.keys = []
    for (let i = 0; i < nKeys; i++) {
      const sLen = d.readVarIntNum()
      const serial = Utils.toUTF8(d.read(sLen))
      const privateKey = new PrivateKey(d.read(32))
      const usedOnChain = d.readVarIntNum() !== 0
      const mLen = d.readVarIntNum()
      const memo = Utils.toUTF8(d.read(mLen))
      this.keys.push({ serial, private: privateKey, public: privateKey.toPublicKey(), usedOnChain, memo })
    }

    // coins
    const nCoins = d.readVarIntNum(); this.coins = []
    for (let i = 0; i < nCoins; i++) {
      const txid = Utils.toHex(d.read(32))
      const outputIndex = d.readVarIntNum()
      const memoLen = d.readVarIntNum()
      const memo = Utils.toUTF8(d.read(memoLen))
      const ksLen = d.readVarIntNum()
      const keySerial = Utils.toUTF8(d.read(ksLen))
      this.coins.push({ txid, outputIndex, memo, keySerial })
    }

    // tx log
    const nTx = d.readVarIntNum(); this.transactionLog = []
    for (let i = 0; i < nTx; i++) {
      const at = d.readVarIntNum()
      const txid = Utils.toHex(d.read(32))
      const net = d.readVarIntNum()
      const memoLen = d.readVarIntNum()
      const memo = Utils.toUTF8(d.read(memoLen))
      const processed = d.readVarIntNum() !== 0
      this.transactionLog.push({ at, txid, net, memo, processed })
    }

    // vault log
    const nVaultLog = d.readVarIntNum(); this.vaultLog = []
    for (let i = 0; i < nVaultLog; i++) {
      const at = d.readVarIntNum()
      const eLen = d.readVarIntNum()
      const event = Utils.toUTF8(d.read(eLen))
      const dLen = d.readVarIntNum()
      const data = Utils.toUTF8(d.read(dLen))
      this.vaultLog.push({ at, event, data })
    }

    // settings (v1: 5 items, v2+: 6 items)
    this.confirmIncomingCoins = d.readVarIntNum() !== 0
    this.confirmOutgoingCoins = d.readVarIntNum() !== 0
    this.persistHeadersOlderThanBlocks = d.readVarIntNum()
    this.reverifyRecentHeadersAfterSeconds = d.readVarIntNum()
    this.reverifyCurrentBlockHeightAfterSeconds = d.readVarIntNum()
    this.useUserEntropyForRandom = d.readVarIntNum() !== 0

    // persisted headers
    const nPH = d.readVarIntNum(); this.persistedHeaderClaims = []
    for (let i = 0; i < nPH; i++) {
      const at = d.readVarIntNum()
      const mrLen = d.readVarIntNum()
      const merkleRoot = Utils.toUTF8(d.read(mrLen))
      const height = d.readVarIntNum()
      const memoLen = d.readVarIntNum()
      const memo = Utils.toUTF8(d.read(memoLen))
      this.persistedHeaderClaims.push({ at, merkleRoot, height, memo })
    }

    // global beef store
    const beefLen = d.readVarIntNum()
    const beefBin = d.read(beefLen)
    this.beefStore = beefLen > 0 ? Beef.fromBinary(beefBin) : new Beef()

    this.logSession('vault.deserialize.ok')
  }

  // -------------------------------------------------------------------------
  // Key & coin management (no prompts)
  // -------------------------------------------------------------------------
  private nextSerial (): string {
    const n = this.keys.length + 1
    return `K${String(n).padStart(4, '0')}`
  }

  async generateKey (memo: string = ''): Promise<KeyRecord> {
    const priv = await this.newPrivateKey()
    const rec: KeyRecord = {
      serial: this.nextSerial(),
      private: priv,
      public: priv.toPublicKey(),
      usedOnChain: false,
      memo
    }
    this.keys.push(rec)
    this.logVault('key.generated', `serial=${rec.serial} pkh=${rec.public.toHash('hex')}`)
    return rec
  }

  async downloadDepositSlipTxt (serial: string): Promise<void> {
    const key = this.keys.find(k => k.serial === serial)
    if (!key) throw new Error('Key not found.')
    if (key.usedOnChain) {
      const ok = await this.ui.confirm('WARNING: this key appears used on-chain. Continue to download deposit info?', 'Used Key Warning')
      if (!ok) return
    }

    const body =
`BSV Deposit Slip (text)
------------------------
Vault:         ${this.vaultName}
Vault Rev:     ${this.vaultRevision}
Key Serial:    ${key.serial}
Memo:          ${key.memo || ''}

Public key:    ${key.public.toString()}
Pubkey hash:   ${key.public.toHash('hex')}
P2PKH Script:  ${new P2PKH().lock(key.public.toHash()).toHex()}
Address:       ${key.public.toAddress()}

Created At:    ${new Date().toISOString()}

Instructions:
- Send funds only to the above script/address.
- Obtain Atomic BEEF format transactions from each recipient.
- Update the vault with new Atomic BEEFs whenever they are received.
- Keep the vault file updated and saved after each receive.
`
    const blob = new Blob([body], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `deposit_${key.serial}.txt`; a.click()
    URL.revokeObjectURL(url)
  }

  private matchOurOutputs (tx: Transaction): MatchedOutput[] {
    const results: MatchedOutput[] = []
    const byPkh = new Map<string, KeyRecord>()
    for (const k of this.keys) byPkh.set(k.public.toHash('hex'), k)

    for (let i = 0; i < tx.outputs.length; i++) {
      const out = tx.outputs[i]
      const lock = out.lockingScript
      const asm = lock.toASM()
      const m = asm.match(/^OP_DUP OP_HASH160 ([0-9a-fA-F]{40}) OP_EQUALVERIFY OP_CHECKSIG$/)
      if (m) {
        const pkh = m[1].toLowerCase()
        const key = byPkh.get(pkh)
        if (key) results.push({ outputIndex: i, lockingScript: lock.toHex(), satoshis: out.satoshis as number, serial: key.serial })
      }
    }
    return results
  }

  async previewIncoming (hex: string): Promise<IncomingPreview> {
    const tx = Transaction.fromAtomicBEEF(Utils.toArray(hex, 'hex'))
    const txid = tx.id('hex') as string
    const matches = this.matchOurOutputs(tx)
    if (matches.length === 0) {
      this.logSession('incoming.preview.no-match', txid)
      throw new Error('No outputs to this vault’s keys were found in that transaction.')
    }
    let spvValid = false
    try { spvValid = await tx.verify(this) ?? false } catch { spvValid = false }
    if (!spvValid) {
      this.logSession('incoming.preview.spv.fail', txid)
      throw new Error('SPV verification failed. The transaction may be invalid or unconfirmed on the honest chain.')
    }
    this.logSession('incoming.preview.ok', txid)
    return { tx, txid, hex, matches, spvValid }
  }

  async processIncoming (tx: Transaction, opts: {
    txMemo?: string
    admit: Record<number, boolean>
    perUtxoMemo: Record<number, string>
    processed?: boolean
  }): Promise<{ admitted: string[]; txid: string }> {
    const txid = tx.id('hex') as string
    const allMatches = this.matchOurOutputs(tx)

    const admitted: typeof allMatches = []
    for (const m of allMatches) {
      const ok = opts.admit[m.outputIndex] === true
      if (ok) admitted.push(m)
    }

    if (admitted.length === 0) {
        throw new Error('No outputs were selected to be admitted into the vault.')
    }

    // Merge the incoming Atomic BEEF graph into the global store
    // We convert the verified transaction back to a BEEF to ensure all dependencies & BUMPs are preserved.
    this.beefStore.mergeBeef(tx.toBEEF())
    this.logVault('incoming.merge', `txid=${txid} depsMerged=1`)

    // Update coin set & mark key usage
    for (const m of admitted) {
      this.coins.push({ txid, outputIndex: m.outputIndex, memo: opts.perUtxoMemo?.[m.outputIndex] || '', keySerial: m.serial })
      const k = this.keys.find(kk => kk.serial === m.serial); if (k) k.usedOnChain = true
    }

    const netIn = admitted.reduce((n, a) => n + a.satoshis, 0)
    this.transactionLog.push({
      at: Date.now(), txid, net: netIn, memo: opts?.txMemo || '', processed: !!opts.processed
    })
    this.logVault('incoming.accepted', `${txid}:${admitted.map(a => a.outputIndex).join(',')}`)
    return { admitted: admitted.map(a => `${txid}:${a.outputIndex}`), txid }
  }

  markProcessed (txid: string, processed: boolean): void {
    const t = this.transactionLog.find(t => t.txid === txid)
    if (t) {
      t.processed = processed
      this.logVault('tx.processed', `${txid}:${processed ? '1' : '0'}`)
    }
  }

  // -------------------------------------------------------------------------
  // Outgoing builder (manual-only). UI drives stipulation and selection.
  // -------------------------------------------------------------------------
  private parseOutputSpec (spec: OutgoingOutputSpec): { lockingScript: Script, satoshis: number, memo?: string } {
    const { destinationAddressOrScript: dest, satoshis, memo } = spec
    assert(Number.isFinite(satoshis) && satoshis > 0, `Bad amount: ${satoshis}`)
    let lock: Script
    if (/^[0-9a-fA-F]{20,}$/.test(dest) && !/[O]/i.test(dest)) {
      lock = Script.fromHex(dest)
    } else {
      lock = new P2PKH().lock(dest)
    }
    return { lockingScript: lock, satoshis, memo }
  }

  async buildAndSignOutgoing (opts: BuildOutgoingOptions): Promise<{ tx: Transaction, atomicBEEFHex: string, usedInputIds: string[], changeIds: string[] }> {
    assert(this.coins.length > 0, 'No spendable UTXOs.')
    const outputs = opts.outputs.map(o => this.parseOutputSpec(o))
    assert(outputs.length > 0, 'No outputs specified.')

    // REQUIRE explicit change keys
    assert(opts.changeKeySerials && opts.changeKeySerials.length > 0, 'At least one change key must be selected.')
    const changeKeys = opts.changeKeySerials.map(s => {
      const k = this.keys.find(kk => kk.serial === s)
      if (!k) throw new Error(`Change key not found: ${s}`)
      return k
    })

    // REQUIRE explicit inputs
    assert(opts.inputIds && opts.inputIds.length > 0, 'You must manually select at least one input UTXO.')
    const byId = new Map(this.coins.map(c => [coinIdStr(c.txid, c.outputIndex), c] as const))
    const selected = opts.inputIds.map(id => {
      const c = byId.get(id); if (!c) throw new Error(`Input not found: ${id}`); return c
    })

    const tx = new Transaction()
    for (const o of outputs) tx.addOutput(o)

    const idxToKeySerial = new Map<number, string>()
    for (const k of changeKeys) {
      tx.addOutput({ lockingScript: new P2PKH().lock(k.public.toAddress()), change: true })
      idxToKeySerial.set(tx.outputs.length - 1, k.serial)
    }

    // Hydrate inputs from global BEEF store (ensures merkle paths & ancestry are wired)
    for (const s of selected) {
      const srcTx = getTxFromStore(this.beefStore, s.txid)
      tx.addInput({
        sourceTransaction: srcTx,
        sourceOutputIndex: s.outputIndex,
        unlockingScriptTemplate: new P2PKH().unlock(this.keys.find(x => x.serial === s.keySerial)!.private)
      })
    }

    // Fee to miners, change to change outputs
    await tx.fee() // TODO: support custom fees and fee models

    // Optional outgoing attestation handled by UI via callback
    if (this.confirmOutgoingCoins && opts.perUtxoAttestation && opts.attestationFn) {
      for (const s of selected) {
        const ok = await opts.attestationFn(s)
        if (!ok) throw new Error(`Outgoing attestation declined for ${coinIdStr(s.txid, s.outputIndex)}.`)
      }
    }

    await tx.sign()

    const txid = tx.id('hex') as string
    const selectedIds = new Set(selected.map(s => coinIdStr(s.txid, s.outputIndex)))
    // Remove spent coins
    this.coins = this.coins.filter(c => !selectedIds.has(coinIdStr(c.txid, c.outputIndex)))

    // Merge the new outgoing tx graph into the store
    this.beefStore.mergeBeef(tx.toBEEF())
    this.logVault('outgoing.merge', `txid=${txid}`)

    const changeIds: string[] = []
    tx.outputs.forEach((out: TransactionOutput, outputIndex: number) => {
      if (!out.change) return
      const ser = idxToKeySerial.get(outputIndex) as string
      this.coins.push({ txid, outputIndex, memo: 'change', keySerial: ser })
      // mark change key as used to avoid accidental reuse
      const key = this.keys.find(k => k.serial === ser)
      if (key) key.usedOnChain = true
      changeIds.push(`${txid}:${outputIndex}`)
    })

    // Compute net effect (inputs - outputs - fee)
    const totalInputs = selected.reduce((a, e) => {
      const src = getTxFromStore(this.beefStore, e.txid)
      return a + (src.outputs[e.outputIndex].satoshis!)
    }, 0)
    const changeBack = tx.outputs.reduce((a, o) => a + (o.change ? (o.satoshis as number) : 0), 0)
    const external = tx.outputs.reduce((a, o) => a + (!o.change ? (o.satoshis as number) : 0), 0)
    const fee = totalInputs - (changeBack + external)
    const net = -(external + fee)

    const atomic = Utils.toHex(tx.toAtomicBEEF() as number[])
    this.transactionLog.push({
      at: Date.now(), txid, net, memo: opts.txMemo || '', processed: false
    })

    this.logVault('outgoing.signed', `txid=${txid} inputs=${selected.length} change=${changeIds.length} fee=${fee}`)
    return { tx, atomicBEEFHex: atomic, usedInputIds: [...selectedIds], changeIds }
  }

  // -------------------------------------------------------------------------
  // Log Export
  // -------------------------------------------------------------------------
  private exportLog (log: AuditEvent[], type: 'session' | 'vault'): void {
    const content = `
Vault: ${this.vaultName}, rev: ${this.vaultRevision}
Created: ${new Date(this.created).toISOString()}, Updated: ${new Date(this.lastUpdated).toISOString()}
${type === 'session' ? 'Session' : 'Vault'} Log Exported At: ${new Date().toISOString()}
-----
${log.map(x => `[${new Date(x.at).toISOString()}]: ${x.event}${x.data ? `: ${x.data}`: ''}`).join('\n')}
`
    const blob = new Blob([content.trim()], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a');
    a.href = url;
    a.download = `vault_${type}_log_${Date.now()}.txt`;
    a.click()
    URL.revokeObjectURL(url)
  }

  exportSessionLog (): void {
    this.exportLog(this.sessionLog, 'session')
  }

  exportVaultLog (): void {
    this.exportLog(this.vaultLog, 'vault')
  }
}

/**
 * =============================================================================
 * React App Shell (Tabs + Views)
 * =============================================================================
 */

type TabKey = 'keys' | 'incoming' | 'outgoing' | 'dashboard' | 'settings' | 'logs'

export default function App () {
  return (
    <DialogProvider>
      <AppInner />
    </DialogProvider>
  )
}

function AppInner () {
  const dialog = useDialog()

  const [vault, setVault] = useState<Vault | null>(null)
  const [lastSavedPlainHash, setLastSavedPlainHash] = useState<string | null>(null)
  const [notification, setNotification] = useState<Notification | null>(null)
  const [incomingPreview, setIncomingPreview] = useState<IncomingPreview | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<TabKey>('dashboard')
  const [appKey, setAppKey] = useState(0) // Used to force re-render of components

  const forceAppUpdate = useCallback(() => {
    if (vault) {
      // This creates a new object reference, forcing React to re-render consumers of the vault prop
      setVault(Object.assign(Object.create(Object.getPrototypeOf(vault)), vault))
      setAppKey(k => k + 1)
    }
  }, [vault])


  function notify(type: Notification['type'], message: string) {
    setNotification({ type, message, id: Date.now() })
  }

  // --- Core Vault Actions ---
  async function onOpenVault (file: File) {
    setIsLoading(true);
    try {
      // Basic file validation: non-empty, expected extension
      if (!file || file.size === 0) throw new Error('Selected file is empty.')
      if (!file.name.endsWith('.vaultfile')) {
        const cont = await dialog.confirm(`The selected file (${file.name}) does not have the .vaultfile extension. Continue anyway?`, {
          title: 'Unrecognized Extension',
          confirmText: 'Continue',
          cancelText: 'Cancel'
        })
        if (!cont) return
      }
      const buf = new Uint8Array(await file.arrayBuffer())
      const v = await Vault.loadFromFile(dialog, Array.from(buf))
      setVault(v)
      setLastSavedPlainHash(v.computePlaintextHash())
      notify('success', 'Vault loaded successfully.')
    } catch (e: any) {
      notify('error', e.message || 'Failed to load vault.')
    } finally {
      setIsLoading(false)
    }
  }

  async function onNewVault () {
    setIsLoading(true);
    try {
      const v = await Vault.create(dialog)
      setVault(v)
      setLastSavedPlainHash(v.computePlaintextHash())
      notify('info', 'New vault created. Generate a key to begin.')
      setActiveTab('keys')
    } catch (e: any) {
      notify('error', e.message || 'Failed to create vault.')
    } finally {
      setIsLoading(false)
    }
  }

  // Pre-save enforcement: require users to download & set processed statuses for all pending outgoings,
  // and explicitly record processed states for all unprocessed transactions.
  async function enforcePendingBeforeSave (v: Vault): Promise<boolean> {
    // Handle all unprocessed outgoing txs first
    const outgoingPending = v.transactionLog.filter(t => t.net < 0 && !t.processed)
    for (const t of outgoingPending) {
      await dialog.alert(
        `Before saving, you must securely export the Atomic BEEF for your pending outgoing transaction:\n\nTXID: ${t.txid}\n\nThis ensures you can broadcast/recover if interrupted.`,
        'Pending Outgoing Transaction'
      )
      const beefHex = (() => {
        try { return v.exportAtomicBEEFHexByTxid(t.txid) } catch { return null }
      })()
      if (!beefHex) {
        await dialog.alert('Could not reconstruct the Atomic BEEF from the vault store. This should not happen. Aborting save.', 'Export Error')
        return false
      }
      const download = await dialog.confirm('Download the Atomic BEEF file now?', {
        title: 'Download Required',
        confirmText: 'Download Now',
        cancelText: 'Abort Save'
      })
      if (!download) return false
      try {
        const blob = new Blob([beefHex], { type: 'text/plain' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `tx_${t.txid}.atomic-beef.txt`
        a.click()
        URL.revokeObjectURL(url)
      } catch {
        await dialog.alert('Download failed. Please try again.', 'Download Error')
        return false
      }
      const processed = await dialog.confirm('Has this outgoing transaction been broadcast and processed on the network?', {
        title: 'Processed Status',
        confirmText: 'I Certify',
        cancelText: 'Not Yet'
      })
      v.markProcessed(t.txid, processed)
    }

    // Now ask for all remaining unprocessed (including incoming) to be explicitly classified
    const remaining = v.transactionLog.filter(t => !t.processed)
    for (const t of remaining) {
      const incoming = t.net >= 0
      const ok = await dialog.confirm(
        `${incoming ? 'Incoming' : 'Outgoing'} TX ${t.txid}\n\nHas this transaction processed on the network?`,
        {
          title: 'Confirm Processed Status',
          confirmText: 'I Certify',
          cancelText: 'Not Yet'
        }
      )
      v.markProcessed(t.txid, ok)
    }

    // Ensure no unprocessed outgoing remain
    const stillPendingOutgoing = v.transactionLog.some(t => t.net < 0 && !t.processed)
    if (stillPendingOutgoing) {
      await dialog.alert('You still have pending outgoing transactions without a clear processed status. Resolve them before saving.', 'Save Blocked')
      return false
    }
    return true
  }

  async function onSaveVault () {
    if (!vault) return
    setIsLoading(true);
    try {
      // Enforce pending outgoing management & explicit processed statuses BEFORE saving
      const okToSave = await enforcePendingBeforeSave(vault)
      if (!okToSave) {
        notify('error', 'Save cancelled. Resolve all pending items as instructed.')
        setIsLoading(false)
        return
      }

      const certified = await vault.downloadVaultFileAndCertify()
      if (certified) {
        // Post-save "logout"
        setVault(null)
        setLastSavedPlainHash(null)
        setActiveTab('dashboard')
      } else {
        notify('error', 'Save certification was cancelled. The process was not finished. You must properly perform all steps.')
      }
    } catch (e: any) {
      notify('error', e.message || 'Failed to save vault.')
    } finally {
      setIsLoading(false)
    }
  }

  // --- Derived State ---
  const dirty = useMemo(() => {
    if (!vault || !lastSavedPlainHash) return false
    return vault.computePlaintextHash() !== lastSavedPlainHash
  }, [vault, lastSavedPlainHash, appKey])

  const balance = useMemo(() => {
    if (!vault) return 0
    let sum = 0
    for (const c of vault.coins) {
      try {
        const tx = getTxFromStore(vault.beefStore, c.txid)
        sum += tx.outputs[c.outputIndex].satoshis as number
      } catch {
        // If a tx is missing (shouldn't happen), treat as 0 and surface in logs
        vault['logSession']?.('balance.missing.tx', c.txid)
      }
    }
    return sum
  }, [vault?.coins, vault?.beefStore, appKey])

  // --- Loading / Unloaded State ---
  if (isLoading) {
    return (
      <div style={appShellStyle}>
        <div style={{ ...containerStyle, textAlign: 'center' }}>Loading Vault...</div>
      </div>
    )
  }

  if (!vault) {
    return (
      <div style={appShellStyle}>
        <div style={containerStyle}>
          {notification && <NotificationBanner notification={notification} onDismiss={() => setNotification(null)} />}
          <div style={{ ...panelStyle, padding: 16 }}>
            <h1 style={{ marginTop: 0 }}>BSV Vault Manager Suite</h1>
            <section style={{ border: `1px solid ${COLORS.border}`, padding: 12, borderRadius: 8, display: 'grid', gap: 8 }}>
              <h2 style={{ marginTop: 0, fontSize: 18 }}>Open / New</h2>
              <div style={{ display: 'grid', gap: 8 }}>
                <input style={{ maxWidth: '100%' }} type="file" accept=".vaultfile,application/octet-stream" onChange={e => e.target.files && onOpenVault(e.target.files[0])} />
                <button onClick={onNewVault} style={btnStyle}>Create New Vault</button>
              </div>
            </section>

            <section style={{ ...sectionStyle, marginTop: 12 }}>
              <h2 style={{ marginTop: 0 }}>Important Notices</h2>
              <p><b>Offline, High-Value Security Tool.</b> This software is designed for secure, offline management of BSV funds using SPV and Atomic BEEF data.</p>
              <p><b>No Warranties. Use At Your Own Risk.</b> This software is provided “AS IS,” without warranties of any kind, express or implied, including without limitation merchantability, fitness for a particular purpose, title, and noninfringement. You assume all risks associated with its use.</p>
              <p><b>Operational Discipline Required.</b> Always verify transactions in multiple external tools, follow the Vault Operator’s Manual, and employ trained operators for custody operations. Do not broadcast or process transactions you have not independently verified.</p>
              <p><b>Versioning & Integrity.</b> Always save the vault file after any change, verify the file’s SHA-256 hash, and securely delete prior revisions. Maintain redundant, offline backups. Treat hash verification as mandatory for each load.</p>
              <p><b>No Credential Storage.</b> Never store vault passwords in the browser or password managers. This application attempts to disable such prompts, but you must remain vigilant.</p>
              <p><b>Clipboard Hijacking Risk.</b> After copying any address or script, paste into a trusted editor and compare character-by-character before use. Malware can silently rewrite clipboard contents.</p>
              <p style={{ color: COLORS.gray600, marginTop: 8 }}>By using this software, you acknowledge and accept these terms and assume full responsibility for all outcomes.</p>
            </section>
          </div>
        </div>
      </div>
    )
  }

  // --- Tabs ---
  const tabs: { key: TabKey; label: string }[] = [
    { key: 'dashboard', label: 'Dashboard' },
    { key: 'keys', label: 'Keys' },
    { key: 'incoming', label: 'Incoming' },
    { key: 'outgoing', label: 'Outgoing' },
    { key: 'logs', label: 'Logs' },
    { key: 'settings', label: 'Settings' }
  ]

  return (
    <div style={appShellStyle}>
      <div style={containerStyle}>
        {notification && <NotificationBanner notification={notification} onDismiss={() => setNotification(null)} />}

        {incomingPreview && (
          <ProcessIncomingModal
            vault={vault}
            preview={incomingPreview}
            onClose={() => setIncomingPreview(null)}
            onSuccess={(txid) => {
              setIncomingPreview(null)
              forceAppUpdate()
              notify('success', `Transaction ${txid} processed. SAVE the vault to persist changes.`)
              setActiveTab('dashboard')
            }}
            onError={(err) => notify('error', err)}
          />
        )}

        <div style={{ ...panelStyle, padding: 16, marginBottom: 12 }}>
          {dirty && (
            <div style={{ background: COLORS.red, color: 'white', padding: 12, marginBottom: 12, fontWeight: 700, borderRadius: 8 }}>
              UNSAVED CHANGES — Save the new vault file, verify its integrity, and then securely delete the old version.
            </div>
          )}

          <header style={{ borderBottom: `1px solid ${COLORS.border}`, paddingBottom: 12, marginBottom: 12, display: 'grid', gridTemplateColumns: '1fr', gap: 8 }}>
            <div>
              <h1 style={{ margin: 0, fontSize: 22 }}>BSV Vault Manager Suite</h1>
              <div style={{ color: COLORS.gray600, marginTop: 4 }}>
                Vault: <b>{vault.vaultName}</b> (rev {vault.vaultRevision})
              </div>
            </div>
            <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr', alignItems: 'center' }}>
              <input style={{ gridColumn: 'span 2' }} type="file" accept=".vaultfile,application/octet-stream" onChange={e => e.target.files && onOpenVault(e.target.files[0])} />
              <button onClick={onSaveVault} style={{ ...btnStyle, gridColumn: 'span 2' }}>Save Vault</button>
            </div>
          </header>

          {/* Tabs */}
          <div style={{ display: 'flex', gap: 8, borderBottom: `1px solid ${COLORS.border}`, marginBottom: 12, overflowX: 'auto' }}>
            {tabs.map(t => (
              <button
                key={t.key}
                onClick={() => setActiveTab(t.key)}
                style={{
                  background: activeTab === t.key ? COLORS.blue : 'transparent',
                  color: activeTab === t.key ? '#fff' : COLORS.gray700,
                  border: 'none',
                  borderRadius: 999,
                  padding: '8px 12px',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap'
                }}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Active Tab Panels */}
          {activeTab === 'dashboard' && (
            <DashboardPanel vault={vault} balance={balance} triggerRerender={forceAppUpdate} />
          )}

          {activeTab === 'keys' && (
            <KeyManager
              vault={vault}
              onUpdate={forceAppUpdate}
              notify={notify}
            />
          )}

          {activeTab === 'incoming' && (
            <IncomingManager
              vault={vault}
              onPreview={setIncomingPreview}
              onError={(e) => notify('error', e)}
            />
          )}

          {activeTab === 'outgoing' && (
            <OutgoingWizard
              vault={vault}
              notify={notify}
              onUpdate={forceAppUpdate}
            />
          )}

          {activeTab === 'logs' && (
            <LogsPanel vault={vault} onUpdate={forceAppUpdate} />
          )}

          {activeTab === 'settings' && (
            <SettingsPanel vault={vault} onUpdate={forceAppUpdate} setLastSavedPlainHash={setLastSavedPlainHash} />
          )}
        </div>
      </div>
    </div>
  )
}

/**
 * =============================================================================
 * Panels & Components
 * =============================================================================
 */

const DashboardPanel: FC<{ vault: Vault, balance: number, triggerRerender: () => void }> = ({ vault, balance, triggerRerender }) => {
  return (
    <section style={{ ...sectionStyle }}>
      <h2 style={{ marginTop: 0 }}>Dashboard</h2>
      <div>Total balance: <b>{balance.toLocaleString()}</b> sats (<b>{(balance / 100000000).toFixed(8)}</b> BSV)</div>
      <div style={{ display: 'grid', gap: 16, marginTop: 12, gridTemplateColumns: '1fr' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <h3>Current UTXOs ({vault.coins.length})</h3>
          {vault.coins.length === 0 && <div>No spendable coins</div>}
          {vault.coins.map(c => {
            const id = `${c.txid}:${c.outputIndex}`
            let sats = 0
            try {
              const tx = getTxFromStore(vault.beefStore, c.txid)
              sats = tx.outputs[c.outputIndex].satoshis as number
            } catch {}
            return (
              <div key={id} style={{ borderTop: `1px solid ${COLORS.border}`, padding: '8px 0', fontSize: '12px', wordBreak: 'break-all' }}>
                <div><b>{id}</b> — {sats.toLocaleString()} sats (<b>{(sats / 100000000).toFixed(8)}</b> BSV)</div>
                {c.memo && <div>Memo: {c.memo}</div>}
              </div>
            )
          })}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <h3>Transaction Log ({vault.transactionLog.length})</h3>
          {[...vault.transactionLog].reverse().map(t => (
            <div key={t.at + t.txid} style={{ borderTop: `1px solid ${COLORS.border}`, padding: '8px 0', fontSize: '12px', wordBreak: 'break-all' }}>
              <div><b>{t.txid}</b></div>
              {t.memo && <div>Memo: {t.memo}</div>}
              <div style={{ color: t.net >= 0 ? COLORS.green : COLORS.red }}>
                Net: {t.net.toLocaleString()} sats (<b>{(t.net / 100000000).toFixed(8)}</b> BSV)
              </div>
              <label style={{ display: 'inline-flex', gap: 8, alignItems: 'center', marginTop: 4 }}>
                <input type="checkbox" checked={t.processed} onChange={e => { vault.markProcessed(t.txid, e.target.checked); triggerRerender() }} />
                Mark processed
              </label>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

const KeyManager: FC<{ vault: Vault, onUpdate: () => void, notify: (type: Notification['type'], msg: string) => void }> = ({ vault, onUpdate, notify }) => {
  const dialog = useDialog()
  const [hoverMap, setHoverMap] = useState<Record<string, boolean>>({})
  return (
    <section style={{ ...sectionStyle }}>
      <h2 style={{ marginTop: 0 }}>Keys ({vault.keys.length})</h2>
      <div style={{ display: 'grid', gap: 8 }}>
              <button
          onClick={async () => {
            const memo = (await dialog.prompt('Memo for this key (optional):', { title: 'Key Memo', maxLength: 256, validate: (v) => validateMemo(v, 'Memo', 256) })) || ''
            await vault.generateKey(memo); onUpdate()
          }}
          style={btnStyle}
        >
          Generate New Key
        </button>
      </div>
      <div style={{ marginTop: 12 }}>
        {[...vault.keys].reverse().map(k => (
          <div key={k.serial} style={{ borderTop: `1px solid ${COLORS.border}`, padding: '8px 0', display: 'grid', gridTemplateColumns: '1fr', gap: 8 }}>
            <div>
              <b>{k.serial}</b> {k.memo && `— ${k.memo}`} {k.usedOnChain ? <span style={{ color: '#b36' }}> (used)</span> : <span style={{color: COLORS.green}}>(unused)</span>}
              <div style={{ fontSize: 12, color: COLORS.gray600, fontFamily: 'monospace', wordBreak: 'break-all' }}>{k.public.toAddress()}</div>
            </div>
            <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr' }}>
              <button onClick={async () => { await vault.downloadDepositSlipTxt(k.serial); notify('info', `Deposit slip generated for ${k.serial}`) }} style={btnGhostStyle}>
                Deposit Slip (.txt)
              </button>
              <button
                onMouseEnter={() => setHoverMap(m => ({ ...m, [k.serial]: true }))}
                onMouseLeave={() => setHoverMap(m => ({ ...m, [k.serial]: false }))}
                onClick={async () => {
                  await navigator.clipboard.writeText(k.public.toAddress())
                  await dialog.alert(
                    `Address copied.\n\nFor your security, paste the address into a trusted editor and verify it EXACTLY matches:\n\n${k.public.toAddress()}\n\nMalware can rewrite clipboard contents. Always compare before broadcasting or sending.`,
                    'Verify Copied Address'
                  )
                }}
                style={{ ...btnGhostStyle, background: hoverMap[k.serial] ? '#555' : '#777' }}
              >
                Copy Address
              </button>
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}

const IncomingManager: FC<{ vault: Vault, onPreview: (p: IncomingPreview) => void, onError: (msg: string) => void }> = ({ vault, onPreview, onError }) => {
  const [hex, setHex] = useState('')
  const [isProcessing, setIsProcessing] = useState(false)

  async function handlePreview() {
    if (!hex.trim()) { onError('BEEF hex cannot be empty.'); return }
    const v = validateBeefHex(hex)
    if (v !== true) { onError(typeof v === 'string' ? v : 'Invalid Atomic BEEF hex.'); return }
    setIsProcessing(true)
    try {
      const previewData = await vault.previewIncoming(hex)
      onPreview(previewData)
    } catch(e: any) {
      onError(e.message || 'Failed to process BEEF.')
    } finally {
      setIsProcessing(false)
    }
  }

  return (
    <section style={{ ...sectionStyle }}>
      <h2 style={{ marginTop: 0 }}>Process Incoming Atomic BEEF</h2>
      <p style={{fontSize: 12, color: COLORS.gray600}}>Paste an SPV-valid Atomic BEEF transaction to add new UTXOs to your vault.</p>
      <textarea placeholder="Paste Atomic BEEF hex..." rows={4} style={{ ...inputStyle, width: '100%', fontFamily: 'monospace' }} value={hex} onChange={e => setHex(e.target.value)} />
      <div style={{ marginTop: 8 }}>
        <button onClick={handlePreview} disabled={isProcessing} style={btnStyle}>{isProcessing ? 'Verifying...' : 'Review & Process'}</button>
      </div>
    </section>
  )
}

const ProcessIncomingModal: FC<{
  vault: Vault
  preview: IncomingPreview
  onClose: () => void
  onSuccess: (txid: string) => void
  onError: (msg: string) => void
}> = ({ vault, preview, onClose, onSuccess, onError }) => {
  const dialog = useDialog()
  const needsConfirmation = vault.confirmIncomingCoins
  const allVouts = preview.matches.map(m => m.outputIndex)
  const [admit, setAdmit] = useState<Record<number, boolean>>(() =>
    needsConfirmation ? {} : Object.fromEntries(allVouts.map(v => [v, true]))
  )
  const [memos, setMemos] = useState<Record<number, string>>({})
  const [txMemo, setTxMemo] = useState('')
  const [isFinalizing, setIsFinalizing] = useState(false)

  const handleToggleAdmit = (vout: number) => {
    setAdmit(prev => ({...prev, [vout]: !prev[vout]}))
  }

  const handleFinalize = async () => {
    setIsFinalizing(true)
    try {
      // Require user to explicitly choose processed status for the incoming transaction
      const processed = await dialog.confirm('Has this incoming transaction processed on the network?', {
        title: 'Processed Status',
        confirmText: 'I Certify',
        cancelText: 'Not Yet'
      })
      const res = await vault.processIncoming(preview.tx, { txMemo, admit, perUtxoMemo: memos, processed })
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
      <div style={{display:'flex', gap:8, alignItems:'center', flexWrap:'wrap'}}>
        <p style={{fontSize: 13, margin: 0, wordBreak:'break-all'}}>TXID: <code>{preview.txid}</code></p>
        <button onClick={() => navigator.clipboard.writeText(preview.txid)} style={{ ...btnGhostStyle, padding: '6px 10px', fontSize: 12, maxWidth: 140 }}>Copy TXID</button>
      </div>
      <p style={{fontSize: 13, color: 'green', fontWeight: 'bold'}}>SPV Verified Successfully</p>
      <hr style={{margin: '12px 0'}} />
      <p>The following outputs in this transaction are spendable by your vault's keys. {needsConfirmation ? 'Select which UTXOs to admit:' : 'All matched UTXOs will be admitted automatically.'}</p>

      {preview.matches.map(m => (
        <div key={m.outputIndex} style={{border: `1px solid ${COLORS.border}`, padding: 8, margin: '8px 0', borderRadius: 8}}>
          {needsConfirmation && <input type="checkbox" checked={!!admit[m.outputIndex]} onChange={() => handleToggleAdmit(m.outputIndex)} style={{marginRight: 8}} />}
          <strong>Output #{m.outputIndex}</strong>: {m.satoshis.toLocaleString()} sats (<b>{(m.satoshis / 100000000).toFixed(8)}</b> BSV), to Key <strong>{m.serial}</strong>
          <input
            type="text"
            placeholder="UTXO Memo (optional)"
            style={{...inputStyle, marginTop: 6}}
            value={memos[m.outputIndex] || ''}
            onChange={e => setMemos(prev => ({...prev, [m.outputIndex]: e.target.value}))}
            maxLength={256}
          />
        </div>
      ))}

      <button
        onClick={() => {
          const ids = preview.matches.map(m => `${preview.txid}:${m.outputIndex}`).join('\n')
          navigator.clipboard.writeText(ids)
        }}
        style={{ ...btnGhostStyle, marginTop: 6, fontSize: 12, maxWidth: 220 }}
      >
        Copy All Matched UTXO IDs
      </button>

      <input
        type="text"
        placeholder="Transaction Memo (optional)"
        style={{...inputStyle, marginTop: 12}}
        value={txMemo}
        onChange={e => setTxMemo(e.target.value)}
        maxLength={256}
      />

      <div style={{marginTop: 12, display: 'flex', justifyContent: 'flex-end', gap: 8, flexWrap:'wrap'}}>
        <button onClick={onClose} style={btnGhostStyle}>Cancel</button>
        <button onClick={handleFinalize} disabled={isFinalizing || Object.values(admit).every(v => !v)} style={btnStyle}>
          {isFinalizing ? 'Saving...' : `Admit ${Object.values(admit).filter(Boolean).length} UTXO(s)`}
        </button>
      </div>
    </Modal>
  )
}

/**
 * -----------------------------------------------------------------------------
 * Outgoing Wizard (one-step-at-a-time)
 * -----------------------------------------------------------------------------
 */

const OutgoingWizard: FC<{ vault: Vault, onUpdate: () => void, notify: (t: Notification['type'], m: string) => void }> = ({ vault, onUpdate, notify }) => {
  const dialog = useDialog()
  type Step = 1 | 2 | 3 | 4 | 5
  const [step, setStep] = useState<Step>(1)

  // State for the new multi-output UI
  const [outputs, setOutputs] = useState([{ destinationAddressOrScript: '', satoshis: '', memo: '' }])

  const [parsedOutputs, setParsedOutputs] = useState<OutgoingOutputSpec[]>([])
  const [manualInputs, setManualInputs] = useState<Record<string, boolean>>({})
  const [changeSerials, setChangeSerials] = useState<Record<string, boolean>>({})
  const [txMemo, setTxMemo] = useState<string>('')
  const [requirePerUtxoAttestation, setRequirePerUtxoAttestation] = useState<boolean>(false)

  const [beefHex, setBeefHex] = useState<string | null>(null)
  const [beefTxid, setBeefTxid] = useState<string | null>(null)
  const [isBuilding, setIsBuilding] = useState(false)

  // Handlers for the multi-output UI
  const handleOutputChange = (index: number, field: keyof typeof outputs[0], value: string) => {
    const newOutputs = [...outputs]
    newOutputs[index] = { ...newOutputs[index], [field]: value }
    setOutputs(newOutputs)
  }

  const addOutput = () => {
    setOutputs([...outputs, { destinationAddressOrScript: '', satoshis: '', memo: '' }])
  }

  const removeOutput = (index: number) => {
    if (outputs.length > 1) {
      setOutputs(outputs.filter((_, i) => i !== index))
    }
  }

  const resetWizard = () => {
    setStep(1)
    setOutputs([{ destinationAddressOrScript: '', satoshis: '', memo: '' }])
    setParsedOutputs([])
    setManualInputs({})
    setChangeSerials({})
    setTxMemo('')
    setRequirePerUtxoAttestation(false)
    setBeefHex(null)
    setBeefTxid(null)
  }

  const totalOutputSats = useMemo(() => {
    return parsedOutputs.reduce((sum, o) => sum + o.satoshis, 0)
  }, [parsedOutputs])

  const totalInputSats = useMemo(() => {
    const selectedIds = Object.keys(manualInputs).filter(id => manualInputs[id])
    let sum = 0
    for (const id of selectedIds) {
      const [txid, voutStr] = id.split(':')
      const coin = vault.coins.find(c => c.txid === txid && c.outputIndex === Number(voutStr))
      if (coin) {
        try {
          const tx = getTxFromStore(vault.beefStore, coin.txid)
          sum += tx.outputs[coin.outputIndex].satoshis as number
        } catch {}
      }
    }
    return sum
  }, [manualInputs, vault.coins, vault.beefStore])

  function nextFromOutputs() {
    try {
      const specs: OutgoingOutputSpec[] = []
      for (const output of outputs) {
        const dest = output.destinationAddressOrScript.trim()
        const satStr = output.satoshis.trim()
        const memo = output.memo.trim()

        // Skip completely empty rows silently
        if (!dest && !satStr && !memo) continue

        if (!dest) {
          throw new Error('An output is missing a destination address or script.')
        }
        const destOk = validateAddressOrScript(dest)
        if (destOk !== true) throw new Error(destOk)
        const satOk = validateSatoshis(satStr)
        if (satOk !== true) throw new Error(typeof satOk === 'string' ? satOk : 'Invalid satoshi amount.')
        const sat = Number(satStr)
        const memoOk = validateMemo(memo, 'Memo', 256)
        if (memoOk !== true) throw new Error(memoOk)

        specs.push({ destinationAddressOrScript: dest, satoshis: sat, memo: memo || undefined })
      }

      if (specs.length === 0) {
        throw new Error('You must define at least one valid output.')
      }

      setParsedOutputs(specs)
      setStep(2)
    } catch (e: any) {
      notify('error', e.message || 'Invalid outputs.')
    }
  }

  function nextFromInputs() {
    const selectedIds = Object.keys(manualInputs).filter(id => manualInputs[id])
    if (!selectedIds.length) { notify('error', 'Select at least one input UTXO.'); return }
    if (totalInputSats < totalOutputSats) {
        notify('error', `Selected inputs (${totalInputSats.toLocaleString()} sats) do not cover the required output amount (${totalOutputSats.toLocaleString()} sats).`); return
    }

    // Warn if any selected inputs are from unprocessed transactions
    const unprocessedParents: string[] = []
    for (const id of selectedIds) {
      const [txid] = id.split(':')
      const t = vault.transactionLog.find(tl => tl.txid === txid)
      if (t && !t.processed) unprocessedParents.push(id)
    }
    if (unprocessedParents.length > 0) {
      dialog.confirm(
        `WARNING: You are consuming inputs from transactions not yet marked as "processed":\n\n${unprocessedParents.join('\n')}\n\nProceed anyway?`,
        {
          title: 'Unprocessed Inputs Warning',
          confirmText: 'Proceed Anyway',
          cancelText: 'Review Inputs'
        }
      ).then(ok => {
        if (ok) setStep(3)
      })
      return
    }

    setStep(3)
  }

  function nextFromChange() {
    const change = Object.keys(changeSerials).filter(s => changeSerials[s])
    if (!change.length) { notify('error', 'Select at least one change key.'); return }

    // Privacy warning if change key(s) already used
    const usedSelected = change
      .map(s => vault.keys.find(k => k.serial === s))
      .filter(k => k?.usedOnChain)
      .map(k => `${k!.serial}${k!.memo ? ` (${k!.memo})` : ''}`)
    if (usedSelected.length > 0) {
      dialog.confirm(
        `PRIVACY WARNING: You selected change key(s) that are already used on-chain:\n\n${usedSelected.join('\n')}\n\nReusing addresses harms privacy and may leak linkage. Proceed anyway?`,
        {
          title: 'Change Key Reuse',
          confirmText: 'Proceed Anyway',
          cancelText: 'Pick Different Keys'
        }
      ).then(ok => {
        if (ok) setStep(4)
      })
      return
    }

    setStep(4)
  }

  async function handleGenerateNewChangeKey() {
    const memo = await dialog.prompt('Enter a memo for the new change key:', { title: 'New Key', maxLength: 256, validate: (v) => validateMemo(v, 'Memo', 256) })
    if (memo === null) return // User cancelled
    await vault.generateKey(memo || '')
    onUpdate() // This will cause the component to get the new key list
    notify('success', 'New key generated and added to the list.')
  }

  async function buildAndSign() {
    setIsBuilding(true)
    try {
      const selectedIds = Object.keys(manualInputs).filter(id => manualInputs[id])
      const change = Object.keys(changeSerials).filter(s => changeSerials[s])

      const attestationFn: AttestationFn | undefined =
        (vault.confirmOutgoingCoins && requirePerUtxoAttestation)
          ? async (coin) => {
            const id = `${coin.txid}:${coin.outputIndex}`
            return await dialog.confirm(
              `ATTESTATION REQUIRED:\n\nConfirm this UTXO is unspent on the HONEST chain:\n\n${id}`,
              {
                title: 'Per-UTXO Attestation',
                confirmText: 'I Certify',
                cancelText: 'Abort Signing'
              }
            )
          }
          : undefined

      const { tx, atomicBEEFHex } = await vault.buildAndSignOutgoing({
        outputs: parsedOutputs,
        inputIds: selectedIds,
        changeKeySerials: change,
        perUtxoAttestation: requirePerUtxoAttestation,
        attestationFn,
        txMemo
      })

      setBeefHex(atomicBEEFHex)
      setBeefTxid(tx.id('hex') as string)

      onUpdate()
      notify('success', 'Transaction built & signed. The Atomic BEEF will be exported during the SAVE process. SAVE the vault to persist changes.')
      await dialog.alert(
        'Next step: SAVE the vault. The SAVE process will require you to download the new Atomic BEEF, send it to the transaction recipient for processing, and confirm processed status.',
        'Post-Sign Instructions'
      )
      setStep(5)
    } catch (e: any) {
      notify('error', e.message || String(e))
    } finally {
      setIsBuilding(false)
    }
  }

  const btnRemoveStyle: React.CSSProperties = { ...btnGhostStyle, background: COLORS.red, color: 'white', padding: '8px 12px', lineHeight: 1, minWidth: 'auto', fontWeight: 'bold', maxWidth: 120 }

  const StepIndicator = () => (
    <div style={{ display: 'flex', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
      {[1, 2, 3, 4, 5].map(n => (
        <div key={n} style={{
          padding: '6px 10px',
          borderRadius: 999,
          background: step === n ? COLORS.blue : '#eee',
          color: step === n ? '#fff' : '#444',
          fontSize: 12
        }}>
          {n}. {n === 1 ? 'Outputs' : n === 2 ? 'Inputs' : n === 3 ? 'Change' : n === 4 ? 'Review & Sign' : 'Result'}
        </div>
      ))}
    </div>
  )

  // Helpers: Select/Deselect all inputs; "all funds available" flow
  const selectAllInputs = () => {
    const next: Record<string, boolean> = {}
    vault.coins.forEach(c => { next[`${c.txid}:${c.outputIndex}`] = true })
    setManualInputs(next)
  }
  const clearAllInputs = () => setManualInputs({})

  return (
    <section style={{ ...sectionStyle }}>
      <h2 style={{ marginTop: 0 }}>Build Outgoing Transaction (Wizard)</h2>
      <StepIndicator />

      {step === 1 && (
        <div>
          <div style={{ marginBottom: 8, color: COLORS.gray600, fontSize: 12 }}>
            Add one or more outputs for the transaction.
          </div>
          <div style={{ display: 'grid', gap: 8 }}>
            {outputs.map((output, index) => (
              <div key={index} style={{ display: 'grid', gap: 8, gridTemplateColumns: '1fr', alignItems: 'center' }}>
                <input
                  placeholder="Address or Script Hex"
                  value={output.destinationAddressOrScript}
                  onChange={(e) => handleOutputChange(index, 'destinationAddressOrScript', e.target.value)}
                  style={{ ...inputStyle }}
                  autoComplete="off"
                />
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  placeholder="Satoshis"
                  value={output.satoshis}
                  onChange={(e) => handleOutputChange(index, 'satoshis', e.target.value)}
                  style={{ ...inputStyle }}
                  autoComplete="off"
                  maxLength={16}
                />
                <input
                  placeholder="Memo (optional)"
                  value={output.memo}
                  onChange={(e) => handleOutputChange(index, 'memo', e.target.value)}
                  style={{ ...inputStyle }}
                  autoComplete="off"
                  maxLength={256}
                />
                <button onClick={() => removeOutput(index)} disabled={outputs.length <= 1} style={btnRemoveStyle}>
                  &times;
                </button>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 10, display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr' }}>
            <button onClick={addOutput} style={{ ...btnGhostStyle, background: COLORS.green, color: 'white' }}>+ Add Output</button>
            <button onClick={nextFromOutputs} style={btnStyle}>Next: Select Inputs</button>
          </div>
        </div>
      )}

      {step === 2 && (
        <div>
          <b>Input Selection</b>
          <div style={{
            background: '#eee', padding: '8px 12px', borderRadius: 8, marginTop: 8,
            borderLeft: `4px solid ${totalInputSats >= totalOutputSats ? COLORS.green : COLORS.red}`
          }}>
            <div>Required for outputs: <b>{totalOutputSats.toLocaleString()} sats</b></div>
            <div>Selected from inputs: <b style={{ color: totalInputSats >= totalOutputSats ? COLORS.green : COLORS.red }}>{totalInputSats.toLocaleString()} sats</b></div>
            {totalInputSats < totalOutputSats && <div style={{ fontSize: 12, color: COLORS.red, marginTop: 4 }}>
                You need to select at least {(totalOutputSats - totalInputSats).toLocaleString()} more sats.
            </div>}
          </div>

          <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
            <button onClick={selectAllInputs} style={btnGhostStyle}>Select All UTXOs</button>
            <button onClick={clearAllInputs} style={btnGhostStyle}>Clear All</button>
          </div>

          {vault.coins.length === 0 && <div style={{ marginTop: 8 }}>No spendable UTXOs</div>}
          {vault.coins.map(c => {
            const id = `${c.txid}:${c.outputIndex}`
            let sats = 0
            try {
              const tx = getTxFromStore(vault.beefStore, c.txid)
              sats = tx.outputs[c.outputIndex].satoshis as number
            } catch { }
            return <div key={id} style={{ padding: '6px 0', wordBreak:'break-all' }}><label>
              <input type="checkbox" checked={!!manualInputs[id]} onChange={e => setManualInputs(prev => ({ ...prev, [id]: e.target.checked }))} />
              {' '}
              {id} — {sats.toLocaleString()} sats ({(sats / 100000000).toFixed(8)} BSV)
            </label></div>
          })}
          <div style={{ marginTop: 10, display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr' }}>
            <button onClick={() => setStep(1)} style={btnGhostStyle}>Back</button>
            <button onClick={nextFromInputs} style={btnStyle}>Next: Choose Change</button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 8 }}>
            <div>
              <b>Change Keys</b>
              <div style={{ marginTop: 6, color: COLORS.gray600, fontSize: 12 }}>Select at least one key to receive change.</div>
            </div>
            <button onClick={handleGenerateNewChangeKey} style={{ ...btnGhostStyle, background: COLORS.green }}>Generate New Key</button>
          </div>
          
          {vault.keys.map(k => <div key={k.serial} style={{ padding: '6px 0' }}><label>
            <input type="checkbox" checked={!!changeSerials[k.serial]} onChange={e => setChangeSerials(prev => ({ ...prev, [k.serial]: e.target.checked }))} />
            {' '}
            {k.serial} {k.memo && `— ${k.memo}`} {k.usedOnChain ? <span style={{ color: '#b36' }}> (used)</span> : <span style={{ color: COLORS.green }}>(unused)</span>}
          </label></div>)}
          <div style={{ marginTop: 12, display: 'grid', alignItems: 'center', gap: 8 }}>
            {vault.confirmOutgoingCoins && (
              <label><input type="checkbox" checked={requirePerUtxoAttestation} onChange={e => setRequirePerUtxoAttestation(e.target.checked)} /> {' '}Per-UTXO Attestation</label>
            )}
            <input placeholder="Transaction Memo (optional)" value={txMemo} onChange={e => setTxMemo(e.target.value)} style={{ ...inputStyle }} autoComplete="off" />
          </div>
          <div style={{ marginTop: 10, display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr' }}>
            <button onClick={() => setStep(2)} style={btnGhostStyle}>Back</button>
            <button onClick={nextFromChange} style={btnStyle}>Next: Review & Sign</button>
          </div>
        </div>
      )}

      {step === 4 && (
        <div>
          <b>Review</b>
          <div style={{ display: 'grid', gap: 12, marginTop: 8 }}>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>Outputs</div>
              <div style={{ border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 8, marginTop: 6, fontFamily: 'monospace', whiteSpace: 'pre-wrap', fontSize: 12, overflowX: 'auto' }}>
                {parsedOutputs.map((o, i) => `${i + 1}. ${o.destinationAddressOrScript} ${o.satoshis}${o.memo ? ` (${o.memo})` : ''}`).join('\n')}
              </div>
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>Inputs</div>
              <div style={{ border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 8, marginTop: 6, fontFamily: 'monospace', whiteSpace: 'pre-wrap', fontSize: 12 }}>
                {Object.keys(manualInputs).filter(id => manualInputs[id]).join('\n') || '—'}
              </div>
              <div style={{ marginTop: 8, fontSize: 12 }}>
                Change Keys: <b>{Object.keys(changeSerials).filter(s => changeSerials[s]).join(', ') || '—'}</b>
              </div>
              <div style={{ marginTop: 4, fontSize: 12 }}>
                Per-UTXO Attestation: <b>{vault.confirmOutgoingCoins ? (requirePerUtxoAttestation ? 'Enabled' : 'Disabled') : 'Policy off'}</b>
              </div>
              {txMemo && <div style={{ marginTop: 4, fontSize: 12 }}>Tx Memo: <b>{txMemo}</b></div>}
            </div>
          </div>

          <div style={{ marginTop: 12, display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr' }}>
            <button onClick={() => setStep(3)} style={btnGhostStyle}>Back</button>
            <button onClick={buildAndSign} disabled={isBuilding} style={btnStyle}>{isBuilding ? 'Building...' : 'Finalize & Sign'}</button>
          </div>
        </div>
      )}

      {step === 5 && (
        <div>
          <b>Result</b>
          {/* IMPORTANT: Do not reveal Atomic BEEF here; only inform user to save */}
          {beefHex && beefTxid ? (
            <div style={{ border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 12, marginTop: 8 }}>
              <p style={{fontSize: 12, margin: 0, wordBreak:'break-all'}}>TXID: <code>{beefTxid}</code></p>
              <div style={{ marginTop: 8, fontSize: 12, color: COLORS.gray600 }}>
                The Atomic BEEF has been prepared in memory. <b>It will be made available for download during the SAVE process.</b>
              </div>
            </div>
          ) : (
            <div style={{ marginTop: 8 }}>No result to show.</div>
          )}
          <div style={{ marginTop: 12, display: 'grid', justifyContent: 'end' }}>
            <button onClick={resetWizard} style={btnStyle}>Create Another</button>
          </div>
        </div>
      )}
    </section>
  )
}

const LogsPanel: FC<{ vault: Vault, onUpdate: () => void }> = ({ vault, onUpdate }) => {
    const [customLogEntry, setCustomLogEntry] = useState('')
    const dialog = useDialog()
  
    const addCustomLog = async () => {
      if (!customLogEntry.trim()) return
      const ok = await dialog.confirm('Are you sure you want to add this custom entry to the permanent vault log? This action cannot be undone.', {
        title: 'Confirm Log Entry',
        confirmText: 'Add Entry',
        cancelText: 'Keep Editing'
      })
      if (ok) {
        vault.logVault('custom.entry', customLogEntry)
        setCustomLogEntry('')
        onUpdate()
      }
    }
  
    const LogViewer: FC<{ log: AuditEvent[] }> = ({ log }) => (
      <div style={{ height: 200, overflowY: 'auto', border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 8, background: '#fcfcfc', fontFamily: 'monospace', fontSize: 12 }}>
        {[...log].reverse().map(e => (
          <div key={e.at + e.event} style={{ wordBreak:'break-all' }}>{`[${new Date(e.at).toISOString()}] ${e.event}${e.data ? `: ${e.data}` : ''}`}</div>
        ))}
      </div>
    )
  
    return (
      <section style={{ ...sectionStyle }}>
        <h2 style={{ marginTop: 0 }}>Logs</h2>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8, gap: 8 }}>
              <h3 style={{ margin: 0 }}>Vault Log (Permanent)</h3>
              <button onClick={() => vault.exportVaultLog()} style={btnGhostStyle}>Download</button>
            </div>
            <LogViewer log={vault.vaultLog} />
            <div style={{ marginTop: 8, display: 'grid', gap: 8 }}>
              <input
                placeholder="Add custom vault log entry..."
                value={customLogEntry}
                onChange={e => setCustomLogEntry(e.target.value)}
                style={{ ...inputStyle }}
              />
              <button onClick={addCustomLog} style={btnStyle}>Add Entry</button>
            </div>
          </div>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8, gap: 8 }}>
              <h3 style={{ margin: 0 }}>Session Log (Ephemeral)</h3>
              <button onClick={() => vault.exportSessionLog()} style={btnGhostStyle}>Download</button>
            </div>
            <LogViewer log={vault.sessionLog} />
          </div>
        </div>
      </section>
    )
  }

const SettingsPanel: FC<{ vault: Vault, onUpdate: () => void, setLastSavedPlainHash: (h: string | null) => void }> = ({ vault, onUpdate, setLastSavedPlainHash }) => {
  const [incoming, setIncoming] = useState(vault.confirmIncomingCoins)
  const [outgoing, setOutgoing] = useState(vault.confirmOutgoingCoins)
  const [phOld, setPhOld] = useState(String(vault.persistHeadersOlderThanBlocks))
  const [rvRecent, setRvRecent] = useState(String(vault.reverifyRecentHeadersAfterSeconds))
  const [rvHeight, setRvHeight] = useState(String(vault.reverifyCurrentBlockHeightAfterSeconds))
  const [useUserEntropy, setUseUserEntropy] = useState(vault.useUserEntropyForRandom)

  const [newName, setNewName] = useState(vault.vaultName)

  const dialog = useDialog()

  async function save() {
    // Validate inputs first
    const nameOk = validateVaultName(newName)
    if (nameOk !== true) { await dialog.alert(typeof nameOk === 'string' ? nameOk : 'Invalid vault name.', 'Invalid Name'); return }
    const phOk = requireIntegerString(phOld, 'Persist headers (blocks)', { min: 0 })
    if (phOk !== true) { await dialog.alert(typeof phOk === 'string' ? phOk : 'Invalid number.', 'Invalid Setting'); return }
    const rvROk = requireIntegerString(rvRecent, 'Re-verify recent headers (seconds)', { min: 1 })
    if (rvROk !== true) { await dialog.alert(typeof rvROk === 'string' ? rvROk : 'Invalid number.', 'Invalid Setting'); return }
    const rvHOk = requireIntegerString(rvHeight, 'Re-verify height (seconds)', { min: 1 })
    if (rvHOk !== true) { await dialog.alert(typeof rvHOk === 'string' ? rvHOk : 'Invalid number.', 'Invalid Setting'); return }

    const ok = await dialog.confirm('Are you sure you want to apply these settings? This will mark the vault as having unsaved changes.', {
      title: 'Confirm Settings',
      confirmText: 'Apply Settings',
      cancelText: 'Keep Editing'
    })
    if (!ok) return
    vault.confirmIncomingCoins = !!incoming
    vault.confirmOutgoingCoins = !!outgoing
    vault.persistHeadersOlderThanBlocks = parseInteger(phOld)
    vault.reverifyRecentHeadersAfterSeconds = parseInteger(rvRecent)
    vault.reverifyCurrentBlockHeightAfterSeconds = parseInteger(rvHeight)
    vault.useUserEntropyForRandom = !!useUserEntropy
    if (newName.trim() !== vault.vaultName) {
      await vault.renameVault(newName.trim())
    }
    onUpdate()
  }

  async function doChangePassword() {
    try {
      await vault.changePassword()
      onUpdate()
      // Changing password changes plaintext (salt & settings), update dirty hash baseline? No: we want to show unsaved.
      await dialog.alert('Password updated. You must SAVE the vault file to persist the change.', 'Password Changed')
    } catch (e: any) {
      await dialog.alert(e.message || 'Failed to change password.', 'Error')
    }
  }

  return (
    <section style={{ ...sectionStyle }}>
      <h2 style={{ marginTop: 0 }}>Settings</h2>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 12 }}>
        <div>
          <div style={{ fontSize: 12, color: COLORS.gray600, marginBottom: 4 }}>Vault Display Name</div>
          <input value={newName} onChange={e => setNewName(e.target.value)} style={inputStyle} autoComplete="off" maxLength={64} />
        </div>

        <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input type="checkbox" checked={incoming} onChange={e => setIncoming(e.target.checked)} />
          Require attestation for incoming UTXOs
        </label>
        <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input type="checkbox" checked={outgoing} onChange={e => setOutgoing(e.target.checked)} />
          Require attestation for outgoing UTXOs
        </label>
        <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input type="checkbox" checked={useUserEntropy} onChange={e => setUseUserEntropy(e.target.checked)} />
          Require user-provided entropy for randomness (keys & salts)
        </label>

        <div>
          <div style={{ fontSize: 12, color: COLORS.gray600 }}>Persist headers older than N blocks</div>
          <input type="text" inputMode="numeric" pattern="[0-9]*" value={phOld} onChange={e => setPhOld(e.target.value)} style={inputStyle} autoComplete="off" maxLength={10} />
        </div>
        <div>
          <div style={{ fontSize: 12, color: COLORS.gray600 }}>Re-verify recent headers after (seconds)</div>
          <input type="text" inputMode="numeric" pattern="[0-9]*" value={rvRecent} onChange={e => setRvRecent(e.target.value)} style={inputStyle} autoComplete="off" maxLength={10} />
        </div>
        <div>
          <div style={{ fontSize: 12, color: COLORS.gray600 }}>Re-verify current block height after (seconds)</div>
          <input type="text" inputMode="numeric" pattern="[0-9]*" value={rvHeight} onChange={e => setRvHeight(e.target.value)} style={inputStyle} autoComplete="off" maxLength={10} />
        </div>

        <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr', alignItems: 'center' }}>
          <button onClick={save} style={btnStyle}>Apply Changes</button>
          <button onClick={doChangePassword} style={btnGhostStyle}>Change Password</button>
        </div>
      </div>
    </section>
  )
}
