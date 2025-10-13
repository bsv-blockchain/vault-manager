import React, { useEffect, useMemo, useState, FC, ReactNode, createContext, useCallback, useContext } from 'react'
import {
  PrivateKey, P2PKH, Script, Transaction, PublicKey, ChainTracker,
  Utils, Hash, SymmetricKey, Random, TransactionOutput, Beef
} from '@bsv/sdk'

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
const containerStyle: React.CSSProperties = { padding: 16, maxWidth: 1180, margin: '0 auto' }
const panelStyle: React.CSSProperties = { background: COLORS.panel, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 16, boxShadow: '0 2px 10px rgba(0,0,0,0.03)' }
const sectionStyle: React.CSSProperties = { ...panelStyle, marginBottom: 16 }
const btnStyle: React.CSSProperties = { background: COLORS.blue, color: 'white', border: 'none', padding: '10px 14px', borderRadius: 6, cursor: 'pointer' }
const btnGhostStyle: React.CSSProperties = { background: '#777', color: '#fff', border: 'none', padding: '10px 14px', borderRadius: 6, cursor: 'pointer' }
const inputStyle: React.CSSProperties = {
  border: `1px solid ${COLORS.border}`,
  borderRadius: 6,
  padding: '8px 10px',
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
      position: 'fixed', top: 16, right: 16, background: colors[notification.type], color: 'white',
      padding: '12px 16px', borderRadius: 8, zIndex: 1000, boxShadow: '0 8px 24px rgba(0,0,0,0.2)',
      display: 'flex', alignItems: 'center', gap: 16
    }}>
      <span>{notification.message}</span>
      <button onClick={onDismiss} style={{ background: 'none', border: 'none', color: 'white', fontSize: 18, cursor: 'pointer' }}>&times;</button>
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
      zIndex: 1000
    }}>
      <div style={{
        background: 'white',
        color: '#111',
        padding: 20,
        borderRadius: 10,
        minWidth: 540,
        maxWidth: 900,
        width: '90%'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: `1px solid ${COLORS.border}`, paddingBottom: 10, marginBottom: 15 }}>
          <h2 style={{ margin: 0 }}>{title}</h2>
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
  | { kind: 'confirm'; title?: string; message: string; resolve: (ok: boolean) => void }
  | { kind: 'prompt'; title?: string; message: string; password?: boolean; defaultValue?: string; resolve: (val: string | null) => void }

type DialogAPI = {
  alert(msg: string, title?: string): Promise<void>
  confirm(msg: string, title?: string): Promise<boolean>
  prompt(msg: string, opts?: { title?: string; password?: boolean; defaultValue?: string }): Promise<string | null>
}

const DialogCtx = createContext<DialogAPI | null>(null)

const DialogHost: FC<{ queue: DialogRequest[]; setQueue: React.Dispatch<React.SetStateAction<DialogRequest[]>> }> = ({ queue, setQueue }) => {
  if (!queue.length) return null
  const req = queue[0]
  const close = () => setQueue(q => q.slice(1))

  if (req.kind === 'alert') {
    return (
      <Modal title={req.title || 'Notice'} onClose={() => { req.resolve(); close() }}>
        <p style={{ whiteSpace: 'pre-wrap' }}>{req.message}</p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12 }}>
          <button onClick={() => { req.resolve(); close() }} style={btnStyle}>OK</button>
        </div>
      </Modal>
    )
  }
  if (req.kind === 'confirm') {
    return (
      <Modal title={req.title || 'Confirm'} onClose={() => { req.resolve(false); close() }}>
        <p style={{ whiteSpace: 'pre-wrap' }}>{req.message}</p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12, gap: 8 }}>
          <button onClick={() => { req.resolve(false); close() }} style={btnGhostStyle}>Cancel</button>
          <button onClick={() => { req.resolve(true); close() }} style={btnStyle}>OK</button>
        </div>
      </Modal>
    )
  }
  // prompt
  const [val, setVal] = React.useState(req.defaultValue || '')
  return (
    <Modal title={req.title || 'Input required'} onClose={() => { req.resolve(null); close() }}>
      <p style={{ whiteSpace: 'pre-wrap' }}>{req.message}</p>
      <input
        type={req.password ? 'password' : 'text'}
        value={val}
        onChange={e => setVal(e.target.value)}
        style={{ ...inputStyle, marginTop: 8 }}
        autoFocus
      />
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12, gap: 8 }}>
        <button onClick={() => { req.resolve(null); close() }} style={btnGhostStyle}>Cancel</button>
        <button onClick={() => { req.resolve(val); close() }} style={btnStyle}>OK</button>
      </div>
    </Modal>
  )
}

export const DialogProvider: FC<{ children: ReactNode }> = ({ children }) => {
  const [queue, setQueue] = React.useState<DialogRequest[]>([])
  const push = useCallback(<T,>(req: Omit<DialogRequest, 'resolve'>) =>
    new Promise<T>(resolve => setQueue(q => [...q, { ...(req as any), resolve }]))
  , [])

  const api: DialogAPI = {
    alert: (message, title) => push<void>({ kind: 'alert', title, message }),
    confirm: (message, title) => push<boolean>({ kind: 'confirm', title, message }),
    prompt: (message, opts) => push<string | null>({ kind: 'prompt', title: opts?.title, message, password: opts?.password, defaultValue: opts?.defaultValue })
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
  prompt: (msg: string, opts?: { title?: string; password?: boolean; defaultValue?: string }) => Promise<string | null>
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

  /** UI-only flags */
  saved = false

  // -------------------------------------------------------------------------
  // Logging (forensic; strictly sanitized)
  // -------------------------------------------------------------------------
  private logSession (event: string, data?: string) {
    this.sessionLog.push({ at: Date.now(), event, data })
  }
  private logVault (event: string, data?: string) {
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
      let memo = await this.ui.prompt('Enter the source(s) used to confirm this merkle root:', { title: 'Merkle Root Memo' })
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
        const input = await this.ui.prompt('Enter the current block height for the HONEST chain:', { title: 'Block Height' })
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

    const roundsIn = await ui.prompt(`PBKDF2 rounds? (default ${v.passwordRounds})`, { title: 'PBKDF2 Rounds', defaultValue: String(v.passwordRounds) })
    if (roundsIn && /^\d+$/.test(roundsIn)) {
      const n = Number(roundsIn)
      if (n >= 1) v.passwordRounds = n
    }
    v.passwordSalt = Random(32)
    v.logKV('vault', 'passwordRounds', String(v.passwordRounds))
    v.logKV('vault', 'passwordSalt.len', String(v.passwordSalt.length))

    // Require password once, derive and cache key
    const pw = (await ui.prompt('Set a password for this vault file (required):', { title: 'Vault Password', password: true })) || ''
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
    const older = await ui.prompt(`Persist headers older than how many blocks? (default ${v.persistHeadersOlderThanBlocks})`, { title: 'Header Persistence', defaultValue: String(v.persistHeadersOlderThanBlocks) })
    if (older && /^\d+$/.test(older)) v.persistHeadersOlderThanBlocks = Number(older)
    const recentSec = await ui.prompt(`Re-verify recent headers after how many seconds? (default ${v.reverifyRecentHeadersAfterSeconds})`, { title: 'Re-verify Recent Headers', defaultValue: String(v.reverifyRecentHeadersAfterSeconds) })
    if (recentSec && /^\d+$/.test(recentSec)) v.reverifyRecentHeadersAfterSeconds = Number(recentSec)
    const heightSec = await ui.prompt(`Re-verify current block height after how many seconds? (default ${v.reverifyCurrentBlockHeightAfterSeconds})`, { title: 'Re-verify Height', defaultValue: String(v.reverifyCurrentBlockHeightAfterSeconds) })
    if (heightSec && /^\d+$/.test(heightSec)) v.reverifyCurrentBlockHeightAfterSeconds = Number(heightSec)

    v.logSession('wizard.complete', 'create')
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
    if (proto !== v.protocolVersion) throw new Error(`Vault protocol version mismatch. File=${proto} Software=${v.protocolVersion}`)
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
    return v
  }

  /** Deterministic plaintext hash (for “unsaved changes” banner). */
  computePlaintextHashHex (): string {
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

  async downloadVaultFile (): Promise<void> {
    const bytes = await this.saveToFileBytes()
    const hashHex = Utils.toHex(Hash.sha256(bytes))
    const blob = new Blob([new Uint8Array(bytes)], { type: 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${this.vaultName.replace(/\s+/g, '_')}_rev${this.vaultRevision}_${Date.now()}.vaultfile`
    a.click()
    URL.revokeObjectURL(url)
    const msg = `Vault file downloaded.\n\nRevision: ${this.vaultRevision}\nSHA-256 (hex):\n${hashHex}\n\nVerify and store this new file safely. Securely delete any old vault versions.`
    await this.ui.alert(msg, 'Vault Saved')
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

    // settings
    this.confirmIncomingCoins = d.readVarIntNum() !== 0
    this.confirmOutgoingCoins = d.readVarIntNum() !== 0
    this.persistHeadersOlderThanBlocks = d.readVarIntNum()
    this.reverifyRecentHeadersAfterSeconds = d.readVarIntNum()
    this.reverifyCurrentBlockHeightAfterSeconds = d.readVarIntNum()

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

  generateKey (memo: string = ''): KeyRecord {
    const priv = PrivateKey.fromRandom()
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
      at: Date.now(), txid, net: netIn, memo: opts?.txMemo || '', processed: false
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
  // Session Log export (sanitized)
  // -------------------------------------------------------------------------
  exportSessionLog (): void {
    const redacted: AuditEvent[] = this.sessionLog.map(e => ({ at: e.at, event: e.event, data: e.data }))
    const blob = new Blob([`
Vault: ${this.vaultName}, rev: ${this.vaultRevision}
Created: ${this.created}, Updated: ${this.lastUpdated}
Session Log:
-----
${redacted.map(x => `[${x.at}]: ${x.event}, ${x.data}`)}
`], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `vault_session_${Date.now()}.txt`; a.click()
    URL.revokeObjectURL(url)
  }
}

/**
 * =============================================================================
 * React App Shell (Tabs + Views)
 * =============================================================================
 */

type TabKey = 'keys' | 'incoming' | 'outgoing' | 'dashboard' | 'settings'

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

  function notify(type: Notification['type'], message: string) {
    setNotification({ type, message, id: Date.now() })
  }

  // --- Core Vault Actions ---
  async function onOpenVault (file: File) {
    setIsLoading(true);
    try {
      const buf = new Uint8Array(await file.arrayBuffer())
      const v = await Vault.loadFromFile(dialog, Array.from(buf))
      setVault(v)
      setLastSavedPlainHash(v.computePlaintextHashHex())
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
      setLastSavedPlainHash(v.computePlaintextHashHex())
      notify('info', 'New vault created. Generate a key to begin.')
      setActiveTab('keys')
    } catch (e: any) {
      notify('error', e.message || 'Failed to create vault.')
    } finally {
      setIsLoading(false)
    }
  }

  async function onSaveVault () {
    if (!vault) return
    setIsLoading(true);
    try {
      await vault.downloadVaultFile()
      setLastSavedPlainHash(vault.computePlaintextHashHex())
      triggerRerender() // To update revision number in UI
    } catch (e: any) {
      notify('error', e.message || 'Failed to save vault.')
    } finally {
      setIsLoading(false)
    }
  }

  function triggerRerender () {
    if (!vault) return
    setVault(Object.assign(Object.create(Object.getPrototypeOf(vault)), vault))
  }

  // --- Derived State ---
  const dirty = useMemo(() => {
    if (!vault || !lastSavedPlainHash) return false
    return vault.computePlaintextHashHex() !== lastSavedPlainHash
  }, [vault, lastSavedPlainHash])

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
  }, [vault?.coins, vault?.beefStore])

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
          <div style={{ ...panelStyle, padding: 24 }}>
            <h1 style={{ marginTop: 0 }}>BSV Vault Manager Suite</h1>
            <section style={{ border: `1px solid ${COLORS.border}`, padding: 16, borderRadius: 8 }}>
              <h2 style={{ marginTop: 0 }}>Open / New</h2>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <input type="file" accept=".vaultfile,application/octet-stream" onChange={e => e.target.files && onOpenVault(e.target.files[0])} />
                <button onClick={onNewVault} style={btnStyle}>Create New Vault</button>
              </div>
            </section>
            <p style={{ color: COLORS.gray600, marginTop: 12 }}>Open an existing vault or create a new one.</p>
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
              triggerRerender()
              notify('success', `Transaction ${txid} processed. SAVE the vault to persist changes.`)
            }}
            onError={(err) => notify('error', err)}
          />
        )}

        <div style={{ ...panelStyle, padding: 24, marginBottom: 16 }}>
          {dirty && (
            <div style={{ background: COLORS.red, color: 'white', padding: 12, marginBottom: 12, fontWeight: 700, borderRadius: 6 }}>
              UNSAVED CHANGES — Save the new vault file, verify its integrity, and then securely delete the old version.
            </div>
          )}

          <header style={{ borderBottom: `1px solid ${COLORS.border}`, paddingBottom: 12, marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <h1 style={{ margin: 0 }}>BSV Vault Manager Suite</h1>
              <div style={{ color: COLORS.gray600, marginTop: 4 }}>
                Vault: <b>{vault.vaultName}</b> (rev {vault.vaultRevision})
              </div>
            </div>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
              <input type="file" accept=".vaultfile,application/octet-stream" onChange={e => e.target.files && onOpenVault(e.target.files[0])} />
              <button onClick={onSaveVault} style={btnStyle}>Save Vault</button>
              <button onClick={() => { vault.exportSessionLog() }} style={btnGhostStyle}>Export Session Log</button>
            </div>
          </header>

          {/* Tabs */}
          <div style={{ display: 'flex', gap: 8, borderBottom: `1px solid ${COLORS.border}`, marginBottom: 16, overflowX: 'auto' }}>
            {tabs.map(t => (
              <button
                key={t.key}
                onClick={() => setActiveTab(t.key)}
                style={{
                  background: activeTab === t.key ? COLORS.blue : 'transparent',
                  color: activeTab === t.key ? '#fff' : COLORS.gray700,
                  border: 'none',
                  borderRadius: 8,
                  padding: '8px 12px',
                  cursor: 'pointer'
                }}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Active Tab Panels */}
          {activeTab === 'dashboard' && (
            <DashboardPanel vault={vault} balance={balance} triggerRerender={triggerRerender} />
          )}

          {activeTab === 'keys' && (
            <KeyManager
              vault={vault}
              onUpdate={triggerRerender}
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
              onUpdate={triggerRerender}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsPanel vault={vault} onUpdate={triggerRerender} />
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
      <div style={{ display: 'flex', gap: 24, marginTop: 16, flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 300 }}>
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
              <div key={id} style={{ borderTop: `1px solid ${COLORS.border}`, padding: '8px 0', fontSize: '12px' }}>
                <div><b>{id}</b> — {sats.toLocaleString()} sats (<b>{(sats / 100000000).toFixed(8)}</b> BSV)</div>
                {c.memo && <div>Memo: {c.memo}</div>}
              </div>
            )
          })}
        </div>
        <div style={{ flex: 1, minWidth: 300 }}>
          <h3>Transaction Log ({vault.transactionLog.length})</h3>
          {[...vault.transactionLog].reverse().map(t => (
            <div key={t.at + t.txid} style={{ borderTop: `1px solid ${COLORS.border}`, padding: '8px 0', fontSize: '12px' }}>
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
  return (
    <section style={{ ...sectionStyle }}>
      <h2 style={{ marginTop: 0 }}>Keys ({vault.keys.length})</h2>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
        <button
          onClick={async () => {
            const memo = (await dialog.prompt('Memo for this key (optional):', { title: 'Key Memo' })) || ''
            vault.generateKey(memo); onUpdate()
          }}
          style={btnStyle}
        >
          Generate New Key
        </button>
      </div>
      <div style={{ marginTop: 12 }}>
        {[...vault.keys].reverse().map(k => (
          <div key={k.serial} style={{ borderTop: `1px solid ${COLORS.border}`, padding: '8px 0', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <b>{k.serial}</b> {k.memo && `— ${k.memo}`} {k.usedOnChain ? <span style={{ color: '#b36' }}> (used)</span> : <span style={{color: COLORS.green}}>(unused)</span>}
              <div style={{ fontSize: 12, color: COLORS.gray600, fontFamily: 'monospace' }}>{k.public.toAddress()}</div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={async () => { await vault.downloadDepositSlipTxt(k.serial); notify('info', `Deposit slip generated for ${k.serial}`) }} style={btnGhostStyle}>
                Deposit Slip (.txt)
              </button>
              <button onClick={() => navigator.clipboard.writeText(k.public.toAddress())} style={btnGhostStyle}>Copy Address</button>
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
      const res = await vault.processIncoming(preview.tx, { txMemo, admit, perUtxoMemo: memos })
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
      <div style={{display:'flex', gap:8, alignItems:'center'}}>
        <p style={{fontSize: 13, margin: 0}}>TXID: <code>{preview.txid}</code></p>
        <button onClick={() => navigator.clipboard.writeText(preview.txid)} style={{ ...btnGhostStyle, padding: '6px 10px', fontSize: 12 }}>Copy TXID</button>
      </div>
      <p style={{fontSize: 13, color: 'green', fontWeight: 'bold'}}>SPV Verified Successfully</p>
      <hr style={{margin: '16px 0'}} />
      <p>The following outputs in this transaction are spendable by your vault's keys. {needsConfirmation ? 'Select which UTXOs to admit:' : 'All matched UTXOs will be admitted automatically.'}</p>

      {preview.matches.map(m => (
        <div key={m.outputIndex} style={{border: `1px solid ${COLORS.border}`, padding: 8, margin: '8px 0', borderRadius: 6}}>
          {needsConfirmation && <input type="checkbox" checked={!!admit[m.outputIndex]} onChange={() => handleToggleAdmit(m.outputIndex)} style={{marginRight: 8}} />}
          <strong>Output #{m.outputIndex}</strong>: {m.satoshis.toLocaleString()} sats (<b>{(m.satoshis / 100000000).toFixed(8)}</b> BSV), to Key <strong>{m.serial}</strong>
          <input
            type="text"
            placeholder="UTXO Memo (optional)"
            style={{...inputStyle, marginTop: 6}}
            value={memos[m.outputIndex] || ''}
            onChange={e => setMemos(prev => ({...prev, [m.outputIndex]: e.target.value}))}
          />
        </div>
      ))}

      <button
        onClick={() => {
          const ids = preview.matches.map(m => `${preview.txid}:${m.outputIndex}`).join('\n')
          navigator.clipboard.writeText(ids)
        }}
        style={{ ...btnGhostStyle, marginTop: 6, fontSize: 12 }}
      >
        Copy All Matched UTXO IDs
      </button>

      <input
        type="text"
        placeholder="Transaction Memo (optional)"
        style={{...inputStyle, marginTop: 12}}
        value={txMemo}
        onChange={e => setTxMemo(e.target.value)}
      />

      <div style={{marginTop: 16, display: 'flex', justifyContent: 'flex-end', gap: 12}}>
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

  const [outputsText, setOutputsText] = useState<string>('') // "<address_or_script> <sats> [memo]"
  const [parsedOutputs, setParsedOutputs] = useState<OutgoingOutputSpec[]>([])

  const [manualInputs, setManualInputs] = useState<Record<string, boolean>>({})
  const [changeSerials, setChangeSerials] = useState<Record<string, boolean>>({})
  const [txMemo, setTxMemo] = useState<string>('')
  const [requirePerUtxoAttestation, setRequirePerUtxoAttestation] = useState<boolean>(false)

  const [beefHex, setBeefHex] = useState<string | null>(null)
  const [beefTxid, setBeefTxid] = useState<string | null>(null)
  const [isBuilding, setIsBuilding] = useState(false)

  function parseOutgoingLines(text: string): OutgoingOutputSpec[] {
    const lines = text.split('\n').map(s => s.trim()).filter(Boolean)
    return lines.map(line => {
      const parts = line.match(/^(\S+)\s+(\d+)(?:\s+(.*))?$/)
      if (!parts) throw new Error(`Invalid output line format: ${line}`)
      const [, dest, satStr, memo] = parts
      const sat = Number(satStr)
      if (!Number.isFinite(sat) || sat <= 0) throw new Error(`Bad amount on line: ${line}`)
      return { destinationAddressOrScript: dest, satoshis: sat, memo: memo || '' }
    })
  }

  function nextFromOutputs() {
    try {
      const out = parseOutgoingLines(outputsText)
      if (!out.length) throw new Error('Enter at least one output.')
      setParsedOutputs(out)
      setStep(2)
    } catch (e: any) {
      notify('error', e.message || 'Invalid outputs.')
    }
  }

  function nextFromInputs() {
    const selectedIds = Object.entries(manualInputs).filter(([_, on]) => on).map(([id]) => id)
    if (!selectedIds.length) { notify('error', 'Select at least one input UTXO.'); return }
    setStep(3)
  }

  function nextFromChange() {
    const change = Object.entries(changeSerials).filter(([_, on]) => on).map(([s]) => s)
    if (!change.length) { notify('error', 'Select at least one change key.'); return }
    setStep(4)
  }

  async function buildAndSign() {
    setIsBuilding(true)
    try {
      const selectedIds = Object.entries(manualInputs).filter(([_, on]) => on).map(([id]) => id)
      const change = Object.entries(changeSerials).filter(([_, on]) => on).map(([s]) => s)

      const attestationFn: AttestationFn | undefined =
        (vault.confirmOutgoingCoins && requirePerUtxoAttestation)
          ? async (coin) => {
              const id = `${coin.txid}:${coin.outputIndex}`
              return await dialog.confirm(
                `ATTESTATION REQUIRED:\n\nConfirm this UTXO is unspent on the HONEST chain:\n\n${id}`,
                'Per-UTXO Attestation'
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

      // cleanup & advance
      setOutputsText('')
      setManualInputs({})
      setChangeSerials({})
      setTxMemo('')
      onUpdate()
      notify('success', 'Transaction built & signed. SAVE the vault to persist changes.')
      setStep(5)
    } catch (e: any) {
      notify('error', e.message || String(e))
    } finally {
      setIsBuilding(false)
    }
  }

  const StepIndicator = () => (
    <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
      {[1,2,3,4,5].map(n => (
        <div key={n} style={{
          padding: '6px 10px',
          borderRadius: 999,
          background: step === n ? COLORS.blue : '#eee',
          color: step === n ? '#fff' : '#444',
          fontSize: 12
        }}>
          {n}. {n===1?'Outputs':n===2?'Inputs':n===3?'Change':n===4?'Review & Sign':'Result'}
        </div>
      ))}
    </div>
  )

  return (
    <section style={{ ...sectionStyle }}>
      <h2 style={{ marginTop: 0 }}>Build Outgoing Transaction (Wizard)</h2>
      <StepIndicator />

      {step === 1 && (
        <div>
          <div style={{ marginBottom: 8, color: COLORS.gray600, fontSize: 12 }}>
            Enter outputs, one per line: <code>&lt;address_or_script_hex&gt; &lt;satoshis&gt; [optional memo]</code>
          </div>
          <textarea rows={5} style={{ ...inputStyle, width: '100%', fontFamily: 'monospace' }} value={outputsText} onChange={e => setOutputsText(e.target.value)} placeholder={`1ABC... 546 tip for good work\n76a914...88ac 1000 payment for invoice #123`} />
          <div style={{ marginTop: 10, display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button onClick={nextFromOutputs} style={btnStyle}>Next: Select Inputs</button>
          </div>
        </div>
      )}

      {step === 2 && (
        <div>
          <b>Input Selection</b>
          {vault.coins.length === 0 && <div style={{ marginTop: 8 }}>No spendable UTXOs</div>}
          {vault.coins.map(c => {
            const id = `${c.txid}:${c.outputIndex}`
            let sats = 0
            try {
              const tx = getTxFromStore(vault.beefStore, c.txid)
              sats = tx.outputs[c.outputIndex].satoshis as number
            } catch {}
            return <div key={id} style={{padding: '6px 0'}}><label>
                <input type="checkbox" checked={!!manualInputs[id]} onChange={e => setManualInputs(prev => ({ ...prev, [id]: e.target.checked }))} />
                {' '}
                {id} — {sats.toLocaleString()} sats ({(sats / 100000000).toFixed(8)} BSV)
              </label></div>
          })}
          <div style={{ marginTop: 10, display: 'flex', justifyContent: 'space-between', gap: 8 }}>
            <button onClick={() => setStep(1)} style={btnGhostStyle}>Back</button>
            <button onClick={nextFromInputs} style={btnStyle}>Next: Choose Change</button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div>
          <b>Change Keys</b>
          <div style={{ marginTop: 6, color: COLORS.gray600, fontSize: 12 }}>Select at least one key to receive change.</div>
          {vault.keys.map(k => <div key={k.serial} style={{padding: '6px 0'}}><label>
              <input type="checkbox" checked={!!changeSerials[k.serial]} onChange={e => setChangeSerials(prev => ({ ...prev, [k.serial]: e.target.checked }))}/>
              {' '}
              {k.serial} {k.memo && `— ${k.memo}`} {k.usedOnChain ? <span style={{ color: '#b36' }}> (used)</span> : <span style={{color: COLORS.green}}>(unused)</span>}
            </label></div>)}
          <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            {vault.confirmOutgoingCoins && (
              <label><input type="checkbox" checked={requirePerUtxoAttestation} onChange={e => setRequirePerUtxoAttestation(e.target.checked)} /> {' '}Per-UTXO Attestation</label>
            )}
            <input placeholder="Transaction Memo (optional)" value={txMemo} onChange={e => setTxMemo(e.target.value)} style={{ ...inputStyle, maxWidth: 360 }} />
          </div>
          <div style={{ marginTop: 10, display: 'flex', justifyContent: 'space-between', gap: 8 }}>
            <button onClick={() => setStep(2)} style={btnGhostStyle}>Back</button>
            <button onClick={nextFromChange} style={btnStyle}>Next: Review & Sign</button>
          </div>
        </div>
      )}

      {step === 4 && (
        <div>
          <b>Review</b>
          <div style={{ display: 'flex', gap: 24, marginTop: 8, flexWrap: 'wrap' }}>
            <div style={{ flex: 1, minWidth: 280 }}>
              <div style={{ fontWeight: 600 }}>Outputs</div>
              <div style={{ border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: 8, marginTop: 6, fontFamily: 'monospace', whiteSpace: 'pre-wrap', fontSize: 12 }}>
                {parsedOutputs.map((o, i) => `${i+1}. ${o.destinationAddressOrScript} ${o.satoshis}${o.memo ? ' ' + o.memo : ''}`).join('\n')}
              </div>
            </div>
            <div style={{ flex: 1, minWidth: 280 }}>
              <div style={{ fontWeight: 600 }}>Inputs</div>
              <div style={{ border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: 8, marginTop: 6, fontFamily: 'monospace', whiteSpace: 'pre-wrap', fontSize: 12 }}>
                {Object.entries(manualInputs).filter(([_, on]) => on).map(([id]) => id).join('\n') || '—'}
              </div>
              <div style={{ marginTop: 8, fontSize: 12 }}>
                Change Keys: <b>{Object.entries(changeSerials).filter(([_, on]) => on).map(([s]) => s).join(', ') || '—'}</b>
              </div>
              <div style={{ marginTop: 4, fontSize: 12 }}>
                Per-UTXO Attestation: <b>{vault.confirmOutgoingCoins ? (requirePerUtxoAttestation ? 'Enabled' : 'Disabled') : 'Policy off'}</b>
              </div>
              {txMemo && <div style={{ marginTop: 4, fontSize: 12 }}>Tx Memo: <b>{txMemo}</b></div>}
            </div>
          </div>

          <div style={{ marginTop: 12, display: 'flex', justifyContent: 'space-between', gap: 8 }}>
            <button onClick={() => setStep(3)} style={btnGhostStyle}>Back</button>
            <button onClick={buildAndSign} disabled={isBuilding} style={btnStyle}>{isBuilding ? 'Building...' : 'Finalize & Sign'}</button>
          </div>
        </div>
      )}

      {step === 5 && (
        <div>
          <b>Result</b>
          {beefHex && beefTxid ? (
            <SignedBeefModalInline hex={beefHex} txid={beefTxid} />
          ) : (
            <div style={{ marginTop: 8 }}>No result to show.</div>
          )}
          <div style={{ marginTop: 12, display: 'flex', justifyContent: 'flex-end' }}>
            <button onClick={() => setStep(1)} style={btnStyle}>Create Another</button>
          </div>
        </div>
      )}
    </section>
  )
}

const SignedBeefModalInline: FC<{ hex: string; txid: string }> = ({ hex, txid }) => {
  const copy = async () => { await navigator.clipboard.writeText(hex) }
  const download = () => {
    const blob = new Blob([hex], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `tx_${txid}.atomic-beef.txt`; a.click()
    URL.revokeObjectURL(url)
  }
  return (
    <div style={{ border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 12, marginTop: 8 }}>
      <p style={{fontSize: 12, margin: 0}}>TXID: <code>{txid}</code></p>
      <textarea readOnly rows={8} style={{ ...inputStyle, width: '100%', marginTop: 8, fontFamily: 'monospace' }} value={hex} />
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 8 }}>
        <button onClick={copy} style={btnGhostStyle}>Copy</button>
        <button onClick={download} style={btnStyle}>Download</button>
      </div>
    </div>
  )
}

const SettingsPanel: FC<{ vault: Vault, onUpdate: () => void }> = ({ vault, onUpdate }) => {
  const [incoming, setIncoming] = useState(vault.confirmIncomingCoins)
  const [outgoing, setOutgoing] = useState(vault.confirmOutgoingCoins)
  const [phOld, setPhOld] = useState(String(vault.persistHeadersOlderThanBlocks))
  const [rvRecent, setRvRecent] = useState(String(vault.reverifyRecentHeadersAfterSeconds))
  const [rvHeight, setRvHeight] = useState(String(vault.reverifyCurrentBlockHeightAfterSeconds))

  function save() {
    vault.confirmIncomingCoins = !!incoming
    vault.confirmOutgoingCoins = !!outgoing
    vault.persistHeadersOlderThanBlocks = Number(phOld) || vault.persistHeadersOlderThanBlocks
    vault.reverifyRecentHeadersAfterSeconds = Number(rvRecent) || vault.reverifyRecentHeadersAfterSeconds
    vault.reverifyCurrentBlockHeightAfterSeconds = Number(rvHeight) || vault.reverifyCurrentBlockHeightAfterSeconds
    onUpdate()
  }

  return (
    <section style={{ ...sectionStyle }}>
      <h2 style={{ marginTop: 0 }}>Settings</h2>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input type="checkbox" checked={incoming} onChange={e => setIncoming(e.target.checked)} />
          Require attestation for incoming UTXOs
        </label>
        <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input type="checkbox" checked={outgoing} onChange={e => setOutgoing(e.target.checked)} />
          Require attestation for outgoing UTXOs
        </label>
        <div>
          <div style={{ fontSize: 12, color: COLORS.gray600 }}>Persist headers older than N blocks</div>
          <input value={phOld} onChange={e => setPhOld(e.target.value)} style={inputStyle} />
        </div>
        <div>
          <div style={{ fontSize: 12, color: COLORS.gray600 }}>Re-verify recent headers after (seconds)</div>
          <input value={rvRecent} onChange={e => setRvRecent(e.target.value)} style={inputStyle} />
        </div>
        <div>
          <div style={{ fontSize: 12, color: COLORS.gray600 }}>Re-verify current block height after (seconds)</div>
          <input value={rvHeight} onChange={e => setRvHeight(e.target.value)} style={inputStyle} />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <button onClick={save} style={btnStyle}>Apply</button>
      </div>
    </section>
  )
}
