import { useEffect, useMemo, useRef, useState } from 'react'
import {
  PrivateKey, P2PKH, Script, Transaction, PublicKey, ChainTracker,
  Utils, Hash, SymmetricKey, Random, TransactionOutput, MerklePath
} from '@bsv/sdk'

/**
 * ---------------------------------------------------------------------------
 * Types & Utilities
 * ---------------------------------------------------------------------------
 */

type Hex = string
type UnixMs = number

/** Never include secrets in logs. */
type Redacted<T> = Omit<T, 'private' | 'encryptionKeyBytes' | 'encryptionKey'>

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
  tx: Transaction
  outputIndex: number
  memo: string
  keySerial: string
}

type TxLogRecord = {
  at: UnixMs
  atomicBEEF: number[]       // raw bytes; never keys
  net: number                // positive=in, negative=out
  memo: string
  processed: boolean
  txid: string
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
  dest: string
  satoshis: number
  memo?: string
}

type SelectionStrategy = 'largest-first' | 'smallest-first' | 'oldest-first'

type BuildOutgoingOptions = {
  outputs: OutgoingOutputSpec[]
  /**
   * Optional explicit input set (txid:vout). If omitted, the vault will
   * auto-select using `strategy`.
   */
  inputIds?: string[]
  strategy?: SelectionStrategy
  /**
   * Change keys to use (serials). If omitted, vault will use the newest unused
   * key or fall back to the first key.
   */
  changeKeySerials?: string[]
  /**
   * If true and policy requires outgoing attestation, attest each UTXO
   * individually (UI should surface this list clearly to the user).
   */
  perUtxoAttestation?: boolean
  txMemo?: string
}

/** Format a txid:vout pair */
function coinId (tx: Transaction, vout: number): string {
  return `${tx.id('hex')}:${vout}`
}

function nowIso () { return new Date().toISOString() }

function assert (cond: any, msg: string): asserts cond {
  if (!cond) throw new Error(msg)
}

/**
 * ---------------------------------------------------------------------------
 * Vault class (core, auditable, React-agnostic)
 * ---------------------------------------------------------------------------
 * - Implements ChainTracker.
 * - Holds derived encryption key (NOT the password) so we never re-prompt.
 * - Exposes non-interactive APIs for UI to drive flows without window.prompt.
 * - Keeps interactive prompts only for ChainTracker confirmation steps.
 */

class Vault implements ChainTracker {
  /** File format / policy */
  protocolVersion = 1
  passwordRounds = 80085
  passwordSalt: number[] = new Array(32).fill(0)
  /** Cached symmetric key derived from user password (NOT the password) */
  private encryptionKey?: SymmetricKey
  /** For sanity checks; never logged */
  private encryptionKeyBytes?: number[]

  /** Metadata */
  vaultName = 'Vault'
  vaultRevision = 1
  created: UnixMs = Date.now()
  lastUpdated: UnixMs = Date.now()

  /** Keys & coins */
  keys: KeyRecord[] = []
  coins: CoinRecord[] = []

  /** Activity logs (sanitized; never keys) */
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
  // ChainTracker (explicitly allowed to prompt/confirm)
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

    const accepted = window.confirm(`Do you accept and confirm that block #${height} of the HONEST chain has a merkle root of "${root}"?`)
    if (!accepted) return false

    // Decide whether to persist
    if (this.currentBlockHeight !== 0 && (this.currentBlockHeight - this.persistHeadersOlderThanBlocks) < height) {
      this.ephemeralHeaderClaims.push({ at: Date.now(), merkleRoot: root, height })
      this.logVault('chain.header.ephemeral', `h=${height} root=${root}`)
    } else {
      let memo = window.prompt('Enter the source(s) used to confirm this merkle root:') || 'No memo provided.'
      this.persistedHeaderClaims.push({ at: Date.now(), merkleRoot: root, height, memo })
      this.logVault('chain.header.persisted', `h=${height} root=${root} memo=${memo}`)
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
        const input = window.prompt('Enter the current block height for the HONEST chain:')
        const n = Number(input)
        if (Number.isInteger(n) && n > 0) height = n
        else window.alert('Height must be a positive integer, try again.')
      } catch (e) {
        window.alert((e as any).message || 'Error processing height, try again.')
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
  static async create (): Promise<Vault> {
    const v = new Vault()
    v.logSession('wizard.start', 'create')

    const name = window.prompt('Enter a vault display name:') || 'Vault'
    v.vaultName = name
    v.logVault('vault.created', name)

    const roundsIn = window.prompt(`PBKDF2 rounds? (default ${v.passwordRounds})`)
    if (roundsIn && /^\d+$/.test(roundsIn)) {
      const n = Number(roundsIn)
      if (n >= 1) v.passwordRounds = n
    }
    v.passwordSalt = Random(32)
    v.logKV('vault', 'passwordRounds', String(v.passwordRounds))
    v.logKV('vault', 'passwordSalt.len', String(v.passwordSalt.length))

    // Require password once, derive and cache key
    const pw = window.prompt('Set a password for this vault file (required):') || ''
    if (!pw) throw new Error('Password required to create vault.')
    const keyBytes = Hash.pbkdf2(Utils.toArray(pw), v.passwordSalt, v.passwordRounds, 32)
    v.encryptionKeyBytes = keyBytes
    v.encryptionKey = new SymmetricKey(keyBytes)
    v.logVault('vault.key.derived', `klen=${keyBytes.length}`)

    // Policy toggles
    v.confirmIncomingCoins = window.confirm('Require attestation for incoming UTXOs? (OK = yes)')
    v.confirmOutgoingCoins = window.confirm('Require attestation for outgoing UTXOs? (OK = yes)')
    v.logKV('vault', 'confirmIncomingCoins', String(v.confirmIncomingCoins))
    v.logKV('vault', 'confirmOutgoingCoins', String(v.confirmOutgoingCoins))

    // Header settings
    const older = window.prompt(`Persist headers older than how many blocks? (default ${v.persistHeadersOlderThanBlocks})`)
    if (older && /^\d+$/.test(older)) v.persistHeadersOlderThanBlocks = Number(older)
    const recentSec = window.prompt(`Re-verify recent headers after how many seconds? (default ${v.reverifyRecentHeadersAfterSeconds})`)
    if (recentSec && /^\d+$/.test(recentSec)) v.reverifyRecentHeadersAfterSeconds = Number(recentSec)
    const heightSec = window.prompt(`Re-verify current block height after how many seconds? (default ${v.reverifyCurrentBlockHeightAfterSeconds})`)
    if (heightSec && /^\d+$/.test(heightSec)) v.reverifyCurrentBlockHeightAfterSeconds = Number(heightSec)
    v.logKV('vault', 'persistHeadersOlderThanBlocks', String(v.persistHeadersOlderThanBlocks))
    v.logKV('vault', 'reverifyRecentHeadersAfterSeconds', String(v.reverifyRecentHeadersAfterSeconds))
    v.logKV('vault', 'reverifyCurrentBlockHeightAfterSeconds', String(v.reverifyCurrentBlockHeightAfterSeconds))

    v.logSession('wizard.complete', 'create')
    window.alert('Vault created. Generate at least one key to receive funds.')
    return v
  }

  static loadFromFile (file: number[]): Vault {
    const v = new Vault()
    v.logSession('vault.load.start', `size=${file.length}`)

    const fileHash = Utils.toHex(Hash.sha256(file))
    v.logSession('vault.load.hash', fileHash)
    const ok = window.confirm(`Ensure the SHA-256 of your vault file matches:\n${fileHash}`)
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

    // Prompt ONCE for password on load
    let decrypted: number[] = []
    do {
      const pw = window.prompt('Enter vault password:')
      const kb = Hash.pbkdf2(Utils.toArray(pw || ''), salt, rounds, 32)
      const key = new SymmetricKey(kb)
      try {
        decrypted = key.decrypt(encrypted) as number[]
        v.encryptionKeyBytes = kb
        v.encryptionKey = key
        v.logSession('vault.decrypt.ok', `payload=${decrypted.length}B`)
      } catch {
        v.logSession('vault.decrypt.fail')
        window.alert('Failed to unlock the vault.')
      }
    } while (decrypted.length === 0)

    // Deserialize plaintext payload
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
    const payload = this.serializePlaintext()
    const encrypted = this.encryptionKey!.encrypt(payload) as number[]

    const writer = new Utils.Writer()
    writer.writeVarIntNum(this.protocolVersion)
    writer.writeVarIntNum(this.passwordRounds)
    writer.write(this.passwordSalt) // 32B
    writer.write(encrypted)

    const bytes = writer.toArray() as number[]
    this.saved = true
    this.lastUpdated = Date.now()
    this.logVault('vault.saved', `bytes=${bytes.length}`)
    return bytes
  }

  async downloadVaultFile (): Promise<void> {
    const bytes = await this.saveToFileBytes()
    const hashHex = Utils.toHex(Hash.sha256(bytes))
    const blob = new Blob([new Uint8Array(bytes)], { type: 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${this.vaultName.replace(/\s+/g, '_')}_${Date.now()}.vaultfile`
    a.click()
    URL.revokeObjectURL(url)
    window.alert(`Vault file downloaded.\n\nSHA-256 (hex):\n${hashHex}\n\nVerify and store safely. Delete any old vault versions.`)
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

    // coins
    w.writeVarIntNum(this.coins.length)
    for (const c of this.coins) {
      const beef = c.tx.toAtomicBEEF() as number[]
      w.writeVarIntNum(beef.length); w.write(beef)
      w.writeVarIntNum(c.outputIndex)
      const memoBytes = Utils.toArray(c.memo || ''); w.writeVarIntNum(memoBytes.length); w.write(memoBytes)
      const serBytes = Utils.toArray(c.keySerial); w.writeVarIntNum(serBytes.length); w.write(serBytes)
    }

    // tx log
    w.writeVarIntNum(this.transactionLog.length)
    for (const t of this.transactionLog) {
      w.writeVarIntNum(t.at)
      w.writeVarIntNum(t.atomicBEEF.length); w.write(t.atomicBEEF)
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
      const txLen = d.readVarIntNum()
      const tx = Transaction.fromAtomicBEEF(d.read(txLen))
      const outputIndex = d.readVarIntNum()
      const memoLen = d.readVarIntNum()
      const memo = Utils.toUTF8(d.read(memoLen))
      const ksLen = d.readVarIntNum()
      const keySerial = Utils.toUTF8(d.read(ksLen))
      this.coins.push({ tx, outputIndex, memo, keySerial })
    }

    // txs
    const nTx = d.readVarIntNum(); this.transactionLog = []
    for (let i = 0; i < nTx; i++) {
      const at = d.readVarIntNum()
      const txLen = d.readVarIntNum()
      const atomicBEEF = d.read(txLen)
      const net = d.readVarIntNum()
      const memoLen = d.readVarIntNum()
      const memo = Utils.toUTF8(d.read(memoLen))
      const processed = d.readVarIntNum() !== 0
      const txid = Transaction.fromAtomicBEEF(atomicBEEF).id('hex')
      this.transactionLog.push({ at, atomicBEEF, net, memo, processed, txid })
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

  /** Download a public-only “deposit slip” for a given key. */
  downloadDepositSlipTxt (serial: string): void {
    const key = this.keys.find(k => k.serial === serial)
    if (!key) throw new Error('Key not found.')
    if (key.usedOnChain) {
      const ok = window.confirm('WARNING: this key appears used on-chain. Continue to download deposit info?')
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

  private matchOurOutputs (tx: Transaction): Array<{ vout: number, lockHex: string, satoshis: number, serial: string }> {
    const results: Array<{ vout: number, lockHex: string, satoshis: number, serial: string }> = []
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
        if (key) results.push({ vout: i, lockHex: lock.toHex(), satoshis: out.satoshis as number, serial: key.serial })
      }
    }
    return results
  }

  /**
   * Process an incoming Atomic BEEF (no prompts). UI passes memos/accept flags.
   */
  async processIncoming (hex: string, opts?: {
    txMemo?: string
    /** If confirmIncomingCoins=true, per-UTXO acceptance flags keyed by vout */
    admit?: Record<number, boolean>
    /** Optional per-UTXO memos keyed by vout */
    perUtxoMemo?: Record<number, string>
  }): Promise<{ admitted: string[]; txid: string }> {
    const tx = Transaction.fromAtomicBEEF(Utils.toArray(hex, 'hex'))
    const txid = tx.id('hex') as string
    const matches = this.matchOurOutputs(tx)

    if (matches.length === 0) {
      this.logSession('incoming.no-match', txid)
      throw new Error('No outputs to this vault’s keys were found in that transaction.')
    }

    // SPV check
    let spvValid = false
    try { spvValid = await tx.verify(this) ?? false } catch { spvValid = false }
    if (!spvValid) {
      this.logSession('incoming.spv.fail', txid)
      throw new Error('SPV verification failed.')
    }

    const admitted: typeof matches = []
    for (const m of matches) {
      if (!this.confirmIncomingCoins) { admitted.push(m); continue }
      const ok = opts?.admit?.[m.vout] === true
      if (ok) admitted.push(m)
    }

    // Update coin set & mark key usage
    for (const m of admitted) {
      this.coins.push({ tx, outputIndex: m.vout, memo: opts?.perUtxoMemo?.[m.vout] || '', keySerial: m.serial })
      const k = this.keys.find(kk => kk.serial === m.serial); if (k) k.usedOnChain = true
    }

    const atomic = tx.toAtomicBEEF() as number[]
    const netIn = admitted.reduce((n, a) => n + a.satoshis, 0)
    this.transactionLog.push({
      at: Date.now(), atomicBEEF: atomic, net: netIn, memo: opts?.txMemo || '', processed: false, txid
    })
    this.logVault('incoming.accepted', `${txid}:${admitted.map(a => a.vout).join(',')}`)
    return { admitted: admitted.map(a => `${txid}:${a.vout}`), txid }
  }

  markProcessed (txid: string, processed: boolean): void {
    const t = this.transactionLog.find(t => t.txid === txid)
    if (t) {
      t.processed = processed
      this.logVault('tx.processed', `${txid}:${processed ? '1' : '0'}`)
    }
  }

  // -------------------------------------------------------------------------
  // Outgoing builder (no prompts). UI drives stipulation and selection.
  // -------------------------------------------------------------------------
  private parseOutputSpec (spec: OutgoingOutputSpec): { lockingScript: Script, satoshis: number, memo?: string } {
    const { dest, satoshis, memo } = spec
    assert(Number.isFinite(satoshis) && satoshis > 0, `Bad amount: ${satoshis}`)
    let lock: Script
    if (/^[0-9a-fA-F]{20,}$/.test(dest) && !/[O]/i.test(dest)) {
      lock = Script.fromHex(dest)
    } else {
      lock = new P2PKH().lock(dest)
    }
    return { lockingScript: lock, satoshis, memo }
  }

  private sumInputs (coins: CoinRecord[]): number {
    return coins.reduce((n, c) => n + (c.tx.outputs[c.outputIndex].satoshis as number), 0)
  }

  private sumExternalOutputs (tx: Transaction): number {
    // External outputs are those NOT marked as change
    return tx.outputs.reduce((n, o) => n + (!o.change ? (o.satoshis as number) : 0), 0)
  }

  /** Deterministic, safe coin selection. */
  private selectInputs (need: number, strategy: SelectionStrategy, candidates: CoinRecord[]): CoinRecord[] {
    const coins = [...candidates]
    if (strategy === 'largest-first') coins.sort((a, b) =>
      (b.tx.outputs[b.outputIndex].satoshis as number) - (a.tx.outputs[a.outputIndex].satoshis as number))
    else if (strategy === 'smallest-first') coins.sort((a, b) =>
      (a.tx.outputs[a.outputIndex].satoshis as number) - (b.tx.outputs[b.outputIndex].satoshis as number))
    else if (strategy === 'oldest-first') coins.sort((a, b) =>
      (a.tx.id('hex') as string).localeCompare(b.tx.id('hex') as string))

    const sel: CoinRecord[] = []
    let acc = 0
    for (const c of coins) {
      sel.push(c)
      acc += (c.tx.outputs[c.outputIndex].satoshis as number)
      if (acc >= need) break
    }
    if (acc < need) throw new Error(`Insufficient funds: need ${need} sats, selected ${acc} sats.`)
    return sel
  }

  /**
   * Build & sign an outgoing tx (no prompts).
   * Ensures funding by iteratively estimating fees and selecting additional UTXOs if required.
   */
  async buildAndSignOutgoing (opts: BuildOutgoingOptions): Promise<{ tx: Transaction, atomicBEEFHex: string, usedInputIds: string[], changeIds: string[] }> {
    assert(this.coins.length > 0, 'No spendable UTXOs.')
    const outputs = opts.outputs.map(o => this.parseOutputSpec(o))
    assert(outputs.length > 0, 'No outputs specified.')

    // Determine change keys
    let changeKeys: KeyRecord[] = []
    if (opts.changeKeySerials && opts.changeKeySerials.length > 0) {
      changeKeys = opts.changeKeySerials.map(s => {
        const k = this.keys.find(kk => kk.serial === s)
        if (!k) throw new Error(`Change key not found: ${s}`)
        return k
      })
    } else {
      // default: newest unused key or first key
      const unused = [...this.keys].filter(k => !k.usedOnChain)
      changeKeys = unused.length ? [unused[unused.length - 1]] : (this.keys.length ? [this.keys[0]] : [])
      if (changeKeys.length === 0) throw new Error('No keys available for change.')
    }

    // Candidate inputs (either explicit or from vault)
    let selected: CoinRecord[] = []
    if (opts.inputIds && opts.inputIds.length > 0) {
      const byId = new Map(this.coins.map(c => [coinId(c.tx, c.outputIndex), c] as const))
      selected = opts.inputIds.map(id => {
        const c = byId.get(id); if (!c) throw new Error(`Input not found: ${id}`); return c
      })
    }

    const strategy = opts.strategy || 'largest-first'
    const available = this.coins.filter(c => !selected.includes(c))

    // Iteratively build until funded
    const tx = new Transaction()
    // Add external outputs
    for (const o of outputs) tx.addOutput(o)

    // Always include at least one change output candidate
    const idxToKeySerial = new Map<number, string>()
    for (const k of changeKeys) {
      tx.addOutput({ lockingScript: new P2PKH().lock(k.public.toAddress()), change: true })
      idxToKeySerial.set(tx.outputs.length - 1, k.serial)
    }

    // Seed with any user-provided inputs
    for (const s of selected) {
      tx.addInput({
        sourceTransaction: s.tx,
        sourceOutputIndex: s.outputIndex,
        unlockingScriptTemplate: new P2PKH().unlock(this.keys.find(x => x.serial === s.keySerial)!.private)
      })
    }

    // Estimate & ensure coverage
    const ensureCoverage = () => {
      // Call fee estimator (the sdk mutates change values)
      tx.fee() // deterministic by sdk rules
      const inputSum = tx.inputs.reduce((n, i) => n + (i.sourceTransaction!.outputs[i.sourceOutputIndex!].satoshis as number), 0)
      const outputSum = tx.outputs.reduce((n, o) => n + (o.satoshis as number), 0)
      const delta = inputSum - outputSum
      return { funded: delta >= 0, deficit: Math.max(0, -delta) }
    }

    let { funded, deficit } = ensureCoverage()
    while (!funded) {
      // pick more inputs
      const need = deficit
      const add = this.selectInputs(need, strategy, available.filter(c => !selected.includes(c)))
      for (const s of add) {
        tx.addInput({
          sourceTransaction: s.tx,
          sourceOutputIndex: s.outputIndex,
          unlockingScriptTemplate: new P2PKH().unlock(this.keys.find(x => x.serial === s.keySerial)!.private)
        })
        selected.push(s)
      }
      const r = ensureCoverage(); funded = r.funded; deficit = r.deficit
    }

    // Optional outgoing attestation
    if (this.confirmOutgoingCoins && opts.perUtxoAttestation) {
      for (const s of selected) {
        const id = coinId(s.tx, s.outputIndex)
        const ok = window.confirm(`Attest UTXO is unspent on HONEST chain: ${id}\nAmount: ${s.tx.outputs[s.outputIndex].satoshis} sats`)
        if (!ok) throw new Error(`Outgoing attestation declined for ${id}.`)
      }
    }

    tx.sign()

    // Update coin set atomically: consume inputs, add change
    const txid = tx.id('hex') as string
    const selectedIds = new Set(selected.map(s => coinId(s.tx, s.outputIndex)))

    // remove spent
    this.coins = this.coins.filter(c => !selectedIds.has(coinId(c.tx, c.outputIndex)))

    // add change
    const changeIds: string[] = []
    tx.outputs.forEach((out: TransactionOutput, outputIndex: number) => {
      if (!out.change) return
      const ser = idxToKeySerial.get(outputIndex) as string
      this.coins.push({ tx, outputIndex, memo: 'change', keySerial: ser })
      changeIds.push(`${txid}:${outputIndex}`)
    })

    // Accurate net delta: (sum of inputs we own) - (sum of change back to us) - (fees) - (external outputs)
    const totalInputs = selected.reduce((a, e) => a + (e.tx.outputs[e.outputIndex].satoshis! as number), 0)
    const changeBack = tx.outputs.reduce((a, o) => a + (o.change ? (o.satoshis as number) : 0), 0)
    const external = this.sumExternalOutputs(tx)
    const fee = totalInputs - (changeBack + external)
    const net = -(external + fee) // negative outflow

    const atomic = Utils.toHex(tx.toAtomicBEEF() as number[])
    this.transactionLog.push({
      at: Date.now(),
      atomicBEEF: tx.toAtomicBEEF() as number[],
      net,
      memo: opts.txMemo || '',
      processed: false,
      txid
    })

    this.logVault('outgoing.signed', `txid=${txid} inputs=${selected.length} change=${changeIds.length} fee=${fee}`)
    return { tx, atomicBEEFHex: atomic, usedInputIds: [...selectedIds], changeIds }
  }

  // -------------------------------------------------------------------------
  // Session Log export (sanitized)
  // -------------------------------------------------------------------------
  exportSessionLog (): void {
    const redacted: AuditEvent[] = this.sessionLog.map(e => ({ at: e.at, event: e.event, data: e.data }))
    const blob = new Blob([JSON.stringify({
      vault: { name: this.vaultName, rev: this.vaultRevision },
      createdAt: this.created, lastUpdated: this.lastUpdated,
      sessionLog: redacted, vaultLog: this.vaultLog
    }, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `vault_session_${Date.now()}.json`; a.click()
    URL.revokeObjectURL(url)
  }
}

/**
 * ---------------------------------------------------------------------------
 * React UI (thin adapter): no business logic here.
 * ---------------------------------------------------------------------------
 */

export default function App () {
  const [vault, setVault] = useState<Vault | null>(null)
  const [lastSavedPlainHash, setLastSavedPlainHash] = useState<string | null>(null)
  const [banner, setBanner] = useState<string | null>(null)

  // Outgoing builder state
  const [outLines, setOutLines] = useState<string>('') // "<addr_or_hex> <sats> [memo]" per line
  const [manualInputs, setManualInputs] = useState<Record<string, boolean>>({})
  const [changeSerials, setChangeSerials] = useState<Record<string, boolean>>({})
  const [txMemo, setTxMemo] = useState<string>('')
  const [selectionStrategy, setSelectionStrategy] = useState<SelectionStrategy>('largest-first')
  const [requirePerUtxoAttestation, setRequirePerUtxoAttestation] = useState<boolean>(false)

  async function onOpenVault (file: File) {
    const buf = new Uint8Array(await file.arrayBuffer())
    const v = Vault.loadFromFile(Array.from(buf))
    setVault(v)
    setLastSavedPlainHash(v.computePlaintextHashHex())
  }

  async function onNewVault () {
    const v = await Vault.create()
    setVault(v)
    setLastSavedPlainHash(v.computePlaintextHashHex())
  }

  async function onSaveVault () {
    if (!vault) return
    await vault.downloadVaultFile()
    setLastSavedPlainHash(vault.computePlaintextHashHex())
  }

  // Deterministic “dirty” check – no encryption, no prompts
  useEffect(() => {
    if (!vault) { setBanner(null); return }
    try {
      const hh = vault.computePlaintextHashHex()
      const dirty = !lastSavedPlainHash || (hh !== lastSavedPlainHash)
      setBanner(dirty ? 'UNSAVED CHANGES — save new vault file, verify it, then delete the old one.' : null)
    } catch {
      // ignore
    }
  }, [vault, lastSavedPlainHash])

  const balance = useMemo(() => {
    if (!vault) return 0
    return vault.coins.reduce((n, c) => n + (c.tx.outputs[c.outputIndex].satoshis as number), 0)
  }, [vault])

  function refresh (mut?: (v: Vault) => void) {
    if (!vault) return
    if (mut) mut(vault)
    setVault(Object.assign(Object.create(Object.getPrototypeOf(vault)), vault))
  }

  // Helpers to parse the outgoing text area
  function parseOutgoingLines (): OutgoingOutputSpec[] {
    const lines = outLines.split('\n').map(s => s.trim()).filter(Boolean)
    return lines.map(line => {
      const parts = line.split(' ')
      const dest = parts[0]
      const sat = Number(parts[1])
      if (!Number.isFinite(sat) || sat <= 0) throw new Error(`Bad amount on line: ${line}`)
      const memo = parts.slice(2).join(' ')
      return { dest, satoshis: sat, memo }
    })
  }

  async function buildAndSign () {
    if (!vault) return
    try {
      const outputs = parseOutgoingLines()
      const selectedIds = Object.entries(manualInputs).filter(([_, on]) => on).map(([id]) => id)
      const change = Object.entries(changeSerials).filter(([_, on]) => on).map(([s]) => s)
      const { tx, atomicBEEFHex, usedInputIds, changeIds } = await vault.buildAndSignOutgoing({
        outputs,
        inputIds: selectedIds.length ? selectedIds : undefined,
        strategy: selectionStrategy,
        changeKeySerials: change.length ? change : undefined,
        perUtxoAttestation: requirePerUtxoAttestation,
        txMemo
      })

      // Offer Atomic-BEEF as .txt
      const blob = new Blob([atomicBEEFHex], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = `tx_${tx.id('hex')}.atomic-beef.txt`; a.click()
      URL.revokeObjectURL(url)

      setOutLines('')
      setManualInputs({})
      setTxMemo('')
      refresh()
      alert('Built & signed. Submit externally, then SAVE the vault.')
    } catch (e: any) {
      alert(e.message || String(e))
    }
  }

  if (!vault) {
    return (
      <div style={{ fontFamily: 'Inter, system-ui, sans-serif', padding: 16, maxWidth: 1100, margin: '0 auto' }}>
        <h1>BSV Vault Manager Suite</h1>
        <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
          <h2>Open / New</h2>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            <input type="file" accept=".vaultfile,application/octet-stream" onChange={e => e.target.files && onOpenVault(e.target.files[0])} />
            <button onClick={onNewVault}>Create New Vault</button>
          </div>
        </section>
        <p>Open an existing vault or create a new one.</p>
      </div>
    )
  }

  const utxoList = vault.coins.map(c => ({
    id: `${c.tx.id('hex')}:${c.outputIndex}`,
    sats: c.tx.outputs[c.outputIndex].satoshis as number,
    asm: c.tx.outputs[c.outputIndex].lockingScript.toASM(),
    memo: c.memo
  }))

  return (
    <div style={{ fontFamily: 'Inter, system-ui, sans-serif', padding: 16, maxWidth: 1100, margin: '0 auto' }}>
      <h1>BSV Vault Manager Suite</h1>

      {banner && (
        <div style={{ background: '#8b0000', color: 'white', padding: 12, marginBottom: 12, fontWeight: 700 }}>
          {banner}
        </div>
      )}

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Open / Save / Logs</h2>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <input type="file" accept=".vaultfile,application/octet-stream" onChange={e => e.target.files && onOpenVault(e.target.files[0])} />
          <button onClick={onSaveVault}>Save Vault</button>
          <button onClick={() => { vault.exportSessionLog() }}>Export Session Log (.json)</button>
          <div>Vault: <b>{vault.vaultName}</b> (rev {vault.vaultRevision})</div>
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Keys</h2>
        <div style={{ display: 'flex', gap: 12 }}>
          <button onClick={() => { const memo = prompt('Memo for this key (optional):') || ''; vault.generateKey(memo); refresh() }}>Generate Key</button>
        </div>
        <div style={{ marginTop: 12 }}>
          {vault.keys.map(k => (
            <div key={k.serial} style={{ borderTop: '1px solid #eee', padding: '8px 0' }}>
              <div><b>{k.serial}</b> {k.memo && `— ${k.memo}`} {k.usedOnChain ? <span style={{ color: '#b36' }}> (used)</span> : null}</div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={() => vault.downloadDepositSlipTxt(k.serial)}>Download deposit slip (.txt)</button>
                <span style={{ fontSize: 12, color: '#666' }}>PKH {k.public.toHash('hex')}</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Process Incoming Atomic BEEF</h2>
        <textarea placeholder="Paste Atomic BEEF hex..." rows={4} style={{ width: '100%' }} id="incoming-hex" />
        <div style={{ marginTop: 8, display: 'flex', gap: 8, alignItems: 'center' }}>
          <button onClick={async () => {
            const ta = document.getElementById('incoming-hex') as HTMLTextAreaElement
            const txMemo = prompt('Incoming tx memo (optional):') || ''
            // For attestation-per-UTXO, surface a small UI if needed. Here we admit all if policy disabled.
            try {
              const res = await vault.processIncoming(ta.value, { txMemo, admit: {}, perUtxoMemo: {} })
              ta.value = ''
              refresh()
              alert(`Incoming processed:\n${res.txid}\n“Your transaction is not processed until the new vault is saved.”`)
            } catch (e: any) {
              alert(e.message || String(e))
            }
          }}>Process</button>
          <div style={{ fontSize: 12 }}><i>“Your transaction is not processed until the new vault is saved.”</i></div>
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Build Outgoing</h2>

        <div style={{ marginBottom: 8, color: '#555', fontSize: 12 }}>
          Enter outputs, one per line:<br />
          <code>&lt;address_or_locking_script_hex&gt; &lt;satoshis&gt; [memo]</code>
        </div>
        <textarea rows={4} style={{ width: '100%' }} value={outLines} onChange={e => setOutLines(e.target.value)} placeholder={`1ABC... 546 tip\n76a914...88ac 1000 change`} />

        <div style={{ marginTop: 8, display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <label>Selection strategy:&nbsp;
            <select value={selectionStrategy} onChange={e => setSelectionStrategy(e.target.value as SelectionStrategy)}>
              <option value="largest-first">largest-first</option>
              <option value="smallest-first">smallest-first</option>
              <option value="oldest-first">oldest-first</option>
            </select>
          </label>
          <label><input type="checkbox" checked={requirePerUtxoAttestation} onChange={e => setRequirePerUtxoAttestation(e.target.checked)} /> Require per-UTXO attestation</label>
          <input placeholder="Outgoing memo (optional)" value={txMemo} onChange={e => setTxMemo(e.target.value)} />
        </div>

        <div style={{ marginTop: 12 }}>
          <b>Manual Input Selection (optional)</b>
          {utxoList.length === 0 && <div>No spendable UTXOs</div>}
          {utxoList.map(u => (
            <div key={u.id} style={{ borderTop: '1px solid #eee', padding: '6px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
              <label>
                <input
                  type="checkbox"
                  checked={!!manualInputs[u.id]}
                  onChange={e => setManualInputs(prev => ({ ...prev, [u.id]: e.target.checked }))}
                /> {u.id} — {u.sats} sats — {u.asm.replace(/\s+/g, ' ')}
              </label>
              {u.memo && <span style={{ fontSize: 12, color: '#666' }}>Memo: {u.memo}</span>}
            </div>
          ))}
        </div>

        <div style={{ marginTop: 12 }}>
          <b>Change Keys</b>
          {vault.keys.map(k => (
            <div key={k.serial} style={{ borderTop: '1px solid #eee', padding: '6px 0' }}>
              <label>
                <input
                  type="checkbox"
                  checked={!!changeSerials[k.serial]}
                  onChange={e => setChangeSerials(prev => ({ ...prev, [k.serial]: e.target.checked }))}
                /> {k.serial} {k.memo && `— ${k.memo}`} {k.usedOnChain ? <span style={{ color: '#b36' }}> (used)</span> : null}
              </label>
            </div>
          ))}
        </div>

        <div style={{ marginTop: 12 }}>
          <button onClick={buildAndSign}>Finalize &amp; Sign</button>
        </div>

        <div style={{ marginTop: 8, color: '#555', fontSize: 12 }}>
          After signing: UTXOs are updated (inputs consumed; change added), TX stored, Atomic BEEF offered as .txt. Then <b>save the new vault</b>.
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Transactions</h2>
        <div>Total balance: <b>{balance}</b> sats</div>
        <div style={{ marginTop: 8 }}>
          {vault.transactionLog.map(t => (
            <div key={t.txid} style={{ borderTop: '1px solid #eee', padding: '8px 0' }}>
              <div><b>{t.txid}</b></div>
              {t.memo && <div>Memo: {t.memo}</div>}
              <div style={{ fontSize: 12, color: '#666' }}>
                Net: {t.net} sats {t.net >= 0 ? '(incoming)' : '(outgoing)'}
              </div>
              <div style={{ marginTop: 6 }}>
                <label>
                  <input
                    type="checkbox"
                    checked={t.processed}
                    onChange={e => { vault.markProcessed(t.txid, e.target.checked); refresh() }}
                  /> Mark processed
                </label>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Current UTXOs</h2>
        {vault.coins.length === 0 && <div>No spendable coins</div>}
        {vault.coins.map(c => {
          const out = c.tx.outputs[c.outputIndex]
          const id = `${c.tx.id('hex')}:${c.outputIndex}`
          const asm = out.lockingScript.toASM()
          return (
            <div key={id} style={{ borderTop: '1px solid #eee', padding: '8px 0' }}>
              <div><b>{id}</b> — {out.satoshis} sats — {asm.replace(/\s+/g, ' ')}</div>
              {c.memo && <div>Memo: {c.memo}</div>}
            </div>
          )
        })}
      </section>
    </div>
  )
}
