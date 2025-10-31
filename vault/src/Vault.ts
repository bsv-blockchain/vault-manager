import {
  PrivateKey, P2PKH, Script, Transaction, PublicKey, ChainTracker,
  Utils, Hash, SymmetricKey, Random, TransactionOutput, Beef
} from '@bsv/sdk'

import {
  UiBridge, UnixMs, AuditEvent, KeyRecord, CoinRecord, TxLogRecord,
  PersistedHeaderClaim, EphemeralHeaderClaim, OutgoingOutputSpec,
  MatchedOutput, IncomingPreview, BuildOutgoingOptions, CreateVaultOptions
} from './types'
import {
  requireIntegerString, validatePassword, validatePBKDF2Rounds, validateMemo
} from './validators'
import { assert, coinIdStr, getTxFromStore } from './utils'

/**
 * =============================================================================
 * Vault class
 * - Implements ChainTracker.
 * - Holds derived encryption key (NOT the password).
 * - Maintains a global vault-wide BEEF store.
 * =============================================================================
 */

export class Vault implements ChainTracker {
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
  lastLoadedFileHash: string | null = null
  lastKnownFileName: string | null = null

  // -------------------------------------------------------------------------
  // Randomness Wizard & Helpers
  // -------------------------------------------------------------------------
  private async getRandomBytes(n: number): Promise<number[]> {
    // Always include device entropy
    const dev = Random(Math.max(32, n))
    if (!this.useUserEntropyForRandom || !this.ui.gatherEntropy) {
      this.logSession('random.bytes', `n=${n} userEntropy=0`)
      return dev.slice(0, n)
    }

    let userBytes: number[] = []
    try {
      userBytes = await this.ui.gatherEntropy({ size: Math.max(64, n) })
    } catch {
      this.logSession('random.bytes', `n=${n} userEntropyCancelled=1`)
      return dev.slice(0, n)
    }
    if (!userBytes.length) {
      this.logSession('random.bytes', `n=${n} userEntropy=0`)
      return dev.slice(0, n)
    }

    const userHash = Hash.sha256(userBytes) // 32 bytes
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
    const mixed = out.slice(0, n).map((b, i) => b ^ dev[i % dev.length])
    this.logSession('random.bytes', `n=${n} userEntropy=1 events=${userBytes.length}`)
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
      { title: 'Confirm Merkle Root' }
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

  private recordCurrentHeight(height: number) {
    assert(Number.isInteger(height) && height > 0, 'Block height must be a positive integer.')
    this.currentBlockHeight = height
    this.currentBlockHeightAcquiredAt = Date.now()
    this.logVault('chain.height.set', String(height))
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
    this.recordCurrentHeight(height)
    return height
  }

  // -------------------------------------------------------------------------
  // Creation / Loading / Saving (no re-prompt once key is set)
  // -------------------------------------------------------------------------
  static async create (ui: UiBridge, opts: CreateVaultOptions): Promise<Vault> {
    const v = new Vault(ui)
    v.logSession('wizard.start', 'create')

    v.vaultName = opts.name.trim() || 'Vault'
    v.logVault('vault.created', v.vaultName)

    v.passwordRounds = opts.passwordRounds
    v.persistHeadersOlderThanBlocks = opts.persistHeadersOlderThanBlocks
    v.reverifyRecentHeadersAfterSeconds = opts.reverifyRecentHeadersAfterSeconds
    v.reverifyCurrentBlockHeightAfterSeconds = opts.reverifyCurrentBlockHeightAfterSeconds
    v.useUserEntropyForRandom = opts.useUserEntropyForRandom
    v.confirmIncomingCoins = opts.confirmIncomingCoins
    v.confirmOutgoingCoins = opts.confirmOutgoingCoins

    v.passwordSalt = await v.getRandomBytes(32)
    v.logKV('vault', 'passwordRounds', String(v.passwordRounds))
    v.logKV('vault', 'passwordSalt.len', String(v.passwordSalt.length))

    const keyBytes = Hash.pbkdf2(Utils.toArray(opts.password), v.passwordSalt, v.passwordRounds, 32)
    v.encryptionKey = new SymmetricKey(keyBytes)
    v.logVault('vault.key.derived', `klen=${keyBytes.length}`)

    v.logKV('vault', 'confirmIncomingCoins', String(v.confirmIncomingCoins))
    v.logKV('vault', 'confirmOutgoingCoins', String(v.confirmOutgoingCoins))

    v.recordCurrentHeight(opts.initialBlockHeight)
    v.logSession('wizard.complete', 'create')
    return v
  }

  static async loadFromFile (ui: UiBridge, file: number[], opts?: { fileName?: string }): Promise<Vault> {
    const v = new Vault(ui)
    v.logSession('vault.load.start', `size=${file.length}`)

    const fileHash = Utils.toHex(Hash.sha256(file))
    v.logSession('vault.load.hash', fileHash)
    v.lastLoadedFileHash = fileHash
    v.lastKnownFileName = opts?.fileName || null

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

  /** Deterministic plaintext hash (for "unsaved changes" banner). */
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

  async updateKeyMemo(serial: string, memo: string): Promise<void> {
    const key = this.keys.find(k => k.serial === serial)
    if (!key) throw new Error('Key not found.')
    const cleaned = memo.trim()
    const valid = validateMemo(cleaned, 'Memo', 256)
    if (valid !== true) throw new Error(typeof valid === 'string' ? valid : 'Invalid memo.')
    key.memo = cleaned
    this.logVault('key.memo.updated', `${serial}:${cleaned}`)
  }

  async downloadDepositSlipTxt (serial: string): Promise<void> {
    const key = this.keys.find(k => k.serial === serial)
    if (!key) throw new Error('Key not found.')
    if (key.usedOnChain) {
      const ok = await this.ui.confirm('WARNING: this key appears used on-chain. Continue to download deposit info?', { title: 'Used Key Warning' })
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
    for (const k of this.keys) byPkh.set(k.public.toHash('hex') as string, k)

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
      throw new Error('No outputs to this vault\'s keys were found in that transaction.')
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
    admit?: Record<number, boolean>
    perUtxoMemo: Record<number, string>
    processed?: boolean
  }): Promise<{ admitted: string[]; txid: string }> {
    const txid = tx.id('hex') as string
    const allMatches = this.matchOurOutputs(tx)

    const admitted: typeof allMatches = []
    for (const m of allMatches) {
      const shouldAdmit = opts.admit
        ? opts.admit[m.outputIndex] !== false
        : true
      const ok = shouldAdmit === true
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
    return { tx, atomicBEEFHex: atomic, usedInputIds: Array.from(selectedIds), changeIds }
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

export default Vault
