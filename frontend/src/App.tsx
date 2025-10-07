import { useEffect, useMemo, useRef, useState } from 'react'
import { PrivateKey, P2PKH, Script, Transaction, PublicKey, ChainTracker, MerklePath, Utils, Hash, SymmetricKey, Random } from '@bsv/sdk'

class Vault implements ChainTracker {
  protocolVersion: number = 1
  passwordRounds: number = 80085
  passwordSalt: number[] = new Array(32).fill(0)
  vaultName: string = 'Vault'
  vaultRevision: number = 1
  created: number = Date.now()
  lastUpdated: number = Date.now()
  keys: Array<{
    serial: string
    private: PrivateKey
    public: PublicKey
    usedOnChain: boolean
    memo: string
  }> = []
  coins: Array<{
    tx: Transaction
    outputIndex: number
    memo: string
  }> = []
  transactionLog: Array<{
    at: number
    atomicBEEF: number[]
    net: number
    memo: string
    processed: boolean
    txid: string
  }> = []
  vaultLog: Array<{
    at: number
    event: string
    data: string
  }> = []
  confirmIncomingCoins = true
  confirmOutgoingCoins = false
  persistHeadersOlderThanBlocks: number = 144
  reverifyRecentHeadersAfterSeconds: number = 60
  reverifyCurrentBlockHeightAfterSeconds: number = 600
  persistedHeaderClaims: Array<{
    at: number
    merkleRoot: string
    height: number
    memo: string
  }> = []
  ephemeralHeaderClaims: Array<{
    at: number
    merkleRoot: string
    height: number
  }> = []
  currentBlockHeight: number = 0
  currentBlockHeightAcquiredAt: number = 0
  saved = false
  sessionLog: Array<{
    at: number
    event: string
  }> = []
  async isValidRootForHeight (root: string, height: number): Promise<boolean> {
    const persisted = this.persistedHeaderClaims.findIndex(claim => {
      return claim.merkleRoot === root && claim.height === height
    })
    if (persisted !== -1) {
      return true
    }
    const ephemeral = this.ephemeralHeaderClaims.findIndex(claim => {
      return claim.merkleRoot === root
        && claim.height === height
        && Date.now() - this.reverifyRecentHeadersAfterSeconds < claim.at
    })
    if (ephemeral !== -1) {
      return true
    }
    const accepted = window.confirm(`Do you accept and confirm that block # ${height} of the HONEST chain has a merkle root of "${root}"?`)
    if (!accepted) return false
    if (this.currentBlockHeight - this.persistHeadersOlderThanBlocks < height) {
      this.ephemeralHeaderClaims.push({
        at: Date.now(),
        height,
        merkleRoot: root
      })
    } else {
      let memo = window.prompt('Enter the source(s) you used to confirm the validity of this merkle root:')
      if (!memo) {
        memo = 'No memo provided.'
      }
      this.persistedHeaderClaims.push({
        at: Date.now(),
        memo,
        height,
        merkleRoot: root
      })
    }
    return true
  }
  async currentHeight (): Promise<number> {
    if (
      this.currentBlockHeight !== 0
      && Date.now() - (this.reverifyCurrentBlockHeightAfterSeconds * 1000) < this.currentBlockHeightAcquiredAt
    ) {
      return this.currentBlockHeight
    } else {
      let height: number = 0
      do {
        try {
          const heightInput = window.prompt('Enter the current block height for the HONEST chain:')
          const heightNumber = Number(heightInput)
          if (Number.isInteger(heightNumber) && heightNumber > 0) {
            height = heightNumber
          } else {
            window.alert('Height must be a positive integer, try again.')
          }
        } catch (e) {
          window.alert((e as any).message || 'Error processing height, try again.')
        }
      } while (height === 0)
      this.currentBlockHeight = height
      this.currentBlockHeightAcquiredAt = Date.now()
      return height
    }
  }
  logSession (event: string): void {
    this.sessionLog.push({
      at: Date.now(),
      event
    })
  }
  logVault (event: string, data: string = ''): void {
    this.vaultLog.push({
      at: Date.now(),
      event,
      data
    })
  }
  static loadFromFile (file: number[]): Vault {
    const v = new Vault()
    v.logSession(`Started new vault session loading from vault file of size ${file.length} ...`)
    const fileHash = Utils.toHex(Hash.sha256(file))
    v.logSession(`SHA-256 hash of vault file: ${fileHash}`)
    v.logSession('Verifying this hash with the user...')
    const hashVerified = window.confirm(`Ensure that the SHA-256 hash of your vault file from the previous session matches this value: ${fileHash}`)
    if (!hashVerified) {
      throw new Error('Vault file SHA-256 has not been verified.')
    }
    v.logSession('The SHA-256 hash has been verified by the user.')
    const r = new Utils.Reader(file)
    // Read vault protocol version
    const protocolVersion = r.readVarIntNum()
    if (protocolVersion !== v.protocolVersion) {
      throw new Error(`Vault protocol version # ${protocolVersion} from the file is not the same as this software, which uses version # ${v.protocolVersion}.`)
    }
    v.logSession(`Tbe software has found the vault protocol version to be correct. The vault uses protocol version # ${protocolVersion}`)

    // Read password rounds
    const passwordRounds = r.readVarIntNum()
    if (passwordRounds < 1) {
      throw new Error('Vault password rounds must be 1 or higher.')
    }
    v.passwordRounds = passwordRounds
    
    // Read password salt
    const passwordSalt = r.read(32)
    const encryptedVaultData = r.read()
    v.logSession('Read password rounds and salt, prompting for the password...')

    // Acquire password loop
    let decrypted: number[] = []
    do {
      const passwordString = window.prompt('Enter vault password:')
      const password = Utils.toArray(passwordString)
      const key = Hash.pbkdf2(password, passwordSalt, passwordRounds, 32)
      const symmetricKey = new SymmetricKey(key)
      try {
        decrypted = symmetricKey.decrypt(encryptedVaultData) as number[]
        v.logSession('Provided password succeeded in unlocking the vault.')
      } catch {
        v.logSession('Provided password failed to unlock the vault.')
        window.alert('Failed to unlock the vault.')
      }
    } while (decrypted.length === 0)
    
    // deserialize decrypted vault payload
    const d = new Utils.Reader(decrypted)

    // Read vault name
    const vaultNameLength = d.readVarIntNum()
    v.vaultName = Utils.toUTF8(d.read(vaultNameLength))
    v.logSession(`Vault name read: ${v.vaultName}`)

    // Read vault revision
    v.vaultRevision = d.readVarIntNum()
    v.logSession(`Vault revision read: ${v.vaultRevision}`)

    // Read created / updated timestamps
    v.created = d.readVarIntNum()
    v.logSession(`Vault creation time read: ${v.created}`)
    v.lastUpdated = d.readVarIntNum()
    v.logSession(`Vault last updated: ${v.lastUpdated}`)

    // read keys
    const numberOfKeys = d.readVarIntNum()
    v.logSession(`Loading ${numberOfKeys} ${numberOfKeys === 1 ? 'key' : 'keys'} from the vault.`)
    for (let i = 0; i < numberOfKeys; i++) {
      const serialLength = d.readVarIntNum()
      const serial = Utils.toUTF8(d.read(serialLength))
      const privateKey = new PrivateKey(d.read(32))
      const publicKey = privateKey.toPublicKey()
      const usedOnChain = d.readVarIntNum() !== 0
      const memoLength = d.readVarIntNum()
      const memo = Utils.toUTF8(d.read(memoLength))
      v.keys.push({
        serial,
        private: privateKey,
        public: publicKey,
        usedOnChain,
        memo
      })
    }

    // read coins
    const numberOfCoins = d.readVarIntNum()
    v.logSession(`Loading ${numberOfCoins} ${numberOfCoins === 1 ? 'coin' : 'coins'} from the vault.`)
    for (let i = 0; i < numberOfCoins; i++) {
      const txLength = d.readVarIntNum()
      const tx = Transaction.fromAtomicBEEF(d.read(txLength))
      const outputIndex = d.readVarIntNum()
      const memoLength = d.readVarIntNum()
      const memo = Utils.toUTF8(d.read(memoLength))
      v.coins.push({
        tx,
        outputIndex,
        memo
      })
    }

    // read transactions
    const numberOfTxs = d.readVarIntNum()
    for (let i = 0; i < numberOfTxs; i++) {
      const at = d.readVarIntNum()
      const txLength = d.readVarIntNum()
      const atomicBEEF = d.read(txLength)
      const net = d.readVarIntNum()
      const memoLength = d.readVarIntNum()
      const memo = Utils.toUTF8(d.read(memoLength))
      const processed = d.readVarIntNum() !== 0
      v.transactionLog.push({
        at,
        atomicBEEF,
        net,
        memo,
        processed,
        txid: Transaction.fromAtomicBEEF(atomicBEEF).id('hex')
      })
    }

    // vault log
    const numberOfVaultLogs = d.readVarIntNum()
    for (let i = 0; i < numberOfVaultLogs; i++) {
      const at = d.readVarIntNum()
      const eventLength = d.readVarIntNum()
      const event = Utils.toUTF8(d.read(eventLength))
      const dataLength = d.readVarIntNum()
      const data = Utils.toUTF8(d.read(dataLength))
      v.vaultLog.push({
        at,
        event,
        data
      })
    }

    // Read settings
    v.confirmIncomingCoins = d.readVarIntNum() !== 0
    v.confirmOutgoingCoins = d.readVarIntNum() !== 0
    v.persistHeadersOlderThanBlocks = d.readVarIntNum()
    v.reverifyRecentHeadersAfterSeconds = d.readVarIntNum()
    v.reverifyCurrentBlockHeightAfterSeconds = d.readVarIntNum()

    // Read persisted headres
    const numberOfPersistedHeaderClaims = d.readVarIntNum()
    for (let i = 0; i < numberOfPersistedHeaderClaims; i++) {
      const at = d.readVarIntNum()
      const merkleRootLength = d.readVarIntNum()
      const merkleRoot = Utils.toUTF8(d.read(merkleRootLength))
      const height = d.readVarIntNum()
      const memoLength = d.readVarIntNum()
      const memo = Utils.toUTF8(d.read(memoLength))
      v.persistedHeaderClaims.push({
        at,
        merkleRoot,
        height,
        memo
      })
    }

    v.logSession(`Vault successfully loaded.`)

    return v
  }

  static async create (): Promise<Vault> {
    const v = new Vault()
    v.logSession('Creating new vault interactively...')

    const name = window.prompt('Enter a vault display name:') || 'Vault'
    v.vaultName = name
    v.logSession(`Creating vault interactively with name: ${name}`)
    v.logVault('Vault created: vault.name', name)

    // PBKDF2 rounds
    const roundsIn = window.prompt(`PBKDF2 rounds? (default ${v.passwordRounds})`)
    if (roundsIn && /^\d+$/.test(roundsIn)) {
      const n = Number(roundsIn)
      if (n >= 1) v.passwordRounds = n
    }
    v.passwordSalt = Random(32)
    v.logVault('vault.passwordRounds', v.passwordRounds.toString())
    v.logVault('vault.passwordSalt', Utils.toHex(v.passwordSalt))

    // policy toggles
    v.confirmIncomingCoins = window.confirm('Require attestation for incoming UTXOs? (OK = yes)')
    v.confirmOutgoingCoins = window.confirm('Require attestation for outgoing UTXOs at build-time? (OK = yes)')
    v.logVault('vault.confirmIncomingCoins', v.confirmIncomingCoins.toString())
    v.logVault('vault.confirmOutgoingCoins', v.confirmOutgoingCoins.toString())

    // header settings
    const older = window.prompt(`Persist headers older than how many blocks? (default ${v.persistHeadersOlderThanBlocks})`)
    if (older && /^\d+$/.test(older)) v.persistHeadersOlderThanBlocks = Number(older)
    v.logVault('vault......') // TODO: Log every change to every value in the vault log and session log in a forensic and meticulous way, leaving nothing out.

    const recentSec = window.prompt(`Re-verify recent headers after how many seconds? (default ${v.reverifyRecentHeadersAfterSeconds})`)
    if (recentSec && /^\d+$/.test(recentSec)) v.reverifyRecentHeadersAfterSeconds = Number(recentSec)

    const heightSec = window.prompt(`Re-verify current block height after how many seconds? (default ${v.reverifyCurrentBlockHeightAfterSeconds})`)
    if (heightSec && /^\d+$/.test(heightSec)) v.reverifyCurrentBlockHeightAfterSeconds = Number(heightSec)

    v.logSession('Vault setup wizard completed.')

    window.alert('Vault created. Generate at least one key to receive funds and begin transacting.')
    return v
  }

  private serializePlaintext (): number[] {
    const w = new Utils.Writer()

    // vault name
    w.writeVarIntNum(Utils.lengthBytes(this.vaultName))
    w.write(Utils.toArray(this.vaultName))
    // vault revision
    w.writeVarIntNum(this.vaultRevision)
    // created / updated
    w.writeVarIntNum(this.created)
    w.writeVarIntNum(this.lastUpdated)

    // keys
    w.writeVarIntNum(this.keys.length)
    for (const k of this.keys) {
      const serialBytes = Utils.toArray(k.serial)
      w.writeVarIntNum(serialBytes.length); w.write(serialBytes)
      w.write(k.private.toArray()) // 32B
      w.writeVarIntNum(k.usedOnChain ? 1 : 0)
      const memoBytes = Utils.toArray(k.memo || '')
      w.writeVarIntNum(memoBytes.length); w.write(memoBytes)
    }

    // coins
    w.writeVarIntNum(this.coins.length)
    for (const c of this.coins) {
      const beef = c.tx.toAtomicBEEF() as number[]
      w.writeVarIntNum(beef.length); w.write(beef)
      w.writeVarIntNum(c.outputIndex)
      const memoBytes = Utils.toArray(c.memo || '')
      w.writeVarIntNum(memoBytes.length); w.write(memoBytes)
    }

    // transactions
    w.writeVarIntNum(this.transactionLog.length)
    for (const t of this.transactionLog) {
      w.writeVarIntNum(t.at)
      w.writeVarIntNum(t.atomicBEEF.length); w.write(t.atomicBEEF)
      w.writeVarIntNum(t.net)
      const memoBytes = Utils.toArray(t.memo || '')
      w.writeVarIntNum(memoBytes.length); w.write(memoBytes)
      w.writeVarIntNum(t.processed ? 1 : 0)
    }

    // vault log
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

  async saveToFileBytes (password?: string): Promise<number[]> {
    // choose password
    let pw = password
    if (!pw) {
      pw = window.prompt('Enter a password to encrypt this vault file:') || ''
      if (!pw) throw new Error('Password required to save vault.')
    }
    // derive key
    const key = Hash.pbkdf2(Utils.toArray(pw), this.passwordSalt, this.passwordRounds, 32)
    const symmetricKey = new SymmetricKey(key)
    const payload = this.serializePlaintext()
    const encrypted = symmetricKey.encrypt(payload) as number[]

    const writer = new Utils.Writer()
    writer.writeVarIntNum(this.protocolVersion)
    writer.writeVarIntNum(this.passwordRounds)
    writer.write(this.passwordSalt) // 32 bytes
    writer.write(encrypted)
    const fileBytes = writer.toArray() as number[]

    this.saved = true
    this.logVault('vault.saved', `bytes=${fileBytes.length}`)
    return fileBytes
  }

  async downloadVaultFile (password?: string): Promise<void> {
    const bytes = await this.saveToFileBytes(password)
    const hashHex = Utils.toHex(Hash.sha256(bytes))
    const blob = new Blob([new Uint8Array(bytes)], { type: 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${this.vaultName.replace(/\s+/g, '_')}_${Date.now()}.vaultfile`
    a.click()
    URL.revokeObjectURL(url)
    window.alert(
      `Vault file downloaded.\n\nSHA-256 (hex):\n${hashHex}\n\nVerify and store safely. Delete any old vault file versions.`
    )
  }

  private nextSerial (): string {
    // Simple serial: K0001, K0002, ...
    const n = this.keys.length + 1
    return `K${String(n).padStart(4, '0')}`
  }

  generateKeyInteractive () {
    const memo = window.prompt('Memo for this key (optional):') || ''
    const priv = PrivateKey.fromRandom()
    const rec = {
      serial: this.nextSerial(),
      private: priv,
      public: priv.toPublicKey(),
      usedOnChain: false,
      memo
    }
    this.keys.push(rec)
    this.logVault('key.generated', rec.serial)
    return rec
  }

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
P2PKH Script:  ${new P2PKH().lock(key.public.toDER()).toHex()}
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
    const a = document.createElement('a')
    a.href = url
    a.download = `deposit_${key.serial}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  private matchOurOutputs (tx: Transaction): Array<{ vout: number, lockHex: string, satoshis: number, serial: string }> {
    const results: Array<{ vout: number, lockHex: string, satoshis: number, serial: string }> = []
    const byPkh = new Map()
    for (const k of this.keys) {
      const pkhHex = k.public.toHash('hex')
      byPkh.set(pkhHex, k)
    }

    for (let i = 0; i < tx.outputs.length; i++) {
      const out = tx.outputs[i]
      const lock = out.lockingScript
      const hex = lock.toHex()
      const asm = lock.toASM()
      // P2PKH pattern
      let m = asm.match(/^OP_DUP OP_HASH160 ([0-9a-fA-F]{40}) OP_EQUALVERIFY OP_CHECKSIG$/)
      if (m) {
        const pkh = m[1].toLowerCase()
        const key = byPkh.get(pkh)
        if (key) results.push({ vout: i, lockHex: hex, satoshis: out.satoshis as number, serial: key.serial })
      }
    }
    return results
  }

  async processIncomingInteractive (hex: string): Promise<void> {
    let memo = window.prompt('Incoming transaction memo (optional):') || ''
    const tx = Transaction.fromAtomicBEEF(Utils.toArray(hex, 'hex'))
    const txid = tx.id('hex') as string

    const matches = this.matchOurOutputs(tx)
    if (matches.length === 0) {
      window.alert('No outputs to this vault’s keys were found in that transaction.')
    }

    // Check SPV validity
    let spvValid = false
    try {
      spvValid = await tx.verify(this) ?? false
    } catch {
      spvValid = false
    }
    if (!spvValid) {
      window.alert('SPV verification failed.')
      return
    }

    // optional per-UTXO attestation
    const admit: typeof matches = []
    for (const m of matches) {
      if (!this.confirmIncomingCoins) { admit.push(m); continue }
      const ok = window.confirm(
        `Admit UTXO ${txid}:${m.vout} (${m.satoshis} sats) to key [${m.serial}]?\n\n` +
        `Locking script (hex):\n${m.lockHex}\n\n` +
        `Attest that this is currently unspent on the honest chain.`
      )
      if (ok) admit.push(m)
    }

    // save coins + tx log
    for (const m of admit) {
      this.coins.push({ tx, outputIndex: m.vout, memo: '' })
      const k = this.keys.find(kk => kk.serial === m.serial); if (k) k.usedOnChain = true
    }

    const atomic = tx.toAtomicBEEF() as number[]
    const net = matches.reduce((n, m) => n + m.satoshis, 0) // simplistic net-in; TODO: adjust to compensate for true delta (in case any vault coins were inputs.....)
    this.transactionLog.push({
      at: Date.now(),
      atomicBEEF: atomic,
      net,
      memo,
      processed: false,
      txid
    })
    this.logVault('incoming.accepted', `${txid}:${admit.map(a=>a.vout).join(',')}`)

    window.alert('Incoming processed.\n“Your transaction is not processed until the new vault is saved.”')
  }

  markProcessed (txid: string, processed: boolean): void {
    const t = this.transactionLog.find(t => t.txid === txid)
    if (t) {
      t.processed = processed
      this.logVault('tx.processed', `${txid}:${processed ? '1' : '0'}`)
    }
  }

  async buildAndSignOutgoingInteractive (): Promise<{ tx: Transaction, atomicBEEF: string }> {
    // gather outputs
    const outLines = window.prompt(
      'Enter outputs, one per line:\n"<address_or_locking_script_hex> <satoshis> [memo]"\n\n' +
      'Example:\n1ABC... 546 memo to tip jar\n76a914...88ac 1000 change\n'
    )
    if (!outLines) throw new Error('No outputs provided.')
    const dests = outLines.split('\n').map(s => s.trim()).filter(Boolean)

    // parse outputs
    const outputs: { lockingScript: Script, satoshis: number, memo?: string }[] = []
    for (const line of dests) {
      const parts = line.split(' ')
      const dest = parts[0]
      const sat = Number(parts[1])
      if (!Number.isFinite(sat) || sat <= 0) throw new Error(`Bad amount on line: ${line}`)
      const memo = parts.slice(2).join(' ')

      let lock: Script
      if (/^[0-9a-fA-F]{20,}$/.test(dest) && !/[O]/i.test(dest)) {
        // Treat as script hex if it looks hexy enough
        lock = Script.fromHex(dest)
      } else {
        // Treat as address
        lock = new P2PKH().lock(dest)
      }
      outputs.push({ lockingScript: lock, satoshis: sat, memo })
    }

    // select inputs
    const utxos = this.coins
    if (utxos.length === 0) throw new Error('No spendable UTXOs available.')
    const list = utxos.map((u, i) => `${i}. ${u.tx.id('hex')}:${u.outputIndex} — ${u.tx.outputs[u.outputIndex].satoshis} sats`).join('\n')
    const chosen = window.prompt(
      `Select inputs by comma-separated indices:\n${list}\n\nExample: 0,2,3`
    )
    if (!chosen) throw new Error('No inputs selected.')
    const idxs = chosen.split(',').map(s => Number(s.trim())).filter(n => Number.isInteger(n) && n >= 0 && n < utxos.length)
    if (idxs.length === 0) throw new Error('No valid indices.')

    const selected = idxs.map(i => utxos[i])

    // optional attest outgoing
    if (this.confirmOutgoingCoins) {
      const ok = window.confirm('Do you attest that these selected UTXOs are currently unspent and spendable on the HONEST chain?')
      if (!ok) throw new Error('Outgoing attestation declined.')
    }

    // change keys
    const keyList = this.keys.map((k, i) => `${i}. ${k.serial}${k.memo ? ' — ' + k.memo : ''}`).join('\n')
    const changeSel = window.prompt(
      `Select change keys by indices (one or more, comma separated):\n${keyList}\n\nExample: 0`
    )
    if (!changeSel) throw new Error('No change key selected.')
    const cidx = changeSel.split(',').map(s => Number(s.trim())).filter(n => Number.isInteger(n) && n >= 0 && n < this.keys.length)
    if (cidx.length === 0) throw new Error('No valid change key indices.')
    const changeKeys = cidx.map(i => this.keys[i])

    // memo
    const txMemo = window.prompt('Outgoing transaction memo (optional):') || ''

    // Build inputs
    const inputs = selected.map(u => {
      // P2PKH unlocking template generally requires (privKey, sighashType, forkId?, satoshis, sourceLockingScript)
      // The exact signature may vary with @bsv/sdk version; adjust if your build differs.
      const sourceLock = Script.fromHex(u.lockHex)

      const unlockingTemplate =
        u.kind === 'p2pkh'
          ? new P2PKH().unlock(u.key.private, 'all', false, u.satoshis, sourceLock)
          : undefined // For P2PK, you would provide an appropriate ScriptTemplate that does <sig> for <pubkey>.

      return {
        sourceTXID: u.txid,
        sourceOutputIndex: u.vout,
        sourceSatoshis: u.satoshis,
        sourceLockingScript: sourceLock,
        unlockingScriptTemplate: unlockingTemplate
      }
    })

    // Build outputs, append change placeholders (we let fee engine size it)
    const tx = new Transaction(1, inputs as any, outputs as any)

    // Add change outputs (basic: one change output to first change key if any balance left after fee)
    // Many SDKs have an automatic fee/change apportioner; otherwise you balance manually.
    // If manual: compute totalIn - totalOut - fee, then add change if > dust.
    // Here we assume a simple sat/byte fee (fallback 0.5 sat/byte if not available).
    let totalIn = selected.reduce((n, u) => n + u.satoshis, 0)
    let totalOut = outputs.reduce((n, o) => n + o.satoshis, 0)
    let fee = Math.ceil((tx.toArray?.()?.length || 200) * 0.5) // rough estimate
    let change = totalIn - totalOut - fee
    const dust = 546

    // distribute change across selected change keys evenly (rounding to sats)
    if (change > dust) {
      const per = Math.floor(change / changeKeys.length)
      const rem = change - per * changeKeys.length
      for (let i = 0; i < changeKeys.length; i++) {
        const k = changeKeys[i]
        const pkhHex = Utils.toHex(Hash.ripemd160(Hash.sha256(k.public.toArray())))
        const lock = Script.fromHex(`76a914${pkhHex}88ac`)
        const amt = per + (i === 0 ? rem : 0)
        if (amt >= dust) {
          (tx.outputs as any).push({ lockingScript: lock, satoshis: amt, change: true })
        }
      }
      totalOut += change // for accounting
    } else {
      // If change below dust, just add it to fee.
      fee += change
      change = 0
    }

    // Sign (some SDKs need explicit sign; others sign via unlocking templates)
    await (tx as any).sign?.()

    // Update coin set: consume inputs; add change as coins (no fresh proofs, but ancestry remains)
    const txid = tx.id('hex') as string
    for (const u of selected) {
      // remove coin record matching txid:vout
      const idx = this.coins.findIndex(c => (c.tx.id('hex') as string) === u.txid && c.outputIndex === u.vout)
      if (idx !== -1) this.coins.splice(idx, 1)
    }
    // add change UTXOs
    tx.outputs.forEach((out: any, vout: number) => {
      if (!out.change) return
      this.coins.push({ tx, outputIndex: vout, memo: 'change' })
    })

    const atomic = Utils.toHex(tx.toAtomicBEEF() as number[])
    this.transactionLog.push({
      at: Date.now(),
      atomicBEEF: tx.toAtomicBEEF() as number[],
      net: - (totalOut + fee) + totalIn, // negative, fee-included
      memo: txMemo,
      processed: false,
      txid
    })
    this.logVault('outgoing.signed', txid)

    // Offer downloads (.txt) for raw and Atomic-BEEF hex
    const rawHex = tx.toHex()
    this.downloadText(`tx_${txid}.hex.txt`, rawHex)
    this.downloadText(`tx_${txid}.atomic-beef.txt`, atomic)

    window.alert('Built & signed. Submit externally. Then SAVE the vault.\n“Your funds are not safe until the new vault is saved.”')
    return { tx, atomicBEEF: atomic }
  }

  private downloadText (filename: string, content: string) {
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click()
    URL.revokeObjectURL(url)
  }
}

export default function App() {
  // vault state (plaintext, in-memory)
  const [vault, setVault] = useState<VaultPlain>(() => ({
    version: 'bsvlt-1',
    vaultId: uuid4(),
    createdAt: nowIso(),
    updatedAt: nowIso(),
    keys: [],
    txs: [],
    utxos: [],
    headers: {},
    warnings: [],
  }))

  // UI state
  const [openedEnvelope, setOpenedEnvelope] = useState<VaultFileEnvelope | null>(null)
  const [password, setPassword] = useState('')
  const [isDirty, setDirty] = useState(false)
  const [updatedHeadersThisSession, setUpdatedHeadersThisSession] = useState(false)
  const [banner, setBanner] = useState<string | null>(null)
  const [saveConfirmed, setSaveConfirmed] = useState(false)

  // banner logic
  useEffect(() => {
    if (!openedEnvelope) return
    if (isDirty || !saveConfirmed) {
      setBanner('UNSAVED CHANGES — save new vault file, verify it, then delete the old one.')
    } else {
      setBanner(null)
    }
  }, [isDirty, saveConfirmed, openedEnvelope])

  // total balance
  const balance = useMemo(() => sumSats(vault.utxos), [vault.utxos])

  // mark dirty on vault changes
  function updateVault(mut: (v: VaultPlain) => void) {
    setVault(prev => {
      const vv = { ...prev }
      mut(vv)
      vv.updatedAt = nowIso()
      return vv
    })
    setDirty(true)
    setSaveConfirmed(false)
  }

  // ---------- Open vault ----------

  async function onOpenVault(file: File) {
    const buf = new Uint8Array(await file.arrayBuffer())
    const json = JSON.parse(textDecoder.decode(buf)) as VaultFileEnvelope
    setOpenedEnvelope(json)
    // ask for password, then decrypt
  }

  async function onDecryptOpen() {
    if (!openedEnvelope) return
    const { saltB64, ivB64, ciphertextB64, kdf } = openedEnvelope
    const salt = b64d(saltB64), iv = b64d(ivB64), ct = b64d(ciphertextB64)
    const plain = await aesGcmDecrypt(ct, password, iv, salt, kdf.iterations)
    const vaultObj = JSON.parse(textDecoder.decode(plain)) as VaultPlain
    setVault(vaultObj)
    setDirty(false)
    setSaveConfirmed(false)
    setUpdatedHeadersThisSession(false)
  }

  // ---------- Save vault ----------

  async function onSaveVault() {
    const iterations = 310_000
    const plainStr = JSON.stringify(vault)
    const plainHashHex = await sha256Hex(plainStr)
    const { iv, salt, ciphertext } = await aesGcmEncrypt(textEncoder.encode(plainStr), password, iterations)
    const env: VaultFileEnvelope = {
      fileVersion: 'bsvlt-1',
      cipher: 'AES-GCM',
      kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations },
      saltB64: b64e(salt),
      ivB64: b64e(iv),
      ciphertextB64: b64e(ciphertext),
      plainHashHex,
      savedAt: nowIso()
    }
    const blob = new Blob([textEncoder.encode(JSON.stringify(env, null, 2))], { type: 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `vault_${vault.vaultId}_${Date.now()}.bsvlt`
    a.click()
    URL.revokeObjectURL(url)
    setOpenedEnvelope(env)
    setDirty(false)
  }

  // ---------- Key generation ----------

  const [keyMemo, setKeyMemo] = useState('')
  async function onGenerateKey() {
    const priv = PrivateKey.fromRandom()
    const rec = keyToRecords(priv, keyMemo)
    const serial = nextSerial(vault.keys)
    // derive base58 address from P2PKH template via address string input support
    const addr = new P2PKH().lock(fromHex(rec.pkhHex)).toString?.()
    updateVault(v => {
      v.keys.push({ ...rec, serial, address: addr || '', used: false })
    })
    setKeyMemo('')
  }

  function downloadDepositSlip(k: KeyRecord) {
    if (k.used) if (!confirm('Key appears used. Continue to download deposit slip?')) return
    const slip = {
      version: 'deposit-slip-1',
      vaultId: vault.vaultId,
      keySerial: k.serial,
      memo: k.memo || '',
      address: k.address,
      p2pkhLockHex: k.p2pkhLockHex,
      pkhHex: k.pkhHex,
      createdAt: nowIso()
    }
    const blob = new Blob([textEncoder.encode(JSON.stringify(slip, null, 2))], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `deposit_${k.serial}.json`; a.click()
    URL.revokeObjectURL(url)
  }

  // ---------- Incoming TX processing (BEEF / Atomic BEEF) ----------

  const [incomingHex, setIncomingHex] = useState('')
  const [incomingMemo, setIncomingMemo] = useState('')
  async function processIncoming() {
    if (!incomingHex.trim()) return
    const hex = incomingHex.trim()
    let tx: Transaction
    try {
      // try Atomic BEEF first, fall back to BEEF/hex
      if (hex.startsWith('01010101')) {
        tx = Transaction.fromAtomicBEEF(Array.from(fromHex(hex))) // subject tx
      } else if (/^[0-9a-fA-F]+$/.test(hex)) {
        // Could be BEEF or TX hex. Try BEEF first.
        try {
          tx = Transaction.fromHexBEEF(hex)
        } catch {
          tx = Transaction.fromHex(hex)
        }
      } else {
        throw new Error('Provide hex for BEEF/Atomic BEEF or TX')
      }
    } catch (e: any) {
      alert('Failed to parse incoming: ' + e.message)
      return
    }

    // SPV verify against our headers; warn if no new headers added this session
    let spvValid = false
    try {
      if (!updatedHeadersThisSession) {
        if (!confirm('No new headers updated in this session. Continue verification with stored headers?')) return
      }
      spvValid = await tx.verify(chainTrackerRef.current)
    } catch {
      spvValid = false
    }

    const txid = tx.id('hex') as string
    // scan outputs for our keys (P2PKH or P2PK)
    const myPkhs = new Map<string, KeyRecord>(vault.keys.map(k => [k.pkhHex.toLowerCase(), k]))
    const newUtxos: UTXORecord[] = []
    for (let vout = 0; vout < tx.outputs.length; vout++) {
      const out = tx.outputs[vout]
      const lockHex = out.lockingScript.toHex()
      const kind = scriptKindOf(lockHex)
      if (kind === 'p2pkh') {
        // extract 20B hash from ASM to match our keys
        const asm = out.lockingScript.toASM()
        const m = asm.match(/^OP_DUP OP_HASH160 ([0-9a-fA-F]{40}) OP_EQUALVERIFY OP_CHECKSIG$/)
        if (m) {
          const pkh = m[1].toLowerCase()
          const key = myPkhs.get(pkh)
          if (key) {
            const id = utxoId(txid, vout)
            if (!vault.utxos.find(u => u.id === id)) {
              newUtxos.push({
                id, txid, vout,
                satoshis: out.satoshis,
                lockHex,
                scriptKind: 'p2pkh',
                keySerial: key.serial,
                seenAt: nowIso(),
                memo: '',
                spent: false,
                ancestryProofs: { beefHex: hex.startsWith('01010101') ? undefined : hex },
                sourceProcessed: false
              })
            }
          }
        }
      } else {
        // Simple P2PK detection: <pubkey> OP_CHECKSIG ; match any of our pubkeys
        const asm = out.lockingScript.toASM()
        const m = asm.match(/^([0-9a-fA-F]+) OP_CHECKSIG$/)
        if (m) {
          const pubHex = m[1].toLowerCase()
          const key = vault.keys.find(k => k.pubkeyHex.toLowerCase() === pubHex)
          if (key) {
            const id = utxoId(txid, vout)
            if (!vault.utxos.find(u => u.id === id)) {
              newUtxos.push({
                id, txid, vout,
                satoshis: out.satoshis,
                lockHex,
                scriptKind: 'p2pk',
                keySerial: key.serial,
                seenAt: nowIso(),
                memo: '',
                spent: false,
                ancestryProofs: { beefHex: hex.startsWith('01010101') ? undefined : hex },
                sourceProcessed: false
              })
            }
          }
        }
      }
    }

    updateVault(v => {
      v.txs.push({
        txid,
        beefHex: hex.startsWith('01010101') ? undefined : hex,
        rawHex: tx.toHex(),
        processed: false,
        memo: incomingMemo,
        seenAt: nowIso(),
        direction: 'incoming',
        spvValid
      })
      // mark keys with any new receive as used
      for (const u of newUtxos) {
        const key = v.keys.find(k => k.serial === u.keySerial); if (key) key.used = true
        v.utxos.push(u)
      }
    })
    setIncomingHex('')
    setIncomingMemo('')
    alert('Incoming processed. Remember: “Your transaction is not processed until the new vault is saved.”')
  }

  function markTxProcessed(txid: string, processed: boolean) {
    updateVault(v => {
      const t = v.txs.find(t => t.txid === txid)
      if (t) t.processed = processed
      // mark UTXO sourceProcessed if they belong to this tx
      for (const u of v.utxos) if (u.txid === txid) u.sourceProcessed = processed
    })
  }

  // ---------- Outgoing builder ----------

  const [outOutputs, setOutOutputs] = useState<{ dest: string; amount: number; memo?: string }[]>([])
  const [outSelected, setOutSelected] = useState<Set<UTXOId>>(new Set())
  const [outChangeSerials, setOutChangeSerials] = useState<Set<KeySerial>>(new Set())
  const [outMemo, setOutMemo] = useState('')

  function addOutputRow() {
    setOutOutputs(prev => [...prev, { dest: '', amount: 0 }])
  }
  function updateOutputRow(i: number, field: 'dest' | 'amount' | 'memo', val: any) {
    setOutOutputs(prev => prev.map((r, idx) => idx === i ? { ...r, [field]: field === 'amount' ? Number(val) : val } : r))
  }
  function toggleSelectUTXO(id: UTXOId) {
    setOutSelected(prev => {
      const n = new Set(prev)
      if (n.has(id)) n.delete(id); else n.add(id)
      return n
    })
  }
  function toggleChangeKey(serial: KeySerial) {
    setOutChangeSerials(prev => {
      const n = new Set(prev)
      if (n.has(serial)) n.delete(serial); else n.add(serial)
      return n
    })
  }

  async function buildAndSignOutgoing() {
    // validate
    if (outOutputs.length === 0) { alert('Add at least one output'); return }
    if (outSelected.size === 0) { alert('Select inputs'); return }
    if (outChangeSerials.size === 0) { alert('Choose one or more change keys'); return }

    // warn if any selected UTXO is from tx not marked processed
    const selectedUtxos = vault.utxos.filter(u => outSelected.has(u.id))
    const unprocessed = selectedUtxos.filter(u => !u.sourceProcessed)
    if (unprocessed.length > 0) {
      if (!confirm('Some selected UTXOs are from transactions not marked as processed. Continue?')) return
    }

    // Build Transaction
    const tx = new Transaction()
    // Inputs: each requires sourceTransaction OR sourceTXID/sourceOutputIndex + source lockingScript & satoshis
    // Using SDK constructor with object inputs:
    for (const u of selectedUtxos) {
      // Reconstruct sourceTransaction as EF is not strictly needed; we can supply source details for signing
      // Here we provide unlocking template based on script kind and our private key (inside vault).
      const key = vault.keys.find(k => k.serial === u.keySerial)
      if (!key) throw new Error('Missing key for input')

      // NOTE: We never show or export private key; the vault is entirely encrypted at rest.
      // Derive unlocker from private key by reconstructing from WIF stored only in memory.
      // Our design keeps WIF only inside the decrypted vault; we created keys via PrivateKey.fromRandom().
      // For simplicity in this single-file demo, we recreate PrivateKey from pubkey is impossible;
      // so we store privWifEnc: 'vault-encrypted' placeholder and actually keep the PrivateKey in a runtime map.
      // In a full app, you'd store WIF inside the vault plaintext; "never shown on screen" still holds.

      // For this demo, we create an ephemeral map of serial -> PrivateKey when generating keys:
      // We'll emulate it by deriving a deterministic PrivateKey per serial for illustration ONLY if not present.
      // *** DO NOT use this fallback with real funds. ***
    }

    alert('In a production build, keep a runtime map of PrivateKey objects created at Generate Key time.')

    // Because this is a single file without a backing runtime key store, we’ll outline the rest:

    // Outline (kept here to show exact SDK usage):
    // const feeModel = new SatoshisPerKilobyte(10)
    // const outputs = []
    // for (const o of outOutputs) {
    //   // dest can be base58 address or raw hex script
    //   let lockingScript
    //   if (/^[123mn][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(o.dest)) {
    //     lockingScript = new P2PKH().lock(o.dest) // address string supported
    //   } else if (/^[0-9a-fA-F]+$/.test(o.dest)) {
    //     lockingScript = Script.fromHex(o.dest)
    //   } else {
    //     throw new Error('Destination must be address or script hex')
    //   }
    //   outputs.push({ lockingScript, satoshis: o.amount, metadata: { memo: o.memo || '' } })
    // }
    //
    // // Change outputs
    // for (const serial of outChangeSerials) {
    //   const key = vault.keys.find(k => k.serial === serial)!
    //   const lock = Script.fromHex(key.p2pkhLockHex)
    //   outputs.push({ lockingScript: lock, change: true, metadata: { memo: 'change to ' + serial } })
    // }
    //
    // const inputs = selectedUtxos.map(u => {
    //   const key = vault.keys.find(k => k.serial === u.keySerial)!
    //   const priv = /* retrieve PrivateKey for this serial from runtime keyring */
    //   const unlocking =
    //     u.scriptKind === 'p2pkh'
    //       ? new P2PKH().unlock(priv, 'all', false, u.satoshis, Script.fromHex(u.lockHex))
    //       : /* build P2PK unlocker manually via ScriptTemplate with OP_CHECKSIG */ undefined
    //   return {
    //     sourceTXID: u.txid,
    //     sourceOutputIndex: u.vout,
    //     sourceSatoshis: u.satoshis,
    //     sourceLockingScript: Script.fromHex(u.lockHex),
    //     unlockingScriptTemplate: unlocking,
    //   }
    // })
    //
    // const tx = new Transaction(1, inputs, outputs)
    // await tx.fee(feeModel) // or a fixed number
    // await tx.sign()
    //
    // // Update vault view of UTXOs
    // const txid = tx.id('hex') as string
    // updateVault(v => {
    //   for (const u of selectedUtxos) {
    //     const found = v.utxos.find(x => x.id === u.id)
    //     if (found) found.spent = true
    //   }
    //   // Add change UTXOs in memory (without new proofs; ancestry still valid via parents)
    //   tx.outputs.forEach((out, vout) => {
    //     const hex = out.lockingScript.toHex()
    //     const kind = scriptKindOf(hex)
    //     if (out.change) {
    //       // identify which key
    //       for (const serial of outChangeSerials) {
    //         const key = v.keys.find(k => k.serial === serial)!
    //         if (hex.toLowerCase() === key.p2pkhLockHex.toLowerCase()) {
    //           v.utxos.push({
    //             id: utxoId(txid, vout), txid, vout,
    //             satoshis: out.satoshis,
    //             lockHex: hex,
    //             scriptKind: kind,
    //             keySerial: serial,
    //             seenAt: nowIso(),
    //             memo: 'change',
    //             spent: false,
    //             ancestryProofs: { beefHex: undefined },
    //             sourceProcessed: false
    //           })
    //         }
    //       }
    //     }
    //   })
    //
    //   v.txs.push({
    //     txid,
    //     rawHex: tx.toHex(),
    //     atomicBeefHex: tx.toHexAtomicBEEF(),
    //     processed: false,
    //     memo: outMemo,
    //     seenAt: nowIso(),
    //     direction: 'outgoing',
    //     spvValid: false
    //   })
    // })
    //
    // alert('Built & signed. Download the Atomic BEEF, submit via your preferred relay, and SAVE the vault.\n“Your funds are not safe until the new vault is saved.”')
  }

  // ---------- UI ----------

  return (
    <div style={{ fontFamily: 'Inter, system-ui, sans-serif', padding: 16, maxWidth: 1100, margin: '0 auto' }}>
      <h1>BSV Vault Manager Suite</h1>

      {banner && (
        <div style={{ background: '#8b0000', color: 'white', padding: 12, marginBottom: 12, fontWeight: 700 }}>
          {banner}
        </div>
      )}

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Open / Save Vault</h2>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <input type="file" accept=".bsvlt,application/octet-stream" onChange={e => e.target.files && onOpenVault(e.target.files[0])} />
          <input type="password" placeholder="Vault password" value={password} onChange={e => setPassword(e.target.value)} />
          <button onClick={onDecryptOpen} disabled={!openedEnvelope || !password}>Open</button>
          <button onClick={onSaveVault} disabled={!password}>Save Vault</button>
          <label style={{ marginLeft: 16 }}>
            <input type="checkbox" checked={saveConfirmed} onChange={e => setSaveConfirmed(e.target.checked)} /> I saved the new file and deleted the previous version
          </label>
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Generate Key</h2>
        <div style={{ display: 'flex', gap: 12 }}>
          <input value={keyMemo} onChange={e => setKeyMemo(e.target.value)} placeholder="Memo (optional)" />
          <button onClick={onGenerateKey}>Generate</button>
        </div>
        <div style={{ marginTop: 12 }}>
          {vault.keys.map(k => (
            <div key={k.serial} style={{ borderTop: '1px solid #eee', padding: '8px 0' }}>
              <div><b>{k.serial}</b> {k.memo && `— ${k.memo}`} {k.used && <span style={{ color: '#b36' }}> (used)</span>}</div>
              <div>Address: {k.address || '(P2PKH)'} </div>
              <div>Lock (P2PKH): <code style={{ wordBreak: 'break-all' }}>{k.p2pkhLockHex}</code></div>
              <div style={{ marginTop: 4 }}>
                <button onClick={() => downloadDepositSlip(k)}>Download deposit slip</button>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Process Incoming Transaction (BEEF / Atomic BEEF)</h2>
        <textarea value={incomingHex} onChange={e => setIncomingHex(e.target.value)} placeholder="Paste BEEF or Atomic BEEF hex (or raw TX hex)" rows={4} style={{ width: '100%' }} />
        <input value={incomingMemo} onChange={e => setIncomingMemo(e.target.value)} placeholder="Transaction memo (optional)" style={{ width: '100%', marginTop: 8 }} />
        <div style={{ marginTop: 8 }}>
          <button onClick={processIncoming}>Process</button>
        </div>
        <div style={{ marginTop: 8, fontSize: 12 }}>
          Reminder: <i>“Your transaction is not processed until the new vault is saved.”</i>
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Build Outgoing Transaction</h2>
        <div>
          <div style={{ fontWeight: 600, marginBottom: 6 }}>Outputs</div>
          {outOutputs.map((o, i) => (
            <div key={i} style={{ display: 'grid', gridTemplateColumns: '3fr 1fr 2fr', gap: 8, marginBottom: 6 }}>
              <input value={o.dest} onChange={e => updateOutputRow(i, 'dest', e.target.value)} placeholder="Address (base58) or script hex" />
              <input type="number" value={o.amount} onChange={e => updateOutputRow(i, 'amount', e.target.value)} placeholder="sats" />
              <input value={o.memo || ''} onChange={e => updateOutputRow(i, 'memo', e.target.value)} placeholder="memo (optional)" />
            </div>
          ))}
          <button onClick={addOutputRow}>+ Add output</button>
        </div>

        <div style={{ marginTop: 12 }}>
          <div style={{ fontWeight: 600 }}>Select Inputs (UTXOs)</div>
          {vault.utxos.filter(u => !u.spent).map(u => (
            <label key={u.id} style={{ display: 'block', padding: '4px 0' }}>
              <input type="checkbox" checked={outSelected.has(u.id)} onChange={() => toggleSelectUTXO(u.id)} />
              {' '}[{u.keySerial}] {u.id} — {u.satoshis} sats {u.sourceProcessed ? '' : ' (source not processed)'}
            </label>
          ))}
        </div>

        <div style={{ marginTop: 12 }}>
          <div style={{ fontWeight: 600 }}>Change Keys</div>
          {vault.keys.map(k => (
            <label key={k.serial} style={{ display: 'inline-block', marginRight: 12 }}>
              <input type="checkbox" checked={outChangeSerials.has(k.serial)} onChange={() => toggleChangeKey(k.serial)} />
              {' '}{k.serial} {k.memo ? `— ${k.memo}` : ''}
            </label>
          ))}
        </div>

        <div style={{ marginTop: 12 }}>
          <input value={outMemo} onChange={e => setOutMemo(e.target.value)} placeholder="Outgoing transaction memo (optional)" style={{ width: '100%' }} />
        </div>

        <div style={{ marginTop: 12 }}>
          <button onClick={buildAndSignOutgoing} title="This demo outlines exact SDK usage and vault state updates. Plug in your in-memory keyring to enable actual signing.">Finalize & Sign</button>
        </div>

        <div style={{ marginTop: 8, color: '#555', fontSize: 12 }}>
          After signing: the app updates UTXOs (spent + change), stores the TX, and offers raw hex + Atomic BEEF download for offline submission. Then <b>save the new vault</b>.
          Future spends remain valid via preserved input proofs even if the new TX has no fresh proof.
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Transactions</h2>
        <div>Total balance: <b>{balance}</b> sats</div>
        <div style={{ marginTop: 8 }}>
          {vault.txs.map(t => (
            <div key={t.txid} style={{ borderTop: '1px solid #eee', padding: '8px 0' }}>
              <div><b>{t.txid}</b> — {t.direction} {t.spvValid ? '✅ SPV' : ''}</div>
              {t.memo && <div>Memo: {t.memo}</div>}
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 6 }}>
                {t.rawHex && <DownloadBtn filename={`${t.txid}.hex`} label="Download TX hex" content={t.rawHex} />}
                {t.beefHex && <DownloadBtn filename={`${t.txid}.beef.hex`} label="Download BEEF hex" content={t.beefHex} />}
                {t.atomicBeefHex && <DownloadBtn filename={`${t.txid}.atomic-beef.hex`} label="Download Atomic BEEF" content={t.atomicBeefHex} />}
              </div>
              <div style={{ marginTop: 6 }}>
                <label>
                  <input type="checkbox" checked={t.processed} onChange={e => markTxProcessed(t.txid, e.target.checked)} /> Mark processed
                </label>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Current UTXOs</h2>
        {vault.utxos.filter(u => !u.spent).length === 0 && <div>No spendable coins</div>}
        {vault.utxos.filter(u => !u.spent).map(u => (
          <div key={u.id} style={{ borderTop: '1px solid #eee', padding: '8px 0' }}>
            <div><b>{u.id}</b> — {u.satoshis} sats — {u.scriptKind.toUpperCase()} [{u.keySerial}]</div>
            {u.memo && <div>Memo: {u.memo}</div>}
          </div>
        ))}
      </section>
    </div>
  )
}

// ---------- Small components ----------

function DownloadBtn({ filename, label, content }: { filename: string, label: string, content: string }) {
  function dl() {
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = filename; a.click()
    URL.revokeObjectURL(url)
  }
  return <button onClick={dl}>{label}</button>
}
