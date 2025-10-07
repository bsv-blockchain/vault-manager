import { useEffect, useMemo, useRef, useState } from 'react'
import { PrivateKey, P2PKH, Script, Transaction, PublicKey, ChainTracker, MerklePath, Utils, Hash, SymmetricKey, Random, TransactionOutput } from '@bsv/sdk'

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
    keySerial: string
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
      const keySerialLength = d.readVarIntNum()
      const keySerial = Utils.toUTF8(d.read(keySerialLength))
      v.coins.push({
        tx,
        outputIndex,
        memo,
        keySerial
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
    w.writeVarIntNum(this.vaultName.length)
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
      const keySerialBytes = Utils.toArray(c.keySerial)
      w.writeVarIntNum(keySerialBytes.length); w.write(keySerialBytes)
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
      this.coins.push({ tx, outputIndex: m.vout, memo: '' /* todo: prmpot for each memo */, keySerial: m.serial })
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
      // TODO: We need to attest each one individually
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

    const tx = new Transaction()

    // Build inputs
    for (const s of selected) {
      tx.addInput({
        sourceTransaction: s.tx,
        sourceOutputIndex: s.outputIndex,
        unlockingScriptTemplate: new P2PKH().unlock(this.keys.find(x => x.serial === s.keySerial)!.private)
      })
    }
    for (const o of outputs) {
      tx.addOutput(o)
    }
    const indexToKeySerial = new Map<number, string>()
    for (const k of changeKeys) {
      tx.addOutput({
        lockingScript: new P2PKH().lock(k.public.toAddress()),
        change: true
      })
      indexToKeySerial.set(tx.outputs.length, k.serial)
    }
    tx.fee(undefined, 'random')
    tx.sign()

    // Update coin set: consume inputs; add change as coins (no fresh proofs, but ancestry remains)
    const txid = tx.id('hex') as string
    for (const u of selected) {
      // remove coin record matching txid:vout
      const idx = this.coins.findIndex(c => (c.tx.id('hex') as string) === u.tx.id('hex') && c.outputIndex === u.outputIndex)
      if (idx !== -1) this.coins.splice(idx, 1)
    }
    // add change UTXOs
    tx.outputs.forEach((out: TransactionOutput, outputIndex: number) => {
      if (!out.change) return
      this.coins.push({ tx, outputIndex, memo: 'change', keySerial: indexToKeySerial.get(outputIndex) as string })
    })

    const atomic = Utils.toHex(tx.toAtomicBEEF() as number[])
    this.transactionLog.push({
      at: Date.now(),
      atomicBEEF: tx.toAtomicBEEF() as number[],
      net: (selected.reduce((a, e) => a + e.tx.outputs[e.outputIndex].satoshis! as number, 0) - tx.outputs.reduce((a, e) => a + e.change ? e.satoshis as number : 0, 0)) * -1, // inputs - change * -1
      memo: txMemo,
      processed: false,
      txid
    })
    this.logVault('outgoing.signed', txid)

    // Offer downloads (.txt) for Atomic-BEEF hex
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

function nowIso () { return new Date().toISOString() }

export default function App () {
  const [vault, setVault] = useState<Vault | null>(null)
  const [lastSavedHashHex, setLastSavedHashHex] = useState<string | null>(null)
  const [banner, setBanner] = useState<string | null>(null)

  // open/load vault (use your existing file format)
  async function onOpenVault (file: File) {
    const buf = new Uint8Array(await file.arrayBuffer())
    const v = Vault.loadFromFile(Array.from(buf))
    setVault(v)
    // compute hash of bytes opened (for mismatch banner logic)
    const openedHash = Utils.toHex(Hash.sha256(Array.from(buf)))
    setLastSavedHashHex(openedHash)
  }

  // create new vault
  async function onNewVault () {
    const v = await Vault.create()
    setVault(v)
    setLastSavedHashHex(null)
  }

  // save/download vault
  async function onSaveVault () {
    if (!vault) return
    await vault.downloadVaultFile()
    // recompute "would save" bytes to set our lastSavedHashHex
    const bytes = await vault.saveToFileBytes() // this re-encrypts; identical content gives identical ciphertext because SymmetricKey.encrypt may be randomized;
    // If your SymmetricKey uses a random IV internally, the outer file hash will change every save. That’s fine:
    // we’ll store the current “last saved” hash so that unsaved-changes banner turns off right after saving.
    const h = Utils.toHex(Hash.sha256(bytes))
    setLastSavedHashHex(h)
  }

  // regenerate banner: unsaved changes if would-save hash ≠ lastSavedHashHex
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      if (!vault) { setBanner(null); return }
      try {
        const bytes = await vault.saveToFileBytes() // NOTE: see remark above about randomized IVs
        const hh = Utils.toHex(Hash.sha256(bytes))
        const dirty = !lastSavedHashHex || (hh !== lastSavedHashHex)
        setBanner(dirty ? 'UNSAVED CHANGES — save new vault file, verify it, then delete the old one.' : null)
      } catch {
        // ignore
      }
    })()
    return () => { cancelled = true }
  }, [vault, lastSavedHashHex])

  const balance = useMemo(() => {
    if (!vault) return 0
    // sum of all current coins' outputs
    return vault.coins.reduce((n, c) => n + c.tx.outputs[c.outputIndex].satoshis, 0)
  }, [vault])

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

  function refresh (mut: (v: Vault) => void) {
    mut(vault)
    // force rerender
    setVault(Object.assign(Object.create(Object.getPrototypeOf(vault)), vault))
  }

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
          <input type="file" accept=".vaultfile,application/octet-stream" onChange={e => e.target.files && onOpenVault(e.target.files[0])} />
          <button onClick={onSaveVault}>Save Vault</button>
          <div>Vault: <b>{vault.vaultName}</b> (rev {vault.vaultRevision})</div>
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Keys</h2>
        <div style={{ display: 'flex', gap: 12 }}>
          <button onClick={async () => { await vault.generateKeyInteractive(); refresh(()=>{}) }}>Generate Key</button>
        </div>
        <div style={{ marginTop: 12 }}>
          {vault.keys.map(k => (
            <div key={k.serial} style={{ borderTop: '1px solid #eee', padding: '8px 0' }}>
              <div><b>{k.serial}</b> {k.memo && `— ${k.memo}`} {k.usedOnChain ? <span style={{ color: '#b36' }}> (used)</span> : null}</div>
              <div>
                <button onClick={() => vault.downloadDepositSlipTxt(k.serial)}>Download deposit slip (.txt)</button>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Process Incoming Atomic BEEF</h2>
        <textarea id="incoming-hex" placeholder="Paste hex..." rows={4} style={{ width: '100%' }} />
        <div style={{ marginTop: 8 }}>
          <button onClick={async () => {
            const ta = document.getElementById('incoming-hex') as HTMLTextAreaElement
            try { await vault.processIncomingInteractive(ta.value) ; ta.value = '' ; refresh(()=>{}) }
            catch (e:any) { alert(e.message || String(e)) }
          }}>Process</button>
        </div>
        <div style={{ marginTop: 8, fontSize: 12 }}>
          Reminder: <i>“Your transaction is not processed until the new vault is saved.”</i>
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 12, marginBottom: 16 }}>
        <h2>Build Outgoing</h2>
        <button onClick={async () => {
          try { await vault.buildAndSignOutgoingInteractive(); refresh(()=>{}) }
          catch (e:any) { alert(e.message || String(e)) }
        }}>Finalize & Sign (interactive)</button>
        <div style={{ marginTop: 8, color: '#555', fontSize: 12 }}>
          After signing: the app updates UTXOs (spent + change), stores the TX, and offers raw hex + Atomic BEEF downloads (.txt). Then <b>save the new vault</b>.
          Future spends remain valid via preserved input proofs even if the new TX has no fresh proof.
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
              <div style={{ marginTop: 6 }}>
                <label>
                  <input
                    type="checkbox"
                    checked={t.processed}
                    onChange={e => { vault.markProcessed(t.txid, e.target.checked); refresh(()=>{}) }}
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