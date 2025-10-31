import { PrivateKey, PublicKey, Transaction } from '@bsv/sdk'

export type UnixMs = number

/** Dialog bridge for Vault business logic (no window.*) */
export type UiBridge = {
  alert: (msg: string, title?: string) => Promise<void>
  confirm: (msg: string, opts?: { title?: string; confirmText?: string; cancelText?: string }) => Promise<boolean>
  prompt: (msg: string, opts?: { title?: string; password?: boolean; defaultValue?: string; placeholder?: string; maxLength?: number; validate?: (val: string) => true | string }) => Promise<string | null>
  gatherEntropy?: (opts: { size: number }) => Promise<number[]>
}

/** A serializable, sanitized session/vault event. */
export type AuditEvent = {
  at: UnixMs
  event: string
  data?: string
}

export type KeyRecord = {
  serial: string
  private: PrivateKey        // NEVER log
  public: PublicKey
  usedOnChain: boolean
  memo: string
}

export type CoinRecord = {
  txid: string
  outputIndex: number
  memo: string
  keySerial: string
}

export type TxLogRecord = {
  at: UnixMs
  txid: string
  net: number // positive=in, negative=out (includes fee)
  memo: string
  processed: boolean
}

export type PersistedHeaderClaim = {
  at: UnixMs
  merkleRoot: string
  height: number
  memo: string
}

export type EphemeralHeaderClaim = {
  at: UnixMs
  merkleRoot: string
  height: number
}

export type OutgoingOutputSpec = {
  /** Address (Base58/BSV) OR full locking script hex */
  destinationAddressOrScript: string
  satoshis: number
  memo?: string
}

export type MatchedOutput = {
  outputIndex: number
  lockingScript: string
  satoshis: number
  serial: string
}

export type IncomingPreview = {
  tx: Transaction
  txid: string
  hex: string
  matches: MatchedOutput[]
  spvValid: boolean
}

export type AttestationFn = (coin: CoinRecord) => Promise<boolean>

export type BuildOutgoingOptions = {
  outputs: OutgoingOutputSpec[]
  inputIds?: string[]          // REQUIRED now (enforced)
  changeKeySerials?: string[]  // REQUIRED now (enforced)
  perUtxoAttestation?: boolean
  attestationFn?: AttestationFn
  txMemo?: string
}

export type CreateVaultOptions = {
  name: string
  password: string
  passwordRounds: number
  useUserEntropyForRandom: boolean
  confirmIncomingCoins: boolean
  confirmOutgoingCoins: boolean
  persistHeadersOlderThanBlocks: number
  reverifyRecentHeadersAfterSeconds: number
  reverifyCurrentBlockHeightAfterSeconds: number
  initialBlockHeight: number
}

export type HashRecord = {
  fileHash: string
  savedAt: number
  fileName?: string
}

export type BackupRecord = {
  id: string
  fileHash: string
  storedAt: number
  fileName?: string
  hex: string
}

export type LoadedFileMeta = {
  fileHash: string
  fileName: string | null
  loadedAt: number
  expectedHash?: string | null
  mismatch?: boolean
}

export type EntropyRequest = {
  size: number
  resolve: (bytes: number[]) => void
  reject: (err: Error) => void
}

export type Notification = {
  type: 'success' | 'error' | 'info'
  message: string
  id: number
}
