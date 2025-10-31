import React, { useMemo, useState, useCallback } from 'react'
import { Hash, Utils } from '@bsv/sdk'

// Import types
import {
  LoadedFileMeta,
  IncomingPreview,
  EntropyRequest,
  Notification,
  CreateVaultOptions,
  UiBridge,
  BackupRecord
} from './types'

// Import utilities
import {
  recordVaultLoadMetadata,
  recordVaultSaveMetadata,
  hexToBytes,
  getBackupsForPlain,
  getExpectedHashRecord,
  getTxFromStore
} from './utils'

// Import Vault class
import { Vault } from './Vault'

// Import components
import { DialogProvider, useDialog } from './components/dialogs/DialogProvider'
import NotificationBanner from './components/common/NotificationBanner'
import NewVaultForm from './components/forms/NewVaultForm'
import EntropyCaptureModal from './components/forms/EntropyCaptureModal'
import DashboardPanel from './components/tabs/DashboardPanel'
import KeyManager from './components/tabs/KeyManager'
import IncomingManager from './components/tabs/IncomingManager'
import ProcessIncomingModal from './components/tabs/ProcessIncomingModal'
import OutgoingWizard from './components/tabs/OutgoingWizard'
import LogsPanel from './components/tabs/LogsPanel'
import SettingsPanel from './components/tabs/SettingsPanel'

// Import styles
import './styles/index.css'

/**
 * =============================================================================
 * Main App Component
 * =============================================================================
 */

type TabKey = 'keys' | 'incoming' | 'outgoing' | 'dashboard' | 'settings' | 'logs'

export default function App() {
  return (
    <DialogProvider>
      <AppInner />
    </DialogProvider>
  )
}

function AppInner() {
  const dialog = useDialog()

  // Core state
  const [vault, setVault] = useState<Vault | null>(null)
  const [lastSavedPlainHash, setLastSavedPlainHash] = useState<string | null>(null)
  const [notification, setNotification] = useState<Notification | null>(null)
  const [incomingPreview, setIncomingPreview] = useState<IncomingPreview | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<TabKey>('dashboard')
  const [appKey, setAppKey] = useState(0) // Used to force re-render of components
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [loadedFileMeta, setLoadedFileMeta] = useState<LoadedFileMeta | null>(null)
  const [entropyRequest, setEntropyRequest] = useState<EntropyRequest | null>(null)

  // Derived state
  const plainHash = lastSavedPlainHash
  const backupEntries = useMemo(
    () => plainHash ? getBackupsForPlain(plainHash) : [],
    [plainHash, appKey]
  )
  const expectedHashRecord = plainHash ? getExpectedHashRecord(plainHash) : undefined

  // Force update helper
  const forceAppUpdate = useCallback(() => {
    if (vault) {
      // This creates a new object reference, forcing React to re-render consumers of the vault prop
      setVault(Object.assign(Object.create(Object.getPrototypeOf(vault)), vault))
      setAppKey(k => k + 1)
    }
  }, [vault])

  // Backup download handler
  const handleDownloadBackup = useCallback((entry: BackupRecord) => {
    try {
      const bytes = hexToBytes(entry.hex)
      const blob = new Blob([new Uint8Array(bytes)], { type: 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const baseName = (entry.fileName || loadedFileMeta?.fileName || vault?.vaultName || 'vault').replace(/[^a-z0-9_\-\.]+/gi, '_')
      const suffix = new Date(entry.storedAt).toISOString().replace(/[:]/g, '-')
      const a = document.createElement('a')
      a.href = url
      a.download = `${baseName || 'vault'}.backup.${suffix}.vaultfile`
      a.click()
      URL.revokeObjectURL(url)
      notify('info', 'Backup downloaded.')
    } catch (err: any) {
      notify('error', err?.message || 'Failed to download backup copy.')
    }
  }, [loadedFileMeta?.fileName, vault])

  // Entropy gathering
  const gatherEntropy = useCallback(({ size }: { size: number }) => {
    return new Promise<number[]>((resolve, reject) => {
      setEntropyRequest({ size: Math.max(64, size), resolve, reject })
    })
  }, [])

  // UI Bridge for Vault
  const uiBridge = useMemo<UiBridge>(() => ({
    alert: dialog.alert,
    confirm: dialog.confirm,
    prompt: dialog.prompt,
    gatherEntropy
  }), [dialog.alert, dialog.confirm, dialog.prompt, gatherEntropy])

  // Notification helper
  function notify(type: Notification['type'], message: string) {
    setNotification({ type, message, id: Date.now() })
  }

  // --- Core Vault Actions ---

  async function onOpenVault(file: File) {
    setIsLoading(true)
    try {
      // Basic file validation: non-empty, expected extension
      if (!file || file.size === 0) throw new Error('Selected file is empty.')
      if (!file.name.endsWith('.vaultfile')) {
        const cont = await dialog.confirm(
          `The selected file (${file.name}) does not have the .vaultfile extension. Continue anyway?`,
          {
            title: 'Unrecognized Extension',
            confirmText: 'Continue',
            cancelText: 'Cancel'
          }
        )
        if (!cont) return
      }
      const buf = new Uint8Array(await file.arrayBuffer())
      const bytes = Array.from(buf)
      const v = await Vault.loadFromFile(uiBridge, bytes, { fileName: file.name })
      const plainHash = v.computePlaintextHash()
      const fileHash = v.lastLoadedFileHash || Utils.toHex(Hash.sha256(bytes))
      const meta = recordVaultLoadMetadata({
        plainHash,
        fileHash,
        fileName: file.name || null,
        bytes
      })
      setVault(v)
      setLastSavedPlainHash(plainHash)
      setLoadedFileMeta({
        fileHash,
        fileName: file.name || null,
        loadedAt: Date.now(),
        expectedHash: meta.expected?.fileHash || null,
        mismatch: meta.mismatch
      })
      setShowCreateForm(false)
      notify(
        meta.mismatch ? 'error' : 'success',
        meta.mismatch
          ? 'Vault loaded, but the file hash differs from the last approved version.'
          : 'Vault loaded successfully.'
      )
    } catch (e: any) {
      notify('error', e.message || 'Failed to load vault.')
    } finally {
      setIsLoading(false)
    }
  }

  async function handleCreateVault(options: CreateVaultOptions) {
    setIsLoading(true)
    try {
      const v = await Vault.create(uiBridge, options)
      setVault(v)
      setLastSavedPlainHash(v.computePlaintextHash())
      setLoadedFileMeta(null)
      notify('info', 'New vault created. Generate a key to begin.')
      setActiveTab('keys')
      setShowCreateForm(false)
    } catch (e: any) {
      notify('error', e.message || 'Failed to create vault.')
    } finally {
      setIsLoading(false)
    }
  }

  // Pre-save enforcement: require users to download & set processed statuses for all pending outgoings,
  // and explicitly record processed states for all unprocessed transactions.
  async function enforcePendingBeforeSave(v: Vault): Promise<boolean> {
    const pending = v.transactionLog.filter(t => !t.processed)
    if (!pending.length) return true

    const lines = pending
      .map(t => {
        const direction = t.net >= 0 ? 'Incoming' : 'Outgoing'
        return `${direction} · ${t.txid}`
      })
      .join('\n')

    const proceed = await dialog.confirm(
      `These transactions are still marked as "Not processed":\n\n${lines}\n\nYou can update their status from the Dashboard tab once you have independent confirmation. Continue with SAVE anyway?`,
      {
        title: 'Pending Transactions',
        confirmText: 'Save Anyway',
        cancelText: 'Review First'
      }
    )
    return proceed
  }

  async function onSaveVault() {
    if (!vault) return
    setIsLoading(true)
    try {
      // Enforce pending outgoing management & explicit processed statuses BEFORE saving
      const okToSave = await enforcePendingBeforeSave(vault)
      if (!okToSave) {
        notify('error', 'Save cancelled. Resolve all pending items as instructed.')
        setIsLoading(false)
        return
      }

      const bytes = await vault.saveToFileBytes()
      const hashHex = Utils.toHex(Hash.sha256(bytes))
      const suggestedName =
        loadedFileMeta?.fileName || vault.lastKnownFileName || `${vault.vaultName.replace(/\s+/g, '_')}.vaultfile`
      const fileName = suggestedName.replace(/[^a-z0-9_\-\.]+/gi, '_') || `vault_${Date.now()}.vaultfile`

      const blob = new Blob([new Uint8Array(bytes)], { type: 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = fileName
      a.click()
      URL.revokeObjectURL(url)

      vault.lastKnownFileName = fileName
      vault.lastLoadedFileHash = hashHex
      const plainHashNow = vault.computePlaintextHash()
      setLastSavedPlainHash(plainHashNow)
      recordVaultSaveMetadata({ plainHash: plainHashNow, fileHash: hashHex, fileName, bytes })
      setLoadedFileMeta({
        fileHash: hashHex,
        fileName,
        loadedAt: Date.now(),
        expectedHash: hashHex,
        mismatch: false
      })
      setAppKey(k => k + 1)

      try {
        await navigator.clipboard.writeText(hashHex)
        notify('success', `Vault saved to ${fileName}. SHA-256 hash copied to clipboard.`)
      } catch {
        notify('success', `Vault saved to ${fileName}. SHA-256 hash: ${hashHex}`)
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
      <div className="app-shell">
        <div className="container" style={{ textAlign: 'center' }}>
          Loading Vault...
        </div>
      </div>
    )
  }

  if (!vault) {
    return (
      <div className="app-shell">
        <div className="container">
          {notification && <NotificationBanner notification={notification} onDismiss={() => setNotification(null)} />}
          <div className="panel" style={{ padding: 16, display: 'grid', gap: 16 }}>
            <h1 style={{ marginTop: 0 }}>BSV Vault Manager Suite</h1>
            <section className="section">
              <div>
                <h2 style={{ margin: '0 0 4px 0', fontSize: 18 }}>Open an Existing Vault</h2>
                <p style={{ margin: 0, fontSize: 13, color: 'var(--gray-600)' }}>
                  Select your saved <code>.vaultfile</code>. Integrity and backups will be checked automatically.
                </p>
              </div>
              <input
                style={{ maxWidth: '100%' }}
                type="file"
                accept=".vaultfile,application/octet-stream"
                onChange={e => e.target.files && onOpenVault(e.target.files[0])}
              />
            </section>

            {showCreateForm ? (
              <NewVaultForm onCancel={() => setShowCreateForm(false)} onSubmit={handleCreateVault} submitting={isLoading} />
            ) : (
              <section className="section">
                <h2 style={{ marginTop: 0 }}>Create a New Vault</h2>
                <p style={{ marginTop: 0, fontSize: 13, color: 'var(--gray-600)' }}>
                  Configure the core policies, password, and block height in a single step. You can adjust advanced settings
                  later in <b>Settings</b>.
                </p>
                <button onClick={() => setShowCreateForm(true)} className="btn btn-primary">
                  Launch Setup Form
                </button>
              </section>
            )}

            <div
              style={{
                fontSize: 12,
                color: 'var(--gray-600)',
                borderTop: '1px solid var(--border)',
                paddingTop: 12
              }}
            >
              This offline tool ships without warranty. Keep copies of your vault file on secure, redundant media. The
              application will surface latest hash and automatic backup guidance after each save.
            </div>
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
    <div className="app-shell">
      <div className="container">
        {notification && <NotificationBanner notification={notification} onDismiss={() => setNotification(null)} />}

        {loadedFileMeta && (
          <div
            className="panel"
            style={{
              marginBottom: 12,
              borderColor: loadedFileMeta.mismatch ? '#d9534f' : 'var(--border)',
              background: loadedFileMeta.mismatch ? '#fff6f6' : '#f9fbff',
              display: 'grid',
              gap: 6
            }}
          >
            <div style={{ fontWeight: 600, color: loadedFileMeta.mismatch ? '#a12121' : 'var(--gray-700)' }}>
              Loaded file details
            </div>
            <div style={{ fontSize: 13, wordBreak: 'break-all' }}>
              <b>File:</b> {loadedFileMeta.fileName || 'Unknown (.vaultfile)'} &nbsp;·&nbsp;
              <b>Loaded at:</b> {new Date(loadedFileMeta.loadedAt).toLocaleString()}
            </div>
            <div style={{ fontSize: 13, wordBreak: 'break-all' }}>
              <b>SHA-256:</b> <code>{loadedFileMeta.fileHash}</code>
            </div>
            {loadedFileMeta.expectedHash && (
              <div style={{ fontSize: 13, wordBreak: 'break-all' }}>
                <b>Last saved hash on this device:</b> <code>{loadedFileMeta.expectedHash}</code>
                {loadedFileMeta.mismatch ? (
                  <span style={{ color: '#a12121', fontWeight: 600 }}> — mismatch detected</span>
                ) : (
                  <span style={{ color: 'var(--green)' }}> — matches</span>
                )}
              </div>
            )}
            <div style={{ fontSize: 12, color: 'var(--gray-600)' }}>
              {loadedFileMeta.mismatch
                ? 'Hashes differ from the last approved version. Pause operations, investigate the discrepancy, and recover from an automatic backup in Settings.'
                : 'Hash stored for quick comparison next time you load this file. You can export verified backups from Settings.'}
            </div>
            <div>
              <button
                onClick={() => navigator.clipboard.writeText(loadedFileMeta.fileHash)}
                className="btn btn-ghost"
                style={{ width: '100%', maxWidth: 220 }}
              >
                Copy SHA-256 Hash
              </button>
            </div>
          </div>
        )}

        {entropyRequest && (
          <EntropyCaptureModal
            bytesNeeded={entropyRequest.size}
            onComplete={(bytes: number[]) => {
              entropyRequest.resolve(bytes)
              setEntropyRequest(null)
            }}
            onCancel={() => {
              entropyRequest.reject(new Error('Entropy collection cancelled'))
              setEntropyRequest(null)
            }}
          />
        )}

        {incomingPreview && (
          <ProcessIncomingModal
            vault={vault}
            preview={incomingPreview}
            onClose={() => setIncomingPreview(null)}
            onSuccess={(txid: string) => {
              setIncomingPreview(null)
              forceAppUpdate()
              notify('success', `Transaction ${txid} processed. SAVE the vault to persist changes.`)
              setActiveTab('dashboard')
            }}
            onError={(err: string) => notify('error', err)}
          />
        )}

        <div className="panel" style={{ padding: 16, marginBottom: 12 }}>
          {dirty && (
            <div
              style={{
                background: 'var(--red)',
                color: 'white',
                padding: 12,
                marginBottom: 12,
                fontWeight: 700,
                borderRadius: 8
              }}
            >
              UNSAVED CHANGES — Save the new vault file, verify its integrity, and then securely delete the old version.
            </div>
          )}

          <header
            style={{
              borderBottom: '1px solid var(--border)',
              paddingBottom: 12,
              marginBottom: 12,
              display: 'grid',
              gridTemplateColumns: '1fr',
              gap: 8
            }}
          >
            <div>
              <h1 style={{ margin: 0, fontSize: 22 }}>BSV Vault Manager Suite</h1>
              <div style={{ color: 'var(--gray-600)', marginTop: 4 }}>
                Vault: <b>{vault.vaultName}</b> (rev {vault.vaultRevision})
              </div>
            </div>
            <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '1fr 1fr', alignItems: 'center' }}>
              <input
                style={{ gridColumn: 'span 2' }}
                type="file"
                accept=".vaultfile,application/octet-stream"
                onChange={e => e.target.files && onOpenVault(e.target.files[0])}
              />
              <button onClick={onSaveVault} className="btn btn-primary" style={{ gridColumn: 'span 2' }}>
                Save Vault
              </button>
            </div>
          </header>

          {/* Tabs */}
          <div
            style={{
              display: 'flex',
              gap: 8,
              borderBottom: '1px solid var(--border)',
              marginBottom: 12,
              overflowX: 'auto'
            }}
          >
            {tabs.map(t => (
              <button
                key={t.key}
                onClick={() => setActiveTab(t.key)}
                className={activeTab === t.key ? 'tab tab-active' : 'tab'}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Active Tab Panels */}
          {activeTab === 'dashboard' && <DashboardPanel vault={vault} balance={balance} triggerRerender={forceAppUpdate} />}

          {activeTab === 'keys' && <KeyManager vault={vault} onUpdate={forceAppUpdate} notify={notify} />}

          {activeTab === 'incoming' && (
            <IncomingManager vault={vault} onPreview={setIncomingPreview} onError={(e: string) => notify('error', e)} />
          )}

          {activeTab === 'outgoing' && <OutgoingWizard vault={vault} notify={notify} onUpdate={forceAppUpdate} />}

          {activeTab === 'logs' && <LogsPanel vault={vault} onUpdate={forceAppUpdate} />}

          {activeTab === 'settings' && (
            <SettingsPanel
              vault={vault}
              onUpdate={forceAppUpdate}
              setLastSavedPlainHash={setLastSavedPlainHash}
              plainHash={plainHash}
              expectedHash={expectedHashRecord}
              backups={backupEntries}
              onDownloadBackup={handleDownloadBackup}
              loadedFileMeta={loadedFileMeta}
            />
          )}
        </div>
      </div>
    </div>
  )
}
