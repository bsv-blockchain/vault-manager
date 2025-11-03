import { useState } from 'react'
import SendCreate from './components/send/SendCreate'
import SendQueue from './components/send/SendQueue'
import Receive from './components/receive/Receive'
import './styles/index.css'

type Mode = 'send' | 'receive'
type SendView = 'create' | 'queue'

export default function App() {
  const [mode, setMode] = useState<Mode>('send')
  const [sendView, setSendView] = useState<SendView>('create')
  const [error, setError] = useState<string | null>(null)

  const handleTransactionCreated = () => {
    setSendView('queue')
  }

  const handleError = (errorMessage: string) => {
    setError(errorMessage)
  }

  return (
    <div className="app-shell">
      <div className="container">
        <div className="panel" style={{ padding: 24 }}>
          <h1 style={{
            marginTop: 0,
            fontSize: 22,
            fontWeight: 300,
            letterSpacing: '0.02em',
            color: 'var(--color-text-primary)',
            borderBottom: '1px solid var(--color-border-accent)',
            paddingBottom: 16,
            marginBottom: 24,
            background: 'linear-gradient(90deg, var(--color-accent-gold) 0%, var(--color-text-primary) 40%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text'
          }}>
            VAULT TRANSFER
          </h1>

          {/* Mode Selector */}
          <div style={{
            display: 'flex',
            gap: 8,
            marginBottom: 24,
            borderBottom: '1px solid var(--color-border-primary)',
            paddingBottom: 8
          }}>
            <button
              onClick={() => setMode('send')}
              className={mode === 'send' ? 'tab tab-active' : 'tab'}
            >
              Send
            </button>
            <button
              onClick={() => setMode('receive')}
              className={mode === 'receive' ? 'tab tab-active' : 'tab'}
            >
              Receive
            </button>
          </div>

          {error && (
            <div style={{
              background: 'rgba(196, 92, 92, 0.15)',
              border: '1px solid var(--color-error)',
              color: 'var(--color-error)',
              padding: 14,
              marginBottom: 16,
              borderRadius: 4,
              fontSize: 13
            }}>
              {error}
            </div>
          )}

          {/* SEND MODE */}
          {mode === 'send' && (
            <>
              {/* Send Subsection Navigation */}
              <div style={{
                display: 'flex',
                gap: 8,
                marginBottom: 16,
                borderBottom: '1px solid var(--color-border-secondary)',
                paddingBottom: 8
              }}>
                <button
                  onClick={() => setSendView('create')}
                  className={sendView === 'create' ? 'tab tab-active' : 'tab'}
                  style={{ fontSize: 13 }}
                >
                  Create New
                </button>
                <button
                  onClick={() => setSendView('queue')}
                  className={sendView === 'queue' ? 'tab tab-active' : 'tab'}
                  style={{ fontSize: 13 }}
                >
                  Outbound Queue
                </button>
              </div>

              {sendView === 'create' && <SendCreate onTransactionCreated={handleTransactionCreated} />}
              {sendView === 'queue' && <SendQueue onError={handleError} />}
            </>
          )}

          {/* RECEIVE MODE */}
          {mode === 'receive' && <Receive onError={handleError} />}
        </div>
      </div>
    </div>
  )
}
