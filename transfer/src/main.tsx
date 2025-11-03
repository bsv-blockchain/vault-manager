import React, { useMemo } from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { WalletContext } from './context/wallet'
import { TransactionProvider } from './context/transactions'
import { WalletClient } from '@bsv/sdk'

function Root() {
  const wallet = useMemo(() => new WalletClient(), [])

  return (
    <WalletContext.Provider value={wallet}>
      <TransactionProvider wallet={wallet}>
        <App />
      </TransactionProvider>
    </WalletContext.Provider>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
)
