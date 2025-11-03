# Vault Transfer App

A sleek, institutional-themed transaction management app for BSV blockchain transfers. Features Send and Receive modes with animated QR code support for transmitting AtomicBEEF transactions.

## Features

### Send Mode
- Define multiple transaction outputs (addresses and amounts)
- Scan QR codes for addresses using camera
- Create transactions using WalletClient.createAction
- Display AtomicBEEF as animated chunked QR codes (for large transactions)
- Institutional dark theme matching Vault Manager

### Receive Mode
- Generate receive addresses using BRC-42 derivation (date-based)
- Display address as QR code for easy sharing
- Scan animated QR codes from Vault Manager
- Internalize incoming transactions using WalletClient.internalizeAction

## Setup

1. Install dependencies:
```bash
npm install
```

2. Run development server:
```bash
npm run dev
```

The app will be available at `http://localhost:3001`

3. Build for production:
```bash
npm run build
```

## Integration with Wallet

**IMPORTANT**: This app requires a `WalletInterface` implementation to function. The current implementation includes placeholder code that needs to be replaced with your actual wallet integration.

### Required Changes

1. **Create/Import WalletInterface**: Replace the placeholder wallet initialization with your actual WalletInterface implementation:

```typescript
// In App.tsx, replace the demo implementation with:
import { WalletClient } from '@bsv/sdk'
import { yourWalletInterface } from './your-wallet-implementation'

const wallet = new WalletClient(yourWalletInterface, 'transfer.app')
```

2. **Send Mode Integration**: Uncomment and use the real `createAction` implementation in `handleCreateTransaction`:

```typescript
const result = await wallet.createAction({
  description: 'BSV Transfer Transaction',
  outputs: actionOutputs,
  labels: ['transfer', 'outbound']
})

setBeefTxid(result.txid)
// Get the actual BEEF hex from your wallet implementation
const tx = await wallet.getTransaction({ txid: result.txid })
setBeefHex(tx.beef)
```

3. **Receive Mode Integration**: Uncomment and use the real `getPublicKey` implementation in `handleGenerateReceiveAddress`:

```typescript
const { publicKey } = await wallet.getPublicKey({
  protocolID: [2, '3241645161d8'],
  keyID: derivationPrefix + ' ' + derivationSuffix,
  counterparty: 'anyone',
  forSelf: true
})
const address = PublicKey.fromString(publicKey).toAddress()
setReceiveAddress(address)
```

4. **Internalize Transaction**: Uncomment and use the real `internalizeAction` implementation in `handleReceiveQRScan`:

```typescript
await wallet.internalizeAction({
  tx: data, // Atomic BEEF hex from scanned QR
  description: 'Received BSV via Transfer',
  outputs: [{
    outputIndex: 0, // Determine from parsing the transaction
    protocol: 'wallet payment',
    paymentRemittance: {
      senderIdentityKey: senderPublicKey,
      derivationPrefix,
      derivationSuffix
    }
  }],
  labels: ['transfer', 'inbound']
})
```

## QR Code System

The app uses the same chunked QR code system as the Vault Manager:

- **Chunking**: Data >100 characters is split into 80-character chunks
- **Format**: `CHUNK:id:index:total:data`
- **Animation**: 200ms interval cycling through chunks
- **Scanning**: Automatic chunk collection and reassembly

This allows transmission of large AtomicBEEF transactions via QR codes between Transfer app and Vault Manager.

## Usage with Vault Manager

### Sending to Vault Manager

1. Open Transfer app in Send mode
2. Define outputs (address, amount, memo)
3. Create transaction
4. Display as QR Code (animated if large)
5. Scan with Vault Manager's "Process Incoming Atomic BEEF" scanner

### Receiving from Vault Manager

1. Open Transfer app in Receive mode
2. Generate receive address
3. Share address QR with sender (or paste into Vault Manager)
4. When Vault Manager creates outgoing transaction, scan the BEEF QR
5. Transaction is internalized into your wallet

## Styling

Uses the same institutional dark theme as Vault Manager:
- Dark graphite background (#0f1216, #1a1d24)
- Gold accents (#c9a961)
- Metallic highlights
- Precise typography with Inter font
- Swiss vault aesthetic

## Tech Stack

- React 19
- TypeScript
- @bsv/sdk for blockchain operations
- qrcode for QR generation
- qr-scanner for camera scanning
- Vite for build tooling

## Development

The app runs on port 3001 by default to avoid conflicts with Vault Manager (port 3000).

```bash
# Development
npm run dev

# Build
npm run build

# Preview production build
npm run preview
```

## Notes

- Ensure camera permissions are granted for QR scanning
- For real-world use, implement proper WalletInterface
- Test QR transmission with Vault Manager for end-to-end flows
- BRC-42 derivation uses date-based key IDs for privacy
