# BSV Vault Manager Suite

This is a comprehensive, self-contained React application for a high-security BSV Vault Manager. It's designed to function as a software-based "cold wallet" or secure storage system that operates with a high degree of manual control and user verification, minimizing online attack surfaces.

## Core Purpose & Philosophy

The system's primary goal is to securely manage BSV private keys and the coins (UTXOs) they control. Its design philosophy is built around maximum user sovereignty and security, achieved through several key principles:

- No Network Communication: The application itself makes no external network calls. It does not connect to a Bitcoin node, blockchain explorer, or any third-party API. All blockchain information is provided manually by the user. This is a core feature of an "air-gapped" or offline wallet design.
- User as the Oracle: The user is responsible for providing critical blockchain state information, such as the current block height and the validity of Merkle roots for SPV (Simplified Payment Verification). The application prompts the user to confirm this data rather than trusting an external source.
- Portable, Encrypted Vault File: The entire state of the vault—including all private keys, transaction history, UTXO set, known-good headers, and logs—is stored in a single, portable .vaultfile. This file is encrypted using a password-derived key (PBKDF2), making it secure at rest.
- Atomic BEEF for Transactions: The system exclusively uses Atomic BEEF (BRC-95) for importing and exporting transactions. BEEF is a format that bundles a transaction with Merkles proofs on all input transactions, allowing for complete, offline SPV verification.
- Performative Certification: When saving the vault, the system forces the user through a multi-step confirmation process. This isn't just a simple "Save" button; it requires the user to certify that they have stored the new file securely, recorded its hash for future integrity checks, and deleted old versions. This enforces good security hygiene.
- Detailed Auditing: Every significant action is logged. There is a permanent vaultLog (for actions like key generation and settings changes) and an ephemeral sessionLog (for actions within the current session). This provides a forensic trail.

## Breakdown of Key Components

1. **The Vault Class**

This is the "brain" or the backend logic of the entire application. It is a plain TypeScript class that encapsulates all the state and functionality. It holds all critical data:

- `keys`: An array of KeyRecord objects, each containing a private key, public key, and metadata.

- `coins`: The set of unspent transaction outputs (UTXOs) the vault can spend.

- `beefStore`: A global store of all known transactions and their proofs in BEEF format.

- `transactionLog`, `vaultLog`, `sessionLog`: For history and auditing.

### Cryptography & Security

The `Vault` class:

- Handles password derivation using PBKDF2 to create a SymmetricKey.
- Encrypts the entire vault state for saving and decrypts it upon loading.
- Generates new PrivateKeys.

### Blockchain Logic (as a ChainTracker)

Implements the ChainTracker interface from the `@bsv/sdk`.

- Instead of looking up data online, it prompts the user for confirmation of Merkle roots (isValidRootForHeight) and the current block height (currentHeight).

### Transaction Management

- `processIncoming`: Validates an incoming Atomic BEEF transaction, verifies its SPV proof against user-confirmed data, and adds the new coins to the vault.

- `buildAndSignOutgoing`: A powerful function that constructs a new transaction from user-selected inputs and outputs, calculates fees, handles change, signs it with the correct private keys, and exports it as a new Atomic BEEF file.

2. **The UI System (Lightweight & Secure)**

We define a custom, dependency-free UI and dialog system.

Components: NotificationBanner, Modal, and a full DialogProvider for alert, confirm, and prompt dialogs.

Security Focus: By avoiding native browser dialogs (window.alert, etc.), the application maintains full control over the user interface, preventing potential phishing or spoofing attacks that might somehow exploit browser-level UI.

3. **The React Application (App and Panels)**

This is the frontend that provides a user interface for the Vault class.

Dashboard Panel: Shows the total balance, a list of current UTXOs, and the transaction history.

Key Manager: Allows the user to generate new keys and download "deposit slips" (text files with the key's public information and address).

Incoming Manager: Provides an interface to paste an Atomic BEEF hex string to process incoming funds.

Outgoing Wizard: A crucial multi-step process for building a transaction:

Define Outputs: Specify destination addresses/scripts and amounts.

Select Inputs: Manually select which of the vault's UTXOs to spend.

Choose Change: Select which key(s) should receive any leftover change.

Review & Sign: Review the complete transaction details before signing.

Result: Get the final, signed Atomic BEEF transaction, ready to be broadcast by an external tool.

Logs Panel: Displays the permanent vault log and the temporary session log.

Settings Panel: Allows tweaking of security policies, like whether to require manual attestation for incoming/outgoing UTXOs.

## License

Open BSV