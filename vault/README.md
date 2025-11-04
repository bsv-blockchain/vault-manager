# BSV Vault Manager Frontend

This Vite + React application is the operator console that runs inside the air-gapped vault environment. It embeds the BSV TypeScript SDK to verify Atomic BEEF payloads, manage the encrypted vault state, and guide operators through dual-control ceremonies.

Refer to the repository-level [`README.md`](../README.md) for project context and the authoritative operational policies in [`MANUAL.md`](../MANUAL.md).

## Development Commands

- `npm run dev` — Launch the Vite dev server (default `http://localhost:8080`). Use only on a connected development workstation.
- `npm run build` — Produce the production bundle with separate assets in `build/`.
- `npm run build:single` — **Produce a single self-contained HTML file** for airgapped deployment (recommended for vault environments).
- `npm run build:dev` — Generate a non-minified build useful for debugging in production mode.
- `npm run preview` — Serve the last production build locally for smoke testing.

All production bundles must follow the clean-media, hashing, and transfer process documented in [Section 8 of the manual](../MANUAL.md#8-build-and-release-flow).

## Single-File Deployment for Airgapped Devices

The vault application can be bundled into a **single self-contained HTML file** (~650KB) for maximum portability and security on airgapped devices. This approach eliminates the need for web servers and simplifies transfer via USB, QR codes, or other physical media.

### Building the Single-File Bundle

```bash
# First, install dependencies if not already installed
npm install

# Build the single-file bundle
npm run build:single

# The output will be in: build/index.html
```

### Deploying to Airgapped Devices

**Method 1: USB Transfer (Recommended)**
```bash
# Copy the single HTML file to a clean USB drive
cp build/index.html /Volumes/USB_DRIVE/vault.html

# Transfer to the airgapped device
# Open the file directly in any modern browser
```

**Method 2: QR Code Transfer**
For devices without USB ports, you can encode the file as a QR code:
```bash
# Generate base64 encoding
base64 build/index.html > vault.b64

# Use a QR code generator to encode in chunks if needed
# Scan on the airgapped device and decode
```

**Method 3: Local Web Server**
If the `file://` protocol has restrictions (e.g., camera access):
```bash
# On the airgapped device, serve locally with Python
cd build
python3 -m http.server 8080

# Access via: http://localhost:8080
```

### Features & Requirements

**✅ Fully Offline:**
- Zero network dependencies
- All JavaScript, CSS, and assets inlined
- BSV SDK fully embedded (~459KB)
- QR scanner worker inlined

**✅ Browser Compatibility:**
- Works on modern Chrome, Firefox, Safari, Edge
- Supports both desktop and mobile browsers
- Requires modern ES6+ JavaScript support

**⚠️ Browser Permissions:**
- **Camera Access:** Required for QR code scanning. Some browsers may require HTTPS or localhost for camera API access.
- **localStorage:** Required for vault persistence. Enabled by default in most browsers.
- **File API:** Required for vault file import/export. Universally supported.

**💾 Storage:**
- All vault data stored in browser's localStorage
- No IndexedDB or external storage
- Data persists between sessions
- Keys: `bsvvault:last-hashes`, `bsvvault:backups`

### Security Considerations

1. **Hash Verification:** Always verify the SHA-256 hash of `index.html` before deployment
2. **Clean Media:** Use freshly formatted USB drives for transfers
3. **Browser Security:** Keep browsers updated on the airgapped device
4. **Private Browsing:** Consider using private/incognito mode to ensure no cloud sync
5. **Clear on Exit:** For maximum security, clear browser data after vault operations

### Troubleshooting

**Problem:** Camera doesn't work when opening the file directly
- **Solution:** Serve the file via localhost (`python3 -m http.server 8080`)
- **Reason:** Some browsers restrict camera access to HTTPS or localhost only

**Problem:** Vault data doesn't persist
- **Solution:** Ensure localStorage is enabled in browser settings
- **Solution:** Don't use private/incognito mode if you want data to persist

**Problem:** File size seems too large
- **Expected:** ~650KB is normal due to base64 encoding overhead
- **Note:** The @bsv/sdk library accounts for most of the size

### File Size Breakdown

| Component | Size |
|-----------|------|
| JavaScript (bundled) | ~612KB |
| CSS (inlined) | ~8KB |
| QR Scanner Worker | ~57KB |
| HTML Overhead | ~5KB |
| **Total** | **~680KB** |

This is well within acceptable limits for USB or secure transfer methods.
