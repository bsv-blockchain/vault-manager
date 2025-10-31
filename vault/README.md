# BSV Vault Manager Frontend

This Vite + React application is the operator console that runs inside the air-gapped vault environment. It embeds the BSV TypeScript SDK to verify Atomic BEEF payloads, manage the encrypted vault state, and guide operators through dual-control ceremonies.

Refer to the repository-level [`README.md`](../README.md) for project context and the authoritative operational policies in [`MANUAL.md`](../MANUAL.md).

## Development Commands

- `npm run start` — Launch the Vite dev server (default `http://localhost:5173`). Use only on a connected development workstation.
- `npm run build` — Produce the production bundle placed in `frontend/build/`. Add `-- --base ./` when preparing artifacts for removable media.
- `npm run build:dev` — Generate a non-minified build useful for debugging in production mode.
- `npm run preview` — Serve the last production build locally for smoke testing.

All production bundles must follow the clean-media, hashing, and transfer process documented in [Section 8 of the manual](../MANUAL.md#8-build-and-release-flow).
