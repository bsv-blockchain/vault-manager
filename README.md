# Vault Manager

Offline-first tooling for operating a high-assurance Bitcoin SV cold vault. The application keeps signing decisions inside an air gap, enforces SPV with operator-supplied headers, and requires Atomic BEEF for every transaction artifact.

## Quick Links

- [Operator’s Manual](MANUAL.md) — definitive operational policy.
- [Room-ready checklists](MANUAL.md#appendix-a-quick-reference-checklists) — bring these into the vault.
- [Build flow for air-gapped delivery](#build-for-air-gapped-delivery).

## System Highlights

- **Deterministic SPV:** The TypeScript vault engine implements `ChainTracker` so incoming/outgoing flows are accepted only after Merkle proofs match independently sourced headers.
- **Atomic BEEF everywhere:** Every ingress and egress uses BRC-95 containers, keeping proofs attached to the subject transaction for auditability.
- **Evidence-driven UX:** Two-person controls, attestation prompts, and checksum workflows align with the Operator’s Manual.
- **Offline bundle:** React/Vite frontend produces a static build that runs from removable media with zero outbound networking.

## Repository Layout

- `frontend/` — Vite + React source, tests, and build tooling.
- `frontend/build/` — Generated static bundle to transfer into the vault.
- `MANUAL.md` — Operational playbook governing facilities, ceremonies, and governance.
- `deployment-info.json` — Deployment metadata used by the automation toolchain.
- `package.json` (root) — Wrapper scripts for the BSV automation stack.

## Development Setup

1. Install Node.js 20.19+ (or 22.12+) and npm 10+ on a networked workstation.
2. Clone this repository and install dependencies:

```bash
cd frontend
npm ci
```

3. Start the dev server only on non-air-gapped machines:

```bash
npm run start
```

Use `npm run build:dev` for debugging builds and `npm run preview` to serve the latest production bundle locally.

## Build for Air-Gapped Delivery

These steps mirror Section 8 of the Operator’s Manual and should be recorded in your build logbook.

1. From the repository root run `npm ci` if top-level scripts are needed, then `cd frontend`.
2. `npm ci`
3. `npm run build -- --base ./` to emit a static bundle at `frontend/build/`.
4. Optionally dry-run with `npm run preview` (still on a connected workstation).
5. Generate hashes inside `frontend/build/` and store them with the bundle:

```bash
cd build
shasum -a 256 * assets/* > SHA256SUMS.txt
```

6. Copy the bundle and hash file to a pre-scanned `IN` drive, seal it, and follow the removable-media process described in the manual.
7. Inside the vault, verify hashes before loading the UI and serve it via an approved offline static server (for example, `python3 -m http.server 4173`).

## Operational Guardrails

- Always operate with two-person control, active video recording, and serialized media, per [Part II](MANUAL.md#part-ii-environment-hardening).
- Supply at least two header sources every session; reject any BEEF that cannot be verified against both, per [Section 7](MANUAL.md#7-header-sources-and-spv-inputs).
- Treat the manual as the source of truth for password policy, incident response, and governance; keep the README and manual updated together when procedures change.

## License

Open BSV
