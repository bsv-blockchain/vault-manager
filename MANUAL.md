# BSV Vault Operator's Manual

Release Candidate — October 16, 2025  
Maintainer: Peer-to-Peer Privacy Systems Research, LLC

---

## How to Use This Manual

- Audience: operations leads, custodians, and auditors responsible for BSV cold-vault sessions.
- Read Part I once to absorb the threat model and protocol fundamentals; keep Parts II–IV at hand during ceremonies.
- Appendix A surfaces the checklists you need in the room; Appendix B contains the scripts we read aloud on camera.
- The React application that enforces these procedures is documented in `README.md`; this manual describes the physical, human, and evidentiary controls that surround it.
- When you change policy or software, update the relevant sections and re-issue the manual with a new version tag.

## Table of Contents

- [Part I: Foundation](#part-i-foundation)
  - [1. Scope and Goals](#1-scope-and-goals)
  - [2. Protocol Fundamentals](#2-protocol-fundamentals)
- [Part II: Environment Hardening](#part-ii-environment-hardening)
  - [3. Facility Controls](#3-facility-controls)
  - [4. Air-Gapped Workstations](#4-air-gapped-workstations)
  - [5. Removable Media Workflow](#5-removable-media-workflow)
  - [6. Credentials and Secret Storage](#6-credentials-and-secret-storage)
- [Part III: Software Supply Chain](#part-iii-software-supply-chain)
  - [7. Header Sources and SPV Inputs](#7-header-sources-and-spv-inputs)
  - [8. Build and Release Flow](#8-build-and-release-flow)
- [Part IV: Vault Operations](#part-iv-vault-operations)
  - [9. Session Preparation](#9-session-preparation)
  - [10. Receiving Atomic BEEF](#10-receiving-atomic-beef)
  - [11. Building and Signing Outbound Transactions](#11-building-and-signing-outbound-transactions)
  - [12. Saving, Hashing, and Archiving](#12-saving-hashing-and-archiving)
  - [13. Incident Response and Recovery](#13-incident-response-and-recovery)
- [Part V: Governance and Auditing](#part-v-governance-and-auditing)
  - [14. Staffing and Oversight](#14-staffing-and-oversight)
- [Appendices](#appendices)
  - [Appendix A: Quick Reference Checklists](#appendix-a-quick-reference-checklists)
  - [Appendix B: Ceremony Scripts](#appendix-b-ceremony-scripts)
  - [Appendix C: Reference Specifications and Rationales](#appendix-c-reference-specifications-and-rationales)

---

## Part I: Foundation

### 1. Scope and Goals

The vault exists to sign and preserve Bitcoin SV transactions with the same repeatability as an aircraft pre-flight. This manual sets the minimum standard for:

- Maintaining a physically isolated signing environment with evidentiary controls.
- Enforcing Simplified Payment Verification (SPV) using independent block headers before money moves.
- Ensuring every ingress and egress uses Atomic BEEF so proofs travel with the transaction.
- Capturing tamper-evident logs, hashes, and operator attestations for every step.

Everything described here is mandatory unless a change is recorded, reviewed, and re-issued as a new manual revision.

### 2. Protocol Fundamentals

A cold vault is ultimately an SPV engine. The software uses the BSV TypeScript SDK to enforce the following standards end to end:

- **SPV — BRC-67.** Transactions are trusted only when their Merkle path recomputes the block root and the root matches a header you obtained independently.[brc-67]
- **BUMP — BRC-74.** All Merkle paths arrive in the BUMP format, letting the SDK verify multiple transaction proofs from the same block in a consistent structure.[brc-74]
- **BEEF — BRC-62.** BEEF containers bundle a subject transaction, its ancestors, and the proofs you need to validate inputs locally. Hex payloads are versioned with `0100BEEF` by design.[brc-62]
- **Atomic BEEF — BRC-95.** Operations demand Atomic BEEF so every artifact pertains to exactly one subject transaction. Incoming artifacts are rejected unless they meet this stricter envelope; outgoing artifacts are exported in the same format.[brc-95]
- **SDK trust, but verify.** We lean on `@bsv/sdk` APIs such as `Transaction.fromBEEF`, `verify`, and `ChainTracker` to parse proofs, but operators confirm the headers on camera and record the sources used.[sdk-docs]

Key takeaway: if the Merkle root does not match your headers from at least two sources, the vault session stops.

---

## Part II: Environment Hardening

### 3. Facility Controls

- Select a lockable room where you control sightlines, cables, and lighting. Avoid public-facing windows; if unavoidable, apply opaque film or blinds.[tempest]
- Keep the space RF-quiet: remove unused antennas, disable wireless gear, and position sensitive screens away from exterior walls. Light shielding or a grounded rack can provide 60–100 dB attenuation when needed.[tempest]
- Only approved equipment enters the room. Phones stay outside, indicator LEDs can be covered, and any external visitors are logged.
- All sessions run under the two-person rule: no critical action (media handling, password entry, signing, certifications) happens without two trained operators present from unlock to relock.[two-person]

### 4. Air-Gapped Workstations

- Provision two identical laptops (primary and hot spare) that will never touch a network. Install the OS from a known-good, offline image and disable radios in firmware when possible.[wired-airgap]
- Maintain a build history for each machine: installation media hash, date of provisioning, firmware versions, and any applied patches.
- Record BIOS/UEFI passwords and tamper-evident seals in the logbook. Break a seal only on camera with dual signatures authorizing the action.
- Remember that air gaps reduce attack surface but do not eliminate it. Media remains the likely infection path; vigilance around USB handling is mandatory.[wired-led]

### 5. Removable Media Workflow

- Maintain separate, serialized inventories for `IN` (toward the air gap) and `OUT` (away from the air gap) drives. Color-code and lock them when not in use.
- Before a drive enters the vault, scan it on a dedicated staging workstation with current signatures. Disable autorun everywhere and keep the scanner itself off production networks when inactive.[splunk]
- Prefer hardware write-protect toggles when media only needs to be read. Set the switch before crossing the air gap.[industrial-cyber]
- When media changes trust zones or is retired, sanitize it following NIST SP 800-88 guidance (crypto-erase for SSDs, verified overwrites for spinning disks). Record the method, tool, operator, and result.[nist-800-88]
- Treat detachable batteries and firmware on USB devices as potential attack vectors. Acquire media from reputable suppliers and inspect housings regularly.

### 6. Credentials and Secret Storage

- Passphrases must be at least 12 characters; in practice we recommend memorable 16–20+ character phrases aligned with modern NIST guidance favoring length over complexity tricks.[nist-63b]
- The application enforces a minimum of 80,000 PBKDF2 rounds. Evaluate higher values periodically and document your chosen parameter.
- Password composition ceremonies happen in the vault with Operator A typing and Operator B eyes-on verifying; cameras record compliance, not the secret itself.
- If you must escrow the passphrase, use a t-of-n Shamir Secret Sharing scheme and store each share in separately controlled safes. Reconstruction takes place only during documented continuity exercises with dual control.[shamir]

---

## Part III: Software Supply Chain

### 7. Header Sources and SPV Inputs

- Maintain two independent header sources (for example, a curated local header set and a second provider you snapshot at session start).
- Record the height and hash obtained from each source on camera at the start of every session. Keep screenshots or printed outputs alongside the session log.
- For every BUMP proof relied upon, derive the Merkle root locally and match it against both header sources. Any mismatch halts the session pending investigation.[brc-74][brc-67]

### 8. Build and Release Flow

All software provisioning happens on a network-connected build workstation that never enters the air-gapped room.

#### 8.1 Prepare the Build Workstation

1. Install Node.js 20.19+ (or 22.12+) and npm 10+. Verify versions with `node --version` and `npm --version`.
2. Clone or update the repository. Record commit IDs for each build you promote.

#### 8.2 Produce an Offline Bundle

1. From the repository root, run `npm ci` if you maintain the top-level automation scripts.
2. `cd frontend`
3. `npm ci`
4. `npm run build -- --base ./` to emit a static bundle under `frontend/build/`.

#### 8.3 Verify Artifacts

1. Optionally smoke-test the bundle using `npm run preview`, but do not connect the machine to production networks.
2. Generate hashes inside `frontend/build/`:  
   `shasum -a 256 * assets/* > SHA256SUMS.txt`
3. Record the SHA-256 of the entire bundle (zip or directory) in the build logbook and have two operators sign off.

#### 8.4 Transfer into the Air Gap

1. Copy the `frontend/build/` contents and `SHA256SUMS.txt` to an `IN` drive that already passed the scanning workflow.
2. Seal the drive with tamper tape, annotate the chain-of-custody log, and escort it to the vault.
3. Inside the vault, verify the recorded hashes before use. Serve the bundle using a local-only HTTP server (for example, `python3 -m http.server 4173`) or equivalent offline kiosk.

---

## Part IV: Vault Operations

### 9. Session Preparation

- Two authorized operators unlock the room, start video recording, and sweep the area for unauthorized devices. Phones and smart watches remain outside.
- Document the session purpose, date, time, operator names, and vault revision in the logbook and on camera.
- Stage sanitized `IN` and `OUT` drives within sight. Read their serial numbers aloud.
- Reconfirm header sources (Section 7) and note the heights and hashes on camera.
- Load the vault file from the most recent certified media, verify its SHA-256 against the sealed checksum card, and document the match before decrypting.

### 10. Receiving Atomic BEEF

1. Obtain Atomic BEEF hex from the payer both on paper and on an `IN` drive.
2. Import or paste the payload into the application. The SDK validates the structure and recomputes the Merkle root.
3. On camera, confirm that the computed root matches both header sources. Any failure results in immediate rejection and a log entry.[sdk-example]
4. Review the outputs that target your keys, annotate memos, and approve only the ones that comply with policy.
5. Mark the transaction as “processed” only after it reaches your required confirmation depth; record the height and evidence used.
6. Merge the BEEF into the vault store, save a new vault revision, and certify the hash as described in Section 12.

### 11. Building and Signing Outbound Transactions

1. Define destination outputs (script or address, sats, memo) and capture approvals on camera.
2. Manually select inputs. If a parent transaction is unprocessed, the software warns you; resolve before proceeding unless you intentionally spend zero-conf.
3. Choose fresh change keys. Reuse is discouraged and flagged in the UI.
4. Perform per-UTXO attestations when policy requires it—both operators confirm the input’s on-chain state and sign the attestation log.
5. Build fees and sign. The application exports Atomic BEEF to an `OUT` drive; treat this as the authoritative artifact for downstream broadcast.
6. Mark the transaction “pending” until you receive independent confirmation it was mined. Update memos with the block height and proof sources.

### 12. Saving, Hashing, and Archiving

- After any state change (incoming, outgoing, rotation), save the vault file and compute its SHA-256. Operator A reads the hash aloud; Operator B verifies and repeats it.
- Record the hash in the session log, print or hand-write it on a checksum card, and seal the card in an envelope stored separately from digital media.
- Retire prior vault revisions immediately. Follow NIST SP 800-88 sanitization guidance to destroy or sanitize superseded media and log the action.[nist-800-88]
- Export session logs, vault logs, and any supporting attachments to an `OUT` drive. Print representative pages for the physical binder.

### 13. Incident Response and Recovery

- Quarantine any `IN` drive that fails scanning or triggers antivirus during the session. Bag it, label it, and film the chain of custody for forensic review.
- If an outgoing artifact repeatedly fails validation downstream, treat the signing workstation as potentially compromised. Halt operations, export logs, and re-image the machine from a known-good offline installer.
- Document every anomaly in the incident ledger and escalate to leadership. Resume normal operations only after the root cause is identified and mitigated.

---

## Part V: Governance and Auditing

### 14. Staffing and Oversight

- Maintain an operator roster with background checks proportional to assets under custody. Train alternates and require periodic cross-checks.
- Enforce forced vacation policies so no operator controls the vault without peer observation for extended periods.
- Schedule at least one third-party audit annually. Auditors should observe a full session, spot-check logs, and attempt a red-team walkthrough of procedures.
- Update training materials whenever the software or manual changes. Operators attest in writing that they read the latest revision before their next session.

---

## Appendices

### Appendix A: Quick Reference Checklists

**Session Opening**

1. Room secured, video recording started.  
2. Operators A & B present; phones removed.  
3. Header sources queried; heights and hashes recorded.  
4. `IN`/`OUT` drives verified and serials logged.  
5. Vault file hash matched against sealed checksum card.

**Incoming Atomic BEEF**

1. Payload imported from paper and `IN` drive.  
2. Merkle root matches Source A and Source B.  
3. Outputs reviewed, memos updated, approvals recorded.  
4. Required confirmations reached; proofs captured.  
5. Vault saved, hash certified, prior media sanitized.

**Outgoing Transaction**

1. Destination scripts and amounts approved.  
2. Inputs and change keys selected; reuse warnings resolved.  
3. Per-UTXO attestations signed.  
4. Atomic BEEF exported to `OUT` drive.  
5. Vault saved, pending status noted pending confirmations.

**Vault Save & Certification**

1. SHA-256 computed and read aloud by both operators.  
2. Hash recorded in logbook and on checksum card.  
3. Card sealed separately from media.  
4. Previous revision destroyed per NIST SP 800-88.  
5. Logs exported to `OUT` drive and binder updated.

### Appendix B: Ceremony Scripts

Use these verbatim reads on camera to anchor your evidence record.

- **Session open:**  
  “Session start. Date/time: ___. Operators A and B present. Purpose: ___. Room swept, phones outside, air-gap verified. Media staging complete; `IN` drive serial ___ inspected and scanned. Proceeding.”
- **Incoming BEEF:**  
  “Atomic BEEF for TXID ___ loaded. SPV verification succeeded against header source A height ___ and source B height ___. Outputs matched to keys: ___. Admitting vout(s) ___ as per policy.”
- **Outgoing sign:**  
  “Outputs reviewed. Inputs selected: ___. Change keys: ___. Per-UTXO attestations performed (Yes/No). Transaction signed; Atomic BEEF exported to `OUT` drive serial ___. Pending processed confirmation.”
- **Save & certify:**  
  “Saving vault rev ___. SHA-256: ___. Dual entry matched. Old rev sealed for destruction per 800-88; destruction scheduled.”

### Appendix C: Reference Specifications and Rationales

- [BRC-62 — Background Evaluation Extended Format][brc-62]: container for subject transactions, ancestors, and proofs. Recognizable by the `0100BEEF` version word.
- [BRC-67 — Simplified Payment Verification][brc-67]: defines the Merkle-path verification model underpinning every acceptance decision.
- [BRC-74 — BSV Unified Merkle Path][brc-74]: standard proof format for verifying multiple transaction paths per block.
- [BRC-95 — Atomic BEEF][brc-95]: enforces single-subject scope for proofs you import or export.
- [BSV TypeScript SDK documentation][sdk-docs] and [Atomic BEEF verification example][sdk-example]: APIs used by the application for parsing, verifying, and exporting proofs.
- [TEMPEST/EMSEC overview][tempest]: public guidance on limiting emanations.
- [USB threat advisories][industrial-cyber] and [air-gap case studies][wired-airgap][wired-led]: reminders that removable media remains the likeliest attack vector.
- [NIST SP 800-63B password guidance][nist-63b] and [NIST SP 800-88 media sanitization guidance][nist-800-88]: normative references for password policy and data destruction.
- **Operational rationales:**
  - *Atomic BEEF only:* reducing ambiguity keeps audits simple and limits the blast radius of malformed inputs.
  - *Video evidence:* a continuous recording provides a tamper-evident chain of custody for people, media, and procedures.
  - *No auto-broadcast:* the vault is for authoritative signing and evidence gathering; broadcasting remains a networked function outside the air gap.
  - *Strict media lifecycle:* USB-borne malware still exists; kiosks, scanning, and sanitization are your firewall.

---

[brc-62]: https://bsv.brc.dev/transactions/0062?utm_source=chatgpt.com "Background Evaluation Extended Format (BEEF) Transactions"
[brc-67]: https://raw.githubusercontent.com/bitcoin-sv/BRCs/master/transactions/0067.md?utm_source=chatgpt.com "Simplified Payment Verification"
[brc-74]: https://bsv.brc.dev/transactions/0074?utm_source=chatgpt.com "BSV Unified Merkle Path (BUMP) Format"
[brc-95]: https://bsv.brc.dev/transactions/0095?utm_source=chatgpt.com "Atomic BEEF Transactions"
[sdk-docs]: https://docs.bsvblockchain.org/guides/sdks/ts?utm_source=chatgpt.com "TypeScript SDK — BSV Skills Center"
[sdk-example]: https://docs.bsvblockchain.org/guides/sdks/ts/examples/example_verifying_beef?utm_source=chatgpt.com "Verifying a BEEF Structure"
[tempest]: https://en.wikipedia.org/wiki/Tempest_%28codename%29?utm_source=chatgpt.com "TEMPEST"
[two-person]: https://en.wikipedia.org/wiki/Two-person_rule?utm_source=chatgpt.com "Two-person rule"
[wired-airgap]: https://www.wired.com/2014/12/hacker-lexicon-air-gap?utm_source=chatgpt.com "Hacker Lexicon: What Is an Air Gap?"
[wired-led]: https://www.wired.com/2017/02/malware-sends-stolen-data-drone-just-pcs-blinking-led?utm_source=chatgpt.com "Malware Lets a Drone Steal Data by Watching a Computer's Blinking LED"
[splunk]: https://www.splunk.com/en_us/blog/learn/cis-critical-security-controls.html?utm_source=chatgpt.com "CIS Critical Security Controls"
[industrial-cyber]: https://industrialcyber.co/nist/nist-publication-warns-that-usb-devices-pose-serious-cybersecurity-threats-to-ics-offers-guidance-for-mitigation/?utm_source=chatgpt.com "USB Device Threat Advisory"
[nist-800-88]: https://csrc.nist.gov/pubs/sp/800/88/r1/final?utm_source=chatgpt.com "SP 800-88 Rev.1 Guidelines for Media Sanitization"
[nist-63b]: https://pages.nist.gov/800-63-3/sp800-63b.html?utm_source=chatgpt.com "NIST SP 800-63B Digital Identity Guidelines"
[shamir]: https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf?utm_source=chatgpt.com "How to Share a Secret"
