# BSV Vault Operator’s Manual

DRAFT — NOT APPROVED FOR USE

**Version 1 — October 16, 2025**
**Author:** Peer-to-Peer Privacy Systems Research, LLC

---

## 0) What this manual is (and isn’t)

This is the canonical, end-to-end playbook for running a high-assurance BSV cold-vault using SPV proofs and Atomic BEEF. It starts with the conceptual bedrock (SPV, BEEF/BUMP/Atomic BEEF, and how the TypeScript SDK enforces those rules), then codifies the physical and operational security that keeps your funds safe: how to choose and harden a room, buy and prepare air-gapped machines, move files via clean media, verify block headers from more than one source, run two-person procedures, film and audit sessions, and keep ironclad logs. After the foundation, you’ll get exact procedures for every vault task you’ll actually do: creating a vault, generating keys, receiving with Atomic BEEF, building and signing outbound, exporting and certifying files, rotating passwords, and exporting logs. The goal is boring, reproducible excellence.

Nothing here is hand-wavy. Where standards exist, we cite them and align the procedures. For BSV internals and the SDK, we reference the BRC specifications and the official SDK docs and examples. ([bsv.brc.dev][1])

---

## 1) Background you must internalize

### 1.1 SPV, Merkle paths, BUMP, BEEF, and Atomic BEEF — how they fit together

**SPV (BRC-67)** defines how a light client verifies that specific transactions really made it into specific blocks by validating Merkle paths against an independently obtained block-header chain. In a vault, “independent” means *not* trusting the sender or a single server; you bring your own header set or verify with at least two sources. ([GitHub][2])

**BUMP (BRC-74)** is the *unified* Merkle path format used across BSV. It standardizes how proofs are encoded and checked. Your software takes the BUMP path, recomputes the Merkle root, and then checks that root against a known-good header at a given height. ([bsv.brc.dev][3])

**BEEF (BRC-62)** is a compact container that bundles a subject transaction, its ancestors, and the Merkle paths needed to verify all inputs — the full validation payload without schlepping the entire chain. It’s designed so anyone who receives it can do SPV locally. In hex, you’ll recognize it by the `0100BEEF` little-endian version word. ([bsv.brc.dev][1])

**Atomic BEEF (BRC-95)** is a stricter variant that guarantees everything in the container pertains to one “subject transaction.” No unrelated baggage, no ambiguity; it’s the operationally clean artifact you will demand from payers and the exact thing you export when you build & sign. ([bsv.brc.dev][4])

**SDK reality check.** The BSV TypeScript SDK (`@bsv/sdk`) implements these ideas directly: you can deserialize BEEF/Atomic BEEF, resolve inputs, verify BUMP proofs using your header source via a `ChainTracker`, and sign P2PKH or custom scripts. The official examples show BEEF verification flows; the API includes helpers such as `Transaction.fromBEEF(...)`, `verify(...)`, `toAtomicBEEF()`, and the high-level primitives you’re already using in this app. ([docs.bsvblockchain.org][5])

Takeaway: your vault is a deterministic SPV engine. If the Merkle root checks out against your independent headers, and the script transitions are valid, you can accept incoming or construct outgoing — all without trusting anyone’s node.

---

## 2) Physical & environmental security (where “cold” really lives)

### 2.1 Location selection

Pick a room you can lock and control. You want: line-of-sight control of all ports and cables, no public windows, RF-quiet surroundings if possible, and space to film procedures. Your goal isn’t classified-grade TEMPEST, but you *do* care about emanations and shoulder-surfing. While formal TEMPEST levels are overkill for most, the public EMSEC guidance is clear: shielding, distance, and filtering reduce leakage. If you have neighbors on the other side of a thin wall, don’t put the air-gap there. ([Wikipedia][6])

### 2.2 EMF/EMSEC hygiene

At minimum: ferrite chokes on power leads, no unneeded antennas or wireless devices in the room, blinds or opaque film on windows, and keep sensitive screens away from exterior walls. If you want belt-and-suspenders, a modestly shielded enclosure or a grounded rack cabinet can deliver significant attenuation; public sources reference 60–100 dB insertion loss targets across broad bands for serious shielding. ([Wikipedia][6])

### 2.3 Two-person rule

Every vault session runs with two authorized operators present from unlock to relock. Neither person can complete a critical step alone (media access, password entry, file certification, signing). This practice is canon in COMSEC and other sensitive domains because it prevents single-actor compromise and mistakes. Use it. ([Wikipedia][7])

---

## 3) Air-gapped machines & removable media, done right

### 3.1 Air-gapped hardware

Acquire two identical laptops (primary and hot-spare) that will **never** touch a network. Wipe them and install a clean OS from a known-good offline image. Disable all radios in firmware if possible. The point isn’t magical immunity — Stuxnet proved media can bridge gaps — but controlled exposure. ([WIRED][8])

### 3.2 Clean-room USB workflow

You’ll move data via flash drives. That’s risk. Counter it with process:

* **Media lifecycle.** Keep “IN” drives (headed *into* the air-gap) separate from “OUT” drives. Color code them. Every drive is serialized in a logbook.
* **Scanning.** Before any “IN” drive touches an air-gapped machine, scan it on a standalone, sacrificial station with current AV and a *fully updated* signature set. Disable autorun everywhere. Consider a USB-scanning kiosk workflow if you have many sessions. ([Splunk][9])
* **Write protection.** Use hardware write-protect toggles where practical. When you only need to *read*, set the tab. ([Industrial Cyber][10])
* **Sanitization.** When a drive changes trust zones or is retired, sanitize it per NIST SP 800-88 — or the draft Rev.2 when finalized. Crypto-erase or vendor Secure Erase for SSDs; verify. Document the method and result. ([NIST Computer Security Resource Center][11])

Remember: malware can exfiltrate via sneaky channels (LEDs, ultrasound, RF). Keep phones out; cover indicator LEDs if needed; don’t face screens toward windows. ([WIRED][12])

---

## 4) Passwords, key derivation, and secrets splitting

### 4.1 Password policy and PBKDF2

The app enforces **≥12 chars** with upper/lower/digit/symbol, and a **minimum of 80,000 PBKDF2 rounds**. That’s fine; in practice we recommend *longer* passphrases (16–20+) composed for memorability, and no forced rotation absent evidence of compromise — consistent with modern NIST thinking that favors length over baroque complexity. For rounds, 80k is a sane floor in JavaScript contexts; raise it as performance allows. Document your chosen parameter. ([NIST Pages][13])

### 4.2 Shamir Secret Sharing (optional, for password escrow)

If you must escrow the vault passphrase for business continuity, use a (t, n) Shamir scheme with verifiable procedures for distributing shares and reconstructing only under dual control. Shamir’s 1979 construction is information-theoretically secure: *any* t shares recover, *fewer than t* reveal nothing. Do reconstruction only in controlled ceremonies, air-gapped, on throwaway hardware. ([Massachusetts Institute of Technology][14])

---

## 5) Header discipline: don’t trust; verify twice

Your SPV checks are only as good as your headers source. Maintain two independent ways to confirm the current tip height and the merkle root for a given height: e.g., a locally curated header set plus a second source you query during sessions. The point is to cross-check BUMP roots — “trust but verify” as a rule, not a slogan. ([GitHub][2])

---

## 6) The application model you’re running

The provided React/TypeScript application wraps the BSV TS SDK. A few design choices you should be mindful of:

* **Vault file:** Encrypted payload (PBKDF2 with a salt you generate on the air-gap). Your “plaintext” includes keys, coins, logs, settings, and a global BEEF store.
* **Keys:** Locally generated via device RNG, with an option to mix user entropy.
* **Incoming:** You **require** SPV-valid Atomic BEEF. The app extracts matches to your keys, verifies BUMP/headers via `ChainTracker`, and admits only what you select.
* **Outgoing:** You must hand-select inputs and change keys; the app signs, then **forces** you to export Atomic BEEF before marking as processed.
* **Logs:** Two classes — session (ephemeral) and vault (permanent). Both are text-exportable for audits.

All of this maps onto the SDK’s `Transaction`, `P2PKH`, `Beef`, and `ChainTracker` primitives, which implement BRC-62/67/74/95. ([docs.bsvblockchain.org][5])

---

## 7) Standard Operating Procedures (SOPs)

What follows is the exact choreography. Every session is filmed end-to-end, with a slate showing date, time, operators, and purpose. Two-person rule active throughout.

### 7.1 Commissioning the vault room (one-time)

Arrive with empty machines and new media still in packaging. Film the unboxing. Install OS from an offline image you prepared elsewhere. Disable radios in firmware. Apply window film or close blinds; position machines away from exterior walls. Label the room and cabinets. Place a printed checklist and a logbook on clipboards mounted by the door. (EMSEC notes above.) ([Wikipedia][6])

### 7.2 Preparing removable media (per batch)

On a networked *staging* box: download the app build and any documentation. Copy to a fresh “IN” USB drive. Scan it with two different engines. Apply a tamper-evident seal over the USB cap with the serial and hash manifest on the seal (QR okay). Log the drive ID.

On the sacrificial scanning station just outside the vault: rescan, confirm expected hashes. Break the seal on camera, read the serial aloud, and hand to Operator-B on the air-gap.

### 7.3 Creating a new vault (air-gap)

1. **Launch app.** Read the legal disclaimers.
2. **Name the vault** and set **PBKDF2 rounds** (≥80,000). Record these in the logbook. ([NIST Pages][13])
3. **Salt & randomness.** If you distrust device RNG, enable user-entropy and follow the two-prompt flow; mix both sources as the app does.
4. **Password ceremony.** Compose the passphrase verbally (no filming of keys), type by Operator-A, confirmed by Operator-B eyes-on. Record only password policy compliance, not the secret.
5. **Header policy.** Set persistence thresholds and re-verification cadence.
6. **Set two-person flags:** require attestations for incoming/outgoing coins.
7. **Record current block height** using independent sources and enter it. Videotape both sources in the frame. ([GitHub][2])
8. **Save and certify.** Export the vault file; compute and read aloud the SHA-256 on camera; print the hash on a paper checksum slip. Confirm operators wrote the same hash, then seal the slip in an envelope labeled with the vault rev and date.

### 7.4 Generating a deposit key

Generate a new key with a memo. Immediately produce the “deposit slip” text (address, P2PKH script, pubkey hash) and store it on an “OUT” drive for distribution to payers, plus a paper print if desired. Mark keys used on-chain once funds arrive to reduce reuse risk.

### 7.5 Processing incoming funds (Atomic BEEF required)

1. Receive **Atomic BEEF hex** from the payer *on paper and on an “IN” drive.*
2. On the air-gap, paste or import the hex.
3. The app performs **SPV verification**: it checks BUMP merkle roots against your headers. On camera, show the headers confirmation. If verification fails, **reject**. ([docs.bsvblockchain.org][15])
4. Review which outputs pay your keys; admit only the ones you approve; annotate UTXO memos.
5. Classify transaction “processed” only after independent confirmation that the network has mined/confirmed it (your policy: minimum N blocks).
6. **Merge BEEF** into the store and **save the vault**; re-compute and certify the file hash; seal the prior revision as invalid; destroy per policy. (Sanitization guidance at 800-88.) ([NIST Computer Security Resource Center][11])

### 7.6 Building and signing an outgoing transaction

1. Define outputs: destination address or full script, sats, and memo.
2. Manually select inputs (by coin ID). If inputs derive from unprocessed parents, the app will warn you; review and proceed only if intentional.
3. Choose **change keys** (prefer new/unseen keys). The app warns on reuse; heed it to preserve privacy.
4. Enable **per-UTXO attestation** if your policy requires it: both operators inspect the input’s on-chain state and certify.
5. Build fees; sign.
6. Export **Atomic BEEF** to an “OUT” drive and deliver to the counterparty/processor for broadcast. The vault marks the outgoing as “pending” until you certify it as processed.
7. Save and certify the new vault revision; destroy old revisions. (Document the exact SHA-256 at save time; store the checksum in a separate, sealed envelope.) ([bsv.brc.dev][4])

### 7.7 Header verification procedure (per session)

At session start, re-query the current height from Source-A and Source-B; note the absolute value on the whiteboard. For any BUMP proof you rely on, compute the root from the proof, then confirm that root against your known header at the claimed height. If it’s older than your “persist after N blocks” threshold, persist the claim with a memo citing the sources you used. ([bsv.brc.dev][3])

### 7.8 Log management & audits

Export the **vault log** and **session log** at the end of every session to an “OUT” drive, and print to paper for the binder. Read a random sample of entries on camera to prove continuity. The logs are sanitized by design (no secrets) but contain enough detail for forensics.

---

## 8) Hygiene around keys, change, and UTXOs

Use **fresh keys** for receipts and **fresh change keys** to avoid linkage. Your app flags reuse; resist the urge to ignore it. Summarize UTXO sets on the dashboard and keep memos crisp; during audit, you should be able to narrate why each UTXO exists and how it will be spent.

---

## 9) File integrity: hashes, seals, and paper trails

Every vault save is followed by a SHA-256, recorded twice (operator A and B) and matched on camera. The checksum is printed or handwritten on a checksum card tagged with revision, date, and time; the card is sealed and stored separately from the drive. At the next load, confirm the hash of the file *before* decrypting — your software already prompts this; treat it as mandatory. (Media handling and destruction per NIST 800-88.) ([NIST Computer Security Resource Center][11])

---

## 10) Password rotation (don’t churn; rotate with purpose)

Rotate only for cause (policy change, staff change, suspected exposure) or at measured intervals that your team can execute *without error*. When rotating, generate a new salt, re-derive PBKDF2 with your chosen rounds, and **immediately save and certify** the vault file. NIST’s current stance favors strong, longer passwords and discourages frequent forced changes that create user workarounds; we follow that philosophy. ([NIST Pages][13])

---

## 11) Incident response

If an “IN” drive fails post-scan checks, quarantine it, film the quarantine, and record its serial. If any outgoing BEEF appears malformed or repeatedly fails external processing, consider the signing machine contaminated: halt operations, export logs, reimage from known-good offline media, and re-establish trust chains (headers, checksums, operator rosters).

---

## 12) Frequently used SDK/format facts you will cite in audits

* **BRC-62**: Background Evaluation Extended Format (BEEF) — compact transport for tx + inputs + proofs; the `0100BEEF` marker is by design; validation rules reference raw tx (BRC-12) and BUMP (BRC-74). ([bsv.brc.dev][1])
* **BRC-67**: SPV — clients validate Merkle paths against headers, not “trust nodes.” ([GitHub][2])
* **BRC-74**: BUMP proof format — one block, many txids, their paths, and the block height. ([bsv.brc.dev][3])
* **BRC-95**: Atomic BEEF — single subject transaction, strict atomicity for operational clarity. ([bsv.brc.dev][4])
* **TS SDK**: `Transaction.fromBEEF`, `verify(chainTracker)`, `toAtomicBEEF`, `P2PKH.lock/unlock`, `Beef.mergeBeef`, etc. Official docs and examples show end-to-end verification. ([docs.bsvblockchain.org][5])

---

## 13) Ceremony templates (read-aloud scripts)

**Session open:**
“Session start. Date/time: ___. Operators A and B present. Purpose: ___. Room swept, phones outside, air-gap verified. Media staging complete; ‘IN’ drive serial ___ inspected and scanned. Proceeding.”

**Incoming BEEF:**
“Atomic BEEF for TXID ___ loaded. SPV verification succeeded against header source A height ___ and source B height ___. Outputs matched to keys: ___. Admitting vout(s) ___ as per policy.”

**Outgoing sign:**
“Outputs reviewed. Inputs selected: ___. Change keys: ___. Per-UTXO attestations performed (Yes/No). Transaction signed; Atomic BEEF exported to ‘OUT’ drive serial ___. Pending processed confirmation.”

**Save & certify:**
“Saving vault rev ___. SHA-256: ___. Dual entry matched. Old rev sealed for destruction per 800-88; destruction scheduled.”

---

## 14) Governance and staffing

Maintain an operator roster with background checks proportional to the value under custody. Train alternates. Force vacation and cross-checks. Enforce the two-person rule literally — not one and a friend drifting in later. Use a real auditor once a year to sit in on a full session and attempt a red-team walkthrough of the procedures.

---

## 15) Appendices

**A. Why we insist on Atomic BEEF** — it’s simpler to reason about and audit: one subject transaction, proofs for exactly its inputs, no unrelated baggage. That tight scope reduces attack surface and operator confusion. (See BRC-95.) ([bsv.brc.dev][4])

**B. Why we film** — video gives you a tamper-evident narrative of every material step; in custody disputes or post-mortems, it’s priceless.

**C. Why we don’t auto-broadcast** — the vault is for *authoritative signing and evidence gathering*, not network participation. Peers broadcast; you retain proof you built the right thing.

**D. Air-gap reality** — USB-borne malware is still a thing; kiosk-style scanning and strict zone controls are what keep you safe, not magical isolation. ([WIRED][16])

**E. Sanitization crib** — when media leaves your control or shifts zones, sanitize per NIST 800-88 (or Rev.2 when finalized); prefer crypto-erase/Secure Erase on SSDs; document the method and result. ([NIST Computer Security Resource Center][11])

---

## 16) Final checklist for day-to-day operations

Operate like this is money — because it is:

* Two people. Camera rolling.
* Clean “IN” drive; scan; no autorun; write-protect. ([Splunk][9])
* SPV or it didn’t happen: BUMP → root → header(s) you trust. ([bsv.brc.dev][3])
* Save → hash → dual-record → seal → destroy old. ([NIST Computer Security Resource Center][11])
* Fresh change keys; avoid reuse.
* Logs exported each session; binder updated.
* Paper checksum slips kept separate from media.

Run this like a flight deck: slow is smooth, smooth is fast.

---

### References (primary)

BRC-62 (BEEF), BRC-67 (SPV), BRC-74 (BUMP), BRC-95 (Atomic BEEF), official SDK docs and examples. These are the standards your vault procedures implement and the APIs your software uses to enforce them. ([bsv.brc.dev][1])

(Additional sources supporting EMSEC, removable-media, and password guidance are cited inline where we rely on them.)

[1]: https://bsv.brc.dev/transactions/0062?utm_source=chatgpt.com "Background Evaluation Extended Format (BEEF) Transactions"
[2]: https://raw.githubusercontent.com/bitcoin-sv/BRCs/master/transactions/0067.md?utm_source=chatgpt.com "https://raw.githubusercontent.com/bitcoin-sv/BRCs/..."
[3]: https://bsv.brc.dev/transactions/0074?utm_source=chatgpt.com "BSV Unified Merkle Path (BUMP) Format - README | BRC"
[4]: https://bsv.brc.dev/transactions/0095?utm_source=chatgpt.com "Atomic BEEF Transactions - README | BRC"
[5]: https://docs.bsvblockchain.org/guides/sdks/ts?utm_source=chatgpt.com "TypeScript - BSV Skills Center"
[6]: https://en.wikipedia.org/wiki/Tempest_%28codename%29?utm_source=chatgpt.com "Tempest (codename)"
[7]: https://en.wikipedia.org/wiki/Two-person_rule?utm_source=chatgpt.com "Two-person rule"
[8]: https://www.wired.com/2014/12/hacker-lexicon-air-gap?utm_source=chatgpt.com "Hacker Lexicon: What Is an Air Gap?"
[9]: https://www.splunk.com/en_us/blog/learn/cis-critical-security-controls.html?utm_source=chatgpt.com "CIS Critical Security Controls: The Complete Guide"
[10]: https://industrialcyber.co/nist/nist-publication-warns-that-usb-devices-pose-serious-cybersecurity-threats-to-ics-offers-guidance-for-mitigation/?utm_source=chatgpt.com "NIST publication warns that USB devices pose serious ..."
[11]: https://csrc.nist.gov/pubs/sp/800/88/r1/final?utm_source=chatgpt.com "SP 800-88 Rev. 1, Guidelines for Media Sanitization | CSRC"
[12]: https://www.wired.com/2017/02/malware-sends-stolen-data-drone-just-pcs-blinking-led?utm_source=chatgpt.com "Malware Lets a Drone Steal Data by Watching a Computer's Blinking LED"
[13]: https://pages.nist.gov/800-63-3/sp800-63b.html?utm_source=chatgpt.com "NIST Special Publication 800-63B"
[14]: https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf?utm_source=chatgpt.com "How to Share a Secret"
[15]: https://docs.bsvblockchain.org/guides/sdks/ts/examples/example_verifying_beef?utm_source=chatgpt.com "Verifying a BEEF Structure | BSV Skills Center"
[16]: https://www.wired.com/story/china-usb-sogu-malware?utm_source=chatgpt.com "Chinese Spies Infected Dozens of Networks With Thumb Drive Malware"
