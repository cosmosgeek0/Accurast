# Accurast recovery

The complete private GitHub restore and resume check passed: 15 artifacts and 404,504 file hashes verified. Offline staging and both ACL inventories also passed validation. Evidence and the remaining live-host prerequisites are recorded in [verification/readiness.json](verification/readiness.json), [verification/clean-restore.json](verification/clean-restore.json) and [verification/offline-staging.json](verification/offline-staging.json). A replacement Linux host has not been started; keep the existing AWS host until live replacement is validated.

Private disaster-recovery kit for the owner's Acurast control host and original Grass, PacketStream, Proxyrack, Repocket, TraffMonetizer and Pawns state. The live host source, credentials, identities, journals and phone checkpoints are stored as private GitHub release archives. Git contains recovery tools and manifests; the recovery archives contain the actual original secret material.

Start with [RECOVER.md](RECOVER.md). With this repository cloned, the documented dependencies installed and GitHub CLI authenticated to the private repository, the entry command is:

```sh
./recover restore --work /secure/Accurast-restored
```

It checks private GitHub access, downloads the pinned release assets, verifies SHA256 hashes, extracts into an isolated directory, verifies every archived file and database, checks canonical Grass account/device/private-key consistency, and decrypts saved Pawns sessions with their original key to validate account/device bindings. There is no added backup-encryption layer or separate recovery key. The applications' existing encryption and original keys are preserved together as required for their operation. Re-running verifies and resumes completed artifacts without starting services, renting phones, broadcasting transactions or creating identities.

This command restores an isolated recovery copy. A replacement host requires the separate fenced staging and reconciliation steps in RECOVER.md. A successful isolated test does not prove live host provisioning, provider acceptance, phone availability or renewed leases. Original physical phones and IP addresses may no longer be available after lease expiry.

The same entry command writes `reconciliation-plan.json`. Without fresh evidence it explicitly holds all actions as **not reconciled**. Add `--evidence /secure/fresh-evidence.json` to check a snapshot-bound transaction/phone review plan after restoration; this never enables launches or signing.

The last reported rental-wallet balance was **0.447484638472 ACU**; this is a dated observation, not spendable-balance verification. Provider credits, rental funds and the separate funding wallet are distinct. No funds are spent by these tools.

See `release-assets.json` for pinned remote artifacts, `dependencies.json` for recovery dependencies, and `verification/` for published test evidence when present. Access to the owner's private GitHub account must remain available after the Mac reset; recovery does not require the old Mac or AWS host.

