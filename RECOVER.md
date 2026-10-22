# Recover from a replacement machine

## Required external inputs

1. Access to the private GitHub repository `cosmosgeek0/Accurast` and its release assets. Authenticate `gh` as the owner; never paste a token into shell history or this repository.
2. Python 3.9 or newer with SQLite, Node.js 22 and GitHub CLI. Tested versions are in `dependencies.json`.
3. For live operation: a compatible Linux replacement host, continued provider/account access and any required new rental funds. These are separate from downloading and restoring the archives.

No separate backup key or password-manager login is needed. Private GitHub release archives contain the original app keys and credentials alongside their existing native encrypted state; the recovery kit adds no outer encryption layer.

No old AWS URL or old Mac path is needed to retrieve the pinned artifacts. Use a canonical absolute work path without symlinked parent directories. Allow disk space for the downloaded archives and expanded trees; the local preservation archive is several GB uncompressed.

The full Linux host snapshot contains distinct `Index.html` and `index.html` files, so its restore destination must use a case-sensitive filesystem: ordinary Linux filesystems or a case-sensitive APFS volume/image on macOS. A normal case-insensitive Mac volume cannot represent both files. Recovery checks for this before copying case-colliding members; it does not format or change any production disk.

Archive inventories are bounded to 256 MiB of JSON to accommodate the captured host's large file/dependency inventory. The verifier holds archive member metadata and this inventory in memory while streaming file contents in archive order; it never loads whole payload archives into memory. Use a machine with enough available RAM for those metadata structures and enough disk space for both preserved trees and any staged copies. Path restrictions, exact manifest coverage and every member's SHA256 remain mandatory.

Large release archives may use an ordered `parts` array in the schema-2 manifest. The logical artifact retains its full `name`, `sha256`, `bytes`, `kind` and `destination`; each part records its own `name`, `sha256` and `bytes` and is at most 1 GiB. Recovery verifies and caches each private GitHub part, streams them in the recorded order into a temporary archive, and adopts it only after its full size and SHA256 match. Resuming reuses verified parts or an already verified complete archive. Corrupt existing cache files fail without deletion. Allow additional disk space for both cached parts and the assembled compressed archive, as well as its expanded tree.

```sh
gh repo clone cosmosgeek0/Accurast
cd Accurast
./recover restore --work /secure/Accurast-restored
```

The result is `/secure/Accurast-restored/restore-verification.json`; `ok: true` is required. Its artifact rows verify the downloaded hashes, exact file inventory, SQLite integrity, canonical Grass vault/profile consistency and native Pawns account/session envelopes. Pawns verification checks the original key pair, decrypts every saved session, checks plaintext hashes and account/device bindings, and makes no provider request; it does not prove a saved token is still accepted. Downloaded archives and restored trees use owner-only permissions. The command has no signing, admission, launch or renewal capability. Keep recovery state in the private release assets and private restoration directories, outside git history.

The entry command also writes `reconciliation-plan.json`, bound to the selected snapshot hash. The default status is `not-reconciled-no-fresh-evidence`, with all live actions held. This explicit hold is not a claim that old transactions or phone state have been reconciled. Supply `--evidence /secure/fresh-evidence.json` to run the read-only planner after asset validation; an evidence snapshot-hash mismatch fails. The resulting plan is included by hash in the restore report, and no plan enables a launch or signature.

Keep the same work path to resume. Completed artifacts are checked again rather than re-extracted. A corrupt download, changed restored file, conflicting unverified destination or another recovery process fails closed. Move a failed artifact directory aside for inspection before retrying. `--offline` can reuse a complete asset cache, but does not verify current remote access.

## What the assets contain

`release-assets.json` names the exact assets and destinations. The authoritative host snapshot holds current deployed source/configuration and server state. The owner-local archive retains local signing material, wallet provenance, transaction/refund journals, historical receipts, patches and provider source/state. Local historical source must never overwrite a newer deployed file without comparison: the four-app `launch-fleet.py` and `coverage-recovery/snapshot.py` were known to diverge from their corrected live counterparts.

Immutable images are fetched from the same private release by checksum. They are restored as opaque files under the configured image destination. Preserve the release manifest hashes when configuring the replacement image server; do not fall back to old temporary Cloudflare or AWS asset URLs. Different application versions are different components: PacketStream client 2.5.0 and bootstrap 1.0.1 are not interchangeable version claims.

When a final owner-local delta is listed, assemble it into a new directory after restoration. The merger checks its pinned base artifact and each prior-file hash before copying, preserves both inputs and refuses deletion:

```sh
python3 scripts/merge-local-delta.py --work /secure/Accurast-restored \
  --output /secure/Accurast-owner-local-current
```

Use that assembled owner-local tree for final local journals and Pawns repair/queue handoff context. It does not replace the separate authoritative host snapshot.

The separately dated `host-pawns-checkpoint` was captured on 2026-10-22 at 02:23:21–02:23:46 UTC, after the main host capture. It preserves newer Pawns identities, saved sessions, holds, pacing, queue results and its consistent provider database. Keep it separate from the main snapshot: compare its dated state during live reconciliation, and do not pass it to `stage-host.py --supplement` or blindly overwrite the older host tree. The queue continued running during capture; stable per-file reads and a SQLite backup do not establish one global transaction across all files. Validate its original account/session keys independently with:

```sh
node scripts/verify-pawns.mjs /secure/Accurast-restored/restored/host-pawns-checkpoint
```

The `host-continuity` artifact is an earlier historical supplement. Its dated mutable files must also remain separate; the full host snapshot is authoritative for deployment and current Grass vault state.

When `owner-sdk` is listed, assemble its preserved patched chain dependencies into another new owner-local tree:

```sh
python3 scripts/install-owner-sdk.py --owner-local /secure/Accurast-owner-local-current \
  --sdk /secure/Accurast-restored/restored/owner-sdk \
  --output /secure/Accurast-owner-local-with-sdk --platform linux-x64
```

Select `linux-arm64` for an ARM64 replacement control host, or `auto` on the intended host. The helper verifies the preserved package lock and files, restores SDK executable bits and points esbuild and both project dependency links at the matching preserved native binary. It performs no npm download, SDK execution, client launch or signing, and leaves both inputs unchanged.

The original rental signer is `local/private/acurast-grass-20260928/wallet.json` inside that assembled owner-local tree. Its derived address is `5EM65P4HEtpkadoDXp9aRPzbGjxBCy6aCQUMLUmKMLC14JFu`. Keep its owner-only permissions and configure the preserved signing scripts to use that file during reviewed provisioning; do not generate a replacement wallet. The separate funding-wallet signer was not identified or backed up. It is not needed to restore this rental controller, but recovery of that other wallet requires its own owner-held material.

## Stage a replacement Linux host while fenced

Use the captured host metadata (`metadata/systemd.json`, package list, users/groups, mounts and manifests) to match the Linux architecture, runtime dependencies, service UIDs/GIDs and filesystem permissions. A source package manifest is not proof that a dependency installed successfully; the replacement host must satisfy all captured runtime requirements.

Copy `config/recovery.example.json` to secure storage and set replacement source paths, domain overrides and the local image directory. Mappings specify intended migration paths; arbitrary text substitution in private keys, signed state or serialized identities is forbidden. The staging script maps filesystem placement and records domain changes for review. It does not rewrite hardcoded references automatically.

```sh
python3 scripts/stage-host.py \
  --snapshot /secure/Accurast-restored/restored/host \
  --target-root /secure/replacement-root \
  --config /secure/recovery-config.json \
  --supplement /secure/Accurast-restored/restored/host-runtime \
  --supplement /secure/Accurast-restored/restored/host-credentials \
  --supplement /secure/Accurast-restored/restored/host-accounting \
  --artifact-work /secure/Accurast-restored
```

For faithful Linux permissions, run staging as root with `--preserve-ownership` to apply captured numeric owners. The target must be empty and independent of `/` and the snapshot. Staging copies verified files with captured modes, restores recorded directory metadata and safe links, and adds a missing-marker condition to captured systemd services/timers/sockets. It does not enable or start units. Inspect `/secure/replacement-root/var/lib/accurast-recovery/staging-report.json` for missing metadata, unresolved links, paths and domains before installing this filesystem on a replacement host.

The captured host has 5,101 SGID directories, including telemetry directories whose new files must inherit the original group. Explicit Linux ownership restoration applies `chown` before the original directory mode and verifies the result; file setuid/setgid bits are not restored. Mac staging records special directory modes as deferred. `prepare-linux-root.py --apply-ownership` reapplies original directory ownership and modes after its final directory changes, so a later `chown` cannot silently clear SGID. Apply POSIX ACLs only after this final ownership/mode step.

Use `--supplement` only when that runtime artifact is listed in the release manifest; omit it otherwise. Supplements may add files or repeat identical hashes, and cannot silently overwrite changed authoritative files. `--artifact-work` copies pinned, already verified immutable assets into the configured image directory and records their hashes. The default directory matches the original Grass artifact location; a changed location requires the corresponding source/configuration references to be reviewed.

For databases explicitly captured through the SQLite backup API, separately captured `-wal`, `-shm` and `-journal` files are copied into owner-only `var/lib/accurast-recovery/forensic-sqlite-sidecars/`, not beside the coherent database backup. Selection uses each main/supplement manifest's `sqlite_backups` records and verifies the base SQLite header; arbitrary similarly named files are not moved. The staging report retains each original path, hash and quarantine destination. Original archives and restored source trees remain unchanged. Migration and ACL checks verify quarantine and never recreate these sidecars at their database paths.

Prepare the captured service account IDs, locked password entries and required home/state/runtime directories without executing any service or package installation script:

```sh
python3 scripts/prepare-linux-root.py \
  --snapshot /secure/Accurast-restored/restored/host \
  --target-root /secure/replacement-root --config /secure/recovery-config.json
python3 scripts/audit-migration.py \
  --snapshot /secure/Accurast-restored/restored/host \
  --target-root /secure/replacement-root --config /secure/recovery-config.json \
  --out /secure/migration-audit.json
```

On a replacement Linux machine, add `--require-native-platform` to reject a distribution/version/CPU mismatch before native provisioning, and `--apply-ownership` as root to apply numeric ownership. The default architecture matches the captured control host; it does not assume that the host CPU matches the Android phones. Account ID/name conflicts stop preparation. Package versions are recorded in `packages.lock.json`; packages are not installed by this helper. A `policy-rc.d` guard also blocks conventional package-triggered service starts inside the offline root.

Some copied source files retain unnamed numeric owners (UID 501 in this capture). Their numeric metadata is preserved and reported without inventing a Linux account. Preparation rejects a replacement account already occupying such an ID; unresolved accounts actually referenced by a service still fail.

The private migration audit lists missing executables/working directories, captured bind mounts, configured path changes, image placement and hostname references without copying URL credentials or query strings into its report. Resolve those items before activation. The staged directory is an application filesystem overlay, not a bootable Linux image; a compatible installed OS and its package dependencies remain necessary.

When the ACL metadata supplement is listed, validate its original Linux POSIX ACLs after staging and account preparation:

```sh
python3 scripts/restore-acls.py \
  --snapshot /secure/Accurast-restored/restored/host \
  --acl-root /secure/Accurast-restored/restored/host-acls \
  --target-root /secure/replacement-root --config /secure/recovery-config.json
```

The accounting supplement carries its additional database/parent ACLs separately. After staging `host-accounting`, validate them with:

```sh
python3 scripts/restore-acls.py \
  --snapshot /secure/Accurast-restored/restored/host \
  --acl-root /secure/Accurast-restored/restored/host-accounting \
  --policy-path metadata/posix-acls-accounting.json \
  --target-root /secure/replacement-root --config /secure/recovery-config.json
```

This writes a separate accounting ACL report. ACLs belonging to quarantined database sidecars are validated and preserved as forensic metadata, but deliberately not applied; quarantine retains owner-only access.

This validates captured access/default ACL binary hashes, permission masks, path types and numeric identities. On macOS it reports `validated-not-applied`. On Linux, after applying original ownership and preparing the matching user/group names, root may add `--apply-xattrs` to restore and read back the exact ACL bytes in the offline root. Missing/mismatched target account identities, symlinks, a live approval marker, unsupported filesystems and `/` are rejected. No service runs. Apply ACLs after ownership and mode changes, because later `chmod` operations can change ACL masks. Coverage is limited to the paths recorded in the supplement and is included in `acl-restoration.json`.

The binary parser follows the [Linux POSIX ACL xattr format](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/posix_acl_xattr.h). The isolated Linux probe in `verification/acl-isolated-probe.json` checks access/default xattr round trips only on newly created temporary files; it is not proof that the complete replacement host has had its ACLs applied.

Recreate users/groups, bind mounts, runtime dependencies and image serving from the captured metadata. Restore Cloudflare tunnel credentials to the reviewed destination and update owner-controlled DNS/tunnel routing only after the replacement service is ready. Do not run the old and replacement control authority concurrently. Do not open inbound ports as a shortcut; the old host used SSM and tunnels.

## Reconcile before adoption or launch

Preserve the copied change/signing locks and sole-controller records. A stale lock is evidence to investigate, not permission to remove it. Prove the previous authority is fenced or inaccessible to signing, and reconcile all uncertain transaction hashes/nonces against finalized chain events before any write. Never replay a transaction merely because a prior command timed out or its process disappeared.

Gather fresh chain assignments and fresh independent physical process/identity observations for every candidate. SSH failure is unknown process state. Assignment failure can coexist with a living client. Reconcile exact job, processor, canonical identity, IP, account and lease end; do not treat historical inventory or provider balance as available rental capacity.

The read-only planner accepts explicit evidence in `config/reconciliation.example.json` format:

```sh
python3 scripts/reconcile.py /secure/fresh-evidence.json --out /secure/reconciliation-plan.json
```

For the entry command to validate and bind that evidence to the restored snapshot, use:

```sh
./recover restore --work /secure/Accurast-restored --evidence /secure/fresh-evidence.json
```

Populate `source_snapshot_sha256` with the selected `kind: snapshot` artifact's SHA256 from `release-assets.json`. Supply evidence gathered from fresh finalized chain state and independent physical observations; this command performs no RPC, provider call or signing itself.

The planner never authorizes a launch. It holds stale/unfenced/ambiguous state, pending transactions, duplicate identity/IP observations, revoked jobs and unresolved physical processes. A proven matching existing client becomes an adoption candidate. A proven stopped original identity on an eligible current assignment goes to review by the existing admission controller. New rentals require fresh funds and separate authorization.

Jobs 314473, 314474, 314476, 314478, 314481, 314484 and 314490 were already cancelled and revoked: retain their journals and do not replay cancellation. Physical absence of 314476 was unresolved. Job 313173 lost its assignment while its original process remained alive; preserve that uncertainty. Pawns must retain saved sessions, encryption/launch keys, Retry-After/account pacing, queue history, holds and provider ledgers. Resume only its existing sole queue after fresh reconciliation.

Do not create `/var/lib/accurast-recovery/LIVE-RECONCILIATION-APPROVED` until the migration has been reviewed, old authority fenced, all journals reconciled and the permitted services explicitly selected. That marker is only an additional fence; it is not an automatic safety approval. Start read-only observation first, then the sole authority through its preserved locks. Phone adoption/launch is a separate live operation, not part of the preservation test.

## Verification and deletion boundary

Run `python3 -m unittest discover -s tests -v` for archive traversal/link/tamper defenses, private-repository checks, downloaded hash verification, resume verification, native vault consistency, SQLite checking and reconciliation/fence behavior. Published clean-clone evidence must separately show downloads from GitHub and the real preserved state. Synthetic tests alone do not prove the recovery kit complete.

An isolated restore proves the captured assets can be fetched, verified and staged, including opening their native identity vault with its original key, without starting clients or signing. It does not prove replacement Linux service provisioning, DNS cutover, current phone reachability or current provider sessions. Preserve these distinctions in every status report.

Do not delete AWS state, reset the Mac or call the kit safe until remote artifact verification and access through the owner's GitHub account are confirmed. Essential authority state, keys, receipts, queues, journals, historical object references and configured source are not disposable. Only specifically inventoried redundant caches/logs/images may be considered for deletion after all referenced recovery artifacts pass restore verification. These scripts perform no deletion on AWS.

