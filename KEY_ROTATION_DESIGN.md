# Index-Level Encryption: Key Rotation Design

Status: **online rotation implemented & verified on a live cluster; two gates open (see §8).**
Branch: `feat/segment-key-rotation`.
Build: `JAVA_HOME=<corretto-21> ./gradlew --offline <task>`.

---

## 1. Problem

Index-Level Encryption (ILE) encrypts Lucene index data at rest at the Directory level. We need to
**rotate the encryption key** — for compliance/proactive hygiene, and (harder) to **recover from a key
compromise**. The two are fundamentally different:

- **Re-wrapping** a key (change what it is encrypted *under*) is cheap and metadata-only. It is the right
  answer for a CMK/wrapping-level concern.
- If a **plaintext data key leaks**, re-wrapping does nothing — the attacker holds the raw bytes. The only
  true remediation is **re-encrypting the data under a fresh key**, then destroying the old key.

Lucene segments are **immutable** — you cannot rewrite a segment in place. So "re-encrypt the data" is not
a key operation; it is a **data-rewrite** operation that can only happen via the engine's normal segment
production (flush / merge / force-merge). Rotation therefore piggybacks on segment production.

## 2. Key hierarchy (as implemented)

```
L0  Customer CMK / master-key provider (KMS; never leaves the provider)
     │  generateDataPair()  -> encrypted data key persisted as "keyfile[.N]"
L1  Per-index master key (the "data key")   -- one per rotation EPOCH
     │  HKDF(masterKey, messageId)           (local, per file)
L2  Per-file key                             -- encrypts each segment file
     │
   segment data on disk (immutable)
```

- Translog has an analogous per-generation key derivation (`TranslogFrameManager`, HKDF base-IV folds the
  epoch).

## 3. The epoch model

Rotation introduces a **key-rotation epoch** (a monotonically increasing `int`, starting at 0):

- Each **segment footer** is stamped with the epoch that encrypted it (in the previously-reserved,
  length-prefixed `keyMetadata` slot; epoch 0 = empty slot = **byte-compatible with pre-rotation files**).
- Each **translog generation** stamps its epoch in the super-header.
- The **reader extracts the epoch pre-auth** and selects the matching master key, so a segment written
  under an old epoch stays readable after rotation (**online dual-key reads**).
- New writes use the **current (highest) epoch**.
- Master keys are stored per epoch: `keyfile` (epoch 0, legacy name) and `keyfile.N` (epoch N), in the
  **index-level directory** (`CryptoDirectoryFactory.newDirectory` → `location.getParent().getParent()`).

Invariant: **a segment / translog generation is pinned to its epoch for life.** Rotation never rewrites
existing data; convergence to the new epoch happens as merges/force-merge rewrite old segments.

## 4. Rotation lifecycle

1. **Prepare** — `rotate()` mints `keyfile.<N+1>` via the key provider, advances `currentEpoch`.
2. **Cutover (writes)** — new flushes are stamped epoch N+1 and encrypted under its key.
3. **Backfill (data-plane)** — old-epoch segments migrate to N+1 only when **rewritten** (natural merges,
   or an explicit `force-merge`). There is no in-place re-key (immutability).
4. **Retire** — once no segment/generation remains on the old epoch, the old `keyfile` can be destroyed.

- **Proactive rotation**: steps 1–2, let natural merges drain the tail over time. Cheap.
- **Compromise recovery**: steps 1–4 with a **forced** merge, urgently, because the leaked key opens old
  segments (and any snapshot/backup copies) until they are gone.

### 4a. Key transition in action (concrete walkthrough)

A single-shard trace showing the on-disk state, footer epochs, and API calls at each step. `keyfile` is
the epoch-0 key; `keyfile.N` is epoch N. Segment `_X.cfs[eE]` means segment `_X` stamped with epoch E.

```
STEP 0 — steady state (epoch 0, pre-rotation)
  index dir : keyfile
  segments  : _0.cfs[e0] _1.cfs[e0]
  resolver  : currentEpoch=0
  reads     : getDataKey(0)  writes -> stamp e0, encrypt with key0

STEP 1 — operator triggers rotation
  POST /_plugins/_opensearch_storage_encryption/my-index/_rotate_key
    └─ TransportRotateKeyAction fans out to each node hosting a primary of my-index
       └─ DefaultKeyResolver.rotate():
            reconcile currentEpoch from disk (still 0)
            mint keyfile.1  (provider.generateDataPair())
            writeKeyFileDurably: keyfile.1.<shard>.<nanos>.tmp -> sync -> rename keyfile.1 -> syncMetaData
            currentEpoch = 1
    response: { rotated_shards: [ { index: my-index, shard: 0, new_epoch: 1 } ], _shards: {successful:1} }

  index dir : keyfile  keyfile.1
  segments  : _0.cfs[e0] _1.cfs[e0]         <-- data UNCHANGED, still epoch 0
  resolver  : currentEpoch=1

STEP 2 — writes cut over (no data movement)
  new doc -> flush -> _2.cfs[e1]            <-- new segment stamped epoch 1, encrypted with key1
  index dir : keyfile  keyfile.1
  segments  : _0.cfs[e0] _1.cfs[e0] _2.cfs[e1]

  READ PATH (online dual-key): open _0 -> footer says e0 -> getDataKey(0)=key0 -> decrypt OK
                               open _2 -> footer says e1 -> getDataKey(1)=key1 -> decrypt OK
  (both epochs served simultaneously; a search spanning all segments works)

STEP 3 — backfill: force-merge (or let natural merges do it)
  POST /my-index/_forcemerge?max_num_segments=1
  Lucene reads _0[e0],_1[e0],_2[e1] (each under ITS epoch key) and writes ONE new segment
  under the CURRENT epoch:
  segments  : _3.cfs[e1]                    <-- everything now epoch 1; old segment files deleted

STEP 4 — retire old key  (NOT yet implemented — gate §10.2)
  verify no segment/translog generation is stamped e0  (scan footers via extractKeyEpoch)
  delete keyfile ; evict + zeroize key0 from NodeLevelKeyCache
  index dir : keyfile.1
  segments  : _3.cfs[e1]
  -> the leaked epoch-0 key can no longer decrypt anything live. (Snapshots/backups holding _0[e0]
     remain readable by key0 until they are also purged — see §10.1/§4 immutability note.)
```

Notes:
- Steps 1–2 are **instant and data-free** (metadata only). Step 3 is the expensive rewrite. Step 4 is the
  only step that actually *contains* a compromise, and it depends on step 3 completing.
- Translog transitions the same way per generation: after rotation, the next generation roll writes a
  super-header stamped epoch 1; existing generations keep their epoch and stay decryptable.
- Cross-node: after STEP 1, if shard 0 relocates or a replica recovers, `keyfile.1` travels inside the
  shard directory, so the target node resolves epoch 1 correctly (verified, §7).

### Cost
- Space: +4 bytes/segment footer once rotated (0 at epoch 0); N resident master keys; negligible.
- Speed: one extra pre-auth epoch read + per-epoch cache lookup on file open; **zero** for never-rotated
  (epoch-0) indices. The real cost is the **force-merge** (full rewrite, ~2× transient disk) — inherent to
  immutability, deferrable for proactive rotation.

## 5. The trigger

`POST /_plugins/_opensearch_storage_encryption/{index}/_rotate_key`

- `TransportRotateKeyAction extends TransportBroadcastByNodeAction` — fans out to each node hosting a
  targeted **primary**, calls `DefaultKeyResolver.rotate()` on the node-local resolver.
- `RotateKeyRequest.validate()` refuses an empty index list (no accidental all-index rotation).
- Response reports per-shard new epoch + standard broadcast shard counters/failures.

## 6. Crash-safety & coordination

- **Durable atomic write** (`DefaultKeyResolver.writeKeyFileDurably`): temp → `sync()` → atomic `rename` →
  `syncMetaData()`. A crash never leaves a half-written keyfile.
- **Verified epoch discovery** (`discoverCurrentEpoch`): only accept a `keyfile.N` whose bytes actually
  **decrypt**; skip `.tmp`. Rejects a torn keyfile from a crash mid-rotation (which would otherwise advance
  the epoch to an unreadable key).
- **Disk-authoritative `rotate()`**: reconciles `currentEpoch` from disk before advancing, so a stale
  in-memory epoch after restore/recovery/relocation cannot mint a duplicate/lower epoch.
- **Idempotent across co-located shards**: the keyfile dir is shared per index per node, so sibling shards
  adopt an existing `keyfile.N` instead of racing on create.

## 7. Cross-node behaviour (verified)

`keyfile.N` lives inside the shard's transferred directory, so **peer recovery and shard relocation carry
it with the segments** — a replica/relocated shard on a node that never rotated still decrypts the new
epoch. Verified on a live multi-node cluster (see §9). This corrected an early assumption that nodes would
diverge.

## 8. Security review (summary)

- **Epoch downgrade / tamper → SAFE.** The epoch bytes are inside the footer GCM AAD; flipping them changes
  both key selection and AAD → fail-closed. Wrong-key-that-authenticates is cryptographically impossible.
  Pre-auth `keyMetadataLength` is now bounds-validated (fail closed, no unchecked exceptions).
- **Cross-epoch nonce/IV reuse → SAFE.** `rotate()` mints a fresh master key that feeds both the GCM key
  (`fileKey = HKDF(masterKey, messageId)`) and the frame IV; a repeated nonce under a different key is not a
  GCM catastrophe. `messageId` is random per file.
- **Key lifecycle → NEEDS WORK (medium).** Plaintext AES keys are not zeroized on cache eviction, and
  rotation multiplies resident keys with no retirement. Deliberately **not** patched naively: the cache
  shares one `SecretKeySpec` per epoch across concurrent readers, so zeroize-on-evict would risk zeroing an
  array mid-decrypt. Needs a ref-counted / copy-on-read design.

## 9. Test coverage (live cluster = OpenSearch internalClusterTest, real nodes)

| PoC | What it proves | Status |
|---|---|---|
| `EncryptionFooterKeyEpochTests` (unit) | epoch stamp/round-trip, dual-epoch read, wrong-epoch fails auth, tamper fails closed | ✅ 7/7 |
| `KeyRotationUnderTrafficIntegTests` | **headline**: rotate under traffic → dual-epoch reads → force-merge → full-restart recovery; multi-rotation; concurrent search | ✅ 3/3 |
| `KeyRotationMultiNodeIntegTests` | replica peer-recovery + primary relocation across an epoch boundary (distinct per-epoch keys) | ✅ 2/2 |
| `RotateKeyActionIntegTests` | the REST/transport trigger end-to-end; empty-index guard | ✅ 2/2 |
| `KeyRotationSnapshotRestoreIntegTests` | rotate → snapshot → restore → read both epochs | ❌ **failing by design** (§10) |

Full module suite: 745 tests, 0 failures (excluding the intentional known-failing snapshot test and a
pre-existing unrelated `BlockSlotTinyCache` concurrency flake).

## 10. Open gates (NOT production-ready until closed)

1. **Snapshot/restore & clone/resize lose `keyfile.N`** — CONFIRMED bug, reproduced on a live cluster.
   Diagnostic on the restored shard: `keyfiles=[keyfile] currentEpoch=0` — the base keyfile is captured but
   the rotated `keyfile.N` is not (it is index-level, outside the Lucene commit). Under a real
   (non-identity) KMS the restored index would be **unable to decrypt rotated-epoch data → data loss**.
   Same gap the existing `handleResizeOperation` works around for the base keyfile only.
   **Fix**: propagate the full `keyfile*` set wherever the base keyfile goes — extend
   `handleResizeOperation` to copy `keyfile.N`, and ensure snapshot captures the index-level keyfiles.
2. **Old-key retirement / destruction** — not built. Required for true compromise recovery: after
   force-merge convergence, verify zero old-epoch segments remain, then delete the old keyfile and evict +
   zeroize the old key.
3. **Key zeroization on eviction** — see §8 (needs ref-counted design).
4. **Real KMS** — all tests use mock providers; rotation under real KMS latency/throttle/failure is
   unexercised (cannot be validated without real infra).

## 11. Deployment-mode note

Cross-node agreement via shard transfer is verified for **classic peer-recovery**. **Remote-store /
segment-replication** propagation of `keyfile.N` is closely related to gate #1 (both hinge on the
index-level keyfile travelling with the data) and is not independently verified.

## 12. File map

- Trigger: `action/RotateKey*.java`, `rest/RestRotateKeyAction.java`
- Rotate primitive + crash-safety: `key/DefaultKeyResolver.java`
- Per-epoch key cache: `key/NodeLevelKeyCache.java`
- Epoch stamping/reading: `footer/EncryptionFooter.java` (segments), `translog/TranslogFrameManager.java`
- Epoch-aware read paths: `niofs/CryptoBufferedIndexInput.java`, `niofs/CryptoNIOFSDirectory.java`,
  `bufferpoolfs/BufferPoolDirectory.java`, `bufferpoolfs/BufferIOWithCaching.java`,
  `block_loader/CryptoDirectIOBlockLoader.java`
- Tests: `internalClusterTest/.../KeyRotation*IntegTests.java`, `.../RotateKeyActionIntegTests.java`,
  `test/.../footer/EncryptionFooterKeyEpochTests.java`, `test/.../DistinctKeyPerEpochProviderPlugin.java`
