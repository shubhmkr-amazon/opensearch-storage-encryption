# C2 — Seal-on-force durability: implementation design (this branch)

**Branch:** `fix/translog-partial-write-jdk21`. Fixes the live `AEADBadTagException` reproduced under update-conflict + realtime-GET load: a realtime GET reads an uncommitted op from the **open block whose GCM tag is not yet on disk** (it's only written by `finalizeCurrentBlock()` at the next 8192 boundary or `close()`), so `decryptWithTag` reads non-tag bytes → tag verification fails. **This is reachable with no crash.**

## Root cause (verified)
- `writeToChunks` streams ciphertext to disk immediately (`TranslogChunkManager.java` write loop) but the 16-byte tag is buffered in `currentCipher` until `finalizeCurrentBlock()`.
- `CryptoFileChannelWrapper.force(metaData)` only calls `delegate.force()` — it does **not** finalize the open block. So after a sync/checkpoint (and for any read of the open block), the tag isn't on disk.
- The reader assumes a fixed 8208-byte stride (`getChunkInfo`: `chunkIndex = dataPosition/8192`, `diskPosition = headerSize + chunkIndex*8208`; `readAndDecryptChunk` reads `CHUNK_WITH_TAG_SIZE`). So a sealed *short interior* block can't be represented — an in-format finalize is impossible (proven by the spec).

## Chosen design: buffer-per-block + seal-on-force, variable-length self-describing chunks

Replace the streaming-update writer with a **buffer-one-block** writer, and make each on-disk chunk **length-prefixed** so the reader walks variable-length chunks and builds an offset index at open. This is a one-time pre-GA on-disk format break (acceptable).

### On-disk format (v2)
```
[plaintext TranslogHeader, H bytes]                       (unchanged, written by core)
repeated, per block:
  [u16 ptLen]              big-endian plaintext length of this block, 1..8192
  [ptLen bytes ciphertext] AES-256-GCM(nonce = baseIV[0:8] || BE32(blockIndex), plaintext)
  [16 bytes GCM tag]
```
- On-disk chunk record size = `2 + ptLen + 16`. Blocks are full (ptLen=8192) except the last sealed one.
- `baseIV` is already per-(generation) (C1) and the nonce is per-block (e28a466) — unchanged, still collision-free.

### Writer (TranslogChunkManager)
- New state: `byte[] blockBuf = new byte[8192]`, `int blockBufLen`, `long currentBlockNumber`, `long logicalDataWritten`, `long fileWritePosition` (disk cursor).
- `writeToChunks(src, position)`: keep the header-write branch, the M4 append-only assert, and the C6 guard. Then append `src` bytes into `blockBuf`; whenever `blockBufLen == 8192`, **seal** the block. Return bytes consumed.
- `sealCurrentBlock()` (replaces finalizeCurrentBlock + the streaming encrypt): if `blockBufLen == 0` return; else one-shot `AesGcmCipherFactory.encryptWithTag(key, computeGcmNonce(baseIV, currentBlockNumber), blockBuf, blockBufLen)` → write `[u16 blockBufLen][ciphertext||tag]` via `writeFully`; advance `fileWritePosition`; `currentBlockNumber++`; `blockBufLen = 0`.
- `flushSeal()` (NEW, called by force() and close()): seal the partial block now. After it, the on-disk file ends on a complete tagged chunk. **This is the C2 fix.**
- `close()`: `flushSeal()`.

> One-shot per block (not streaming update) removes the OpenSSL ctx lifecycle/leak and makes seal-on-force trivial. Cost: re-buffer 8KB — negligible.

### force() path (CryptoFileChannelWrapper)
```
public void force(boolean metaData) {
    ensureOpen();
    positionLock.writeLock().lock();
    try { chunkManager.flushSeal(); } finally { positionLock.writeLock().unlock(); }
    delegate.force(metaData);
}
```
Now every checkpoint/sync is preceded by sealing → the open block's tag is durable before `force()` returns. A realtime GET of the open region now reads a complete tagged chunk.

### Reader: variable-length walk + offset index
- At first read (or open), scan from `H`: read `u16 ptLen`, skip `ptLen+16`, record `(cumulativePlaintextOffset -> diskOffset, ptLen)` per block, until EOF. Build `long[] blockDiskOffset` + `int[] blockPtLen` (or a cumulative-offset array). Bounded memory (~ one entry per 8KB).
- `getChunkInfo(logicalPos)`: binary-search the cumulative-plaintext array to find the block and `offsetInChunk`. Returns `diskPosition` of that block's record.
- `readAndDecryptChunk(blockIndex)`: seek to `blockDiskOffset[blockIndex]`, read `u16 ptLen`, `readFully(ptLen+16)`, `decryptWithTag(computeGcmNonce(baseIV, blockIndex), ...)`.
- Re-scan/extend the index when `delegate.size()` grows (a writer appended/sealed more) — or rebuild on each read for simplicity if perf allows (translog reads are bounded by checkpoint).

### Crash consistency (the proof)
Core sync order: write ops → `channel.force(false)` → write+fsync `.ckp` → advance `lastSyncedCheckpoint`. With `force()` sealing first: every byte the checkpoint references belongs to a complete, tagged, fsynced chunk. A hard crash after the checkpoint loses nothing; a crash mid-seal leaves a torn trailing chunk **beyond** the last durable checkpoint offset, which core never reads. No acked op lost, no nonce reuse.

## Tests
- **C2 regression (the repro, deterministic, no crash):** write < 8192 bytes, `force(false)`, then **without close** open a fresh read-only `CryptoChannelFactory` channel and `readFullyLoop` → must `assertArrayEquals(data)` (today: throws "Failed to decrypt chunk"). This is the test that flips from fail→pass with the fix.
- **Variable-length round-trip:** many lengths incl. multi-block + short last; byte-identity; new size = `H + sum(2 + ptLen_i + 16)`.
- **Crash-before-close at a sync point:** seal via force(), drop the writer, reopen → all sealed data recovers.
- Update `expectedFileSize` and all size asserts to the v2 per-block formula.
- Re-run the 5 internalClusterTests (full restart, multi-gen, on-disk-encrypted) — must stay green.

## Migration
One-time pre-GA on-disk break: old `[8192 ct||16 tag]` fixed-stride files are unreadable by the v2 reader (no `u16` length prefix). Acceptable — test clusters reseed. (A version byte in a future header would avoid this, but the encryption layer has no sub-header here; deferred.)

## Scope note
This is a self-contained format change touching `TranslogChunkManager` (writer state machine, sealCurrentBlock, flushSeal, getChunkInfo, readAndDecryptChunk, readFromChunks, close), `CryptoFileChannelWrapper.force()`, and the size-asserting tests. It is the only remaining translog fix; P0/C1/intra-gen-nonce/M3/M4/L6/C6 are already committed.
