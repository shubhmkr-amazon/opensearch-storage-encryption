/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.apache.lucene.store;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.lucene.util.Unwrappable;
import org.opensearch.index.store.iv.KeyIvResolver;
import org.opensearch.index.store.mmap.CryptoMMapDirectory;

public final class CryptoIndexInputProvider
    implements
        MMapDirectory.MMapIndexInputProvider<ConcurrentHashMap<String, RefCountedSharedArena>> {
    private final Optional<NativeAccess> nativeAccess = NativeAccess.getImplementation();

    private final KeyIvResolver keyResolver;
    private final int sharedArenaMaxPermits;

    public CryptoIndexInputProvider(KeyIvResolver keyResolver, int maxPermits) {
        this.keyResolver = keyResolver;
        this.sharedArenaMaxPermits = checkMaxPermits(maxPermits);
    }

    @Override
    public IndexInput openInput(
        Path path,
        IOContext context,
        int chunkSizePower,
        boolean preload,
        Optional<String> group,
        ConcurrentHashMap<String, RefCountedSharedArena> arenas
    ) throws IOException {
        path = (Path) Unwrappable.unwrapAll(path);
        long size = java.nio.file.Files.size(path);
        String resourceDescription = "CryptoMemorySegmentIndexInput(path=\"" + path + "\")";
        boolean success = false;
        boolean confined = context == IOContext.READONCE;
        Arena arena = confined ? Arena.ofConfined() : getSharedArena(group, arenas);

        try (FileChannel fc = FileChannel.open(path, StandardOpenOption.READ)) {
            int fd = CryptoMMapDirectory.getFD(fc);
            MemorySegment[] segments = CryptoMMapDirectory
                .mmapAndDecrypt(path, fd, size, arena, keyResolver.getDataKey().getEncoded(), keyResolver.getIvBytes(), chunkSizePower);

            IndexInput input = MemorySegmentIndexInput.newInstance(resourceDescription, arena, segments, size, chunkSizePower, confined);
            success = true;
            return input;
        } catch (Throwable t) {
            if (!success) {
                arena.close();
            }
            throw new IOException("Failed to mmap and decrypt: " + path, t);
        }
    }

    @Override
    public long getDefaultMaxChunkSize() {
        return 1L << 30; // 1 GiB
    }

    @Override
    public ConcurrentHashMap<String, RefCountedSharedArena> attachment() {
        return new ConcurrentHashMap<>();
    }

    @Override
    public boolean supportsMadvise() {
        return this.nativeAccess.isPresent();
    }

    private Arena getSharedArena(Optional<String> group, ConcurrentHashMap<String, RefCountedSharedArena> arenas) {
        if (group.isEmpty()) {
            return Arena.ofShared();
        }

        String key = group.get();
        RefCountedSharedArena arena = arenas
            .computeIfAbsent(key, s -> new RefCountedSharedArena(s, () -> arenas.remove(s), sharedArenaMaxPermits));

        return arena.acquire() ? arena : arenas.compute(key, (s, v) -> {
            if (v != null && v.acquire()) {
                return v;
            }
            RefCountedSharedArena newArena = new RefCountedSharedArena(s, () -> arenas.remove(s), sharedArenaMaxPermits);
            newArena.acquire();
            return newArena;
        });
    }

    private static int checkMaxPermits(int maxPermits) {
        if (RefCountedSharedArena.validMaxPermits(maxPermits)) {
            return maxPermits;
        } else {
            return 1024;
        }
    }
}
