/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.mmap;

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.security.Provider;
import java.util.Arrays;
import java.util.Set;
import java.util.function.BiPredicate;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.MMapDirectory;
import org.apache.lucene.util.SuppressForbidden;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.index.store.cipher.CipherFactory;
import org.opensearch.index.store.iv.DefaultKeyIvResolver;
import org.opensearch.index.store.iv.KeyIvResolver;

@SuppressForbidden(reason = "temporary bypass")
public final class CryptoMMapDirectory extends MMapDirectory {

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LIBC = SymbolLookup.libraryLookup("c", Arena.global());

    private static final int PROT_READ = 0x1;
    private static final int PROT_WRITE = 0x2;
    private static final int MAP_PRIVATE = 0x02;

    private static final MethodHandle MMAP;

    private final KeyIvResolver keyResolver;

    static {
        try {
            MMAP = LINKER
                .downcallHandle(
                    LIBC.find("mmap").orElseThrow(),
                    FunctionDescriptor
                        .of(
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS, // addr
                            ValueLayout.JAVA_LONG, // length
                            ValueLayout.JAVA_INT, // prot
                            ValueLayout.JAVA_INT, // flags
                            ValueLayout.JAVA_INT, // fd
                            ValueLayout.JAVA_LONG // offset
                        )
                );
        } catch (Throwable e) {
            throw new RuntimeException("Failed to load mmap", e);
        }
    }

    public CryptoMMapDirectory(Path path, Provider provider, MasterKeyProvider keyProvider) throws IOException {
        super(path);
        this.keyResolver = new DefaultKeyIvResolver(this, provider, keyProvider);
    }

    /**
    * Sets the preload predicate based on file extension list.
    *
    * @param preLoadExtensions extensions to preload (e.g., ["dvd", "tim", "*"])
    * @throws IOException if preload configuration fails
    */
    public void setPreloadExtensions(Set<String> preLoadExtensions) throws IOException {
        if (!preLoadExtensions.isEmpty()) {
            this.setPreload(createPreloadPredicate(preLoadExtensions));
        }
    }

    private static BiPredicate<String, IOContext> createPreloadPredicate(Set<String> preLoadExtensions) {
        if (preLoadExtensions.contains("*")) {
            return MMapDirectory.ALL_FILES;
        }
        return (fileName, context) -> {
            int dotIndex = fileName.lastIndexOf('.');
            if (dotIndex > 0) {
                String ext = fileName.substring(dotIndex + 1);
                return preLoadExtensions.contains(ext);
            }
            return false;
        };
    }

    public static MemorySegment[] mmapAndDecrypt(Path path, int fd, long size, Arena arena, byte[] key, byte[] iv, int chunkSizePower)
        throws Throwable {
        final long chunkSize = 1L << chunkSizePower;
        final int numSegments = (int) (size >>> chunkSizePower) + 1;
        MemorySegment[] segments = new MemorySegment[numSegments];

        long offset = 0;
        for (int i = 0; i < numSegments; i++) {
            long remaining = size - offset;
            long segmentSize = Math.min(chunkSize, remaining);

            MemorySegment addr = (MemorySegment) MMAP
                .invoke(MemorySegment.NULL, segmentSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, offset);

            if (addr.address() == 0 || addr.address() == -1) {
                throw new IOException("mmap failed at offset: " + offset);
            }
            MemorySegment segment = MemorySegment.ofAddress(addr.address()).reinterpret(segmentSize);

            decryptSegment(segment, key, iv, offset);

            segments[i] = segment;
            offset += segmentSize;
        }

        return segments;
    }

    // TODO: This can be invoked via FFI for zero copy.
    private static void decryptSegment(MemorySegment segment, byte[] key, byte[] baseIv, long offset) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        byte[] ivCopy = Arrays.copyOf(baseIv, baseIv.length);

        int blockOffset = (int) (offset / CipherFactory.AES_BLOCK_SIZE_BYTES);
        for (int i = CipherFactory.IV_ARRAY_LENGTH - 1; i >= CipherFactory.IV_ARRAY_LENGTH - CipherFactory.COUNTER_SIZE_BYTES; i--) {
            ivCopy[i] = (byte) blockOffset;
            blockOffset >>>= Byte.SIZE;
        }

        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivCopy));

        ByteBuffer buffer = segment.asByteBuffer();
        byte[] input = new byte[buffer.remaining()];
        buffer.get(input);
        byte[] output = cipher.doFinal(input);
        buffer.rewind();
        buffer.put(output);
    }

    public static int getFD(FileChannel channel) {
        try {
            var fdField = FileChannel.class.getDeclaredField("fd");
            fdField.setAccessible(true);
            Object fdObj = fdField.get(channel);

            var fdValField = fdObj.getClass().getDeclaredField("fd");
            fdValField.setAccessible(true);
            return fdValField.getInt(fdObj);
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchFieldException | SecurityException e) {
            throw new RuntimeException("Unable to get file descriptor from FileChannel", e);
        }
    }
}
