/* * SPDX-License-Identifier: Apache-2.0 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.index.store;

import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.store.LockFactory;
import org.apache.lucene.store.NIOFSDirectory;
import org.opensearch.common.Randomness;
import org.opensearch.common.crypto.DataKeyPair;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.util.io.IOUtils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A hybrid directory implementation that encrypts files
 * to be stored based on a user supplied key
 *
 * @opensearch.internal
 */
public final class CryptoDirectory extends NIOFSDirectory {
    private Path location;
    private Key dataKey;
    private ConcurrentSkipListMap<String, String> ivMap;
    private final Provider provider;

    private final AtomicLong nextTempFileCounter = new AtomicLong();

    CryptoDirectory(LockFactory lockFactory, Path location, Provider provider, MasterKeyProvider keyProvider) throws IOException {
        super(location, lockFactory);
        this.location = location;
        ivMap = new ConcurrentSkipListMap<>();
        IndexInput in;
        this.provider = provider;

        try {
            in = super.openInput("ivMap", new IOContext());
        } catch (java.nio.file.NoSuchFileException nsfe) {
            in = null;
        }
        if (in != null) {
            Map<String, String> tmp = in.readMapOfStrings();
            ivMap.putAll(tmp);
            in.close();
            dataKey = new SecretKeySpec(keyProvider.decryptKey(getWrappedKey()), "AES");
        } else {
            DataKeyPair dataKeyPair = keyProvider.generateDataPair();
            dataKey = new SecretKeySpec(dataKeyPair.getRawKey(), "AES");
            storeWrappedKey(dataKeyPair.getEncryptedKey());
        }
    }

    private void storeWrappedKey(byte[] wrappedKey) {
        try (IndexOutput out = super.createOutput("keyfile", new IOContext())) {
            out.writeInt(wrappedKey.length);
            out.writeBytes(wrappedKey, 0, wrappedKey.length);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] getWrappedKey() {
        try (IndexInput in = super.openInput("keyfile", new IOContext())) {
            int size = in.readInt();
            byte[] ret = new byte[size];
            in.readBytes(ret, 0, ret.length);
            return ret;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     * @param source the file to be renamed
     * @param dest the new file name
     */
    @Override
    public void rename(String source, String dest) throws IOException {
        super.rename(source, dest);
        if (!(source.contains("segments_") || source.endsWith(".si"))) ivMap.put(
            getDirectory() + "/" + dest,
            ivMap.remove(getDirectory() + "/" + source)
        );
    }

    /**
     * {@inheritDoc}
     * @param name the name of the file to be opened for reading
     * @param context the IO context
     */
    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        if (name.contains("segments_") || name.endsWith(".si")) return super.openInput(name, context);
        ensureOpen();
        ensureCanRead(name);
        Path path = getDirectory().resolve(name);
        FileChannel fc = FileChannel.open(path, StandardOpenOption.READ);
        boolean success = false;
        try {
            Cipher cipher = CipherFactory.getCipher(provider);
            String ivEntry = ivMap.get(getDirectory() + "/" + name);
            if (ivEntry == null) throw new IOException("failed to open file. " + name);
            byte[] iv = Base64.getDecoder().decode(ivEntry);
            CipherFactory.initCipher(cipher, this, Optional.of(iv), Cipher.DECRYPT_MODE, 0);
            final IndexInput indexInput;
            indexInput = new CryptoBufferedIndexInput("CryptoBufferedIndexInput(path=\"" + path + "\")", fc, context, cipher, this);
            success = true;
            return indexInput;
        } finally {
            if (success == false) {
                IOUtils.closeWhileHandlingException(fc);
            }
        }
    }

    /**
     * {@inheritDoc}
     * @param name the name of the file to be opened for writing
     * @param context the IO context
     */
    @Override
    public IndexOutput createOutput(String name, IOContext context) throws IOException {
        if (name.contains("segments_") || name.endsWith(".si")) return super.createOutput(name, context);
        ensureOpen();
        Path path = directory.resolve(name);
        OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);
        Cipher cipher = CipherFactory.getCipher(provider);
        SecureRandom random = Randomness.createSecure();
        byte[] iv = new byte[CipherFactory.IV_ARRAY_LENGTH];
        random.nextBytes(iv);
        if (dataKey == null) throw new RuntimeException("dataKey is null!");
        CipherFactory.initCipher(cipher, this, Optional.of(iv), Cipher.ENCRYPT_MODE, 0);
        ivMap.put(getDirectory() + "/" + name, Base64.getEncoder().encodeToString(iv));
        return new CryptoIndexOutput(name, path, fos, cipher);
    }

    /**
     * {@inheritDoc}
     * @param prefix the desired temporary file prefix
     * @param suffix the desired temporary file suffix
     * @param context the IO context
     */
    @Override
    public IndexOutput createTempOutput(String prefix, String suffix, IOContext context) throws IOException {
        if (prefix.contains("segments_") || prefix.endsWith(".si")) return super.createTempOutput(prefix, suffix, context);
        ensureOpen();
        String name;
        while (true) {
            name = getTempFileName(prefix, suffix, nextTempFileCounter.getAndIncrement());
            Path path = directory.resolve(name);
            OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);
            Cipher cipher = CipherFactory.getCipher(provider);
            SecureRandom random = Randomness.createSecure();
            byte[] iv = new byte[CipherFactory.IV_ARRAY_LENGTH];
            random.nextBytes(iv);
            CipherFactory.initCipher(cipher, this, Optional.of(iv), Cipher.ENCRYPT_MODE, 0);
            ivMap.put(getDirectory() + "/" + name, Base64.getEncoder().encodeToString(iv));
            return new CryptoIndexOutput(name, path, fos, cipher);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void close() throws IOException {
        try {
            deleteFile("ivMap");
        } catch (java.nio.file.NoSuchFileException fnfe) {

        }
        IndexOutput out = super.createOutput("ivMap", new IOContext());
        out.writeMapOfStrings(ivMap);
        out.close();
        isOpen = false;
        deletePendingFiles();
        dataKey = null;
    }

    /**
     * {@inheritDoc}
     * @param name the name of the file to be deleted
     */
    @Override
    public void deleteFile(String name) throws IOException {
        ivMap.remove(getDirectory() + "/" + name);
        super.deleteFile(name);
    }

    static class CipherFactory {
        static final int AES_BLOCK_SIZE_BYTES = 16;
        static final int COUNTER_SIZE_BYTES = 4;
        static final int IV_ARRAY_LENGTH = 16;

        public static Cipher getCipher(Provider provider) {
            try {
                return Cipher.getInstance("AES/CTR/NoPadding", provider);
            } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
                throw new RuntimeException();
            }
        }

        public static void initCipher(Cipher cipher, CryptoDirectory directory, Optional<byte[]> ivarray, int opmode, long newPosition) {
            try {
                byte[] iv = ivarray.isPresent() ? ivarray.get() : cipher.getIV();
                if (newPosition == 0) {
                    Arrays.fill(iv, IV_ARRAY_LENGTH - COUNTER_SIZE_BYTES, IV_ARRAY_LENGTH, (byte) 0);
                } else {
                    int counter = (int) (newPosition / AES_BLOCK_SIZE_BYTES);
                    for (int i = IV_ARRAY_LENGTH - 1; i >= IV_ARRAY_LENGTH - COUNTER_SIZE_BYTES; i--) {
                        iv[i] = (byte) counter;
                        counter = counter >>> Byte.SIZE;
                    }
                }
                IvParameterSpec spec = new IvParameterSpec(iv);
                cipher.init(opmode, directory.dataKey, spec);
                int bytesToRead = (int) (newPosition % AES_BLOCK_SIZE_BYTES);
                if (bytesToRead > 0) {
                    cipher.update(new byte[bytesToRead]);
                }
            } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
