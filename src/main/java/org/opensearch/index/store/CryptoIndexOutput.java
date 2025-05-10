/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.apache.lucene.store.OutputStreamIndexOutput;

/**
 * An IndexOutput implementation that encrypts data before writing
 *
 * @opensearch.internal
 */
public final class CryptoIndexOutput extends OutputStreamIndexOutput {
    /**
     * The maximum chunk size is 8192 bytes, because file channel mallocs a native buffer outside of
     * stack if the write buffer size is larger.
     */
    static final int CHUNK_SIZE = 8192;

    /**
     * Creates a new CryptoIndexOutput
     *
     * @param name The name of the output
     * @param path The path to write to
     * @param os The output stream
     * @param cipher The cipher to use for encryption
     * @throws IOException If there is an I/O error
     */
    public CryptoIndexOutput(String name, Path path, OutputStream os, Cipher cipher) throws IOException {
        super("FSIndexOutput(path=\"" + path + "\")", name, new FilterOutputStream(os) {

            /**
             * {@inheritDoc}
             */
            @Override
            public void close() throws IOException {
                try {
                    out.write(cipher.doFinal());
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    throw new RuntimeException(e);
                }
                super.close();
            }

            /**
            * {@inheritDoc}
            */
            @Override
            public void write(byte[] b, int offset, int length) throws IOException {
                int count = 0;
                byte[] res;
                while (length > 0) {
                    count++;
                    final int chunk = Math.min(length, CHUNK_SIZE);
                    try {
                        res = cipher.update(b, offset, chunk);
                        if (res != null)
                            out.write(res);
                    } catch (IllegalStateException e) {
                        throw new IllegalStateException("count is " + count + " " + e.getMessage());
                    }
                    length -= chunk;
                    offset += chunk;
                }
            }
        }, CHUNK_SIZE);
    }
}
