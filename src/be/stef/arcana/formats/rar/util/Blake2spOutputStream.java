/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.stef.arcana.formats.rar.util;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * OutputStream that updates a {@link Blake2sp.Digest} while forwarding the
 * written bytes to an underlying stream.
 *
 * <p>Counterpart of {@link CrcOutputStream} for BLAKE2sp. Both
 * {@link #write(int)} and {@link #write(byte[], int, int)} are implemented so
 * that bulk writes stay bulk all the way through.</p>
 *
 * <p>The caller keeps ownership of the {@link Blake2sp.Digest} instance and
 * reads its value once decompression is finished, so the extracted file never
 * has to be read back from disk for verification.</p>
 *
 * @author Stef
 * @since 2.0.1
 */
public class Blake2spOutputStream extends FilterOutputStream {

    private final Blake2sp.Digest digest;
    private final byte[] one = new byte[1];

    /**
     * Wraps the given output stream and feeds every written byte into the
     * supplied BLAKE2sp accumulator.
     *
     * @param out    the underlying stream to forward bytes to
     * @param digest the BLAKE2sp accumulator to update (owned by the caller)
     */
    public Blake2spOutputStream(OutputStream out, Blake2sp.Digest digest) {
        super(out);
        this.digest = digest;
    }

    @Override
    public void write(int b) throws IOException {
        one[0] = (byte) b;
        digest.update(one, 0, 1);
        out.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        digest.update(b, off, len);
        out.write(b, off, len);
    }
}
