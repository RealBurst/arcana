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
import java.util.zip.CRC32;

/**
 * OutputStream that updates a {@link CRC32} checksum while forwarding the
 * written bytes to an underlying stream.
 *
 * <p>Both {@link #write(int)} and {@link #write(byte[], int, int)} are
 * implemented so that bulk writes stay bulk all the way through: a single
 * decompressor call produces a single CRC update and a single underlying
 * write instead of one call per byte.</p>
 *
 * <p>The caller keeps ownership of the {@link CRC32} instance and reads its
 * value (via {@link #getValue()} or the passed-in object) once decompression
 * is finished.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class CrcOutputStream extends FilterOutputStream {

    private final CRC32 crc;

    /**
     * Wraps the given output stream and feeds every written byte into the
     * supplied CRC accumulator.
     *
     * @param out the underlying stream to forward bytes to
     * @param crc the CRC32 accumulator to update (owned by the caller)
     */
    public CrcOutputStream(OutputStream out, CRC32 crc) {
        super(out);
        this.crc = crc;
    }

    @Override
    public void write(int b) throws IOException {
        crc.update(b);
        out.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        crc.update(b, off, len);
        out.write(b, off, len);
    }

    /**
     * Returns the current CRC32 value.
     *
     * @return the checksum accumulated so far
     */
    public long getValue() {
        return crc.getValue();
    }
}
