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
package be.stef.arcana.formats.rar.rar5;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.util.List;

/**
 * InputStream that chains the compressed-data segments of a single file
 * spread across multiple RAR5 volumes, presenting them as one continuous
 * stream.
 *
 * <p>Mirrors the RAR4 implementation: the concatenated stream lets the LZ
 * decoder (and, when applicable, a single AES-CBC decrypting stream wrapped
 * around it) read transparently across volume boundaries.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class Rar5MultiVolumeInputStream extends InputStream {

    /** A contiguous chunk of a file's compressed data within one volume. */
    public static class Segment {
        final File volume;
        final long dataStart;
        final long size;
        public Segment(File volume, long dataStart, long size) {
            this.volume = volume;
            this.dataStart = dataStart;
            this.size = size;
        }
    }

    private final List<Segment> segments;
    private int               idx;
    private RandomAccessFile  raf;
    private long              remaining;

    public Rar5MultiVolumeInputStream(List<Segment> segments) throws IOException {
        this.segments = segments;
        openCurrent();
    }

    private void openCurrent() throws IOException {
        if (raf != null) { raf.close(); raf = null; }
        if (idx >= segments.size()) return;
        Segment s = segments.get(idx);
        raf = new RandomAccessFile(s.volume, "r");
        raf.seek(s.dataStart);
        remaining = s.size;
    }

    @Override
    public int read() throws IOException {
        byte[] b = new byte[1];
        int n = read(b, 0, 1);
        return n == -1 ? -1 : b[0] & 0xFF;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            while (raf != null && remaining == 0) { idx++; openCurrent(); }
            if (raf == null) break;
            int toRead = (int) Math.min(len - total, remaining);
            int n = raf.read(b, off + total, toRead);
            if (n == -1) { idx++; openCurrent(); continue; }
            remaining -= n;
            total += n;
        }
        return total == 0 ? -1 : total;
    }

    @Override
    public void close() throws IOException {
        if (raf != null) raf.close();
    }
}
