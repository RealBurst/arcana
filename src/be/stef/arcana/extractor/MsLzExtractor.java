/*
 * Copyright 2026 Stephane Bury
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
package be.stef.arcana.extractor;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.List;

/**
 * Extractor for files compressed by the Microsoft COMPRESS.EXE tool
 * ("SZDD" format, the "*.ex_", "*.dl_" files of old Windows and DOS setup
 * disks), written from the public description of the format.
 *
 * <p>Header (14 bytes): "SZDD" 0x88 0xF0 0x27 0x33, mode 'A', the last
 * character of the original name (replaced by '_'), the original size. Data:
 * LZSS with a 4 KiB window filled with spaces, writing from 4096 - 16; each
 * flag byte announces 8 items, low bit first: 1 = literal byte, 0 = match
 * of 2 bytes (12-bit window position, 4-bit length - 3).</p>
 *
 * @author Stef
 * @since 1.0.4
 */
public class MsLzExtractor implements ArchiveExtractor {

    private static final byte[] MAGIC = {'S', 'Z', 'D', 'D', (byte) 0x88, (byte) 0xF0, 0x27, 0x33};

    @Override
    public boolean supportsStream() {
        return true;
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        try (InputStream in = new BufferedInputStream(new FileInputStream(archive))) {
            final byte[] h = header(in);
            return Collections.singletonList(new ArcanaEntry.Builder(outputName(archive.getName(), h[9])).uncompressedSize(le32(h, 10) & 0xffffffffL).compressedSize(archive.length()).format(ArcanaFormat.MSLZ).build());
        }
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (InputStream in = new BufferedInputStream(new FileInputStream(archive), 65536)) {
            final byte[] h = header(in);
            final File target = SafePathBuilder.buildSafePath(destination, outputName(archive.getName(), h[9]));
            try (OutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                decompress(in, out, le32(h, 10) & 0xffffffffL);
            }
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final byte[] h = header(in);
        try (OutputStream out = new BufferedOutputStream(ExtractionGuard.open(new File(destination, "output")), 65536)) {
            decompress(in, out, le32(h, 10) & 0xffffffffL);
        }
    }

    private static byte[] header(final InputStream in) throws IOException {
        final byte[] h = new byte[14];
        int n = 0;
        while (n < h.length) {
            final int r = in.read(h, n, h.length - n);
            if (r < 0) throw new ArcanaCorruptedException("SZDD header truncated");
            n += r;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (h[i] != MAGIC[i]) throw new ArcanaCorruptedException("Not an SZDD file");
        }
        if (h[8] != 'A') throw new ArcanaUnsupportedFormatException("SZDD compression mode " + (h[8] & 0xff) + " is not supported");
        return h;
    }

    /** "setup.ex_" + 'e' gives "setup.exe"; without the character the '_' is dropped. */
    static String outputName(final String packed, final byte missing) {
        if (!packed.endsWith("_")) return packed.endsWith(".") || packed.isEmpty() ? packed + "out" : packed;
        final String base = packed.substring(0, packed.length() - 1);
        final int c = missing & 0xff;
        if (c > 0x20 && c < 0x7f && c != '/' && c != '\\' && c != ':') {
            final boolean lower = !base.equals(base.toUpperCase());
            return base + (lower ? Character.toLowerCase((char) c) : (char) c);
        }
        return base.endsWith(".") ? base.substring(0, base.length() - 1) : base;
    }

    private static void decompress(final InputStream in, final OutputStream out, final long size) throws IOException {
        final byte[] window = new byte[4096];
        java.util.Arrays.fill(window, (byte) ' ');
        int pos = 4096 - 16;
        long written = 0;
        while (written < size) {
            final int flags = in.read();
            if (flags < 0) break;
            for (int bit = 0; bit < 8 && written < size; bit++) {
                if ((flags >> bit & 1) != 0) {
                    final int c = in.read();
                    if (c < 0) break;
                    out.write(c);
                    written++;
                    window[pos] = (byte) c;
                    pos = (pos + 1) & 4095;
                } else {
                    final int b1 = in.read();
                    final int b2 = in.read();
                    if (b2 < 0) break;
                    int from = b1 | (b2 & 0xf0) << 4;
                    for (int len = (b2 & 0x0f) + 3; len > 0 && written < size; len--) {
                        final byte c = window[from];
                        from = (from + 1) & 4095;
                        out.write(c);
                        written++;
                        window[pos] = c;
                        pos = (pos + 1) & 4095;
                    }
                }
            }
        }
        if (written != size) throw new ArcanaCorruptedException("SZDD data truncated (" + written + " of " + size + " bytes)");
    }

    private static int le32(final byte[] b, final int p) {
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8 | (b[p + 2] & 0xff) << 16 | (b[p + 3] & 0xff) << 24;
    }
}
