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
package be.stef.arcana.formats.recover;

import be.stef.arcana.exceptions.ArcanaLimitExceededException;
import be.stef.arcana.formats.bzip2.BZip2InputStream;
import be.stef.arcana.formats.carve.ByteSource;
import be.stef.arcana.formats.deflate64.Deflate64InputStream;
import be.stef.arcana.formats.xz.LZMAInputStream;
import be.stef.arcana.formats.xz.XZInputStream;
import be.stef.arcana.formats.zstd.ZstdInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Recovery of a damaged ZIP: the central directory (at the end, often the first
 * victim of a truncation) is ignored and the local headers are searched one by
 * one. Each entry is decoded as far as possible: an entry whose data is damaged
 * is written up to the error (PARTIAL), and the search resumes after it, so the
 * following entries are still recovered.
 *
 * @author Stef
 * @since 1.3
 */
final class ZipRecovery {

    private static final byte[] LOCAL = {'P', 'K', 3, 4};
    private static final byte[] DESCRIPTOR = {'P', 'K', 7, 8};

    private ZipRecovery() {}

    static void recover(final File zip, final Outputs out, final RecoveryReport report) throws IOException {
        int found = 0;
        try (ByteSource s = new ByteSource(zip)) {
            final long len = s.length();
            long pos = 0;
            while ((pos = s.indexOf(LOCAL, pos, len)) >= 0) {
                final long next = entry(s, pos, out, report);
                if (next == -1) { pos += 4; continue; } // not a plausible header
                found++;
                pos = Math.max(pos + 4, next);
            }
        }
        if (found == 0) report.note("No ZIP local header found: nothing to recover.");
    }

    /**
     * Recovers the entry at {@code pos}.
     *
     * @return where to search the next header, or -1 if this is not a plausible header
     */
    private static long entry(final ByteSource s, final long pos, final Outputs out, final RecoveryReport report) throws IOException {
        final int flags = s.u16le(pos + 6);
        final int method = s.u16le(pos + 8);
        final long crc = s.u32le(pos + 14);
        long csize = s.u32le(pos + 18);
        long usize = s.u32le(pos + 22);
        final int nameLen = s.u16le(pos + 26);
        final int extraLen = s.u16le(pos + 28);
        if (nameLen <= 0 || nameLen > 4096 || extraLen < 0) return -1;
        final byte[] nameBytes = s.bytes(pos + 30, nameLen);
        if (nameBytes == null) return -1;
        for (final byte b : nameBytes) if ((b & 0xFF) < 0x20) return -1;
        final String name = decodeName(nameBytes, (flags & 0x800) != 0);
        // ZIP64 extra field
        final long extra = pos + 30 + nameLen;
        for (long e = extra; e + 4 <= extra + extraLen; ) {
            final int id = s.u16le(e), sz = s.u16le(e + 2);
            if (id == 1) {
                int k = 0;
                if (usize == 0xFFFFFFFFL && 8 * k + 8 <= sz) { usize = s.u64le(e + 4 + 8 * k); k++; }
                if (csize == 0xFFFFFFFFL && 8 * k + 8 <= sz) { csize = s.u64le(e + 4 + 8 * k); }
            }
            e += 4 + sz;
        }
        final long dataStart = extra + extraLen;
        final boolean descriptor = (flags & 8) != 0;
        final boolean sizeKnown = !descriptor || csize > 0;
        if (name.endsWith("/") || name.endsWith("\\")) {
            out.directory(name);
            return dataStart + (sizeKnown ? csize : 0);
        }
        if ((flags & 1) != 0) {
            report.add(name, RecoveryReport.Status.LOST, 0, sizeKnown ? usize : -1, "encrypted entry: not recoverable in forced mode");
            return dataStart + (sizeKnown ? csize : 0);
        }
        final CRC32 c = new CRC32();
        final long[] written = {0};
        long consumed = -1; // compressed bytes used, when known exactly
        String error = null;
        try (OutputStream o = out.file(name)) {
            if (method == 8 || (method == 0 && !sizeKnown)) {
                consumed = method == 8 ? inflate(s, dataStart, sizeKnown ? csize : s.length() - dataStart, o, c, written) : storedUnknown(s, dataStart, o, c, written);
            } else {
                final long limit = sizeKnown ? csize : s.length() - dataStart;
                final InputStream raw = new SourceInputStream(s, dataStart, limit);
                final InputStream in = decoder(method, raw, flags, usize);
                if (in == null) {
                    error = "compression method " + method + " not supported";
                } else {
                    copy(in, o, c, written);
                    if (sizeKnown) consumed = csize;
                }
            }
        } catch (final ArcanaLimitExceededException e) {
            throw e;
        } catch (final IOException | RuntimeException | DataFormatException e) {
            error = e.getClass().getSimpleName() + (e.getMessage() != null ? ": " + e.getMessage() : "");
        }
        // Expected CRC / size: from the data descriptor when the header does not carry them
        long expCrc = crc, expSize = usize;
        long afterData = consumed >= 0 ? dataStart + consumed : -1;
        if (descriptor && afterData >= 0) {
            long d = afterData;
            if (s.matches(d, DESCRIPTOR)) d += 4;
            expCrc = s.u32le(d);
            expSize = s.u32le(d + 8);
            afterData = d + 12;
        }
        final RecoveryReport.Status st;
        if (error != null) {
            if (written[0] == 0) out.dropLastIfEmpty();
            st = written[0] == 0 ? RecoveryReport.Status.LOST : RecoveryReport.Status.PARTIAL;
        } else if (c.getValue() == expCrc && (expSize < 0 || written[0] == expSize || expSize == 0xFFFFFFFFL)) {
            st = RecoveryReport.Status.OK;
        } else {
            st = RecoveryReport.Status.BAD_CHECKSUM;
            error = String.format("CRC %08x instead of %08x", c.getValue(), expCrc);
        }
        report.add(name, st, written[0], expSize, error);
        // A damaged entry: its announced size cannot be trusted, search the next header right after its header
        if (st == RecoveryReport.Status.OK && afterData > 0) return afterData;
        return sizeKnown && st != RecoveryReport.Status.PARTIAL && st != RecoveryReport.Status.LOST ? dataStart + csize : dataStart;
    }

    private static InputStream decoder(final int method, final InputStream raw, final int flags, final long usize) throws IOException {
        switch (method) {
            case 0:  return raw;
            case 9:  return new Deflate64InputStream(raw, true);
            case 12: return new BZip2InputStream(raw);
            case 14: {
                final byte[] h = new byte[9];
                int n = 0;
                while (n < 9) {
                    final int k = raw.read(h, n, 9 - n);
                    if (k < 0) throw new IOException("truncated LZMA header");
                    n += k;
                }
                final int dict = (h[5] & 0xFF) | ((h[6] & 0xFF) << 8) | ((h[7] & 0xFF) << 16) | ((h[8] & 0xFF) << 24);
                return new LZMAInputStream(raw, (flags & 2) != 0 ? -1L : usize, h[4], dict);
            }
            case 93: return new ZstdInputStream(raw);
            case 95: return new XZInputStream(raw);
            default: return null;
        }
    }

    /** Raw deflate decoding; returns the number of compressed bytes used. */
    private static long inflate(final ByteSource s, final long start, final long limit, final OutputStream o, final CRC32 c, final long[] written) throws IOException, DataFormatException {
        final Inflater inf = new Inflater(true);
        try {
            final byte[] in = new byte[65536];
            final byte[] outBuf = new byte[65536];
            long fed = 0;
            while (!inf.finished()) {
                if (inf.needsInput()) {
                    final int n = s.read(start + fed, in, 0, (int) Math.min(in.length, limit - fed));
                    if (n <= 0) throw new IOException("compressed data ends before the end of the deflate stream");
                    inf.setInput(in, 0, n);
                    fed += n;
                }
                final int k = inf.inflate(outBuf);
                if (k > 0) {
                    o.write(outBuf, 0, k);
                    c.update(outBuf, 0, k);
                    written[0] += k;
                } else if (inf.needsDictionary()) {
                    throw new DataFormatException("preset dictionary required");
                }
            }
            return fed - inf.getRemaining();
        } finally {
            inf.end();
        }
    }

    /** Stored entry of unknown size (data descriptor): up to the descriptor signature. */
    private static long storedUnknown(final ByteSource s, final long start, final OutputStream o, final CRC32 c, final long[] written) throws IOException {
        long end = s.indexOf(DESCRIPTOR, start, s.length());
        if (end < 0) end = s.length();
        final byte[] buf = new byte[65536];
        long p = start;
        while (p < end) {
            final int n = s.read(p, buf, 0, (int) Math.min(buf.length, end - p));
            if (n <= 0) break;
            o.write(buf, 0, n);
            c.update(buf, 0, n);
            written[0] += n;
            p += n;
        }
        return end - start;
    }

    private static void copy(final InputStream in, final OutputStream o, final CRC32 c, final long[] written) throws IOException {
        final byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) {
            o.write(buf, 0, n);
            c.update(buf, 0, n);
            written[0] += n;
        }
    }

    static String decodeName(final byte[] b, final boolean utf8Flag) {
        if (utf8Flag) return new String(b, StandardCharsets.UTF_8);
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString();
        } catch (final CharacterCodingException e) {
            try {
                return new String(b, Charset.forName("IBM437"));
            } catch (final RuntimeException ex) {
                return new String(b, StandardCharsets.ISO_8859_1);
            }
        }
    }
}
