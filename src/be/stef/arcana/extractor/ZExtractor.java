/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.extractor;

import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.List;

/**
 * Extractor for Unix compress format (.Z) using the LZW algorithm.
 * Format: magic 1F 9D + header byte (bits 0-4=maxbits, bit 7=block_mode) + LZW data.
 */
public class ZExtractor implements ArchiveExtractor {

    private static final int MAGIC1     = 0x1F;
    private static final int MAGIC2     = 0x9D;
    private static final int BIT_MASK   = 0x1F;
    private static final int BLOCK_MODE = 0x80;
    private static final int CLEAR_CODE = 256;
    private static final int FIRST_CODE = 257;

    @Override public boolean supportsStream() { return true; }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final String name = stripExt(archive.getName(), ".Z");
        return Collections.singletonList(new ArcanaEntry.Builder(name).format(ArcanaFormat.Z).build());
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final File out = SafePathBuilder.buildSafePath(destination, stripExt(archive.getName(), ".Z"));
        try (InputStream in = new BufferedInputStream(new FileInputStream(archive))) {
            decompressTo(in, out);
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        decompressTo(in, new File(destination, "output"));
    }

    /** Decodes into {@code out}; the partial file is removed when decoding fails. */
    private static void decompressTo(final InputStream in, final File out) throws IOException {
        final OutputStream fos = ExtractionGuard.open(out);
        boolean ok = false;
        try (BufferedOutputStream bos = new BufferedOutputStream(fos)) {
            decompress(in, bos);
            ok = true;
        } finally {
            if (!ok && out.exists() && !out.delete()) out.deleteOnExit();
        }
    }

    // ---- LZW decompressor ----

    private static void decompress(final InputStream in, final OutputStream out) throws IOException {
        final int m1 = in.read(), m2 = in.read(), hdr = in.read();
        if (m1 != MAGIC1 || m2 != MAGIC2) throw new ArcanaCorruptedException("Not a .Z file (bad magic)");
        final int maxbits = hdr & BIT_MASK;
        final boolean block = (hdr & BLOCK_MODE) != 0;
        if (maxbits < 9 || maxbits > 16) throw new ArcanaCorruptedException("Invalid .Z maxbits: " + maxbits);

        final int maxcode = 1 << maxbits;
        final byte[][] tab = new byte[maxcode][];
        for (int i = 0; i < 256; i++) tab[i] = new byte[]{(byte) i};

        int freeEnt = block ? FIRST_CODE : 256;
        int nbits = 9;
        int limit = (1 << nbits) - 1;
        int oldCode = -1;
        byte finChar = 0;
        long bitBuf = 0;
        int bitsLeft = 0;
        int codeCount = 0; // codes read at the current width since the last CLEAR or width change
        final byte[] outBuf = new byte[65536];
        int outLen = 0;

        while (true) {
            while (bitsLeft < nbits) {
                final int b = in.read();
                if (b < 0) {
                    if (outLen > 0) out.write(outBuf, 0, outLen);
                    // compress flushes the last code on the next byte: a whole unused byte means the file was cut
                    if (bitsLeft >= 8) throw new ArcanaCorruptedException("Truncated .Z stream");
                    return;
                }
                bitBuf |= ((long) b) << bitsLeft;
                bitsLeft += 8;
            }
            final int code = (int) (bitBuf & ((1 << nbits) - 1));
            bitBuf >>>= nbits;
            bitsLeft -= nbits;
            codeCount++;

            if (block && code == CLEAR_CODE) {
                if (!skipGroupPadding(in, codeCount, nbits, bitsLeft)) throw new ArcanaCorruptedException("Truncated .Z stream");
                bitBuf = 0; bitsLeft = 0; codeCount = 0;
                for (int i = 256; i < maxcode; i++) tab[i] = null;
                freeEnt = FIRST_CODE; nbits = 9; limit = (1 << 9) - 1; oldCode = -1; continue;
            }
            if (oldCode == -1) {
                if (code > 255) throw new ArcanaCorruptedException("Bad first code in .Z stream");
                finChar = (byte) code;
                outBuf[outLen++] = finChar;
                if (outLen == outBuf.length) { out.write(outBuf, 0, outLen); outLen = 0; }
                oldCode = code; continue;
            }
            final byte[] suffix;
            if (code >= freeEnt) {
                if (code != freeEnt) throw new ArcanaCorruptedException("Bad code in .Z stream: " + code);
                final byte[] old = tab[oldCode];
                suffix = new byte[old.length + 1];
                System.arraycopy(old, 0, suffix, 0, old.length);
                suffix[old.length] = finChar;
            } else {
                suffix = tab[code];
            }
            for (final byte b : suffix) {
                outBuf[outLen++] = b;
                if (outLen == outBuf.length) { out.write(outBuf, 0, outLen); outLen = 0; }
            }
            finChar = suffix[0];
            if (freeEnt < maxcode) {
                final byte[] old = tab[oldCode];
                final byte[] entry = new byte[old.length + 1];
                System.arraycopy(old, 0, entry, 0, old.length);
                entry[old.length] = finChar;
                tab[freeEnt++] = entry;
            }
            oldCode = code;
            if (freeEnt > limit && nbits < maxbits) {
                // the end of the stream inside this padding is a normal end: the next read finds no byte
                skipGroupPadding(in, codeCount, nbits, bitsLeft);
                bitBuf = 0; bitsLeft = 0; codeCount = 0;
                nbits++; limit = nbits == maxbits ? maxcode - 1 : (1 << nbits) - 1;
            }
        }
    }

    /**
     * compress writes its codes in groups of 8 (nbits bytes) and, after a CLEAR or a
     * width change, pads the rest of the group (as ncompress reads it). A group always
     * ends on a byte boundary, so the padding is the buffered bits plus whole bytes.
     * Returns false if the stream ends inside the padding.
     */
    private static boolean skipGroupPadding(final InputStream in, final int codeCount, final int nbits, final int bitsLeft) throws IOException {
        final int padBytes = (((8 - (codeCount & 7)) & 7) * nbits - bitsLeft) >> 3;
        for (int i = 0; i < padBytes; i++) {
            if (in.read() < 0) return false;
        }
        return true;
    }

    /** Removes the suffix (any case); otherwise appends ".out" so that the output never replaces the archive. */
    private static String stripExt(final String name, final String ext) {
        final int n = name.length() - ext.length();
        return n > 0 && name.regionMatches(true, n, ext, 0, ext.length()) ? name.substring(0, n) : name + ".out";
    }
}
