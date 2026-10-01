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
        try (InputStream in = new BufferedInputStream(new FileInputStream(archive));
             BufferedOutputStream bos = new BufferedOutputStream(ExtractionGuard.open(out))) {
            decompress(in, bos);
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (BufferedOutputStream bos = new BufferedOutputStream(ExtractionGuard.open(new File(destination, "output")))) {
            decompress(in, bos);
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
        final byte[] outBuf = new byte[65536];
        int outLen = 0;

        while (true) {
            while (bitsLeft < nbits) {
                final int b = in.read();
                if (b < 0) { if (outLen > 0) out.write(outBuf, 0, outLen); return; }
                bitBuf |= ((long) b) << bitsLeft;
                bitsLeft += 8;
            }
            final int code = (int) (bitBuf & ((1 << nbits) - 1));
            bitBuf >>>= nbits;
            bitsLeft -= nbits;

            if (block && code == CLEAR_CODE) {
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
            if (freeEnt > limit && nbits < maxbits) { nbits++; limit = nbits == maxbits ? maxcode - 1 : (1 << nbits) - 1; }
        }
    }

    private static String stripExt(final String name, final String ext) {
        return name.endsWith(ext) ? name.substring(0, name.length() - ext.length()) : name;
    }
}
