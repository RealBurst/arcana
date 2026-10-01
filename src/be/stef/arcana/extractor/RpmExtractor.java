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
import be.stef.arcana.formats.cpio.CpioEntry;
import be.stef.arcana.formats.cpio.CpioInputStream;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;

/**
 * Extractor for RPM packages (.rpm).
 * Structure: 96-byte Lead + Signature header (aligned 8) + Main header + CPIO payload.
 * The payload compressor is read from RPM tag 1124 (RPMTAG_PAYLOADCOMPRESSOR).
 */
public class RpmExtractor implements ArchiveExtractor {

    private static final int LEAD_SIZE             = 96;
    private static final int TAG_PAYLOADCOMPRESSOR = 1124;
    private static final int TYPE_STRING           = 6;

    @Override public boolean supportsStream() { return false; }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (CpioInputStream cpio = openCpio(archive)) {
            CpioEntry entry;
            while ((entry = cpio.getNextEntry()) != null) {
                final String name = stripDotSlash(entry.getName());
                if (!name.equals("TRAILER!!!")) {
                    result.add(new ArcanaEntry.Builder(name)
                            .uncompressedSize(entry.getSize())
                            .directory(entry.isDirectory())
                            .format(ArcanaFormat.RPM)
                            .build());
                }
                cpio.closeEntry();
            }
        }
        return result;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (CpioInputStream cpio = openCpio(archive)) {
            CpioEntry entry;
            while ((entry = cpio.getNextEntry()) != null) {
                final String name = stripDotSlash(entry.getName());
                if (name.equals("TRAILER!!!")) { cpio.closeEntry(); break; }
                final File out = SafePathBuilder.buildSafePath(destination, name.replace("/", File.separator));
                if (entry.isDirectory()) {
                    IOHelper.mkdirs(out);
                } else {
                    IOHelper.mkdirs(out.getParentFile());
                    try (BufferedOutputStream bos = new BufferedOutputStream(ExtractionGuard.open(out))) {
                        IOHelper.copy(cpio, bos);
                    }
                }
                cpio.closeEntry();
            }
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        throw new UnsupportedOperationException("RPM extraction requires seekable file");
    }

    // ---- RPM parsing ----

    private static CpioInputStream openCpio(final File archive) throws IOException {
        final InputStream raw = new BufferedInputStream(new FileInputStream(archive));
        // Lead
        final byte[] lead = new byte[LEAD_SIZE]; readFully(raw, lead);
        if ((lead[0]&0xFF)!=0xED||(lead[1]&0xFF)!=0xAB||(lead[2]&0xFF)!=0xEE||(lead[3]&0xFF)!=0xDB)
            throw new ArcanaCorruptedException("Not an RPM file");
        // Signature header + alignment
        skipRpmHeaderAligned(raw);
        // Main header -> read payload compressor
        final String compressor = readMainHeader(raw);
        return new CpioInputStream(wrapPayload(raw, compressor));
    }

    private static void skipRpmHeaderAligned(final InputStream in) throws IOException {
        checkHdrMagic(in);
        final int nindex = readInt32BE(in), hsize = readInt32BE(in);
        skipFully(in, (long)nindex*16 + hsize);
        final long total = 8+4+4+(long)nindex*16+hsize;
        skipFully(in, ((8-(total%8))%8));
    }

    private static String readMainHeader(final InputStream in) throws IOException {
        checkHdrMagic(in);
        final int nindex = readInt32BE(in), hsize = readInt32BE(in);
        final int[] tags=new int[nindex], types=new int[nindex], offsets=new int[nindex];
        for (int i=0;i<nindex;i++) { tags[i]=readInt32BE(in); types[i]=readInt32BE(in); offsets[i]=readInt32BE(in); readInt32BE(in); }
        final byte[] store = new byte[hsize]; readFully(in, store);
        for (int i=0;i<nindex;i++) {
            if (tags[i]==TAG_PAYLOADCOMPRESSOR && types[i]==TYPE_STRING) {
                int off=offsets[i], end=off;
                while (end<store.length && store[end]!=0) end++;
                return new String(store, off, end-off, "ASCII").toLowerCase();
            }
        }
        return "gzip";
    }

    private static void checkHdrMagic(final InputStream in) throws IOException {
        final byte[] m = new byte[8]; readFully(in, m);
        if ((m[0]&0xFF)!=0x8E||(m[1]&0xFF)!=0xAD||(m[2]&0xFF)!=0xE8) throw new ArcanaCorruptedException("Invalid RPM header magic");
    }

    private static InputStream wrapPayload(final InputStream in, final String comp) throws IOException {
        if ("gzip".equals(comp)||"gz".equals(comp))   return new GZIPInputStream(in);
        if ("bzip2".equals(comp)||"bz2".equals(comp)) return new be.stef.arcana.formats.bzip2.BZip2InputStream(in);
        if ("xz".equals(comp))                        return new be.stef.arcana.formats.xz.XZInputStream(in);
        if ("zstd".equals(comp)||"zst".equals(comp))  return new be.stef.arcana.formats.zstd.ZstdInputStream(in);
        if ("lzma".equals(comp))                      return new be.stef.arcana.formats.xz.LZMAInputStream(in);
        return in;
    }

    // ---- I/O helpers ----
    private static int readInt32BE(final InputStream in) throws IOException { int b0=in.read(),b1=in.read(),b2=in.read(),b3=in.read(); if(b3<0)throw new IOException("EOF"); return (b0<<24)|(b1<<16)|(b2<<8)|b3; }
    private static void readFully(final InputStream in, final byte[] buf) throws IOException { int o=0; while(o<buf.length){int n=in.read(buf,o,buf.length-o);if(n<0)throw new IOException("EOF");o+=n;} }
    private static void skipFully(final InputStream in, final long n) throws IOException { long r=n; while(r>0){long s=in.skip(r);if(s<=0){in.read();r--;}else r-=s;} }
    private static String stripDotSlash(final String name) { if(name.startsWith("./"))return name.substring(2); if(name.startsWith("/"))return name.substring(1); return name; }
}
