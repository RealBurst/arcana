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
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.tar.TarEntry;
import be.stef.arcana.formats.tar.TarInputStream;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;
import be.stef.arcana.util.StreamBoundedInputStream;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for Unix AR archives (.a, .deb).
 * Format: magic "!<arch>\n" + N*(60-byte header + data + optional pad byte).
 * Supports GNU long names (// entry), BSD long names (#1/N), and short names.
 * Debian packages are unpacked by default (see {@link #ArExtractor(boolean)}).
 */
public class ArExtractor implements ArchiveExtractor {

    private static final byte[] MAGIC = {'!','<','a','r','c','h','>','\n'};
    private static final int    HDR   = 60;

    private final boolean unpackDeb;

    /** Creates an extractor that unpacks Debian packages (see {@link #ArExtractor(boolean)}). */
    public ArExtractor() { this(true); }

    /**
     * @param unpackDeb if true and the archive is a Debian package (first member
     *                  {@code debian-binary}), the package is unpacked like
     *                  {@code dpkg-deb -R}: the contents of {@code data.tar.*} go to the
     *                  destination root and those of {@code control.tar.*} to
     *                  {@code DEBIAN/}; {@code debian-binary} is skipped. If false, the
     *                  AR members are extracted as-is.
     */
    public ArExtractor(final boolean unpackDeb) { this.unpackDeb = unpackDeb; }

    @Override public boolean supportsStream() { return false; }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (InputStream in = new BufferedInputStream(new FileInputStream(archive))) {
            checkMagic(in);
            String gnuNames = null;
            boolean deb = false;
            boolean first = true;
            final byte[] hdr = new byte[HDR];
            while (readHeader(in, hdr)) {
                final String rawName = ascii(hdr, 0, 16).trim();
                final long   size    = parseLong(ascii(hdr, 48, 10).trim());
                if (rawName.equals("//")) { gnuNames = readString(in, (int) size); skipPad(in, size); continue; }
                if (rawName.equals("/") || rawName.equals("/SYM64/")) { skipFully(in, size); skipPad(in, size); continue; }
                final EntryInfo info = resolveEntry(in, rawName, size, gnuNames);
                if (first) { deb = unpackDeb && info.name.equals(DEB_MARKER); first = false; }
                if (deb && isDebTar(info.name)) {
                    final StreamBoundedInputStream member = new StreamBoundedInputStream(in, info.dataSize);
                    listTar(debTarStream(info.name, member), info.name.startsWith(DEB_CONTROL) ? DEB_CONTROL_DIR + "/" : "", result);
                    IOHelper.drain(member);
                } else if (deb && info.name.equals(DEB_MARKER)) {
                    skipFully(in, info.dataSize);
                } else {
                    result.add(new ArcanaEntry.Builder(info.name).uncompressedSize(info.dataSize).format(ArcanaFormat.AR).build());
                    skipFully(in, info.dataSize);
                }
                skipPad(in, size);
            }
        }
        return result;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (InputStream in = new BufferedInputStream(new FileInputStream(archive))) {
            checkMagic(in);
            String gnuNames = null;
            boolean deb = false;
            boolean first = true;
            final byte[] hdr = new byte[HDR];
            while (readHeader(in, hdr)) {
                final String rawName = ascii(hdr, 0, 16).trim();
                final long   size    = parseLong(ascii(hdr, 48, 10).trim());
                if (rawName.equals("//")) { gnuNames = readString(in, (int) size); skipPad(in, size); continue; }
                if (rawName.equals("/") || rawName.equals("/SYM64/")) { skipFully(in, size); skipPad(in, size); continue; }
                final EntryInfo info = resolveEntry(in, rawName, size, gnuNames);
                if (first) { deb = unpackDeb && info.name.equals(DEB_MARKER); first = false; }
                if (deb && isDebTar(info.name)) {
                    // Bounded view: the decompressor cannot read past this member; TarExtractor may close it safely
                    final StreamBoundedInputStream member = new StreamBoundedInputStream(in, info.dataSize);
                    final File target = info.name.startsWith(DEB_CONTROL) ? new File(destination, DEB_CONTROL_DIR) : destination;
                    try (InputStream tarStream = debTarStream(info.name, member)) {
                        new TarExtractor().extractFrom(new TarInputStream(tarStream), target);
                        IOHelper.drain(tarStream); // to the end of the compressed stream: verifies its checksum
                    }
                    IOHelper.drain(member); // compressor padding left unread
                } else if (deb && info.name.equals(DEB_MARKER)) {
                    skipFully(in, info.dataSize); // always "2.0\n", not part of the package contents
                } else {
                    final File out = SafePathBuilder.buildSafePath(destination, info.name.replace("/", File.separator));
                    IOHelper.mkdirs(out.getParentFile());
                    try (BufferedOutputStream bos = new BufferedOutputStream(ExtractionGuard.open(out))) {
                        IOHelper.copyExactly(in, bos, info.dataSize);
                    }
                }
                skipPad(in, size);
            }
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        throw new UnsupportedOperationException("AR extraction requires seekable file");
    }

    // ---- Debian package helpers ----

    private static final String DEB_MARKER      = "debian-binary";
    private static final String DEB_DATA        = "data.tar";
    private static final String DEB_CONTROL     = "control.tar";
    private static final String DEB_CONTROL_DIR = "DEBIAN";

    private static boolean isDebTar(final String name) {
        return name.startsWith(DEB_DATA) || name.startsWith(DEB_CONTROL);
    }

    /** Decompresses a data.tar.* / control.tar.* member according to its suffix. */
    private static InputStream debTarStream(final String name, final InputStream member) throws IOException {
        if (name.endsWith(".tar"))  return member;
        if (name.endsWith(".gz"))   return CompressedStreamExtractor.openDecompressed(ArcanaFormat.GZIP, member);
        if (name.endsWith(".xz"))   return CompressedStreamExtractor.openDecompressed(ArcanaFormat.XZ, member);
        if (name.endsWith(".zst"))  return CompressedStreamExtractor.openDecompressed(ArcanaFormat.ZSTD, member);
        if (name.endsWith(".bz2"))  return CompressedStreamExtractor.openDecompressed(ArcanaFormat.BZIP2, member);
        if (name.endsWith(".lzma")) return CompressedStreamExtractor.openDecompressed(ArcanaFormat.LZMA, member);
        throw new ArcanaUnsupportedFormatException("Unsupported Debian package member compression: " + name);
    }

    private static void listTar(final InputStream in, final String prefix, final List<ArcanaEntry> result) throws IOException {
        final TarInputStream tis = new TarInputStream(in);
        TarEntry e;
        while ((e = tis.getNextTarEntry()) != null) {
            String name = e.getName();
            while (name.startsWith("./")) name = name.substring(2);
            if (name.isEmpty() || name.equals(".")) continue;
            result.add(new ArcanaEntry.Builder(prefix + name).uncompressedSize(e.getSize()).compressedSize(e.getSize()).lastModifiedTime(e.getModTime().getTime() / 1000L).directory(e.isDirectory()).format(ArcanaFormat.AR).build());
        }
    }

    // ---- helpers ----

    private static void checkMagic(final InputStream in) throws IOException {
        final byte[] magic = new byte[8];
        readFully(in, magic);
        for (int i = 0; i < MAGIC.length; i++) if (magic[i] != MAGIC[i]) throw new ArcanaCorruptedException("Not an AR archive");
    }

    private static boolean readHeader(final InputStream in, final byte[] hdr) throws IOException {
        int r = in.read(hdr);
        if (r < 0) return false;
        if (r < HDR) throw new ArcanaCorruptedException("Truncated AR header");
        if (hdr[58] != 0x60 || hdr[59] != '\n') throw new ArcanaCorruptedException("Invalid AR entry magic");
        return true;
    }

    private static final class EntryInfo { final String name; final long dataSize; EntryInfo(String n, long s){name=n;dataSize=s;} }

    private static EntryInfo resolveEntry(final InputStream in, final String rawName, final long size, final String gnuNames) throws IOException {
        if (rawName.startsWith("#1/")) {
            final int nameLen = Integer.parseInt(rawName.substring(3).trim());
            final byte[] nameBuf = new byte[nameLen]; readFully(in, nameBuf);
            int end = nameBuf.length;
            for (int i=0;i<nameBuf.length;i++) if(nameBuf[i]==0){end=i;break;}
            return new EntryInfo(new String(nameBuf,0,end,"ASCII"), size - nameLen);
        }
        if (rawName.startsWith("/")) {
            final int offset = Integer.parseInt(rawName.substring(1).trim());
            if (gnuNames == null) throw new ArcanaCorruptedException("GNU long names table missing");
            int end = gnuNames.indexOf('\n', offset);
            final String name = gnuNames.substring(offset, end<0?gnuNames.length():end).replace("/","").trim();
            return new EntryInfo(name, size);
        }
        final String name = rawName.endsWith("/") ? rawName.substring(0,rawName.length()-1) : rawName;
        return new EntryInfo(name, size);
    }

    private static String readString(final InputStream in, final int n) throws IOException {
        final byte[] buf = new byte[n]; readFully(in, buf); return new String(buf, "ASCII");
    }
    private static String ascii(final byte[] b, final int off, final int len) { return new String(b, off, len); }
    private static long parseLong(final String s) { try { return s.isEmpty()?0:Long.parseLong(s); } catch (NumberFormatException e) { return 0; } }
    private static void readFully(final InputStream in, final byte[] buf) throws IOException { int o=0; while(o<buf.length){int n=in.read(buf,o,buf.length-o);if(n<0)throw new IOException("Unexpected EOF");o+=n;} }
    private static void skipFully(final InputStream in, final long n) throws IOException { long r=n; while(r>0){long s=in.skip(r);if(s<=0){in.read();r--;}else r-=s;} }
    private static void skipPad(final InputStream in, final long size) throws IOException { if((size&1)!=0) in.read(); }
}
