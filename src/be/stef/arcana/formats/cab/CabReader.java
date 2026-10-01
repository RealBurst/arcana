/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.cab;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;

/**
 * Reads Microsoft Cabinet ({@code .cab}) archives and extracts their contents.
 *
 * <p>Implements the CFHEADER, CFFOLDER, CFFILE and CFDATA structures as defined
 * in the MS-CAB specification (sections 2.1-2.4). Supports compression types
 * NONE (0x0000), MSZIP (0x0001) and LZX (0x0003).</p>
 *
 * <p>Quantum (0x0002) is not supported and will throw {@link IOException}.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class CabReader implements Closeable {

    private static final int MAGIC = 0x4643534D; // "MSCF" (bytes 4D 53 43 46 read as little-endian int)

    static final int COMPRESS_NONE  = 0x0000;
    static final int COMPRESS_MSZIP = 0x0001;
    static final int COMPRESS_QUANT = 0x0002;
    static final int COMPRESS_LZX   = 0x0003;

    private static final int FLAG_PREV_CABINET   = 0x0001;
    private static final int FLAG_NEXT_CABINET   = 0x0002;
    private static final int FLAG_RESERVE_FIELDS = 0x0004;
    private static final int ATTR_NAME_IS_UTF    = 0x0080;

    private static final class Folder {
        long dataOffset;
        int  numDataBlocks;
        int  compression;
        int  windowBits;
        int  reservedSize;
    }

    private final RandomAccessFile raf;
    private final List<CabEntry>   entries = new ArrayList<CabEntry>();
    private final List<Folder>     folders = new ArrayList<Folder>();

    private int coffFiles;
    private int cFolders;
    private int cFiles;
    private int flags;
    private int perCabinetReserveSize;
    private int perFolderReserveSize;
    private int perDataBlockReserveSize;

    /**
     * Opens and parses the CAB archive at the given path.
     *
     * @param path path to the .cab file
     * @throws IOException if the file is not a valid Cabinet archive
     */
    public CabReader(String path) throws IOException {
        this.raf = new RandomAccessFile(path, "r");
        try {
            readHeader();
            readFolders();
            readFiles();
        } catch (IOException e) {
            raf.close();
            throw e;
        }
    }

    /** Returns all file entries in the archive. */
    public List<CabEntry> getEntries() { return entries; }

    /**
     * Extracts the given entry, writing all decompressed bytes to {@code out}.
     *
     * @param entry the entry to extract
     * @param out   destination stream
     * @throws IOException if extraction fails
     */
    public void extract(CabEntry entry, OutputStream out) throws IOException {
        extractFromFolder(entry.getFolderIndex(), entry.getFolderOffset(), entry.getSize(), out);
    }

    @Override
    public void close() throws IOException { raf.close(); }

    // =========================================================================
    // Header parsing
    // =========================================================================

    private void readHeader() throws IOException {
        raf.seek(0);
        byte[] hdr = new byte[36];
        readFully(hdr, 0, 36);
        int magic = getInt32LE(hdr, 0);
        if (magic != MAGIC) throw new IOException("CAB: not a Cabinet file (bad magic)");
        coffFiles = getInt32LE(hdr, 16);
        cFolders  = getUInt16LE(hdr, 26);
        cFiles    = getUInt16LE(hdr, 28);
        flags     = getUInt16LE(hdr, 30);

        if ((flags & FLAG_RESERVE_FIELDS) != 0) {
            byte[] res = new byte[4];
            readFully(res, 0, 4);
            perCabinetReserveSize   = getUInt16LE(res, 0);
            perFolderReserveSize    = res[2] & 0xFF;
            perDataBlockReserveSize = res[3] & 0xFF;
            raf.skipBytes(perCabinetReserveSize);
        }
        if ((flags & FLAG_PREV_CABINET) != 0) { skipNullTerminatedString(); skipNullTerminatedString(); }
        if ((flags & FLAG_NEXT_CABINET) != 0) { skipNullTerminatedString(); skipNullTerminatedString(); }
    }

    private void readFolders() throws IOException {
        for (int i = 0; i < cFolders; i++) {
            byte[] buf = new byte[8];
            readFully(buf, 0, 8);
            Folder f = new Folder();
            f.dataOffset     = getUInt32LE(buf, 0);
            f.numDataBlocks  = getUInt16LE(buf, 4);
            int compType     = getUInt16LE(buf, 6);
            f.compression    = compType & 0x000F;
            f.windowBits     = (compType >>> 8) & 0x1F;
            f.reservedSize   = perFolderReserveSize;
            raf.skipBytes(perFolderReserveSize);
            folders.add(f);
        }
    }

    private void readFiles() throws IOException {
        raf.seek(coffFiles);
        for (int i = 0; i < cFiles; i++) {
            byte[] buf = new byte[16];
            readFully(buf, 0, 16);
            CabEntry.Builder b = new CabEntry.Builder();
            b.size         = getUInt32LE(buf, 0);
            b.folderOffset = getUInt32LE(buf, 4);
            b.folderIndex  = getUInt16LE(buf, 8);
            int date       = getUInt16LE(buf, 10);
            int time       = getUInt16LE(buf, 12);
            b.attributes   = getUInt16LE(buf, 14);
            b.lastModified = dosToUnixMs(date, time);
            b.name         = readNullTerminatedString((b.attributes & ATTR_NAME_IS_UTF) != 0);
            entries.add(b.build());
        }
    }

    // =========================================================================
    // Data extraction
    // =========================================================================

    /**
     * Decoding position inside one folder. Files of a folder are stored one after
     * the other in its data blocks: extracting them in order continues from here
     * instead of decoding the folder again from its first block for every file
     * (which was quadratic: a 2000-file cabinet decoded its folder 2000 times).
     */
    private final class FolderCursor {
        final int folderIndex;
        final Folder folder;
        final LzxDecoder lzx;
        byte[] history;          // MSZIP: previous block's output is the next block's dictionary
        long nextDataPos;        // file position of the next CFDATA
        int nextBlock;           // index of the next CFDATA
        long blockStart;         // folder offset of block[0]
        byte[] block = new byte[0];

        FolderCursor(int folderIndex, Folder folder) throws IOException {
            if (folder.compression == COMPRESS_QUANT) throw new IOException("CAB: Quantum compression is not supported");
            this.folderIndex = folderIndex;
            this.folder = folder;
            this.lzx = folder.compression == COMPRESS_LZX ? new LzxDecoder(folder.windowBits == 0 ? 15 : folder.windowBits) : null;
            this.nextDataPos = folder.dataOffset;
        }

        /** Decodes the next CFDATA block; false when the folder has no more blocks. */
        boolean advance() throws IOException {
            if (nextBlock >= folder.numDataBlocks) return false;
            raf.seek(nextDataPos);
            byte[] dataHdr = new byte[8];
            readFully(dataHdr, 0, 8);
            raf.skipBytes(perDataBlockReserveSize);
            long storedSum = getUInt32LE(dataHdr, 0);
            int compSize   = getUInt16LE(dataHdr, 4);
            int uncompSize = getUInt16LE(dataHdr, 6);

            byte[] compData = new byte[compSize];
            readFully(compData, 0, compSize);
            byte[] uncompData = new byte[uncompSize];

            // CFDATA checksum (0 = not computed by the writer)
            if (storedSum != 0 && (checksum(dataHdr, 4, 4, checksum(compData, 0, compSize, 0)) & 0xFFFFFFFFL) != storedSum) {
                throw new IOException("CAB: data block checksum error (block " + nextBlock + ")");
            }

            if (folder.compression == COMPRESS_NONE) {
                if (compSize != uncompSize) throw new IOException("CAB: stored block size mismatch (" + compSize + " / " + uncompSize + ")");
                System.arraycopy(compData, 0, uncompData, 0, compSize);
            } else if (folder.compression == COMPRESS_MSZIP) {
                MszipDecoder.decompress(compData, compSize, uncompData, uncompSize, history);
                history = uncompData;
            } else {
                lzx.decompress(compData, compSize, uncompData, uncompSize);
            }
            nextDataPos = raf.getFilePointer();
            nextBlock++;
            blockStart += block.length;
            block = uncompData;
            return true;
        }
    }

    private FolderCursor cursor;

    private void extractFromFolder(int folderIndex, long fileOffset, long fileSize, OutputStream out) throws IOException {
        // Restart the folder only when going backwards (or to another folder)
        if (cursor == null || cursor.folderIndex != folderIndex || fileOffset < cursor.blockStart) {
            cursor = new FolderCursor(folderIndex, folders.get(folderIndex));
        }
        long written = 0;
        while (written < fileSize) {
            long pos = fileOffset + written;
            if (pos >= cursor.blockStart + cursor.block.length) {
                if (!cursor.advance()) throw new IOException("CAB: file data truncated (" + written + " of " + fileSize + " bytes)");
                continue;
            }
            int from = (int) (pos - cursor.blockStart);
            int len  = (int) Math.min(cursor.block.length - from, fileSize - written);
            out.write(cursor.block, from, len);
            written += len;
        }
    }

    /** CFDATA checksum (MS-CAB / libmspack cabd_checksum): XOR of little-endian 32-bit words, odd tail packed high to low. */
    static int checksum(byte[] data, int off, int len, int seed) {
        int sum = seed;
        int p = off;
        for (int n = len >>> 2; n > 0; n--, p += 4) sum ^= getInt32LE(data, p);
        int ul = 0;
        switch (len & 3) {
            case 3: ul |= (data[p++] & 0xFF) << 16; // fall through
            case 2: ul |= (data[p++] & 0xFF) << 8;  // fall through
            case 1: ul |= data[p] & 0xFF;
            default: break;
        }
        return sum ^ ul;
    }

    // =========================================================================
    // I/O helpers
    // =========================================================================

    private void readFully(byte[] buf, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int n = raf.read(buf, off + total, len - total);
            if (n < 0) throw new IOException("CAB: unexpected end of file");
            total += n;
        }
    }

    private String readNullTerminatedString(final boolean utf8) throws IOException {
        final java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        int b;
        while ((b = raf.read()) > 0) bytes.write(b);
        return new String(bytes.toByteArray(), utf8 ? java.nio.charset.StandardCharsets.UTF_8 : java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    private void skipNullTerminatedString() throws IOException {
        while (raf.read() > 0) {}
    }

    private static int getUInt16LE(byte[] buf, int off) {
        return (buf[off] & 0xFF) | ((buf[off + 1] & 0xFF) << 8);
    }

    private static int getInt32LE(byte[] buf, int off) {
        return (buf[off] & 0xFF) | ((buf[off+1] & 0xFF) << 8) | ((buf[off+2] & 0xFF) << 16) | ((buf[off+3] & 0xFF) << 24);
    }

    private static long getUInt32LE(byte[] buf, int off) {
        return getInt32LE(buf, off) & 0xFFFFFFFFL;
    }

    private static long dosToUnixMs(int date, int time) {
        int year   = 1980 + ((date >>> 9) & 0x7F);
        int month  = (date >>> 5) & 0x0F;
        int day    = date & 0x1F;
        int hour   = (time >>> 11) & 0x1F;
        int minute = (time >>> 5)  & 0x3F;
        int second = (time & 0x1F) * 2;
        if (month < 1 || month > 12 || day < 1) return 0;
        Calendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        cal.set(year, month - 1, day, hour, minute, second);
        cal.set(Calendar.MILLISECOND, 0);
        return cal.getTimeInMillis();
    }
}
