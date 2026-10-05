/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.cab;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.zip.Deflater;

/**
 * Writes a Microsoft Cabinet ({@code .cab}) archive using MSZIP compression (type 0x0001).
 *
 * <p>All files go into one folder: their data is concatenated and cut into CFDATA blocks of
 * 32 768 bytes of uncompressed data (only the last block is shorter). Each block starts with the
 * 2-byte MSZIP signature "CK" followed by a complete raw DEFLATE stream, compressed with the
 * previous block as preset dictionary (MS-ZIP history). Counts and offsets are checked against
 * the 16-bit and 32-bit fields of the format.</p>
 *
 * <p>Call {@link #close()} to finalise and flush the complete Cabinet structure.
 * The output stream is NOT closed by this class.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class CabWriter implements Closeable {

    private static final int MSZIP_BLOCK_SIZE = 32768;
    private static final int COMPRESS_MSZIP   = 0x0001;
    private static final int ATTR_NAME_IS_UTF = 0x0080;

    private static final class PendingEntry {
        String name;
        byte[] data;
        long   lastModMs;
    }

    private final List<PendingEntry> pending = new ArrayList<PendingEntry>();
    private final OutputStream       dest;
    private boolean                  closed = false;

    public CabWriter(OutputStream out) { this.dest = out; }

    /**
     * Adds a file to the archive.
     *
     * @param name      file name (backslash or forward slash as path separator)
     * @param data      uncompressed file data
     * @param lastModMs last-modified time in milliseconds since the Unix epoch
     */
    public void addFile(String name, byte[] data, long lastModMs) {
        PendingEntry e = new PendingEntry();
        e.name      = name.replace('/', '\\');
        e.data      = data;
        e.lastModMs = lastModMs;
        pending.add(e);
    }

    /** Finalises and writes the complete Cabinet file to the output stream. */
    @Override
    public void close() throws IOException {
        if (closed) return;
        closed = true;
        write();
        dest.flush();
    }

    // =========================================================================
    // Cabinet file assembly
    // =========================================================================

    private void write() throws IOException {
        // Phase 1: the data of all files is one folder stream, cut into CFDATA blocks of 32768 bytes
        // (only the last block may be shorter: 7-Zip rejects a short block that is not the last one).
        // MSZIP keeps the deflate history across the blocks of a folder, so each block is compressed
        // with the previous 32 KB of uncompressed data as preset dictionary.
        if (pending.size() > 0xFFFF) throw new IOException("CAB: too many files (" + pending.size() + ", maximum 65535)");
        long totalSize = 0;
        for (PendingEntry e : pending) totalSize += e.data.length;
        if ((totalSize + MSZIP_BLOCK_SIZE - 1) / MSZIP_BLOCK_SIZE > 0xFFFF) throw new IOException("CAB: too much data for one folder (" + totalSize + " bytes, maximum 65535 blocks of 32768 bytes)");
        List<byte[]>  compBlocks  = new ArrayList<byte[]>();
        List<Integer> uncompSizes = new ArrayList<Integer>();
        List<long[]>  fileInfo    = new ArrayList<long[]>();  // [folderOffset, size]

        byte[] block   = new byte[MSZIP_BLOCK_SIZE];
        byte[] history = null;
        int    fill    = 0;
        long folderOffset = 0;
        for (PendingEntry e : pending) {
            fileInfo.add(new long[]{folderOffset, e.data.length});
            int offset = 0;
            while (offset < e.data.length) {
                int take = Math.min(MSZIP_BLOCK_SIZE - fill, e.data.length - offset);
                System.arraycopy(e.data, offset, block, fill, take);
                fill         += take;
                offset       += take;
                folderOffset += take;
                if (fill == MSZIP_BLOCK_SIZE) {
                    compBlocks.add(compressBlock(block, fill, history));
                    uncompSizes.add(fill);
                    history = block.clone();
                    fill    = 0;
                }
            }
        }
        // Last (short) block; an empty archive gets one empty block
        if (fill > 0 || compBlocks.isEmpty()) { compBlocks.add(compressBlock(block, fill, history)); uncompSizes.add(fill); }

        // Phase 2: compute sizes and offsets
        long cfFilesSize = 0;
        for (PendingEntry e : pending) cfFilesSize += 16 + e.name.getBytes("UTF-8").length + 1;
        int headerSize  = 36;
        int folderSize  = 8;
        int coffFiles   = headerSize + folderSize;
        long coffData   = coffFiles + cfFilesSize;

        long totalDataSize = 0;
        for (byte[] b : compBlocks) totalDataSize += 8 + b.length;
        long cabinetSize = coffData + totalDataSize;
        if (cabinetSize > 0xFFFFFFFFL) throw new IOException("CAB: cabinet larger than 4 GB (" + cabinetSize + " bytes)");

        // Phase 3: write the header, folder and file entries, then the data blocks
        ByteArrayOutputStream buf = new ByteArrayOutputStream((int) coffData);

        // CFHEADER (36 bytes)
        writeInt32LE(buf, 0x4643534D); // "MSCF" (bytes 4D 53 43 46 read as little-endian int)
        writeInt32LE(buf, 0);
        writeInt32LE(buf, (int) cabinetSize);
        writeInt32LE(buf, 0);
        writeInt32LE(buf, coffFiles);
        writeInt32LE(buf, 0);
        buf.write(3); buf.write(1); // version 1.3
        writeInt16LE(buf, 1);       // 1 folder
        writeInt16LE(buf, pending.size());
        writeInt16LE(buf, 0);       // flags
        writeInt16LE(buf, 1);       // cabinet set ID
        writeInt16LE(buf, 0);       // iCabinet: number of this cabinet in the set (CFHEADER is 36 bytes)

        // CFFOLDER (8 bytes)
        writeInt32LE(buf, (int) coffData);
        writeInt16LE(buf, compBlocks.size());
        writeInt16LE(buf, COMPRESS_MSZIP);

        // CFILEs
        int fileIdx = 0;
        for (PendingEntry e : pending) {
            long[] info = fileInfo.get(fileIdx++);
            writeInt32LE(buf, (int) e.data.length);
            writeInt32LE(buf, (int) info[0]);
            writeInt16LE(buf, 0); // folder index 0
            int[] dt = toDosDt(e.lastModMs);
            writeInt16LE(buf, dt[1]); // date
            writeInt16LE(buf, dt[0]); // time
            final byte[] nameBytes = e.name.getBytes("UTF-8");
            final boolean utf8 = nameBytes.length != e.name.length(); // non-ASCII name
            writeInt16LE(buf, 0x0020 | (utf8 ? ATTR_NAME_IS_UTF : 0)); // attributes: archive (+ UTF-8 name flag)
            buf.write(nameBytes);
            buf.write(0);
        }
        dest.write(buf.toByteArray());

        // CFDATA blocks
        for (int i = 0; i < compBlocks.size(); i++) {
            byte[] comp = compBlocks.get(i);
            int uncomp  = uncompSizes.get(i);
            byte[] head = new byte[8];
            byte[] sizes = { (byte) comp.length, (byte) (comp.length >>> 8), (byte) uncomp, (byte) (uncomp >>> 8) };
            int csum = CabReader.checksum(sizes, 0, 4, CabReader.checksum(comp, 0, comp.length, 0)); // lets readers detect corruption
            head[0] = (byte) csum; head[1] = (byte) (csum >>> 8); head[2] = (byte) (csum >>> 16); head[3] = (byte) (csum >>> 24);
            System.arraycopy(sizes, 0, head, 4, 4);
            dest.write(head);
            dest.write(comp);
        }
    }

    /**
     * Compresses one CFDATA block: "CK" + a complete raw deflate stream (final block bit set).
     *
     * @param history uncompressed data of the previous block of the folder (preset dictionary), or null
     */
    private static byte[] compressBlock(byte[] data, int len, byte[] history) throws IOException {
        Deflater def = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        if (history != null) def.setDictionary(history);
        def.setInput(data, 0, len);
        def.finish();
        ByteArrayOutputStream bos = new ByteArrayOutputStream(len / 2 + 4);
        bos.write(0x43); // "C"
        bos.write(0x4B); // "K"
        byte[] tmp = new byte[8192];
        while (!def.finished()) {
            int n = def.deflate(tmp);
            if (n > 0) bos.write(tmp, 0, n);
        }
        def.end();
        // cbData is 16-bit; MS-ZIP requires at most 32768 + 12 bytes of compressed data per block
        if (bos.size() > 0xFFFF) throw new IOException("CAB: compressed block too large (" + bos.size() + " bytes)");
        return bos.toByteArray();
    }

    private static void writeInt16LE(OutputStream out, int v) throws IOException {
        out.write(v & 0xFF); out.write((v >>> 8) & 0xFF);
    }

    private static void writeInt32LE(OutputStream out, int v) throws IOException {
        out.write(v & 0xFF); out.write((v >>> 8) & 0xFF); out.write((v >>> 16) & 0xFF); out.write((v >>> 24) & 0xFF);
    }

    private static int[] toDosDt(long millis) {
        Calendar cal = Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"));
        cal.setTimeInMillis(millis);
        int dosTime = (cal.get(Calendar.HOUR_OF_DAY) << 11) | (cal.get(Calendar.MINUTE) << 5) | (cal.get(Calendar.SECOND) / 2);
        int dosDate = ((Math.max(cal.get(Calendar.YEAR), 1980) - 1980) << 9) | ((cal.get(Calendar.MONTH) + 1) << 5) | cal.get(Calendar.DAY_OF_MONTH);
        return new int[]{dosTime, dosDate};
    }
}
