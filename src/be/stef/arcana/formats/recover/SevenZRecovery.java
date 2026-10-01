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
import be.stef.arcana.formats.carve.ByteSource;
import be.stef.arcana.formats.sevenz.SevenZEntry;
import be.stef.arcana.formats.sevenz.SevenZFile;
import be.stef.arcana.formats.xz.LZMA2InputStream;
import be.stef.arcana.formats.xz.LZMAInputStream;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Recovery of a damaged 7z archive.
 *
 * <ul>
 *   <li>Header readable: every entry is decoded separately; an error only loses
 *       the rest of its solid block (folder): the other folders are still
 *       decoded. When the damaged block is an LZMA2 stream made of independent
 *       segments (Arcana or 7-Zip multithreaded compression), the files after
 *       the damaged segment are recovered too ({@link Lzma2SegmentRecovery}).</li>
 *   <li>Header unreadable (typically a truncated archive: the header is at the
 *       end): the compressed data is decoded as a raw LZMA2 (or LZMA) stream up
 *       to the damage. The file names are lost, the content of the files is
 *       written one after the other in a single file.</li>
 * </ul>
 *
 * @author Stef
 * @since 1.3
 */
final class SevenZRecovery {

    private SevenZRecovery() {}

    static void recover(final File archive, final Outputs out, final RecoveryReport report, final byte[] password) throws IOException {
        final SevenZFile sz;
        try {
            sz = SevenZFile.builder().setFile(archive).setPassword(password == null ? null : new String(password, StandardCharsets.UTF_8)).get();
        } catch (final ArcanaLimitExceededException e) {
            throw e;
        } catch (final IOException | RuntimeException e) {
            report.note("7z header unreadable (" + e.getMessage() + "): raw decoding of the compressed data, file names are lost.");
            raw(archive, out, report);
            return;
        }
        try {
            final List<SevenZEntry> entries = new ArrayList<SevenZEntry>();
            for (final SevenZEntry e : sz.getEntries()) entries.add(e);
            final int[] folderOf = sz.getFolderIndexes();
            final int[] reportIndex = new int[entries.size()];
            java.util.Arrays.fill(reportIndex, -1);
            final java.util.Set<Integer> deadFolders = new java.util.LinkedHashSet<Integer>();
            int deadFolder = -1;
            for (int i = 0; i < entries.size(); i++) {
                final SevenZEntry e = entries.get(i);
                final String name = e.getName() != null ? e.getName() : "entry_" + i;
                if (e.isDirectory()) { out.directory(name); continue; }
                if (folderOf[i] >= 0 && folderOf[i] == deadFolder) {
                    report.add(name, RecoveryReport.Status.LOST, 0, e.getSize(), "follows the damaged point of its solid block");
                    reportIndex[i] = report.lastIndex();
                    continue;
                }
                long written = 0;
                String error = null;
                try (OutputStream o = out.file(name)) {
                    if (e.hasStream()) {
                        try (InputStream in = sz.getInputStream(e)) {
                            final byte[] buf = new byte[65536];
                            int n;
                            while ((n = in.read(buf)) > 0) {
                                o.write(buf, 0, n);
                                written += n;
                            }
                        }
                    }
                } catch (final ArcanaLimitExceededException ex) {
                    throw ex;
                } catch (final IOException | RuntimeException ex) {
                    error = ex.getClass().getSimpleName() + (ex.getMessage() != null ? " - " + ex.getMessage() : "");
                    deadFolder = folderOf[i];
                    if (deadFolder >= 0) deadFolders.add(deadFolder);
                }
                if (error != null && written == 0) out.dropLastIfEmpty();
                if (error != null) report.add(name, written > 0 ? RecoveryReport.Status.PARTIAL : RecoveryReport.Status.LOST, written, e.getSize(), error);
                else if (written != e.getSize()) report.add(name, RecoveryReport.Status.PARTIAL, written, e.getSize(), "size differs");
                else report.add(name, e.getHasCrc() ? RecoveryReport.Status.OK : RecoveryReport.Status.UNVERIFIED, written, e.getSize(), null);
                reportIndex[i] = report.lastIndex();
            }
            // Damaged solid blocks: decode what follows the damage when the LZMA2 stream is made of independent segments
            for (final int f : deadFolders) {
                final long[] info = sz.getLzma2FolderInfo(f);
                if (info != null) recoverTail(archive, info, f, entries, folderOf, reportIndex, out, report);
            }
        } finally {
            sz.close();
        }
    }

    /** Decodes the independent LZMA2 segments after the damage of folder {@code f} and writes the entries they cover. */
    private static void recoverTail(final File archive, final long[] info, final int f, final List<SevenZEntry> entries, final int[] folderOf, final int[] reportIndex, final Outputs out, final RecoveryReport report) throws IOException {
        try (ByteSource s = new ByteSource(archive)) {
            final Lzma2SegmentRecovery.Tail tail = Lzma2SegmentRecovery.findTail(s, info[0], info[1], info[2]);
            if (tail == null) {
                report.note("Solid block " + f + ": no independent LZMA2 segment after the damage (block compressed as a single segment, e.g. by a single-threaded compressor): the rest of the block is lost.");
                return;
            }
            // Entries of the folder with their position in the uncompressed data
            final List<Integer> idx = new ArrayList<Integer>();
            final List<Long> offs = new ArrayList<Long>();
            long off = 0;
            for (int i = 0; i < entries.size(); i++) {
                if (folderOf[i] != f || !entries.get(i).hasStream()) continue;
                idx.add(i);
                offs.add(off);
                off += entries.get(i).getSize();
            }
            // Uncompressed position of every segment, computed from the end
            final long[] segStart = new long[tail.segments.size()];
            long pos = info[2];
            for (int k = tail.segments.size() - 1; k >= 0; k--) {
                pos -= tail.segments.get(k)[2];
                segStart[k] = pos;
            }
            int recovered = 0, badSegments = 0;
            int e = 0; // current entry
            OutputStream o = null;
            java.util.zip.CRC32 crc = null;
            long written = 0;
            boolean broken = false; // current entry misses data (a segment failed)
            try {
                for (int k = 0; k < tail.segments.size(); k++) {
                    byte[] data;
                    try {
                        data = Lzma2SegmentRecovery.decode(s, tail.segments.get(k), (int) info[3]);
                    } catch (final IOException | RuntimeException ex) {
                        data = null;
                        badSegments++;
                    }
                    final long a = segStart[k], b = a + tail.segments.get(k)[2];
                    while (e < idx.size()) {
                        final int i = idx.get(e);
                        final long es = offs.get(e), ee = es + entries.get(i).getSize();
                        if (es >= b) break;               // entry starts in a later segment
                        if (es < a && o == null) { e++; continue; } // entry started before the tail: its beginning is lost
                        if (reportIndex[i] < 0 || report.getEntries().get(reportIndex[i]).status == RecoveryReport.Status.OK) { e++; continue; }
                        if (o == null) {
                            o = out.file(entries.get(i).getName());
                            crc = new java.util.zip.CRC32();
                            written = 0;
                            broken = false;
                        }
                        final long from = Math.max(es, a), to = Math.min(ee, b);
                        if (data != null) {
                            o.write(data, (int) (from - a), (int) (to - from));
                            crc.update(data, (int) (from - a), (int) (to - from));
                            written += to - from;
                        } else {
                            broken = true;
                        }
                        if (ee > b) break;                // continues in the next segment
                        o.close();
                        o = null;
                        final SevenZEntry en = entries.get(i);
                        final boolean ok = !broken && (!en.getHasCrc() || crc.getValue() == en.getCrcValue());
                        report.set(reportIndex[i], broken ? RecoveryReport.Status.PARTIAL : ok ? (en.getHasCrc() ? RecoveryReport.Status.OK : RecoveryReport.Status.UNVERIFIED) : RecoveryReport.Status.BAD_CHECKSUM, written, "recovered after the damaged zone (independent LZMA2 segment)");
                        if (ok) recovered++;
                        e++;
                    }
                }
            } finally {
                if (o != null) o.close();
            }
            report.note("Solid block " + f + ": " + tail.segments.size() + " independent LZMA2 segment(s) found after the damage, " + recovered + " file(s) recovered" + (badSegments > 0 ? ", " + badSegments + " segment(s) undecodable" : "") + ".");
        }
    }

    /** Decodes the packed data (right after the 32-byte signature header) as LZMA2, else LZMA. */
    private static void raw(final File archive, final Outputs out, final RecoveryReport report) throws IOException {
        final String name = ForceUnpacker.stripExtension(archive.getName()) + "_7z_data.bin";
        int first;
        try (InputStream in = new FileInputStream(archive)) {
            if (in.skip(32) != 32) { report.add(name, RecoveryReport.Status.LOST, 0, -1, "no data"); return; }
            first = in.read();
        }
        final boolean lzma2 = first == 0x01 || first >= 0xE0;
        long written = 0;
        String error = null;
        try (InputStream raw = new BufferedInputStream(new FileInputStream(archive), 65536); OutputStream o = out.file(name)) {
            if (raw.skip(32) != 32) throw new IOException("truncated");
            final InputStream in = lzma2 ? new LZMA2InputStream(raw, 1 << 26) : new LZMAInputStream(raw, -1, (byte) 0x5D, 1 << 24);
            final byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                o.write(buf, 0, n);
                written += n;
            }
        } catch (final ArcanaLimitExceededException e) {
            throw e;
        } catch (final IOException | RuntimeException e) {
            error = "decoding stopped: " + e.getClass().getSimpleName() + (e.getMessage() != null ? " - " + e.getMessage() : "");
        }
        report.note("Raw " + (lzma2 ? "LZMA2" : "LZMA (default properties)") + " decoding: the files are concatenated in archive order in " + name + ".");
        report.add(name, written > 0 ? RecoveryReport.Status.PARTIAL : RecoveryReport.Status.LOST, written, -1, error != null ? error : "file names and boundaries lost");
    }
}
