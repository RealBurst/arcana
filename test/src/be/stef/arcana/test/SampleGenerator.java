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
package be.stef.arcana.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Generators of the hand-made test samples of {@code test/samples} (payload
 * tree, crafted or patched files). Pure Java, no dependency beyond the JDK:
 * works on Windows as well as on Linux. {@code test/tools/make-samples.sh}
 * calls it for every sample that no official tool can build.
 *
 * <pre>
 * java -cp bin;test/bin be.stef.arcana.test.SampleGenerator &lt;command&gt; &lt;arguments&gt;
 *   payload DIR                      the payload tree held by every archive
 *   szdd IN OUT                      SZDD (COMPRESS.EXE LZSS) file
 *   pak PAYLOAD OUT                  Quake PAK of the payload
 *   damaged SAMPLES                  SAMPLES/damaged: flipped, truncated and crafted files
 *   zip-aes-tampered SAMPLES         zip/aes256.zip with one encrypted byte flipped
 *   zip-aes-utf8 PAYLOAD OUT         WinZip AE-2 ZIP, password "caf\u00e9" (UTF-8)
 *   zstd-skippable FRAME OUT         Zstandard frame between skippable frames
 *   7z-aes-rounds IN OUT             7z (-mhc=off) whose AES rounds are patched to 2^30
 *   sfx-zip-inside PAYLOAD OUT       minimal PE holding a ZIP inside its section
 *   wim-lzx-uncompressed WORK OUT    WIM whose LZX chunks hold an uncompressed block (wimlib-imagex)
 *   dmg-hfsx PAYLOAD MODE OUT        HFSX volume in a UDIF image: MODE raw, adc, features (zlib, decmpfs, links...) or whole (zlib, one "whole disk" entry holding an Apple partition map)
 *   dmg-encrypted OUT                header of an encrypted disk image (encrcdsa)
 * </pre>
 *
 * <p>The outputs are byte-identical to the ones of the former Python scripts.
 * Exit code: 0 on success, 1 on error or wrong arguments.</p>
 *
 * @author Stef
 * @since 1.0.5
 */
public final class SampleGenerator {

    /** Time stamp of the samples: 2024-01-02 03:04:05 UTC. */
    private static final long STAMP_MS = 1704164645000L;

    private static final int ISO_SECTOR = 2048;

    private SampleGenerator() {
    }

    public static void main(final String[] args) {
        try {
            System.exit(run(args) ? 0 : 1);
        } catch (final Exception e) {
            System.err.println("ERROR: " + e);
            System.exit(1);
        }
    }

    private static boolean run(final String[] a) throws Exception {
        final String cmd = a.length > 0 ? a[0] : "";
        if ("payload".equals(cmd) && a.length == 2) payload(new File(a[1]));
        else if ("szdd".equals(cmd) && a.length == 3) write(new File(a[2]), szdd(read(new File(a[1]))));
        else if ("pak".equals(cmd) && a.length == 3) write(new File(a[2]), pak(new File(a[1])));
        else if ("damaged".equals(cmd) && a.length == 2) damaged(new File(a[1]));
        else if ("zip-aes-tampered".equals(cmd) && a.length == 2) zipAesTampered(new File(a[1]));
        else if ("zip-aes-utf8".equals(cmd) && a.length == 3) write(new File(a[2]), zipAesUtf8(new File(a[1])));
        else if ("zstd-skippable".equals(cmd) && a.length == 3) write(new File(a[2]), zstdSkippable(read(new File(a[1]))));
        else if ("7z-aes-rounds".equals(cmd) && a.length == 3) write(new File(a[2]), sevenZipAesRounds(read(new File(a[1]))));
        else if ("sfx-zip-inside".equals(cmd) && a.length == 3) write(new File(a[2]), sfxZipInside(new File(a[1])));
        else if ("wim-lzx-uncompressed".equals(cmd) && a.length == 3) wimLzxUncompressed(new File(a[1]), new File(a[2]));
        else if ("dmg-hfsx".equals(cmd) && a.length == 4 && a[2].matches("raw|adc|features|whole")) write(new File(a[3]), dmgHfsx(new File(a[1]), a[2]));
        else if ("dmg-encrypted".equals(cmd) && a.length == 2) write(new File(a[1]), dmgEncryptedHeader());
        else {
            usage();
            return false;
        }
        return true;
    }

    private static void usage() {
        System.err.println("Usage: java -cp bin" + File.pathSeparator + "test/bin be.stef.arcana.test.SampleGenerator <command> <arguments>");
        System.err.println("  payload DIR                     the payload tree held by every archive");
        System.err.println("  szdd IN OUT                     SZDD (COMPRESS.EXE LZSS) file");
        System.err.println("  pak PAYLOAD OUT                 Quake PAK of the payload");
        System.err.println("  damaged SAMPLES                 SAMPLES/damaged: flipped, truncated and crafted files");
        System.err.println("  zip-aes-tampered SAMPLES        zip/aes256.zip with one encrypted byte flipped");
        System.err.println("  zip-aes-utf8 PAYLOAD OUT        WinZip AE-2 ZIP with a UTF-8 password");
        System.err.println("  zstd-skippable FRAME OUT        Zstandard frame between skippable frames");
        System.err.println("  7z-aes-rounds IN OUT            7z (-mhc=off) whose AES rounds are patched to 2^30");
        System.err.println("  sfx-zip-inside PAYLOAD OUT      minimal PE holding a ZIP inside its section");
        System.err.println("  wim-lzx-uncompressed WORK OUT   WIM whose LZX chunks hold an uncompressed block (needs wimlib-imagex)");
        System.err.println("  dmg-hfsx PAYLOAD MODE OUT       HFSX volume in a UDIF image: MODE raw, adc, features (zlib, decmpfs, links...) or whole (zlib, \"whole disk\" entry with an Apple partition map)");
        System.err.println("  dmg-encrypted OUT               header of an encrypted disk image (encrcdsa)");
    }

    // -----------------------------------------------------------------------
    // Payload
    // -----------------------------------------------------------------------

    /** The payload tree: text, compressible text, random bytes, empty file, deep tree, empty folder. */
    private static void payload(final File p) throws IOException {
        final StringBuilder readme = new StringBuilder();
        for (int i = 0; i < 20; i++) readme.append("Arcana regression payload.\nEvery archive of test/samples holds these files.\n");
        final StringBuilder notes = new StringBuilder();
        for (int i = 0; i < 400; i++) notes.append(String.format(Locale.ROOT, "%05d The quick brown fox jumps over the lazy dog, line %d of the notes.\n", i, i));
        final MersenneTwister r = new MersenneTwister(20240102L);
        final byte[] random = new byte[4096];
        for (int i = 0; i < random.length; i++) random[i] = (byte) r.getrandbits8();
        mkdirs(new File(p, "empty-dir"));
        write(new File(p, "readme.txt"), ascii(readme.toString()));
        write(new File(p, "docs/notes.txt"), ascii(notes.toString()));
        write(new File(p, "docs/empty.txt"), new byte[0]);
        write(new File(p, "bin/random.bin"), random);
        write(new File(p, "deep/a/b/c/leaf.txt"), ascii("leaf\n"));
        final String[] stamped = {"readme.txt", "docs/notes.txt", "docs/empty.txt", "bin/random.bin", "deep/a/b/c/leaf.txt", "deep/a/b/c", "deep/a/b", "deep/a", "deep", "docs", "bin", "empty-dir", ""};
        for (final String s : stamped) new File(p, s).setLastModified(STAMP_MS);
    }

    /** Python's random.Random(int seed): MT19937 seeded by init_by_array with the 32-bit words of the seed. */
    private static final class MersenneTwister {
        private final int[] mt = new int[624];
        private int mti;

        MersenneTwister(final long seed) {
            final List<Integer> key = new ArrayList<Integer>();
            long n = Math.abs(seed);
            do {
                key.add((int) (n & 0xFFFFFFFFL));
                n >>>= 32;
            } while (n != 0);
            initGenrand(19650218);
            int i = 1;
            int j = 0;
            for (int k = Math.max(624, key.size()); k > 0; k--) {
                mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >>> 30)) * 1664525)) + key.get(j) + j;
                i++;
                j++;
                if (i >= 624) { mt[0] = mt[623]; i = 1; }
                if (j >= key.size()) j = 0;
            }
            for (int k = 623; k > 0; k--) {
                mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >>> 30)) * 1566083941)) - i;
                i++;
                if (i >= 624) { mt[0] = mt[623]; i = 1; }
            }
            mt[0] = 0x80000000;
        }

        private void initGenrand(final int s) {
            mt[0] = s;
            for (mti = 1; mti < 624; mti++) mt[mti] = 1812433253 * (mt[mti - 1] ^ (mt[mti - 1] >>> 30)) + mti;
        }

        int genrandUint32() {
            if (mti >= 624) {
                for (int kk = 0; kk < 624; kk++) {
                    final int y = (mt[kk] & 0x80000000) | (mt[(kk + 1) % 624] & 0x7fffffff);
                    mt[kk] = mt[(kk + 397) % 624] ^ (y >>> 1) ^ ((y & 1) != 0 ? 0x9908b0df : 0);
                }
                mti = 0;
            }
            int y = mt[mti++];
            y ^= y >>> 11;
            y ^= (y << 7) & 0x9d2c5680;
            y ^= (y << 15) & 0xefc60000;
            y ^= y >>> 18;
            return y;
        }

        /** random.getrandbits(8). */
        int getrandbits8() {
            return genrandUint32() >>> 24;
        }
    }

    // -----------------------------------------------------------------------
    // SZDD
    // -----------------------------------------------------------------------

    /** SZDD (Microsoft COMPRESS.EXE): LZSS, 4 KiB window starting at 4096-16 filled with spaces. */
    private static byte[] szdd(final byte[] data) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[] {'S', 'Z', 'D', 'D', (byte) 0x88, (byte) 0xF0, 0x27, 0x33, 'A', 't'}, 0, 10);
        writeLe32(out, data.length);
        final Map<Integer, List<Integer>> heads = new HashMap<Integer, List<Integer>>();
        int pos = 4096 - 16;
        int i = 0;
        while (i < data.length) {
            int flags = 0;
            final ByteArrayOutputStream chunk = new ByteArrayOutputStream();
            for (int bit = 0; bit < 8; bit++) {
                if (i >= data.length) break;
                int bestLen = 0;
                int bestOff = 0;
                final List<Integer> cands = heads.get(key3(data, i));
                if (cands != null) {
                    for (int c = cands.size() - 1; c >= Math.max(0, cands.size() - 32); c--) {
                        final int j = cands.get(c);
                        final int back = i - j;
                        if (back > 4096 - 18) break;
                        int n = 0;
                        while (n < 18 && i + n < data.length && data[j + n] == data[i + n]) n++;
                        if (n > bestLen) {
                            bestLen = n;
                            bestOff = (pos - back) & 0xFFF;
                            if (n == 18) break;
                        }
                    }
                }
                final int step;
                if (bestLen >= 3) {
                    chunk.write(bestOff & 0xFF);
                    chunk.write(((bestOff >> 4) & 0xF0) | (bestLen - 3));
                    step = bestLen;
                } else {
                    flags |= 1 << bit;
                    chunk.write(data[i]);
                    step = 1;
                }
                for (int k = 0; k < step; k++) {
                    final Integer key = key3(data, i + k);
                    List<Integer> list = heads.get(key);
                    if (list == null) {
                        list = new ArrayList<Integer>();
                        heads.put(key, list);
                    }
                    list.add(i + k);
                    pos = (pos + 1) & 0xFFF;
                }
                i += step;
            }
            out.write(flags);
            final byte[] c = chunk.toByteArray();
            out.write(c, 0, c.length);
        }
        return out.toByteArray();
    }

    /** Key of data[i:i+3] (shorter at the end of the data, as a Python slice). */
    private static Integer key3(final byte[] data, final int i) {
        final int n = Math.min(3, data.length - i);
        int v = n << 24;
        for (int k = 0; k < n; k++) v |= (data[i + k] & 0xFF) << (16 - 8 * k);
        return v;
    }

    // -----------------------------------------------------------------------
    // Quake PAK
    // -----------------------------------------------------------------------

    /** PACK, directory offset, directory length; entries of 64 bytes: name (56), offset, size. Folders sorted by path, files by name. */
    private static byte[] pak(final File root) throws IOException {
        final List<String> dirs = new ArrayList<String>();
        listDirs(root, "", dirs);
        Collections.sort(dirs);
        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        final ByteArrayOutputStream entries = new ByteArrayOutputStream();
        int pos = 12;
        for (final String d : dirs) {
            for (final String n : sortedNames(new File(root, d), false)) {
                final String rel = d.isEmpty() ? n : d + "/" + n;
                final byte[] data = read(new File(root, rel));
                final byte[] name = new byte[56];
                final byte[] nb = rel.getBytes(StandardCharsets.US_ASCII);
                if (nb.length > 56 || !rel.equals(new String(nb, StandardCharsets.US_ASCII))) throw new IOException("name not valid in a PAK: " + rel);
                System.arraycopy(nb, 0, name, 0, nb.length);
                entries.write(name, 0, name.length);
                writeLe32(entries, pos);
                writeLe32(entries, data.length);
                body.write(data, 0, data.length);
                pos += data.length;
            }
        }
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[] {'P', 'A', 'C', 'K'}, 0, 4);
        writeLe32(out, pos);
        writeLe32(out, entries.size());
        body.writeTo(out);
        entries.writeTo(out);
        return out.toByteArray();
    }

    // -----------------------------------------------------------------------
    // Damaged samples
    // -----------------------------------------------------------------------

    /** Flipped and truncated copies of other samples, empty and garbage files, crafted ISO images, in SAMPLES/damaged. */
    private static void damaged(final File out) throws IOException {
        final File dir = new File(out, "damaged");
        mkdirs(dir);
        final byte[] z = src(out, "zip/deflate.zip");
        put(dir, "truncated.zip", z == null ? null : Arrays.copyOf(z, z.length / 2));
        put(dir, "bad-crc.zip", flip(z, 1000));
        final byte[] s = src(out, "7z/lzma2.7z");
        put(dir, "flipped.7z", flip(s, 64));
        put(dir, "truncated.7z", s == null ? null : Arrays.copyOf(s, Math.max(0, s.length - 40)));
        final byte[] r = src(out, "rar/rar5.rar");
        put(dir, "flipped.rar", r == null ? null : flip(r, r.length / 2));
        final byte[] r4 = src(out, "rar/rar4.rar");
        put(dir, "truncated-rar4.rar", r4 == null ? null : Arrays.copyOf(r4, r4.length * 2 / 3));
        final byte[] g = src(out, "stream/notes.txt.gz");
        put(dir, "bad-crc.gz", g == null ? null : flip(g, g.length - 6));
        final byte[] x = src(out, "stream/notes.txt.xz");
        put(dir, "flipped.xz", x == null ? null : flip(x, x.length / 2));
        final byte[] b = src(out, "stream/notes.txt.bz2");
        put(dir, "flipped.bz2", b == null ? null : flip(b, b.length / 2));
        final byte[] t = src(out, "tar/ustar.tar");
        put(dir, "truncated.tar", t == null ? null : Arrays.copyOf(t, Math.min(2560, t.length)));
        final byte[] c = src(out, "cab/mszip.cab");
        put(dir, "truncated.cab", c == null ? null : Arrays.copyOf(c, c.length / 2));
        put(dir, "flipped.wim", flip(src(out, "wim/lzx.wim"), 1000));
        put(dir, "flipped.sqfs", flip(src(out, "squashfs/xz.sqfs"), 300));
        put(dir, "empty.zip", new byte[0]);
        final byte[] garbage = new byte[3000];
        for (int i = 0; i < garbage.length; i++) garbage[i] = (byte) (i * 37 + 11);
        put(dir, "garbage.bin", garbage);
        final byte[] zz = src(out, "stream/notes.txt.Z");
        put(dir, "truncated-notes.txt.Z", zz == null ? null : Arrays.copyOf(zz, Math.min(2002, zz.length)));
        final byte[] lz = src(out, "stream/notes.txt.lz");
        put(dir, "bad-crc.lz", flip(lz, -20)); // first byte of the CRC32 in the trailer
        put(dir, "truncated.lz", lz == null ? null : Arrays.copyOf(lz, lz.length - 30));
        final byte[] lo = src(out, "stream/notes.txt.lzo");
        put(dir, "truncated.lzo", lo == null ? null : Arrays.copyOf(lo, lo.length / 2));
        put(dir, "flipped.lzo", flip(lo, 2000)); // inside the compressed data: Adler-32 or LZO error
        damagedIso(dir);
        final byte[] dmg = src(out, "dmg/udzo-hfsplus.dmg");
        put(dir, "truncated.dmg", dmg == null ? null : Arrays.copyOf(dmg, dmg.length / 2)); // no koly trailer left
        put(dir, "flipped.dmg", flip(dmg, 3000)); // inside a zlib chunk: data fork CRC32 or zlib error
    }

    /** Content of a sample, or null when it is missing or empty (the sample is then skipped). */
    private static byte[] src(final File out, final String path) throws IOException {
        final File f = new File(out, path);
        if (!f.isFile()) return null;
        final byte[] d = read(f);
        return d.length == 0 ? null : d;
    }

    private static void put(final File dir, final String name, final byte[] data) throws IOException {
        if (data != null) write(new File(dir, name), data);
    }

    private static byte[] flip(final byte[] d, final int at) {
        if (d == null) return null;
        final byte[] b = d.clone();
        b[Math.floorMod(at, b.length)] ^= 0x55;
        return b;
    }

    // -----------------------------------------------------------------------
    // Crafted ISO 9660 images (loop, huge directory, cut image, bad Rock Ridge, bad record)
    // -----------------------------------------------------------------------

    private static void damagedIso(final File dir) throws IOException {
        final byte[] dots = cat(isoRec(new byte[] {0}, 18, ISO_SECTOR, 2, null), isoRec(new byte[] {1}, 18, ISO_SECTOR, 2, null));
        final byte[] txt = ascii("hello\n");
        // iso-loop.iso: LOOP points back to the root, SUB/SELF points to SUB itself
        final byte[] sub = cat(isoRec(new byte[] {0}, 20, ISO_SECTOR, 2, null), isoRec(new byte[] {1}, 18, ISO_SECTOR, 2, null), isoRec(ascii("SELF"), 20, ISO_SECTOR, 2, null));
        byte[] root = cat(dots, isoRec(ascii("A.TXT;1"), 19, txt.length, 0, null), isoRec(ascii("LOOP"), 18, ISO_SECTOR, 2, null), isoRec(ascii("SUB"), 20, ISO_SECTOR, 2, null));
        write(new File(dir, "iso-loop.iso"), isoImage(root, ISO_SECTOR, txt, sub));
        // iso-huge-dir.iso: directory BIG claims 4 GiB - 2 KiB
        root = cat(dots, isoRec(ascii("A.TXT;1"), 19, txt.length, 0, null), isoRec(ascii("BIG"), 20, 0xFFFFF800L, 2, null));
        write(new File(dir, "iso-huge-dir.iso"), isoImage(root, ISO_SECTOR, txt, dots));
        // iso-cut.iso: valid image cut at 33000 bytes (inside the primary volume descriptor)
        root = cat(dots, isoRec(ascii("A.TXT;1"), 19, txt.length, 0, null));
        write(new File(dir, "iso-cut.iso"), Arrays.copyOf(isoImage(root, ISO_SECTOR, txt), 33000));
        // iso-bad-rr.iso: Rock Ridge; the root ends with an NM entry of length 250, SUB ends with a 4-byte CE
        // (directory lengths are the exact record bytes, so the bad entries reach the end of the extent)
        final int rs = rrRoot(0, 0, txt).length;
        final int ss = rrSub(0, 0, txt).length;
        write(new File(dir, "iso-bad-rr.iso"), isoImage(rrRoot(rs, ss, txt), rs, txt, rrSub(rs, ss, txt)));
        // iso-bad-record.iso: the last record of the root is 40 bytes long but its name length says 200
        final byte[] bad = isoRec(ascii("D.TXT;1"), 19, txt.length, 0, null);
        bad[32] = (byte) 200;
        root = cat(dots, isoRec(ascii("A.TXT;1"), 19, txt.length, 0, null), bad);
        write(new File(dir, "iso-bad-record.iso"), isoImage(root, root.length, txt));
    }

    private static byte[] rrRoot(final int rs, final int ss, final byte[] txt) {
        final byte[] sp = {'S', 'P', 7, 1, (byte) 0xBE, (byte) 0xEF, 0};
        final byte[] rr = cat(new byte[] {'R', 'R', 5, 1, (byte) 0x89}, nm(10, "a.txt"));
        return cat(isoRec(new byte[] {0}, 18, rs, 2, sp), isoRec(new byte[] {1}, 18, rs, 2, null), isoRec(ascii("A.TXT;1"), 19, txt.length, 0, rr), isoRec(ascii("SUB"), 20, ss, 2, nm(8, "sub")), isoRec(ascii("B.TXT;1"), 19, txt.length, 0, nm(0xFA, "b.txt")));
    }

    private static byte[] rrSub(final int rs, final int ss, final byte[] txt) {
        final byte[] su = cat(nm(10, "c.txt"), new byte[] {'C', 'E', 4, 1});
        return cat(isoRec(new byte[] {0}, 20, ss, 2, null), isoRec(new byte[] {1}, 18, rs, 2, null), isoRec(ascii("C.TXT;1"), 19, txt.length, 0, su));
    }

    /** Rock Ridge NM entry with the given length byte. */
    private static byte[] nm(final int len, final String name) {
        return cat(new byte[] {'N', 'M', (byte) len, 1, 0}, ascii(name));
    }

    /** Directory record: length, 0, LBA, size, date, flags, volume sequence 1, name, padding, system use. */
    private static byte[] isoRec(final byte[] name, final int lba, final long size, final int flags, final byte[] su) {
        final int n = name.length;
        final int pad = n % 2 == 0 ? 1 : 0;
        final int suLen = su == null ? 0 : su.length;
        final byte[] r = new byte[33 + n + pad + suLen];
        if (r.length > 255) throw new IllegalArgumentException("record too long");
        r[0] = (byte) r.length;
        both32(r, 2, lba);
        both32(r, 10, size);
        final byte[] date = {124, 1, 2, 3, 4, 5, 0};
        System.arraycopy(date, 0, r, 18, 7);
        r[25] = (byte) flags;
        both16(r, 28, 1);
        r[32] = (byte) n;
        System.arraycopy(name, 0, r, 33, n);
        if (su != null) System.arraycopy(su, 0, r, 33 + n + pad, suLen);
        return r;
    }

    /** Sectors 0-15 empty, 16 = primary volume descriptor, 17 = terminator, 18 = root directory, 19.. = extra sectors. */
    private static byte[] isoImage(final byte[] rootRecords, final int rootSize, final byte[]... extra) {
        final int nsect = 19 + extra.length;
        final byte[] img = new byte[nsect * ISO_SECTOR];
        final int v = 16 * ISO_SECTOR;
        img[v] = 1;
        System.arraycopy(ascii("CD001"), 0, img, v + 1, 5);
        img[v + 6] = 1;
        Arrays.fill(img, v + 8, v + 40, (byte) ' ');
        Arrays.fill(img, v + 40, v + 72, (byte) ' ');
        System.arraycopy(ascii("ARCANA"), 0, img, v + 40, 6);
        both32(img, v + 80, nsect);
        both16(img, v + 120, 1);
        both16(img, v + 124, 1);
        both16(img, v + 128, ISO_SECTOR);
        both32(img, v + 132, 10);
        final byte[] r = isoRec(new byte[] {0}, 18, rootSize, 2, null);
        System.arraycopy(r, 0, img, v + 156, r.length);
        img[v + 881] = 1;
        final int t = 17 * ISO_SECTOR;
        img[t] = (byte) 255;
        System.arraycopy(ascii("CD001"), 0, img, t + 1, 5);
        img[t + 6] = 1;
        sector(img, 18, rootRecords);
        for (int i = 0; i < extra.length; i++) sector(img, 19 + i, extra[i]);
        return img;
    }

    private static void sector(final byte[] img, final int lba, final byte[] data) {
        if (data.length > ISO_SECTOR) throw new IllegalArgumentException("sector too long");
        System.arraycopy(data, 0, img, lba * ISO_SECTOR, data.length);
    }

    private static void both32(final byte[] b, final int off, final long v) {
        for (int i = 0; i < 4; i++) {
            b[off + i] = (byte) (v >>> (8 * i));
            b[off + 7 - i] = (byte) (v >>> (8 * i));
        }
    }

    private static void both16(final byte[] b, final int off, final int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 8);
        b[off + 3] = (byte) v;
    }

    // -----------------------------------------------------------------------
    // ZIP: WinZip AES
    // -----------------------------------------------------------------------

    /** zip/aes256.zip with one encrypted byte of bin/random.bin flipped: AE-2 has no CRC, only the authentication code detects it. */
    private static void zipAesTampered(final File out) throws IOException {
        final byte[] d = read(new File(out, "zip/aes256.zip"));
        final long o = zipHeaderOffset(d, "bin/random.bin");
        final int base = (int) o;
        final int n = le16(d, base + 26);
        final int e = le16(d, base + 28);
        d[base + 30 + n + e + 18 + 100] ^= 0x55; // after the 16-byte salt and the 2-byte verifier
        write(new File(out, "zip/aes256-tampered.zip"), d);
    }

    /** Offset of the local header of an entry, read from the central directory (ZIP64 extra field supported). */
    private static long zipHeaderOffset(final byte[] d, final String name) throws IOException {
        int eocd = -1;
        for (int i = d.length - 22; i >= Math.max(0, d.length - 22 - 65535); i--) {
            if (le32(d, i) == 0x06054b50L) { eocd = i; break; }
        }
        if (eocd < 0) throw new IOException("ZIP end record not found");
        final int count = le16(d, eocd + 10);
        int p = (int) le32(d, eocd + 16);
        for (int k = 0; k < count; k++) {
            if (le32(d, p) != 0x02014b50L) throw new IOException("bad central directory");
            final int nl = le16(d, p + 28);
            final int xl = le16(d, p + 30);
            final int cl = le16(d, p + 32);
            final String n = new String(d, p + 46, nl, StandardCharsets.UTF_8);
            if (n.equals(name)) {
                long off = le32(d, p + 42);
                if (off == 0xFFFFFFFFL) {
                    int x = p + 46 + nl;
                    final int end = x + xl;
                    while (x + 4 <= end) {
                        final int id = le16(d, x);
                        final int sz = le16(d, x + 2);
                        if (id == 1) {
                            int q = x + 4;
                            if (le32(d, p + 24) == 0xFFFFFFFFL) q += 8;
                            if (le32(d, p + 20) == 0xFFFFFFFFL) q += 8;
                            off = le32(d, q) | le32(d, q + 4) << 32;
                        }
                        x += 4 + sz;
                    }
                }
                return off;
            }
            p += 46 + nl + xl + cl;
        }
        throw new IOException("entry not found: " + name);
    }

    /** WinZip AE-2 AES-256 + Deflate, password "caf\u00e9" as UTF-8 bytes, fixed salts (reproducible sample). */
    private static byte[] zipAesUtf8(final File root) throws IOException, GeneralSecurityException {
        final byte[] pw = "caf\u00e9".getBytes(StandardCharsets.UTF_8);
        final List<String> names = new ArrayList<String>();
        listFiles(root, "", names);
        Collections.sort(names);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final ByteArrayOutputStream cd = new ByteArrayOutputStream();
        for (int i = 0; i < names.size(); i++) {
            final String n = names.get(i);
            final byte[] data = read(new File(root, n));
            final byte[] comp = deflate(data, 9);
            final byte[] salt = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(cat(ascii("arcana-salt"), new byte[] {(byte) i})), 16);
            final byte[] k = pbkdf2HmacSha1(pw, salt, 1000, 66);
            final Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
            ecb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, 0, 32, "AES"));
            final byte[] enc = new byte[comp.length];
            final byte[] counter = new byte[16];
            for (int j = 0; j < comp.length; j += 16) {
                long c = j / 16 + 1;
                for (int q = 0; q < 8; q++) counter[q] = (byte) (c >>> (8 * q));
                final byte[] ks = ecb.doFinal(counter);
                for (int q = 0; q < 16 && j + q < comp.length; q++) enc[j + q] = (byte) (comp[j + q] ^ ks[q]);
            }
            final Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(k, 32, 32, "HmacSHA1"));
            final byte[] auth = Arrays.copyOf(mac.doFinal(enc), 10);
            final byte[] payload = cat(salt, Arrays.copyOfRange(k, 64, 66), enc, auth);
            final byte[] nb = n.getBytes(StandardCharsets.UTF_8);
            final ByteArrayOutputStream ex = new ByteArrayOutputStream();
            writeLe16(ex, 0x9901);
            writeLe16(ex, 7);
            writeLe16(ex, 2);
            ex.write(0x41);
            ex.write(0x45);
            ex.write(3);
            writeLe16(ex, 8);
            final ByteArrayOutputStream common = new ByteArrayOutputStream();
            writeLe16(common, 51);
            writeLe16(common, 0x801);
            writeLe16(common, 99);
            writeLe16(common, 0x1882);
            writeLe16(common, 0x5822);
            writeLe32(common, 0);
            writeLe32(common, payload.length);
            writeLe32(common, data.length);
            cd.write(new byte[] {'P', 'K', 1, 2}, 0, 4);
            writeLe16(cd, 51);
            common.writeTo(cd);
            writeLe16(cd, nb.length);
            writeLe16(cd, ex.size());
            writeLe16(cd, 0);
            writeLe16(cd, 0);
            writeLe16(cd, 0);
            writeLe32(cd, 0);
            writeLe32(cd, out.size());
            cd.write(nb, 0, nb.length);
            ex.writeTo(cd);
            out.write(new byte[] {'P', 'K', 3, 4}, 0, 4);
            common.writeTo(out);
            writeLe16(out, nb.length);
            writeLe16(out, ex.size());
            out.write(nb, 0, nb.length);
            ex.writeTo(out);
            out.write(payload, 0, payload.length);
        }
        final int cdOffset = out.size();
        cd.writeTo(out);
        out.write(new byte[] {'P', 'K', 5, 6}, 0, 4);
        writeLe16(out, 0);
        writeLe16(out, 0);
        writeLe16(out, names.size());
        writeLe16(out, names.size());
        writeLe32(out, cd.size());
        writeLe32(out, cdOffset);
        writeLe16(out, 0);
        return out.toByteArray();
    }

    /** PBKDF2-HMAC-SHA1 over the raw password bytes. */
    private static byte[] pbkdf2HmacSha1(final byte[] pw, final byte[] salt, final int rounds, final int len) throws GeneralSecurityException {
        final Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(pw, "HmacSHA1"));
        final byte[] out = new byte[len];
        for (int block = 1, done = 0; done < len; block++) {
            mac.update(salt);
            byte[] u = mac.doFinal(new byte[] {(byte) (block >>> 24), (byte) (block >>> 16), (byte) (block >>> 8), (byte) block});
            final byte[] t = u.clone();
            for (int r = 1; r < rounds; r++) {
                u = mac.doFinal(u);
                for (int q = 0; q < t.length; q++) t[q] ^= u[q];
            }
            final int n = Math.min(t.length, len - done);
            System.arraycopy(t, 0, out, done, n);
            done += n;
        }
        return out;
    }

    // -----------------------------------------------------------------------
    // Zstandard, 7z
    // -----------------------------------------------------------------------

    /** A frame between a leading skippable frame and two trailing ones (the last one empty). */
    private static byte[] zstdSkippable(final byte[] frame) {
        return cat(skippable(0x184D2A50, ascii("leading skippable frame")), frame, skippable(0x184D2A5F, ascii("trailing")), skippable(0x184D2A55, new byte[0]));
    }

    private static byte[] skippable(final int magic, final byte[] data) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeLe32(out, magic);
        writeLe32(out, data.length);
        out.write(data, 0, data.length);
        return out.toByteArray();
    }

    /** 7z with plain headers (-mhc=off): AES NumCyclesPower patched from 19 to 30 (2^30 SHA-256 rounds), CRCs fixed. */
    private static byte[] sevenZipAesRounds(final byte[] in) throws IOException {
        final byte[] d = in.clone();
        final long off = le32(d, 12) | le32(d, 16) << 32;
        final long size = le32(d, 20) | le32(d, 24) << 32;
        final int h = (int) (32 + off);
        final int end = (int) Math.min(d.length, h + size);
        final byte[] coder = {0x06, (byte) 0xF1, 0x07, 0x01}; // AES-256 + SHA-256 coder id, then props size, props
        int i = -1;
        for (int p = h; p + coder.length <= end; p++) {
            if (d[p] == coder[0] && d[p + 1] == coder[1] && d[p + 2] == coder[2] && d[p + 3] == coder[3]) { i = p; break; }
        }
        if (i < 0) throw new IOException("AES coder not found in the header (7z made with -p and -mhc=off expected)");
        if ((d[i + 5] & 0x3F) != 19) throw new IOException("NumCyclesPower is not 19: " + (d[i + 5] & 0x3F));
        d[i + 5] = (byte) ((d[i + 5] & 0xC0) | 30);
        putLe32(d, 28, crc32(d, h, (int) size));
        putLe32(d, 8, crc32(d, 12, 20));
        return d;
    }

    // -----------------------------------------------------------------------
    // SFX: minimal PE whose section holds a ZIP that does not end at the end of the file
    // -----------------------------------------------------------------------

    /** Minimal PE (no code) whose only section holds a ZIP followed by padding, then a text overlay ending with an empty ZIP end record. */
    private static byte[] sfxZipInside(final File src) throws IOException {
        final byte[] zip = pythonStyleZip(src);
        final ByteArrayOutputStream ds = new ByteArrayOutputStream();
        ds.write(0xC3); // ret + int3 padding (never run)
        for (int i = 0; i < 63; i++) ds.write(0xCC);
        ds.write(zip, 0, zip.length);
        ds.write(new byte[0x1000], 0, 0x1000); // ZIP inside the section, padding after it
        final int rawSize = (ds.size() + 0x1FF) & ~0x1FF;
        final byte[] data = Arrays.copyOf(ds.toByteArray(), rawSize);
        final int vsize = rawSize;
        final byte[] hdr = new byte[0x200];
        hdr[0] = 'M';
        hdr[1] = 'Z';
        putLe32(hdr, 0x3C, 0x40);
        final Packer pe = new Packer(hdr, 0x40);
        pe.bytes(new byte[] {'P', 'E', 0, 0}).u16(0x14C).u16(1).u32(0).u32(0).u32(0).u16(0xE0).u16(0x0102);
        final int opt = 0x58;
        new Packer(hdr, opt).u16(0x10B).u8(14).u8(0).u32(rawSize).u32(0).u32(0).u32(0x1000).u32(0x1000).u32(0x1000);
        new Packer(hdr, opt + 28).u32(0x400000).u32(0x1000).u32(0x200).u16(4).u16(0).u16(0).u16(0).u16(4).u16(0).u32(0).u32(0x1000 + ((vsize + 0xFFF) & ~0xFFF)).u32(0x200).u32(0).u16(2).u16(0x8540).u32(0x100000).u32(0x1000).u32(0x100000).u32(0x1000).u32(0).u32(16);
        new Packer(hdr, opt + 0xE0).bytes(new byte[] {'.', 'd', 'a', 't', 'a', 0, 0, 0}).u32(vsize).u32(0x1000).u32(rawSize).u32(0x200).u32(0).u32(0).u16(0).u16(0).u32(0xC0000040);
        final StringBuilder overlay = new StringBuilder();
        for (int i = 0; i < 40; i++) overlay.append(String.format(Locale.ROOT, "overlay line %04d: installer settings, not an archive\n", i));
        final byte[] end = new byte[22]; // end record of an empty ZIP
        end[0] = 'P';
        end[1] = 'K';
        end[2] = 5;
        end[3] = 6;
        return cat(hdr, data, ascii(overlay.toString()), end);
    }

    /** ZIP written as Python's zipfile does it: deflate level 6, files of a top-down walk (folders sorted), 2024-01-02 03:04:04, mode 0644, Unix host. */
    private static byte[] pythonStyleZip(final File src) throws IOException {
        final List<String> files = new ArrayList<String>();
        walkTopDown(src, "", files);
        final int dosTime = 3 << 11 | 4 << 5 | 4 / 2;
        final int dosDate = (2024 - 1980) << 9 | 1 << 5 | 2;
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final ByteArrayOutputStream cd = new ByteArrayOutputStream();
        for (final String n : files) {
            final byte[] data = read(new File(src, n));
            final byte[] comp = deflate(data, Deflater.DEFAULT_COMPRESSION);
            final CRC32 crc = new CRC32();
            crc.update(data, 0, data.length);
            final byte[] nb = n.getBytes(StandardCharsets.UTF_8);
            final int flags = n.equals(new String(nb, StandardCharsets.US_ASCII)) ? 0 : 0x800;
            final int offset = out.size();
            out.write(new byte[] {'P', 'K', 3, 4}, 0, 4);
            writeLe16(out, 20);
            writeLe16(out, flags);
            writeLe16(out, 8);
            writeLe16(out, dosTime);
            writeLe16(out, dosDate);
            writeLe32(out, (int) crc.getValue());
            writeLe32(out, comp.length);
            writeLe32(out, data.length);
            writeLe16(out, nb.length);
            writeLe16(out, 0);
            out.write(nb, 0, nb.length);
            out.write(comp, 0, comp.length);
            cd.write(new byte[] {'P', 'K', 1, 2}, 0, 4);
            writeLe16(cd, 3 << 8 | 20);
            writeLe16(cd, 20);
            writeLe16(cd, flags);
            writeLe16(cd, 8);
            writeLe16(cd, dosTime);
            writeLe16(cd, dosDate);
            writeLe32(cd, (int) crc.getValue());
            writeLe32(cd, comp.length);
            writeLe32(cd, data.length);
            writeLe16(cd, nb.length);
            writeLe16(cd, 0);
            writeLe16(cd, 0);
            writeLe16(cd, 0);
            writeLe16(cd, 0);
            writeLe32(cd, 0644 << 16);
            writeLe32(cd, offset);
            cd.write(nb, 0, nb.length);
        }
        final int cdOffset = out.size();
        cd.writeTo(out);
        out.write(new byte[] {'P', 'K', 5, 6}, 0, 4);
        writeLe16(out, 0);
        writeLe16(out, 0);
        writeLe16(out, files.size());
        writeLe16(out, files.size());
        writeLe32(out, cd.size());
        writeLe32(out, cdOffset);
        writeLe16(out, 0);
        return out.toByteArray();
    }

    /** Little-endian writer into a byte array (struct.pack_into). */
    private static final class Packer {
        private final byte[] b;
        private int p;

        Packer(final byte[] b, final int p) {
            this.b = b;
            this.p = p;
        }

        Packer u8(final int v) {
            b[p++] = (byte) v;
            return this;
        }

        Packer u16(final int v) {
            return u8(v).u8(v >>> 8);
        }

        Packer u32(final long v) {
            return u16((int) v).u16((int) (v >>> 16));
        }

        Packer bytes(final byte[] v) {
            System.arraycopy(v, 0, b, p, v.length);
            p += v.length;
            return this;
        }
    }

    // -----------------------------------------------------------------------
    // WIM whose LZX chunks contain an uncompressed block (wimlib never writes one)
    // -----------------------------------------------------------------------

    /** Two files captured by wimlib-imagex, whose resources are then replaced by hand-made LZX chunks; in a-aligned.bin the block header ends on a 16-bit boundary. */
    private static void wimLzxUncompressed(final File work, final File out) throws IOException, GeneralSecurityException, InterruptedException {
        final File src = new File(work, "wim-lzx-uncompressed");
        mkdirs(src);
        final Map<String, byte[]> chunks = new HashMap<String, byte[]>();
        final Map<String, Integer> sizes = new HashMap<String, Integer>();
        final Object[][] specs = {{"a-aligned.bin", 4064, 3001, 1, 0}, {"b-unaligned.bin", 4070, 2000, 2, 6}};
        for (final Object[] sp : specs) {
            final LzxChunk c = lzxChunk((Integer) sp[1], lzxRawBytes((Integer) sp[2], (Integer) sp[3]));
            if (c.headerEndMod16 != (Integer) sp[4]) throw new IOException("unexpected LZX block header end: " + c.headerEndMod16);
            final File f = new File(src, (String) sp[0]);
            write(f, c.expected);
            f.setLastModified(STAMP_MS);
            final String h = hex(MessageDigest.getInstance("SHA-1").digest(c.expected));
            chunks.put(h, c.stream);
            sizes.put(h, c.expected.length);
        }
        if (out.exists() && !out.delete()) throw new IOException("cannot delete " + out);
        final ProcessBuilder pb = new ProcessBuilder("wimlib-imagex", "capture", src.getPath(), out.getPath(), "Arcana", "--compress=lzx");
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        final Process proc = pb.start();
        final InputStream so = proc.getInputStream();
        final byte[] sink = new byte[4096];
        while (so.read(sink) >= 0) {
            // standard output discarded
        }
        if (proc.waitFor() != 0) throw new IOException("wimlib-imagex capture failed (exit code " + proc.exitValue() + ")");
        final ByteArrayOutputStream w = new ByteArrayOutputStream();
        final byte[] orig = read(out);
        w.write(orig, 0, orig.length);
        final long size7 = le64(orig, 48);
        final long btSize = size7 & 0xFFFFFFFFFFFFFFL;
        final int btOff = (int) le64(orig, 56);
        int done = 0;
        for (int e = btOff; e < btOff + btSize; e += 50) {
            final String h = hex(Arrays.copyOfRange(orig, e + 30, e + 50));
            final byte[] s = chunks.get(h);
            if (s == null) continue;
            final int usize = sizes.get(h);
            if (s.length >= usize) throw new IOException("LZX chunk not smaller than its data");
            final long off = w.size();
            w.write(s, 0, s.length);
            final long flags = (orig[e + 7] & 0xFF) | 0x04; // compressed
            putLe64(orig, e, s.length | flags << 56);
            putLe64(orig, e + 8, off);
            putLe64(orig, e + 16, usize);
            done++;
        }
        if (done != 2) throw new IOException("blob table: " + done + " resources patched instead of 2");
        final byte[] all = w.toByteArray();
        System.arraycopy(orig, 0, all, 0, orig.length);
        write(out, all);
    }

    private static final class LzxChunk {
        byte[] stream;
        byte[] expected;
        int headerEndMod16;
    }

    /** n1 'a' literals in a verbatim block, then raw bytes in an uncompressed block (window order 15, wimlib alignment rule). */
    private static LzxChunk lzxChunk(final int n1, final byte[] raw) {
        final int windowOrder = 15;
        final BitWriter bw = new BitWriter();
        final int nmain = 256 + 8 * (2 * windowOrder);
        bw.put(1, 3); // block 1: verbatim, size n1
        if (n1 == 32768) bw.put(1, 1);
        else {
            bw.put(0, 1);
            bw.put(n1, 16);
        }
        final int[] lit = new int[256];
        lit[0x61] = 1;
        lit[0x62] = 2;
        lit[0x63] = 3;
        lit[0x64] = 3;
        pretree(bw, lit);
        pretree(bw, new int[nmain - 256]);
        pretree(bw, new int[249]);
        for (int i = 0; i < n1; i++) bw.put(0, 1); // 'a' = code 0
        final int k = raw.length;
        bw.put(3, 3); // block 2: uncompressed
        if (k == 32768) bw.put(1, 1);
        else {
            bw.put(0, 1);
            bw.put(k, 16);
        }
        final int hdrEnd = bw.pos;
        final int r = bw.pos % 16;
        if (r != 0) bw.put(0, 16 - r);
        else bw.put(0, 16);
        final ByteArrayOutputStream o = new ByteArrayOutputStream();
        final byte[] words = bw.toByteArray();
        o.write(words, 0, words.length);
        writeLe32(o, 1);
        writeLe32(o, 1);
        writeLe32(o, 1);
        o.write(raw, 0, raw.length);
        if ((k & 1) != 0) o.write(0);
        final LzxChunk c = new LzxChunk();
        c.stream = o.toByteArray();
        c.expected = new byte[n1 + k];
        Arrays.fill(c.expected, 0, n1, (byte) 'a');
        System.arraycopy(raw, 0, c.expected, n1, k);
        c.headerEndMod16 = hdrEnd % 16;
        return c;
    }

    /** Pretree: lengths 4 for symbols 0-11, 5 for 12-19; then each length as a delta from 0 (mod 17). */
    private static void pretree(final BitWriter bw, final int[] lens) {
        for (int x = 0; x < 20; x++) bw.put(x < 12 ? 4 : 5, 4);
        for (final int v : lens) {
            final int x = Math.floorMod(-v + 17, 17);
            if (x < 12) bw.put(x, 4);
            else bw.put(24 + x - 12, 5);
        }
    }

    /** Random bytes (Python's random.Random(seed)) with 0xE8 replaced by 0x17 (no E8 translation). */
    private static byte[] lzxRawBytes(final int k, final int seed) {
        final MersenneTwister r = new MersenneTwister(seed);
        final byte[] b = new byte[k];
        for (int i = 0; i < k; i++) {
            final int v = r.getrandbits8();
            b[i] = (byte) (v == 0xE8 ? 0x17 : v);
        }
        return b;
    }

    /** MSB-first bits packed in little-endian 16-bit words. */
    private static final class BitWriter {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private int acc;
        private int pos;

        void put(final int v, final int n) {
            for (int i = n - 1; i >= 0; i--) {
                acc = acc << 1 | ((v >>> i) & 1);
                pos++;
                if (pos % 16 == 0) {
                    out.write(acc & 0xFF);
                    out.write((acc >>> 8) & 0xFF);
                    acc = 0;
                }
            }
        }

        byte[] toByteArray() {
            if (pos % 16 != 0) throw new IllegalStateException("bit stream not aligned");
            return out.toByteArray();
        }
    }

    // -----------------------------------------------------------------------
    // Apple disk images: HFSX volume (TN1150) in a one-partition UDIF image
    // -----------------------------------------------------------------------

    private static final int HFS_BLOCK = 4096;
    private static final int HFS_FIRST_DATA_BLOCK = 64;
    private static final long MAC_EPOCH = 2082844800L;

    /** One catalog entry of the volume being written. */
    private static final class HfsItem {
        String name;
        HfsItem parent;
        final List<HfsItem> children = new ArrayList<HfsItem>();
        boolean dir;
        int id;
        byte[] data = new byte[0];
        byte[] rsrc = new byte[0];
        byte[] decmpfs;
        int mode;
        int ownerFlags;
        int special;
        String fdType = "\0\0\0\0";
        String fdCreator = "\0\0\0\0";
        long[] dataExtents = new long[0];
        long[] rsrcExtents = new long[0];
    }

    /**
     * dmg-hfsx PAYLOAD MODE OUT: the payload tree in an HFSX volume, in a
     * one-partition UDIF image whose chunks are raw (MODE raw), ADC (adc) or
     * zlib (features: with the extra entries of {@link #hfsFeatures}; whole:
     * one "whole disk" entry holding a driver descriptor, an Apple partition
     * map and the volume at sector 64, as some hdiutil images have).
     */
    private static byte[] dmgHfsx(final File payload, final String mode) throws IOException {
        final HfsItem root = new HfsItem();
        root.name = "ArcanaTest";
        root.dir = true;
        hfsTree(payload, root);
        if (mode.equals("features")) hfsFeatures(root, payload);
        final byte[] volume = hfsVolume(root);
        if (mode.equals("whole")) return udif(wholeDisk(volume), 0x80000005, "whole disk (Apple_HFS : 0)");
        return udif(volume, mode.equals("raw") ? 1 : mode.equals("adc") ? 0x80000004 : 0x80000005, "disk image (Apple_HFS : 0)");
    }

    /** Disk with a driver descriptor ("ER"), an Apple partition map (2 entries) and the volume from sector 64. */
    private static byte[] wholeDisk(final byte[] volume) {
        final int volSectors = volume.length / 512;
        final byte[] disk = new byte[(64 + volSectors) * 512];
        disk[0] = 'E';
        disk[1] = 'R';
        putBe16(disk, 2, 512);
        putBe32(disk, 4, 64 + volSectors);
        final String[][] entries = {{"Apple", "Apple_partition_map", "1", "63"}, {"disk image", "Apple_HFS", "64", String.valueOf(volSectors)}};
        for (int i = 0; i < entries.length; i++) {
            final int e = 512 * (i + 1);
            disk[e] = 'P';
            disk[e + 1] = 'M';
            putBe32(disk, e + 4, entries.length);
            putBe32(disk, e + 8, Integer.parseInt(entries[i][2]));
            putBe32(disk, e + 12, Integer.parseInt(entries[i][3]));
            System.arraycopy(ascii(entries[i][0]), 0, disk, e + 16, entries[i][0].length());
            System.arraycopy(ascii(entries[i][1]), 0, disk, e + 48, entries[i][1].length());
            putBe32(disk, e + 84, Integer.parseInt(entries[i][3]));
        }
        System.arraycopy(volume, 0, disk, 64 * 512, volume.length);
        return disk;
    }

    private static void hfsTree(final File dir, final HfsItem parent) throws IOException {
        for (final String n : sortedNames(dir, true)) {
            final HfsItem d = hfsAdd(parent, n, true);
            hfsTree(new File(dir, n), d);
        }
        for (final String n : sortedNames(dir, false)) hfsAdd(parent, n, false).data = read(new File(dir, n));
    }

    private static HfsItem hfsAdd(final HfsItem parent, final String name, final boolean dir) {
        final HfsItem i = new HfsItem();
        i.name = Normalizer.normalize(name, Normalizer.Form.NFD);
        i.parent = parent;
        i.dir = dir;
        i.mode = dir ? 040755 : 0100644;
        parent.children.add(i);
        return i;
    }

    private static HfsItem hfsChild(final HfsItem parent, final String name) {
        for (final HfsItem c : parent.children) if (c.name.equals(name)) return c;
        return hfsAdd(parent, name, true);
    }

    /**
     * Entries the HFS+ tools cannot write: decomposed Unicode names, a hard
     * link pair, a symbolic link, files compressed with decmpfs (types 3, 4,
     * 7, 8, 12), a fragmented file (extents overflow record) and a resource fork.
     */
    private static void hfsFeatures(final HfsItem root, final File payload) throws IOException {
        hfsAdd(root, "caf\u00e9 \u00e0 la cr\u00e8me.txt", false).data = ascii("accented name\n");
        final HfsItem deja = hfsAdd(root, "d\u00e9j\u00e0 vu", true);
        hfsAdd(deja, "\u00fcber.txt", false).data = ascii("decomposed folder and file names\n");
        final byte[] readme = read(new File(payload, "readme.txt"));
        final byte[] notes = read(new File(payload, "docs/notes.txt"));
        final byte[] big = cat(notes, notes, notes);
        // hard links: two "hlnk" records pointing to iNode<n> in the private metadata folder
        final HfsItem priv = hfsAdd(root, "\u0000\u0000\u0000\u0000HFS+ Private Data", true);
        final HfsItem inode = hfsAdd(priv, "iNode", false);
        inode.data = ascii("hard link target\n");
        inode.special = 2;
        final HfsItem links = hfsAdd(root, "links", true);
        for (final String n : new String[] {"hard-1.txt", "hard-2.txt"}) {
            final HfsItem l = hfsAdd(links, n, false);
            l.fdType = "hlnk";
            l.fdCreator = "hfs+";
            l.special = -1; // set to the iNode number once numbered
        }
        final HfsItem sym = hfsAdd(links, "symlink.txt", false);
        sym.data = ascii("../readme.txt");
        sym.mode = 0120755;
        sym.fdType = "slnk";
        sym.fdCreator = "rhap";
        // decmpfs: 16-byte header ("fpmc", type, size; little-endian), data inline or in the resource fork
        final HfsItem comp = hfsAdd(root, "compressed", true);
        hfsCompressed(hfsAdd(comp, "zlib-inline.txt", false), 3, readme, cat(new byte[] {0x78, (byte) 0xDA}, deflate(readme, 9), adler(readme)));
        hfsCompressed(hfsAdd(comp, "lzvn-inline.txt", false), 7, readme, lzvn(readme));
        final HfsItem zf = hfsAdd(comp, "zlib-fork.txt", false);
        hfsCompressed(zf, 4, big, null);
        zf.rsrc = decmpfsFork(big, 4);
        final HfsItem vf = hfsAdd(comp, "lzvn-fork.txt", false);
        hfsCompressed(vf, 8, big, null);
        vf.rsrc = decmpfsFork(big, 8);
        final HfsItem ff = hfsAdd(comp, "lzfse-fork.txt", false);
        hfsCompressed(ff, 12, big, null);
        ff.rsrc = decmpfsFork(big, 12);
        // 10 blocks in 10 extents: 8 in the catalog record, 2 in the extents overflow file
        final byte[] frag = new byte[10 * HFS_BLOCK];
        for (int i = 0; i < frag.length; i++) frag[i] = (byte) (i / HFS_BLOCK * 16 + i % 13);
        hfsAdd(root, "fragmented.bin", false).data = frag;
        final HfsItem rf = hfsAdd(hfsChild(root, "docs"), "with-resource-fork.txt", false);
        rf.data = ascii("data fork\n");
        rf.rsrc = ascii("resource fork (not extracted)\n");
    }

    private static void hfsCompressed(final HfsItem f, final int type, final byte[] data, final byte[] inline) {
        final byte[] h = new byte[16];
        System.arraycopy(ascii("fpmc"), 0, h, 0, 4);
        putLe32(h, 4, type);
        putLe64(h, 8, data.length);
        f.decmpfs = inline != null ? cat(h, inline) : h;
        f.ownerFlags = 0x20; // UF_COMPRESSED
    }

    /** Resource fork of a decmpfs file: 64 KiB blocks, zlib (type 4, resource file layout), LZVN (8) or LZFSE (12) with an offset table. */
    private static byte[] decmpfsFork(final byte[] data, final int type) {
        final int n = (data.length + 65535) / 65536;
        final List<byte[]> blocks = new ArrayList<byte[]>();
        for (int i = 0; i < n; i++) {
            final byte[] b = Arrays.copyOfRange(data, i * 65536, Math.min(data.length, (i + 1) * 65536));
            if (type == 4) blocks.add(cat(new byte[] {0x78, (byte) 0xDA}, deflate(b, 9), adler(b)));
            else if (type == 8) blocks.add(lzvn(b));
            else blocks.add(lzfseOfLzvn(b));
        }
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (type == 4) {
            // resource file: header (data offset, map offset, data length, map length), the "cmpf" resource
            // (length, block count, block table, blocks), then a resource map naming it
            int resLength = 4 + 8 * n;
            for (final byte[] b : blocks) resLength += b.length;
            writeBe32(out, 0x100);
            writeBe32(out, 0x100 + 4 + resLength);
            writeBe32(out, 4 + resLength);
            writeBe32(out, 50);
            out.write(new byte[0x100 - 16], 0, 0x100 - 16);
            writeBe32(out, resLength);
            writeLe32(out, n);
            int off = 4 + 8 * n;
            for (final byte[] b : blocks) {
                writeLe32(out, off);
                writeLe32(out, b.length);
                off += b.length;
            }
        } else {
            int off = 4 * (n + 1);
            writeLe32(out, off);
            for (final byte[] b : blocks) writeLe32(out, off += b.length);
        }
        for (final byte[] b : blocks) out.write(b, 0, b.length);
        if (type == 4) {
            // resource map: type list at 28 ("cmpf", 1 resource), reference list (ID 1, data at 0), no names
            final byte[] map = new byte[50];
            putBe16(map, 24, 28);
            putBe16(map, 26, 50);
            System.arraycopy(ascii("cmpf"), 0, map, 30, 4);
            putBe16(map, 36, 10);
            putBe16(map, 38, 1);
            putBe16(map, 40, 0xFFFF);
            out.write(map, 0, map.length);
        }
        return out.toByteArray();
    }

    /** LZFSE stream made of one LZVN block ("bvxn") and the end marker. */
    private static byte[] lzfseOfLzvn(final byte[] b) {
        final byte[] v = lzvn(b);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(ascii("bvxn"), 0, 4);
        writeLe32(out, b.length);
        writeLe32(out, v.length);
        out.write(v, 0, v.length);
        out.write(ascii("bvx$"), 0, 4);
        return out.toByteArray();
    }

    /** Builds the volume: header, allocation bitmap, extents / attributes / catalog B-trees, then the data. */
    private static byte[] hfsVolume(final HfsItem root) throws IOException {
        // number the entries (root 2, others from 16) and allocate the forks
        final List<HfsItem> all = new ArrayList<HfsItem>();
        hfsCollect(root, all);
        root.id = 2;
        int next = 16;
        HfsItem inode = null;
        for (final HfsItem i : all) {
            if (i != root) i.id = next++;
            if (i.name.equals("iNode")) inode = i;
        }
        if (inode != null) {
            inode.name = "iNode" + inode.id;
            for (final HfsItem i : all) if (i.special == -1) i.special = inode.id;
        }
        long block = HFS_FIRST_DATA_BLOCK;
        final List<byte[]> extentRecords = new ArrayList<byte[]>();
        for (final HfsItem i : all) {
            if (i.dir) continue;
            final int nd = (i.data.length + HFS_BLOCK - 1) / HFS_BLOCK;
            if (i.name.equals("fragmented.bin")) {
                i.dataExtents = new long[2 * nd];
                for (int k = 0; k < nd; k++) {
                    i.dataExtents[2 * k] = block;
                    i.dataExtents[2 * k + 1] = 1;
                    block += 2; // one free block between the extents
                }
                final byte[] key = new byte[12];
                putBe16(key, 0, 10);
                putBe32(key, 4, i.id);
                putBe32(key, 8, 8);
                final byte[] rec = new byte[64];
                for (int k = 8; k < nd; k++) {
                    putBe32(rec, 8 * (k - 8), (int) i.dataExtents[2 * k]);
                    putBe32(rec, 8 * (k - 8) + 4, 1);
                }
                extentRecords.add(cat(key, rec));
            } else if (nd > 0) {
                i.dataExtents = new long[] {block, nd};
                block += nd;
            }
            final int nr = (i.rsrc.length + HFS_BLOCK - 1) / HFS_BLOCK;
            if (nr > 0) {
                i.rsrcExtents = new long[] {block, nr};
                block += nr;
            }
        }
        final long totalBlocks = block + 2;
        // catalog: folder / file records and their threads, sorted by (parent ID, UTF-16 name): HFSX binary order
        final List<byte[]> catalog = new ArrayList<byte[]>();
        final List<byte[]> attributes = new ArrayList<byte[]>();
        final long now = STAMP_MS / 1000 + MAC_EPOCH;
        for (final HfsItem i : all) {
            final int parentId = i == root ? 1 : i.parent.id;
            final byte[] rec;
            if (i.dir) {
                rec = new byte[88];
                putBe16(rec, 0, 1);
                putBe32(rec, 4, i.children.size());
            } else {
                rec = new byte[248];
                putBe16(rec, 0, 2);
                putBe16(rec, 2, 0x0002 | (i.decmpfs != null ? 0x0004 : 0));
                rec[41] = (byte) i.ownerFlags;
                putBe32(rec, 44, i.special);
                System.arraycopy(i.fdType.getBytes(StandardCharsets.ISO_8859_1), 0, rec, 48, 4);
                System.arraycopy(i.fdCreator.getBytes(StandardCharsets.ISO_8859_1), 0, rec, 52, 4);
                hfsFork(rec, 88, i.decmpfs != null ? 0 : i.data.length, i.dataExtents);
                hfsFork(rec, 168, i.rsrc.length, i.rsrcExtents);
                if (i.decmpfs != null) {
                    final byte[] name = "com.apple.decmpfs".getBytes(StandardCharsets.UTF_16BE);
                    final byte[] key = new byte[14 + name.length];
                    putBe16(key, 0, 12 + name.length);
                    putBe32(key, 4, i.id);
                    putBe16(key, 12, name.length / 2);
                    System.arraycopy(name, 0, key, 14, name.length);
                    final byte[] value = new byte[16 + (i.decmpfs.length + 1) / 2 * 2];
                    putBe32(value, 0, 0x10);
                    putBe32(value, 12, i.decmpfs.length);
                    System.arraycopy(i.decmpfs, 0, value, 16, i.decmpfs.length);
                    attributes.add(cat(key, value));
                }
            }
            putBe32(rec, 8, i.id);
            for (int d = 12; d < 32; d += 4) putBe32(rec, d, (int) now);
            putBe16(rec, 42, i.mode);
            catalog.add(cat(hfsKey(parentId, i.name), rec));
            final byte[] name = i.name.getBytes(StandardCharsets.UTF_16BE);
            final byte[] thread = new byte[10 + name.length];
            putBe16(thread, 0, i.dir ? 3 : 4);
            putBe32(thread, 4, parentId);
            putBe16(thread, 8, name.length / 2);
            System.arraycopy(name, 0, thread, 10, name.length);
            catalog.add(cat(hfsKey(i.id, ""), thread));
        }
        catalog.sort(SampleGenerator::compareHfsKeys);
        // special files: extents (2 nodes of 4 KiB), attributes (2), catalog (8 KiB nodes)
        final byte[] extentsTree = btree(extentRecords, 4096, 2, 0, 10, 2);
        final byte[] attributesTree = btree(attributes, 4096, 2 | 4, 0, 266, 2);
        final byte[] catalogTree = btree(catalog, 8192, 2 | 4, 0xBC, 516, 8);
        final byte[] img = new byte[(int) (totalBlocks * HFS_BLOCK)];
        System.arraycopy(extentsTree, 0, img, 2 * HFS_BLOCK, extentsTree.length);
        System.arraycopy(attributesTree, 0, img, 4 * HFS_BLOCK, attributesTree.length);
        System.arraycopy(catalogTree, 0, img, 8 * HFS_BLOCK, catalogTree.length);
        int files = 0;
        for (final HfsItem i : all) {
            if (i.dir) continue;
            files++;
            final byte[] data = i.decmpfs != null ? new byte[0] : i.data;
            for (int k = 0, pos = 0; k < i.dataExtents.length; k += 2) {
                final int n = (int) Math.min(data.length - pos, i.dataExtents[k + 1] * HFS_BLOCK);
                System.arraycopy(data, pos, img, (int) (i.dataExtents[k] * HFS_BLOCK), n);
                pos += n;
            }
            if (i.rsrc.length > 0) System.arraycopy(i.rsrc, 0, img, (int) (i.rsrcExtents[0] * HFS_BLOCK), i.rsrc.length);
        }
        // allocation bitmap (block 1): the special files, the data, the last block (alternate header)
        final boolean[] used = new boolean[(int) totalBlocks];
        for (int b = 0; b < 8 + catalogTree.length / HFS_BLOCK; b++) used[b] = true;
        for (final HfsItem i : all) {
            for (int k = 0; k < i.dataExtents.length; k += 2) for (long b = 0; b < i.dataExtents[k + 1]; b++) used[(int) (i.dataExtents[k] + b)] = true;
            for (int k = 0; k < i.rsrcExtents.length; k += 2) for (long b = 0; b < i.rsrcExtents[k + 1]; b++) used[(int) (i.rsrcExtents[k] + b)] = true;
        }
        used[used.length - 1] = true;
        int free = 0;
        for (int b = 0; b < used.length; b++) {
            if (used[b]) img[HFS_BLOCK + b / 8] |= (byte) (0x80 >>> (b % 8));
            else free++;
        }
        // volume header at 1024 and its copy 1024 bytes before the end
        final byte[] vh = new byte[512];
        System.arraycopy(ascii("HX"), 0, vh, 0, 2);
        putBe16(vh, 2, 5);
        putBe32(vh, 4, 1 << 8); // cleanly unmounted
        System.arraycopy(ascii("10.0"), 0, vh, 8, 4);
        for (int d = 16; d < 32; d += 4) putBe32(vh, d, (int) now);
        putBe32(vh, 32, files);
        putBe32(vh, 36, all.size() - files - 1);
        putBe32(vh, 40, HFS_BLOCK);
        putBe32(vh, 44, (int) totalBlocks);
        putBe32(vh, 48, free);
        putBe32(vh, 60, 65536);
        putBe32(vh, 64, next);
        putBe32(vh, 68, 1);
        putBe32(vh, 76, 1);
        hfsFork(vh, 112, HFS_BLOCK, new long[] {1, 1});
        putBe32(vh, 112 + 8, HFS_BLOCK);
        hfsFork(vh, 192, extentsTree.length, new long[] {2, 2});
        hfsFork(vh, 272, catalogTree.length, new long[] {8, catalogTree.length / HFS_BLOCK});
        hfsFork(vh, 352, attributesTree.length, new long[] {4, 2});
        System.arraycopy(vh, 0, img, 1024, 512);
        System.arraycopy(vh, 0, img, img.length - 1024, 512);
        return img;
    }

    private static void hfsCollect(final HfsItem i, final List<HfsItem> out) {
        out.add(i);
        for (final HfsItem c : i.children) hfsCollect(c, out);
    }

    /** HFSPlusForkData: logical size, total blocks, up to 8 extents. */
    private static void hfsFork(final byte[] b, final int off, final long size, final long[] extents) {
        putBe32(b, off, (int) (size >>> 32));
        putBe32(b, off + 4, (int) size);
        long blocks = 0;
        for (int k = 0; k < extents.length; k += 2) {
            blocks += extents[k + 1];
            if (k < 16) {
                putBe32(b, off + 16 + 4 * k, (int) extents[k]);
                putBe32(b, off + 20 + 4 * k, (int) extents[k + 1]);
            }
        }
        putBe32(b, off + 12, (int) blocks);
    }

    /** Catalog key: key length, parent ID, UTF-16 name with its length. */
    private static byte[] hfsKey(final int parent, final String name) {
        final byte[] n = name.getBytes(StandardCharsets.UTF_16BE);
        final byte[] k = new byte[8 + n.length];
        putBe16(k, 0, 6 + n.length);
        putBe32(k, 2, parent);
        putBe16(k, 6, n.length / 2);
        System.arraycopy(n, 0, k, 8, n.length);
        return k;
    }

    /** Order of catalog records: parent ID, then the UTF-16 code units (HFSX binary compare). */
    private static int compareHfsKeys(final byte[] a, final byte[] b) {
        final int p = Long.compare(be32(a, 2), be32(b, 2));
        if (p != 0) return p;
        final int la = be16(a, 6);
        final int lb = be16(b, 6);
        for (int i = 0; i < Math.min(la, lb); i++) {
            final int c = Integer.compare(be16(a, 8 + 2 * i), be16(b, 8 + 2 * i));
            if (c != 0) return c;
        }
        return Integer.compare(la, lb);
    }

    /**
     * B-tree file of sorted records (key with its length, then data): header
     * node 0, leaf nodes from 1, one index node above them when there is more
     * than one leaf. The file is {@code nodes} nodes long.
     */
    private static byte[] btree(final List<byte[]> records, final int nodeSize, final int attributes, final int compareType, final int maxKeyLength, final int nodes) throws IOException {
        final List<List<byte[]>> leaves = new ArrayList<List<byte[]>>();
        List<byte[]> cur = null;
        int used = 0;
        for (final byte[] r : records) {
            if (cur == null || used + r.length + 2 > nodeSize - 14 - 2) {
                leaves.add(cur = new ArrayList<byte[]>());
                used = 0;
            }
            cur.add(r);
            used += r.length + 2;
        }
        final int nLeaves = leaves.size();
        final int total = nLeaves + 1 + (nLeaves > 1 ? 1 : 0);
        if (total > nodes) throw new IOException("B-tree larger than " + nodes + " nodes");
        final byte[] f = new byte[nodes * nodeSize];
        for (int l = 0; l < nLeaves; l++) btreeNode(f, (l + 1) * nodeSize, nodeSize, l + 2 <= nLeaves ? l + 2 : 0, l, -1, 1, leaves.get(l));
        final int root = nLeaves == 0 ? 0 : nLeaves == 1 ? 1 : nLeaves + 1;
        if (nLeaves > 1) {
            final List<byte[]> index = new ArrayList<byte[]>();
            for (int l = 0; l < nLeaves; l++) {
                final byte[] first = leaves.get(l).get(0);
                final byte[] key = Arrays.copyOf(first, 2 + be16(first, 0));
                final byte[] ptr = new byte[4];
                putBe32(ptr, 0, l + 1);
                index.add(cat(key, ptr));
            }
            btreeNode(f, root * nodeSize, nodeSize, 0, 0, 0, 2, index);
        }
        // header node: descriptor, header record, user data record (128 bytes), map record
        f[8] = 1;
        putBe16(f, 10, 3);
        putBe16(f, 14, nLeaves == 0 ? 0 : nLeaves > 1 ? 2 : 1);
        putBe32(f, 16, root);
        putBe32(f, 20, records.size());
        putBe32(f, 24, nLeaves == 0 ? 0 : 1);
        putBe32(f, 28, nLeaves);
        putBe16(f, 32, nodeSize);
        putBe16(f, 34, maxKeyLength);
        putBe32(f, 36, nodes);
        putBe32(f, 40, nodes - total);
        putBe32(f, 46, nodeSize);
        f[51] = (byte) compareType;
        putBe32(f, 52, attributes);
        for (int n = 0; n < total; n++) f[248 + n / 8] |= (byte) (0x80 >>> (n % 8));
        putBe16(f, nodeSize - 2, 14);
        putBe16(f, nodeSize - 4, 120);
        putBe16(f, nodeSize - 6, 248);
        putBe16(f, nodeSize - 8, nodeSize - 8);
        return f;
    }

    private static void btreeNode(final byte[] f, final int base, final int nodeSize, final int fLink, final int bLink, final int kind, final int height, final List<byte[]> recs) {
        putBe32(f, base, fLink);
        putBe32(f, base + 4, bLink);
        f[base + 8] = (byte) kind;
        f[base + 9] = (byte) height;
        putBe16(f, base + 10, recs.size());
        int off = 14;
        for (int i = 0; i < recs.size(); i++) {
            putBe16(f, base + nodeSize - 2 * (i + 1), off);
            System.arraycopy(recs.get(i), 0, f, base + off, recs.get(i).length);
            off += recs.get(i).length;
        }
        putBe16(f, base + nodeSize - 2 * (recs.size() + 1), off);
    }

    /**
     * One-partition UDIF image (entry name given, e.g. "disk image (Apple_HFS : 0)"): chunks of 64
     * sectors (8 for raw ones) of the given type, zero-fill or "ignore"
     * chunks for the zero runs; data fork, XML property list, koly trailer,
     * CRC32 checksums (the partition one leaves the "ignore" chunks out).
     */
    private static byte[] udif(final byte[] volume, final int type, final String name) throws IOException {
        final int sectors = volume.length / 512;
        final int per = type == 1 ? 8 : 64;
        final ByteArrayOutputStream fork = new ByteArrayOutputStream();
        final ByteArrayOutputStream chunks = new ByteArrayOutputStream();
        final CRC32 partCrc = new CRC32();
        int count = 0;
        int s = 0;
        while (s < sectors) {
            final int n = Math.min(per, sectors - s);
            final byte[] d = Arrays.copyOfRange(volume, s * 512, (s + n) * 512);
            int t = type;
            byte[] c = d;
            int len = n;
            if (isZero(volume, s * 512, n * 512)) {
                // zero run: zero-fill chunk, or "ignore" chunk (as hdiutil writes for free space) from 64 sectors on
                while (s + len < sectors && isZero(volume, (s + len) * 512, 512)) len++;
                t = len >= 64 ? 2 : 0;
                c = new byte[0];
            } else if (type == 0x80000004) {
                c = adc(d);
            } else if (type == 0x80000005) {
                c = cat(new byte[] {0x78, (byte) 0xDA}, deflate(d, 9), adler(d));
            }
            if (t != 2) partCrc.update(volume, s * 512, len * 512);
            writeBe32(chunks, t);
            writeBe32(chunks, 0);
            writeBe64(chunks, s);
            writeBe64(chunks, len);
            writeBe64(chunks, fork.size());
            writeBe64(chunks, c.length);
            fork.write(c, 0, c.length);
            count++;
            s += len;
        }
        writeBe32(chunks, 0xFFFFFFFF);
        writeBe32(chunks, 0);
        writeBe64(chunks, sectors);
        writeBe64(chunks, 0);
        writeBe64(chunks, fork.size());
        writeBe64(chunks, 0);
        count++;
        final byte[] mish = new byte[204];
        System.arraycopy(ascii("mish"), 0, mish, 0, 4);
        putBe32(mish, 4, 1);
        putBe32(mish, 20, sectors);
        putBe32(mish, 32, 0x208);
        putBe32(mish, 64, 2);
        putBe32(mish, 68, 32);
        putBe32(mish, 72, (int) partCrc.getValue());
        putBe32(mish, 200, count);
        final String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>resource-fork</key>\n\t<dict>\n\t\t<key>blkx</key>\n\t\t<array>\n\t\t\t<dict>\n\t\t\t\t<key>Attributes</key>\n\t\t\t\t<string>0x0050</string>\n\t\t\t\t<key>CFName</key>\n\t\t\t\t<string>" + name + "</string>\n\t\t\t\t<key>Data</key>\n\t\t\t\t<data>\n\t\t\t\t" + java.util.Base64.getEncoder().encodeToString(cat(mish, chunks.toByteArray())) + "\n\t\t\t\t</data>\n\t\t\t\t<key>ID</key>\n\t\t\t\t<string>0</string>\n\t\t\t\t<key>Name</key>\n\t\t\t\t<string>" + name + "</string>\n\t\t\t</dict>\n\t\t</array>\n\t</dict>\n</dict>\n</plist>\n";
        final byte[] data = fork.toByteArray();
        final byte[] x = ascii(xml);
        final byte[] koly = new byte[512];
        System.arraycopy(ascii("koly"), 0, koly, 0, 4);
        putBe32(koly, 4, 4);
        putBe32(koly, 8, 512);
        putBe32(koly, 12, 1);
        putBe32(koly, 36, data.length);
        putBe32(koly, 56, 1);
        putBe32(koly, 60, 1);
        for (int i = 0; i < 16; i++) koly[64 + i] = (byte) (0xA0 + i);
        putBe32(koly, 80, 2);
        putBe32(koly, 84, 32);
        putBe32(koly, 88, crc32(data, 0, data.length));
        putBe32(koly, 220, data.length);
        putBe32(koly, 228, x.length);
        final byte[] sum = new byte[4];
        putBe32(sum, 0, (int) partCrc.getValue());
        putBe32(koly, 352, 2);
        putBe32(koly, 356, 32);
        putBe32(koly, 360, crc32(sum, 0, 4));
        putBe32(koly, 488, 1);
        putBe32(koly, 496, sectors);
        return cat(data, x, koly);
    }

    private static boolean isZero(final byte[] b, final int off, final int len) {
        for (int i = off; i < off + len; i++) if (b[i] != 0) return false;
        return true;
    }

    /** Greedy ADC encoder (Apple Data Compression, UDCO images). */
    private static byte[] adc(final byte[] in) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final int[] head = new int[1 << 16];
        Arrays.fill(head, -1);
        int lit = 0;
        int i = 0;
        while (i < in.length) {
            int best = 0;
            int dist = 0;
            if (i + 3 <= in.length) {
                final int h = ((in[i] & 0xff) << 8 ^ (in[i + 1] & 0xff) << 4 ^ (in[i + 2] & 0xff)) & 0xffff;
                final int cand = head[h];
                head[h] = i;
                if (cand >= 0 && i - cand <= 65536) {
                    while (i + best < in.length && best < 67 && in[cand + best] == in[i + best]) best++;
                    dist = i - cand;
                }
            }
            if (best >= 4 || best == 3 && dist <= 1024) {
                adcLiterals(out, in, lit, i);
                if (best <= 18 && dist <= 1024) {
                    out.write((best - 3) << 2 | (dist - 1) >>> 8);
                    out.write((dist - 1) & 0xff);
                } else {
                    out.write(0x40 | (best - 4));
                    out.write((dist - 1) >>> 8);
                    out.write((dist - 1) & 0xff);
                }
                i += best;
                lit = i;
            } else {
                i++;
            }
        }
        adcLiterals(out, in, lit, i);
        return out.toByteArray();
    }

    private static void adcLiterals(final ByteArrayOutputStream out, final byte[] in, int from, final int to) {
        while (from < to) {
            final int k = Math.min(128, to - from);
            out.write(0x80 | (k - 1));
            out.write(in, from, k);
            from += k;
        }
    }

    /** Greedy LZVN encoder: literal runs, lrg_d matches (L = 0, M 3-10) extended with sml_m / lrg_m, end-of-stream. */
    private static byte[] lzvn(final byte[] in) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final int[] head = new int[1 << 16];
        Arrays.fill(head, -1);
        int lit = 0;
        int i = 0;
        while (i < in.length) {
            int best = 0;
            int dist = 0;
            if (i + 4 <= in.length) {
                final int h = ((in[i] & 0xff) << 8 ^ (in[i + 1] & 0xff) << 4 ^ (in[i + 2] & 0xff) ^ (in[i + 3] & 0xff) << 12) & 0xffff;
                final int cand = head[h];
                head[h] = i;
                if (cand >= 0 && i - cand < 65536) {
                    while (i + best < in.length && in[cand + best] == in[i + best]) best++;
                    dist = i - cand;
                }
            }
            if (best >= 3) {
                lzvnLiterals(out, in, lit, i);
                final int m = Math.min(best, 10);
                out.write((m - 3) << 3 | 7);
                out.write(dist & 0xff);
                out.write(dist >>> 8);
                for (int rem = best - m; rem > 0;) {
                    final int k = Math.min(rem, 271);
                    if (k >= 16) {
                        out.write(0xF0);
                        out.write(k - 16);
                    } else {
                        out.write(0xF0 | k);
                    }
                    rem -= k;
                }
                i += best;
                lit = i;
            } else {
                i++;
            }
        }
        lzvnLiterals(out, in, lit, i);
        out.write(new byte[] {6, 0, 0, 0, 0, 0, 0, 0}, 0, 8);
        return out.toByteArray();
    }

    private static void lzvnLiterals(final ByteArrayOutputStream out, final byte[] in, int from, final int to) {
        while (from < to) {
            final int k = Math.min(271, to - from);
            if (k >= 16) {
                out.write(0xE0);
                out.write(k - 16);
            } else {
                out.write(0xE0 | k);
            }
            out.write(in, from, k);
            from += k;
        }
    }

    /** Adler-32 (big-endian) closing a zlib stream. */
    private static byte[] adler(final byte[] d) {
        final java.util.zip.Adler32 a = new java.util.zip.Adler32();
        a.update(d);
        final byte[] b = new byte[4];
        putBe32(b, 0, (int) a.getValue());
        return b;
    }

    /** Minimal encrypted disk image header ("encrcdsa", version 2): reported as not supported. */
    private static byte[] dmgEncryptedHeader() {
        final byte[] b = new byte[4096];
        System.arraycopy(ascii("encrcdsa"), 0, b, 0, 8);
        putBe32(b, 8, 2);
        putBe32(b, 12, 16);
        putBe32(b, 16, 0x80000001);
        putBe32(b, 32, 128);
        putBe32(b, 52, 4096);
        for (int i = 128; i < b.length; i++) b[i] = (byte) (i * 151 + 7);
        return b;
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Raw deflate (no zlib header), as zlib.compressobj(level, DEFLATED, -15). */
    private static byte[] deflate(final byte[] data, final int level) {
        final Deflater d = new Deflater(level, true);
        try {
            d.setInput(data);
            d.finish();
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            final byte[] buf = new byte[8192];
            while (!d.finished()) {
                final int n = d.deflate(buf);
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } finally {
            d.end();
        }
    }

    /** Relative paths ("/" separator, "" for the root) of every folder of a tree. */
    private static void listDirs(final File dir, final String rel, final List<String> out) throws IOException {
        out.add(rel);
        for (final String n : sortedNames(dir, true)) listDirs(new File(dir, n), rel.isEmpty() ? n : rel + "/" + n, out);
    }

    /** Relative paths ("/" separator) of every file of a tree, unsorted. */
    private static void listFiles(final File dir, final String rel, final List<String> out) throws IOException {
        for (final String n : sortedNames(dir, false)) out.add(rel.isEmpty() ? n : rel + "/" + n);
        for (final String n : sortedNames(dir, true)) listFiles(new File(dir, n), rel.isEmpty() ? n : rel + "/" + n, out);
    }

    /** Files of a top-down walk with sorted folders and files (os.walk with dirs.sort()). */
    private static void walkTopDown(final File dir, final String rel, final List<String> out) throws IOException {
        listFilesOnly(dir, rel, out);
        for (final String n : sortedNames(dir, true)) walkTopDown(new File(dir, n), rel.isEmpty() ? n : rel + "/" + n, out);
    }

    private static void listFilesOnly(final File dir, final String rel, final List<String> out) throws IOException {
        for (final String n : sortedNames(dir, false)) out.add(rel.isEmpty() ? n : rel + "/" + n);
    }

    /** Sorted names of the sub-folders (dirs true) or of the files (dirs false) of a folder. */
    private static List<String> sortedNames(final File dir, final boolean dirs) throws IOException {
        final String[] names = dir.list();
        if (names == null) throw new IOException("cannot list " + dir);
        final List<String> list = new ArrayList<String>();
        for (final String n : names) {
            if (new File(dir, n).isDirectory() == dirs) list.add(n);
        }
        Collections.sort(list);
        return list;
    }

    private static byte[] read(final File f) throws IOException {
        return Files.readAllBytes(f.toPath());
    }

    private static void write(final File f, final byte[] data) throws IOException {
        final File parent = f.getAbsoluteFile().getParentFile();
        if (parent != null) mkdirs(parent);
        Files.write(f.toPath(), data);
    }

    private static void mkdirs(final File d) throws IOException {
        if (!d.isDirectory() && !d.mkdirs()) throw new IOException("cannot create folder " + d);
    }

    private static byte[] ascii(final String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] cat(final byte[]... parts) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (final byte[] p : parts) out.write(p, 0, p.length);
        return out.toByteArray();
    }

    private static String hex(final byte[] b) {
        final StringBuilder sb = new StringBuilder();
        for (final byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    private static int crc32(final byte[] b, final int off, final int len) {
        final CRC32 c = new CRC32();
        c.update(b, off, len);
        return (int) c.getValue();
    }

    private static int le16(final byte[] b, final int off) {
        return (b[off] & 0xFF) | (b[off + 1] & 0xFF) << 8;
    }

    private static long le32(final byte[] b, final int off) {
        return (le16(b, off) | (long) le16(b, off + 2) << 16) & 0xFFFFFFFFL;
    }

    private static long le64(final byte[] b, final int off) {
        return le32(b, off) | le32(b, off + 4) << 32;
    }

    private static void putLe32(final byte[] b, final int off, final int v) {
        for (int i = 0; i < 4; i++) b[off + i] = (byte) (v >>> (8 * i));
    }

    private static void putLe64(final byte[] b, final int off, final long v) {
        for (int i = 0; i < 8; i++) b[off + i] = (byte) (v >>> (8 * i));
    }

    private static int be16(final byte[] b, final int off) {
        return (b[off] & 0xFF) << 8 | (b[off + 1] & 0xFF);
    }

    private static long be32(final byte[] b, final int off) {
        return ((long) be16(b, off) << 16 | be16(b, off + 2)) & 0xFFFFFFFFL;
    }

    private static void putBe16(final byte[] b, final int off, final int v) {
        b[off] = (byte) (v >>> 8);
        b[off + 1] = (byte) v;
    }

    private static void putBe32(final byte[] b, final int off, final int v) {
        for (int i = 0; i < 4; i++) b[off + i] = (byte) (v >>> (24 - 8 * i));
    }

    private static void writeBe32(final ByteArrayOutputStream out, final int v) {
        for (int i = 0; i < 4; i++) out.write(v >>> (24 - 8 * i) & 0xFF);
    }

    private static void writeBe64(final ByteArrayOutputStream out, final long v) {
        writeBe32(out, (int) (v >>> 32));
        writeBe32(out, (int) v);
    }

    private static void writeLe16(final ByteArrayOutputStream out, final int v) {
        out.write(v & 0xFF);
        out.write((v >>> 8) & 0xFF);
    }

    private static void writeLe32(final ByteArrayOutputStream out, final int v) {
        writeLe16(out, v & 0xFFFF);
        writeLe16(out, (v >>> 16) & 0xFFFF);
    }
}
