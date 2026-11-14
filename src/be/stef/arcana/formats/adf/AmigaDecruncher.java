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
package be.stef.arcana.formats.adf;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import java.io.IOException;

/**
 * Unpacks Amiga programs compressed by a "cruncher": the packed data follows a
 * small 68000 routine that unpacks it in memory at a fixed address, then jumps
 * to it. The routine is recognized by its bytes and the unpacking is done in
 * Java, the 68000 code is never run.
 *
 * <p>Known routine: "LZ + RLE, absolute address" (0x168 bytes, data right
 * after it). The family name of this cruncher is not known; it was found in
 * game disks with their own track loader.</p>
 * <ul>
 *   <li>Data: destination end address (long), packed length (long), packed
 *       stream. The stream is read backwards from its end: bit counter, bit
 *       buffer, then one byte that replaces the last entry of the second
 *       offset table; bits are taken from bytes read backwards, highest bit
 *       first, literal bytes come from the same backward stream.</li>
 *   <li>Pass 1 (LZ77, output written backwards from the destination end):
 *       literal run (1 bit, then 1, 2+2 bits, 5+2, 8+3 or 9 bits), then, while
 *       packed bytes remain, a match: length 2 (first offset table) or 3 to 583
 *       (second table), offset = table base + table bits + 1 bits, copied
 *       backwards from the bytes already written.</li>
 *   <li>Pass 2 (RLE, backwards): the output of pass 1 starts with the final
 *       end address, the end address of the RLE data and a zero-run escape
 *       byte; the run escape byte is in the routine (offset 0x107). Escape
 *       value + count + byte writes count + 1 bytes, zero-run escape + count
 *       writes count + 1 zeros; escape + 1 ends. Then the routine jumps to the
 *       absolute address at offset 0x134.</li>
 * </ul>
 *
 * @author Stef
 * @since 1.2.0
 */
public final class AmigaDecruncher {

    /** Result of an unpacking. */
    public static final class Result {
        /** Unpacked bytes, as they are in memory from {@link #loadAddress}. */
        public final byte[] data;
        /** Memory address of the first unpacked byte. */
        public final long loadAddress;
        /** Address the routine jumps to once the data is unpacked. */
        public final long entry;
        /** Name of the cruncher. */
        public final String method;
        /** Offset of the routine in the bytes given to {@link #find}. */
        public final int offset;

        Result(final byte[] data, final long loadAddress, final long entry, final String method, final int offset) {
            this.data = data;
            this.loadAddress = loadAddress;
            this.entry = entry;
            this.method = method;
            this.offset = offset;
        }
    }

    /** Name given to the known routine. */
    public static final String LZ_RLE = "LZ+RLE cruncher (absolute address)";

    /** The routine, "??" for the bytes that change between packed files (screen flash instruction, escape bytes, jump address, patched table entry). */
    public static final String LZ_RLE_STUB = "41FA0166225820182648D1C01E201C2045FA013514A0613E6734613A66287001613654050C050005661C7001612A5A050C05000866107002611E50050C05000F6604700861125345132051CDFFFCB7C86D26600000A6424042854A07660A7E081C20????00DFF180E30EE395530751C8FFEA42404A854E7561DC672C780249FA00B84BFA00C4700261CE10345000E3053235500061C2DA412449D5C55344132251CCFFFC6000FF7049FA00964BFA00AA61A46604780360CE7001619C58050C0500066D3266087001618E5C0560287004618650050C05000967120C050008661670046100FF7406050028600A70086100FF68064500483805608C2449225A205A47FA0007169A74??76??42801020B002670EB0036704130060F210204201600A10200C000001670A1220130151C8FFFC60D84EF9????????020304040506070803030405060708??00000004000C001C002C004C006C00EC00000008001000200040008001000200";

    /** Length of the routine (the packed data follows it). */
    static final int STUB_SIZE = 0x168;

    /** Highest address of a 68000 (24-bit address bus). */
    private static final long MAX_ADDRESS = 0x1000000L;

    private static final int[] STUB = parse(LZ_RLE_STUB);

    private AmigaDecruncher() {}

    /**
     * Looks for a known unpacking routine in {@code b[off .. off + len)} (at
     * even offsets, the 68000 code is word-aligned) and unpacks its data.
     *
     * @return the unpacked data, or null if no known routine is found
     * @throws IOException if a routine is found but its data is not valid
     */
    public static Result find(final byte[] b, final int off, final int len) throws IOException {
        final int end = off + len;
        for (int p = off; p + STUB_SIZE + 8 <= end; p += 2) {
            if (!matches(b, p)) continue;
            return unpack(b, p, end, p - off);
        }
        return null;
    }

    private static boolean matches(final byte[] b, final int p) {
        for (int i = 0; i < STUB.length; i++) {
            if (STUB[i] >= 0 && (b[p + i] & 0xFF) != STUB[i]) return false;
        }
        return true;
    }

    private static int[] parse(final String hex) {
        final int[] r = new int[hex.length() / 2];
        for (int i = 0; i < r.length; i++) {
            final String h = hex.substring(2 * i, 2 * i + 2);
            r[i] = "??".equals(h) ? -1 : Integer.parseInt(h, 16);
        }
        return r;
    }

    /** Bit reader of pass 1: bytes taken backwards, highest bit first. */
    private static final class Bits {
        final byte[] b;
        final int start;
        int pos;
        int count;
        int buffer;

        Bits(final byte[] b, final int start, final int pos) {
            this.b = b;
            this.start = start;
            this.pos = pos;
        }

        int previousByte() throws IOException {
            if (pos <= start) throw new ArcanaCorruptedException("Packed Amiga data: unexpected end of the packed stream");
            pos--;
            return b[pos] & 0xFF;
        }

        int read(final int n) throws IOException {
            int v = 0;
            for (int i = 0; i < n; i++) {
                if (count == 0) {
                    count = 8;
                    buffer = previousByte();
                }
                v = (v << 1) | ((buffer >> 7) & 1);
                buffer = (buffer << 1) & 0xFF;
                count--;
            }
            return v;
        }
    }

    private static Result unpack(final byte[] b, final int p, final int end, final int stubOffset) throws IOException {
        final int[] bits1 = new int[8];
        final int[] bits2 = new int[8];
        final int[] base1 = new int[8];
        final int[] base2 = new int[8];
        for (int i = 0; i < 8; i++) {
            bits1[i] = b[p + 0x138 + i] & 0xFF;
            bits2[i] = b[p + 0x140 + i] & 0xFF;
            base1[i] = u16(b, p + 0x148 + 2 * i);
            base2[i] = u16(b, p + 0x158 + 2 * i);
        }
        final int runEscape = b[p + 0x107] & 0xFF;
        final long entry = u32(b, p + 0x134);
        final int data = p + STUB_SIZE;
        final long destEnd = u32(b, data);
        final long packed = u32(b, data + 4);
        final int start = data + 8;
        if (destEnd <= 0 || destEnd > MAX_ADDRESS) throw new ArcanaCorruptedException("Packed Amiga data: invalid destination address 0x" + Long.toHexString(destEnd));
        if (packed < 3 || start + packed > end) throw new ArcanaCorruptedException("Packed Amiga data: packed length beyond the end of the data");
        final Bits in = new Bits(b, start, (int) (start + packed));
        in.count = in.previousByte();
        in.buffer = in.previousByte();
        bits2[7] = in.previousByte();
        // pass 1: LZ77, written backwards from destEnd
        byte[] mem = new byte[(int) destEnd];
        int out = (int) destEnd;
        while (true) {
            int run = 0;
            if (in.read(1) != 0) {
                if (in.read(1) != 0) {
                    run = 1;
                } else {
                    run = in.read(2) + 2;
                    if (run == 5) {
                        run = in.read(2) + 5;
                        if (run == 8) {
                            run = in.read(3) + 8;
                            if (run == 15) {
                                run = in.read(9);
                                if (run == 0) run = 0x10000; // DBRA on 0 - 1: 65536 bytes
                            }
                        }
                    }
                }
            }
            for (int i = 0; i < run; i++) {
                if (out <= 0) throw new ArcanaCorruptedException("Packed Amiga data: output below address 0");
                out--;
                mem[out] = (byte) in.previousByte();
            }
            if (in.pos <= start) break;
            final int length;
            final int[] bits;
            final int[] base;
            if (in.read(1) != 0) {
                length = 2;
                bits = bits1;
                base = base1;
            } else {
                bits = bits2;
                base = base2;
                if (in.read(1) == 0) {
                    length = 3;
                } else {
                    int v = in.read(2) + 4;
                    if (v == 6) {
                        v = in.read(2) + 6;
                    } else if (v == 7) {
                        v = in.read(5) + 8;
                        if (v == 9) v = in.read(9) + 0x48;
                        else if (v == 8) v = in.read(5) + 0x28;
                    }
                    length = v;
                }
            }
            final int index = in.read(3);
            final int offset = in.read(bits[index] + 1) + base[index];
            int src = out + offset;
            if (src > mem.length || out - length < 0) throw new ArcanaCorruptedException("Packed Amiga data: invalid match");
            for (int i = 0; i < length; i++) {
                src--;
                out--;
                mem[out] = mem[src];
            }
        }
        // pass 2: RLE, its header at the start of the pass 1 output
        if (out + 9 > mem.length) throw new ArcanaCorruptedException("Packed Amiga data: no RLE header");
        final long finalEnd = u32(mem, out);
        final long rleEnd = u32(mem, out + 4);
        final int zeroEscape = mem[out + 8] & 0xFF;
        if (finalEnd <= 0 || finalEnd > MAX_ADDRESS || rleEnd > destEnd || rleEnd < out + 9) throw new ArcanaCorruptedException("Packed Amiga data: invalid RLE header");
        if (finalEnd > mem.length) {
            final byte[] larger = new byte[(int) finalEnd];
            System.arraycopy(mem, 0, larger, 0, mem.length);
            mem = larger;
        }
        final int rleStart = out + 9;
        int r = (int) rleEnd;
        int w = (int) finalEnd;
        while (true) {
            if (r <= rleStart) throw new ArcanaCorruptedException("Packed Amiga data: RLE data without end marker");
            r--;
            int c = mem[r] & 0xFF;
            int value;
            if (c == runEscape) {
                if (r <= rleStart) throw new ArcanaCorruptedException("Packed Amiga data: truncated RLE run");
                r--;
                c = mem[r] & 0xFF;
                if (c == 1) break;
                if (r <= rleStart) throw new ArcanaCorruptedException("Packed Amiga data: truncated RLE run");
                r--;
                value = mem[r];
            } else if (c == zeroEscape) {
                if (r <= rleStart) throw new ArcanaCorruptedException("Packed Amiga data: truncated RLE run");
                r--;
                c = mem[r] & 0xFF;
                value = 0;
            } else {
                if (w <= 0) throw new ArcanaCorruptedException("Packed Amiga data: output below address 0");
                w--;
                mem[w] = (byte) c;
                continue;
            }
            if (w - (c + 1) < 0) throw new ArcanaCorruptedException("Packed Amiga data: output below address 0");
            for (int i = 0; i <= c; i++) {
                w--;
                mem[w] = (byte) value;
            }
        }
        final byte[] result = new byte[(int) finalEnd - w];
        System.arraycopy(mem, w, result, 0, result.length);
        return new Result(result, w, entry, LZ_RLE, stubOffset);
    }

    private static int u16(final byte[] b, final int p) {
        return ((b[p] & 0xFF) << 8) | (b[p + 1] & 0xFF);
    }

    private static long u32(final byte[] b, final int p) {
        return ((b[p] & 0xFFL) << 24) | ((b[p + 1] & 0xFFL) << 16) | ((b[p + 2] & 0xFFL) << 8) | (b[p + 3] & 0xFFL);
    }
}
