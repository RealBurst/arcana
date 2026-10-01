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
package be.stef.arcana.formats.iso;

/**
 * Constants for the ISO 9660 file system format, including Joliet and
 * Rock Ridge extensions.
 *
 * <p>An ISO image is a sequence of 2048-byte logical sectors. The first
 * 16 sectors form the System Area (usually zero-filled or boot code).
 * Volume descriptors start at sector 16.</p>
 *
 * @author Stef
 * @since 1.1
 */
final class IsoConstants {

    private IsoConstants() {}

    /** Size of one logical sector in bytes. */
    static final int SECTOR_SIZE = 2048;

    /** First sector containing volume descriptors. */
    static final int FIRST_VOLUME_DESCRIPTOR_SECTOR = 16;

    // ---- Volume descriptor types (byte 0 of each descriptor) ----
    static final int VD_BOOT_RECORD          = 0;
    static final int VD_PRIMARY              = 1;
    static final int VD_SUPPLEMENTARY        = 2; // Joliet uses this
    static final int VD_PARTITION            = 3;
    static final int VD_SET_TERMINATOR       = 255;

    /** Standard identifier that must appear at offset 1 of every volume descriptor: "CD001". */
    static final byte[] STANDARD_ID = {'C', 'D', '0', '0', '1'};

    // ---- Directory record flags (byte at offset 25 of a directory record) ----
    static final int FILE_FLAG_HIDDEN       = 0x01;
    static final int FILE_FLAG_DIRECTORY    = 0x02;
    static final int FILE_FLAG_ASSOCIATED   = 0x04;
    static final int FILE_FLAG_RECORD       = 0x08;
    static final int FILE_FLAG_PROTECTION   = 0x10;
    static final int FILE_FLAG_MULTI_EXTENT = 0x80;

    // ---- Joliet escape sequences (in the supplementary VD, offset 88) ----
    // These identify UCS-2 (UTF-16BE) level 1, 2, 3.
    static final byte[] JOLIET_ESCAPE_LEVEL1 = {0x25, 0x2F, 0x40}; // "%/@"
    static final byte[] JOLIET_ESCAPE_LEVEL2 = {0x25, 0x2F, 0x43}; // "%/C"
    static final byte[] JOLIET_ESCAPE_LEVEL3 = {0x25, 0x2F, 0x45}; // "%/E"

    // ---- Rock Ridge / SUSP ----
    /** SUSP signature indicating the presence of System Use entries: "SP". */
    static final byte[] SUSP_SP = {'S', 'P'};
    /** Rock Ridge "RR" flag entry (optional presence indicator). */
    static final byte[] RR_RR   = {'R', 'R'};
    /** Rock Ridge alternate name entry: "NM". */
    static final byte[] RR_NM   = {'N', 'M'};
    /** Rock Ridge POSIX attributes entry: "PX". */
    static final byte[] RR_PX   = {'P', 'X'};
    /** Rock Ridge symbolic link entry: "SL". */
    static final byte[] RR_SL   = {'S', 'L'};
    /** SUSP continuation area entry: "CE". */
    static final byte[] SUSP_CE = {'C', 'E'};
    /** SUSP terminator entry: "ST". */
    static final byte[] SUSP_ST = {'S', 'T'};

    /** NM flag bit: name continues in the next NM entry. */
    static final int NM_FLAG_CONTINUE = 0x01;
    /** NM flag bit: refers to "." (current directory). */
    static final int NM_FLAG_CURRENT  = 0x02;
    /** NM flag bit: refers to ".." (parent directory). */
    static final int NM_FLAG_PARENT   = 0x04;
}
