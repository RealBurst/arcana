// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: The XZ for Java authors and contributors
// SPDX-FileContributor: Lasse Collin <lasse.collin@tukaani.org>
// SPDX-FileContributor: Igor Pavlov <https://7-zip.org/>

/* Ported from org.tukaani.xz.lz (XZ for Java). Original licence: 0BSD. Changes: package only. */
package be.stef.arcana.formats.xz.lz;

/**
 * Provides a CRC32 table using the polynomial from IEEE 802.3.
 */
class CRC32Hash {
    private static final int CRC32_POLY = 0xEDB88320;

    static final int[] crcTable = new int[256];

    static {
        for (int i = 0; i < 256; ++i) {
            int r = i;

            for (int j = 0; j < 8; ++j) {
                if ((r & 1) != 0)
                    r = (r >>> 1) ^ CRC32_POLY;
                else
                    r >>>= 1;
            }

            crcTable[i] = r;
        }
    }
}
