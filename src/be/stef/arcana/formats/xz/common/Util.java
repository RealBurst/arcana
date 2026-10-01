// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: The XZ for Java authors and contributors
// SPDX-FileContributor: Lasse Collin <lasse.collin@tukaani.org>

/* Ported from org.tukaani.xz.common (XZ for Java). Original licence: 0BSD. Changes: package only. */
package be.stef.arcana.formats.xz.common;

public class Util {
    public static final int STREAM_HEADER_SIZE = 12;
    public static final long BACKWARD_SIZE_MAX = 1L << 34;
    public static final int BLOCK_HEADER_SIZE_MAX = 1024;
    public static final long VLI_MAX = Long.MAX_VALUE;
    public static final int VLI_SIZE_MAX = 9;

    public static int getVLISize(long num) {
        int size = 0;
        do {
            ++size;
            num >>= 7;
        } while (num != 0);

        return size;
    }
}
