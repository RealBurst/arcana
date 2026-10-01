// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: The XZ for Java authors and contributors
// SPDX-FileContributor: Lasse Collin <lasse.collin@tukaani.org>

/* Ported from org.tukaani.xz.index (XZ for Java). Original licence: 0BSD. Changes: package only. */
package be.stef.arcana.formats.xz.index;

import be.stef.arcana.formats.xz.XZIOException;
import be.stef.arcana.formats.xz.common.Util;

abstract class IndexBase {
    private final XZIOException invalidIndexException;
    long blocksSum = 0;
    long uncompressedSum = 0;
    long indexListSize = 0;
    long recordCount = 0;

    IndexBase(XZIOException invalidIndexException) {
        this.invalidIndexException = invalidIndexException;
    }

    private long getUnpaddedIndexSize() {
        // Index Indicator + Number of Records + List of Records + CRC32
        return 1 + Util.getVLISize(recordCount) + indexListSize + 4;
    }

    public long getIndexSize() {
        return (getUnpaddedIndexSize() + 3) & ~3;
    }

    public long getStreamSize() {
        return Util.STREAM_HEADER_SIZE + blocksSum + getIndexSize()
                + Util.STREAM_HEADER_SIZE;
    }

    int getIndexPaddingSize() {
        return (int)((4 - getUnpaddedIndexSize()) & 3);
    }

    void add(long unpaddedSize, long uncompressedSize) throws XZIOException {
        blocksSum += (unpaddedSize + 3) & ~3;
        uncompressedSum += uncompressedSize;
        indexListSize += Util.getVLISize(unpaddedSize)
                         + Util.getVLISize(uncompressedSize);
        ++recordCount;

        if (blocksSum < 0 || uncompressedSum < 0
                || getIndexSize() > Util.BACKWARD_SIZE_MAX
                || getStreamSize() < 0)
            throw invalidIndexException;
    }
}
