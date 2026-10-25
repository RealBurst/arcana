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
package be.stef.arcana.formats.zstd;

/**
 * The literals and sequences found in one block by a match finder: each
 * sequence is a number of literals, then a match (offset value, length).
 * The offset value is the one of RFC 8878 section 3.1.1.5: 1 to 3 for the
 * repeated offsets, offset + 3 for a new offset.
 *
 * @author Stef
 * @since 1.2.0
 */
final class ZstdSequenceStore {

    final byte[] literals = new byte[Constants.MAX_BLOCK_SIZE];
    int literalCount;

    final int[] literalLengths = new int[Constants.MAX_BLOCK_SIZE / 3 + 1];
    final int[] offsetValues = new int[Constants.MAX_BLOCK_SIZE / 3 + 1];
    final int[] matchLengths = new int[Constants.MAX_BLOCK_SIZE / 3 + 1];
    int count;

    void reset() {
        literalCount = 0;
        count = 0;
    }

    /** A sequence: {@code litLength} literals from {@code src[litStart]}, then a match. */
    void add(final byte[] src, final int litStart, final int litLength, final int offsetValue, final int matchLength) {
        System.arraycopy(src, litStart, literals, literalCount, litLength);
        literalCount += litLength;
        literalLengths[count] = litLength;
        offsetValues[count] = offsetValue;
        matchLengths[count] = matchLength;
        count++;
    }

    /** The literals after the last match. */
    void addLastLiterals(final byte[] src, final int start, final int length) {
        System.arraycopy(src, start, literals, literalCount, length);
        literalCount += length;
    }
}
