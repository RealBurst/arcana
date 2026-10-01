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
package be.stef.arcana.formats.ppmd;

import java.io.IOException;

/**
 * Range decoder used by {@link Ppmd7#decodeSymbol(Ppmd7RangeDecoder)}.
 *
 * <p>PPMd var.H is paired with two different arithmetic coders: the 7-Zip one
 * ({@link Ppmd7Decoder}, 7z archives) and Dmitry Subbotin's carry-less coder
 * ({@link RarRangeDecoder}, RAR 3.x/4.x archives). The model is identical; only
 * these three primitives differ. All values are unsigned 32-bit held in longs.</p>
 *
 * @author Stef
 * @since 1.3
 */
public interface Ppmd7RangeDecoder {

    /** Scales the range by {@code total} and returns the current count in [0, total). */
    long getThreshold(long total);

    /** Consumes the interval [start, start + size) of the last threshold scale. */
    void decode(long start, long size) throws IOException;

    /** Decodes one binary decision whose probability of 0 is {@code size0 / 2^14}. */
    int decodeBit(int size0) throws IOException;
}
