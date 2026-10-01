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
package be.stef.arcana.formats.rar.rar4.decompress;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import be.stef.arcana.formats.rar.rar4.blocks.Rar4FileBlock;

/**
 * Common interface for all RAR4 decompressors.
 *
 * @author Stef
 * @since 1.0
 */
public interface Rar4Decompressor {

    /**
     * Indicates whether this decompressor handles the given method and version.
     *
     * @param compressionMethod  compression method (0x30-0x35)
     * @param compressionVersion compression version (20, 26, 29...)
     * @return true if this decompressor can process this combination
     */
    boolean canHandle(int compressionMethod, int compressionVersion);

    /**
     * Decompresses data from input to output.
     *
     * @param input  compressed data stream
     * @param output decompressed output stream
     * @param file   RAR4 file block (metadata)
     * @throws IOException on I/O error or corrupted data
     */
    void decompress(InputStream input, OutputStream output, Rar4FileBlock file) throws IOException;

    /**
     * Resets or preserves state between two files.
     * Called by the extractor before each file.
     *
     * @param isSolid true if the archive is solid (state must be preserved)
     */
    void resetState(boolean isSolid);
}
