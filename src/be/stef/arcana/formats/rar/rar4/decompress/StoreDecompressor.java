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
import be.stef.arcana.formats.rar.rar4.Rar4Constants;
import be.stef.arcana.formats.rar.rar4.blocks.Rar4FileBlock;

/**
 * RAR4 decompressor for the Store method (0x30) - no compression.
 *
 * @author Stef
 * @since 1.0
 */
public class StoreDecompressor implements Rar4Decompressor {

    private static final int BUFFER_SIZE = 8192;

    @Override
    public boolean canHandle(int compressionMethod, int compressionVersion) {
        return compressionMethod == Rar4Constants.COMPRESS_METHOD_STORE;
    }

    @Override
    public void decompress(InputStream input, OutputStream output, Rar4FileBlock file) throws IOException {
        byte[] buf = new byte[BUFFER_SIZE];
        long remain = file.getUnpackedSize();

        while (remain > 0) {
            int toRead    = (int) Math.min(buf.length, remain);
            int bytesRead = input.read(buf, 0, toRead);
            if (bytesRead == -1) break;
            output.write(buf, 0, bytesRead);
            remain -= bytesRead;
        }
    }

    @Override
    public void resetState(boolean isSolid) {
        // Store has no state to manage
    }
}
