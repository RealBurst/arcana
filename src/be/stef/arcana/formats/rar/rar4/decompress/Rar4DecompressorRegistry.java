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

import java.util.ArrayList;
import java.util.List;
import be.stef.arcana.exceptions.RarUnsupportedMethodException;

/**
 * Registry of RAR4 decompressors.
 * Decompressors are evaluated in registration order, from the most specific
 * to the most generic.
 *
 * @author Stef
 * @since 1.0
 */
public class Rar4DecompressorRegistry {

    private final List<Rar4Decompressor> decompressors = new ArrayList<>();

    public Rar4DecompressorRegistry() {
        register(new StoreDecompressor());
        register(new Lz77Decompressor());
        // PPMd (method 0x35 "Best") is handled by Lz77Decompressor: RAR3 switches between LZ and PPMd blocks inside a file
    }

    /**
     * Registers a decompressor in the registry.
     *
     * @param decompressor the decompressor to add
     */
    public void register(Rar4Decompressor decompressor) {
        decompressors.add(decompressor);
    }

    /**
     * Resolves the appropriate decompressor for a given method and version.
     *
     * @param method  compression method (0x30-0x35)
     * @param version compression version (20, 26, 29...)
     * @return the matching decompressor
     * @throws RarUnsupportedMethodException if no decompressor handles this combination
     */
    public Rar4Decompressor resolve(int method, int version) throws RarUnsupportedMethodException {
        for (Rar4Decompressor d : decompressors) {
            if (d.canHandle(method, version)) return d;
        }
        throw new RarUnsupportedMethodException(method, version);
    }
}
