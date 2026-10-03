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
package be.stef.arcana.formats.arj;

/**
 * A file or directory of an ARJ archive.
 *
 * @author Stef
 * @since 1.0.4
 */
public final class ArjEntry {

    /** Path, '/' separated. */
    public final String name;
    public final boolean directory;
    /** Compression method (0 stored, 1 to 4). */
    public final int method;
    final int flags;
    /** Original size. */
    public final long size;
    /** Compressed size. */
    public final long packedSize;
    final int crc;
    /** Modification time in milliseconds, 0 if unknown. */
    public final long lastModified;

    ArjEntry(final String name, final boolean directory, final int method, final int flags, final long size, final long packedSize, final int crc, final long lastModified) {
        this.name = name;
        this.directory = directory;
        this.method = method;
        this.flags = flags;
        this.size = size;
        this.packedSize = packedSize;
        this.crc = crc;
        this.lastModified = lastModified;
    }

    /** True for an encrypted ("garbled") entry. */
    public boolean isEncrypted() {
        return (flags & 0x01) != 0;
    }
}
