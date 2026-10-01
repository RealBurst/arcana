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
package be.stef.arcana.formats.cpio;

/**
 * Metadata for a single entry in a CPIO archive.
 *
 * @author Stef
 * @since 1.1
 */
public final class CpioEntry {

    private final String name;
    private final int mode;
    private final long size;
    private final long modificationTime;
    private final long checksum;
    private final boolean newc;

    CpioEntry(final String name, final int mode, final long size, final long modificationTime, final long checksum, final boolean newc) {
        this.name = name;
        this.mode = mode;
        this.size = size;
        this.modificationTime = modificationTime;
        this.checksum = checksum;
        this.newc = newc;
    }

    /** Returns the entry name (relative path). */
    public String getName() { return name; }

    /** Returns the POSIX mode bits (permissions + file type). */
    public int getMode() { return mode; }

    /** Returns the data size in bytes. */
    public long getSize() { return size; }

    /** Returns the last modification time as Unix epoch seconds. */
    public long getModificationTime() { return modificationTime; }

    /** Returns the CRC32 checksum (only meaningful for {@code 070702} archives). */
    public long getChecksum() { return checksum; }

    /** Returns {@code true} if this entry came from a NEWC (SVR4) archive. */
    public boolean isNewc() { return newc; }

    /** Returns {@code true} if this entry represents a directory. */
    public boolean isDirectory() { return (mode & 0170000) == 0040000; }

    /** Returns {@code true} if this entry represents a regular file. */
    public boolean isRegularFile() { return (mode & 0170000) == 0100000; }

    /** Returns {@code true} if this entry represents a symbolic link. */
    public boolean isSymbolicLink() { return (mode & 0170000) == 0120000; }

    @Override
    public String toString() { return "CpioEntry[" + name + ", size=" + size + ", mode=" + Integer.toOctalString(mode) + "]"; }
}
