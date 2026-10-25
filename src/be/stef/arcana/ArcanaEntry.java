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
package be.stef.arcana;

/**
 * Represents a single entry (file or directory) inside an archive.
 *
 * <p>An entry is a format-agnostic view of an archived item.  Each
 * {@link be.stef.arcana.extractor.ArchiveExtractor} implementation maps its
 * format-specific metadata onto this common structure so that callers never
 * need to deal with format internals.</p>
 *
 * <p>Fields that are not available for a given format are set to their
 * documented default value rather than {@code null} (e.g. unknown sizes
 * default to {@code -1}).</p>
 *
 * @author Stef
 * @since 1.0
 */
public class ArcanaEntry {

    /** Path of the entry as stored in the archive, using '/' as separator. Never null. */
    private final String name;

    /** Compressed size in bytes, or {@code -1} if unknown. */
    private final long compressedSize;

    /** Uncompressed size in bytes, or {@code -1} if unknown. */
    private final long uncompressedSize;

    /** Last-modification time as a Unix timestamp (seconds since epoch), or {@code -1} if unknown. */
    private final long lastModifiedTime;

    /** {@code true} if this entry represents a directory. */
    private final boolean directory;

    /** {@code true} if this entry is password-protected. */
    private final boolean encrypted;

    /** CRC-32 checksum of the uncompressed data, or {@code -1} if not available. */
    private final long crc32;

    /** The archive format from which this entry was read. */
    private final ArcanaFormat format;

    /** Compression method as named by the format ("Deflate", "LZMA2", "BCJ+LZMA"...), or {@code null} if unknown. */
    private final String method;

    /** Unix mode (file type and permission bits, e.g. 0100644), or {@code -1} if the archive stores none. */
    private final int mode;

    /** Target of a symbolic or hard link, or {@code null} for an ordinary entry. */
    private final String linkTarget;

    /** Comment stored with the entry, or {@code null}. */
    private final String comment;

    // -------------------------------------------------------------------------
    // Construction via Builder
    // -------------------------------------------------------------------------

    private ArcanaEntry(Builder b) {
        this.name             = b.name;
        this.compressedSize   = b.compressedSize;
        this.uncompressedSize = b.uncompressedSize;
        this.lastModifiedTime = b.lastModifiedTime;
        this.directory        = b.directory;
        this.encrypted        = b.encrypted;
        this.crc32            = b.crc32;
        this.format           = b.format;
        this.method           = b.method;
        this.mode             = b.mode;
        this.linkTarget       = b.linkTarget;
        this.comment          = b.comment;
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------

    /** @return path of the entry as stored in the archive, never null */
    public String getName() { return name; }

    /** @return compressed size in bytes, or {@code -1} if unknown */
    public long getCompressedSize() { return compressedSize; }

    /** @return uncompressed size in bytes, or {@code -1} if unknown */
    public long getUncompressedSize() { return uncompressedSize; }

    /** @return last-modification time as Unix timestamp (seconds), or {@code -1} if unknown */
    public long getLastModifiedTime() { return lastModifiedTime; }

    /** @return {@code true} if this entry is a directory */
    public boolean isDirectory() { return directory; }

    /** @return {@code true} if this entry is password-protected */
    public boolean isEncrypted() { return encrypted; }

    /** @return CRC-32 of the uncompressed data, or {@code -1} if not available */
    public long getCrc32() { return crc32; }

    /** @return the archive format from which this entry was read */
    public ArcanaFormat getFormat() { return format; }

    /** @return compression method as named by the format ("Deflate", "LZMA2"...), or {@code null} if unknown */
    public String getMethod() { return method; }

    /** @return Unix mode (file type and permission bits, e.g. 0100644), or {@code -1} if not stored */
    public int getMode() { return mode; }

    /** @return target of a symbolic or hard link, or {@code null} for an ordinary entry */
    public String getLinkTarget() { return linkTarget; }

    /** @return {@code true} if this entry is a symbolic or hard link (see {@link #getLinkTarget()}) */
    public boolean isLink() { return linkTarget != null; }

    /** @return comment stored with the entry, or {@code null} */
    public String getComment() { return comment; }

    @Override
    public String toString() {
        return "ArcanaEntry{name='" + name + "', size=" + uncompressedSize + ", dir=" + directory + ", format=" + format + "}";
    }

    // -------------------------------------------------------------------------
    // Builder
    // -------------------------------------------------------------------------

    /**
     * Fluent builder for {@link ArcanaEntry}.
     *
     * <p>Extractors use this builder to construct entries without exposing a
     * constructor with many positional parameters.</p>
     */
    public static final class Builder {

        private String name;
        private long compressedSize   = -1L;
        private long uncompressedSize = -1L;
        private long lastModifiedTime = -1L;
        private boolean directory     = false;
        private boolean encrypted     = false;
        private long crc32            = -1L;
        private ArcanaFormat format  = ArcanaFormat.UNKNOWN;
        private String method         = null;
        private int mode              = -1;
        private String linkTarget     = null;
        private String comment        = null;

        /**
         * Creates a builder with the mandatory entry name.
         *
         * @param name path of the entry as stored in the archive, must not be null
         */
        public Builder(String name) {
            if (name == null) throw new IllegalArgumentException("name must not be null");
            this.name = name;
        }

        public Builder compressedSize(long size)   { this.compressedSize   = size;  return this; }
        public Builder uncompressedSize(long size) { this.uncompressedSize = size;  return this; }
        public Builder lastModifiedTime(long time) { this.lastModifiedTime = time;  return this; }
        public Builder directory(boolean dir)      { this.directory        = dir;   return this; }
        public Builder encrypted(boolean enc)      { this.encrypted        = enc;   return this; }
        public Builder crc32(long crc)             { this.crc32            = crc;   return this; }
        public Builder format(ArcanaFormat fmt)   { this.format           = fmt;   return this; }
        public Builder method(String m)            { this.method           = m;     return this; }
        public Builder mode(int m)                 { this.mode             = m;     return this; }
        public Builder linkTarget(String target)   { this.linkTarget       = target; return this; }
        public Builder comment(String c)           { this.comment          = c;     return this; }

        /** @return the built {@link ArcanaEntry} */
        public ArcanaEntry build() { return new ArcanaEntry(this); }
    }
}
