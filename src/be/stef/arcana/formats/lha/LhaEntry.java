/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.lha;

/**
 * Metadata for a single entry in an LHA archive.
 *
 * <p>LHA archives support three header levels (0, 1 and 2) with varying
 * amounts of metadata.  This class captures the fields common to all levels
 * that are needed by {@link LhaReader} and Arcana's extractor.</p>
 */
public final class LhaEntry {

    /** Compression method identifier, e.g. {@code "-lh5-"} or {@code "-lh0-"}. */
    private final String compressionMethod;
    /** Full path name of the entry inside the archive (platform separators normalised to '/'). */
    private final String name;
    /** Uncompressed size in bytes; 0 for directory entries. */
    private final long   originalSize;
    /** Compressed size in bytes (data bytes only, not including the header). */
    private final long   compressedSize;
    /** Last-modified time as milliseconds since the Unix epoch (1970-01-01 00:00:00 UTC). */
    private final long   lastModified;
    /** CRC-16 checksum of the uncompressed data. */
    private final int    crc16;
    /** True if this entry represents a directory. */
    private final boolean directory;

    /** Internal builder used by {@link LhaReader}. */
    static final class Builder {
        String  compressionMethod = "-lh0-";
        String  name              = "";
        long    originalSize      = 0;
        long    compressedSize    = 0;
        long    lastModified      = 0;
        int     crc16             = 0;
        boolean directory         = false;

        LhaEntry build() {
            return new LhaEntry(this);
        }
    }

    private LhaEntry(final Builder b) {
        this.compressionMethod = b.compressionMethod;
        this.name              = b.name;
        this.originalSize      = b.originalSize;
        this.compressedSize    = b.compressedSize;
        this.lastModified      = b.lastModified;
        this.crc16             = b.crc16;
        this.directory         = b.directory;
    }

    /** Returns the compression method string, e.g. {@code "-lh5-"}. */
    public String getCompressionMethod() { return compressionMethod; }

    /** Returns the entry name (path within the archive, separators normalised to '/'). */
    public String getName()              { return name; }

    /** Returns the uncompressed size in bytes. */
    public long   getOriginalSize()      { return originalSize; }

    /** Returns the compressed data size in bytes (header not included). */
    public long   getCompressedSize()    { return compressedSize; }

    /**
     * Returns the last-modified timestamp as milliseconds since the Unix epoch.
     * May be 0 if not available (e.g. old level-0 headers with DOS timestamps
     * that cannot be converted precisely).
     */
    public long   getLastModified()      { return lastModified; }

    /** Returns the CRC-16 checksum of the uncompressed data. */
    public int    getCrc16()             { return crc16; }

    /** Returns {@code true} if this entry represents a directory. */
    public boolean isDirectory()         { return directory; }

    @Override
    public String toString() {
        return "LhaEntry[" + compressionMethod + " " + name + " orig=" + originalSize + " comp=" + compressedSize + "]";
    }
}
