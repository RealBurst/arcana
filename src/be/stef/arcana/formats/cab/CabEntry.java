/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.cab;

/**
 * Metadata for a single file entry in a Microsoft Cabinet ({@code .cab}) archive.
 *
 * @author Stef
 * @since 1.3
 */
public final class CabEntry {

    private final long   size;
    private final long   folderOffset;
    private final int    folderIndex;
    private final long   lastModified;
    private final String name;
    private final int    attributes;

    static final class Builder {
        long   size         = 0;
        long   folderOffset = 0;
        int    folderIndex  = 0;
        long   lastModified = 0;
        String name         = "";
        int    attributes   = 0x20;
        CabEntry build() { return new CabEntry(this); }
    }

    private CabEntry(Builder b) {
        this.size         = b.size;
        this.folderOffset = b.folderOffset;
        this.folderIndex  = b.folderIndex;
        this.lastModified = b.lastModified;
        this.name         = b.name.replace('\\', '/');
        this.attributes   = b.attributes;
    }

    public long   getSize()         { return size; }
    public long   getFolderOffset() { return folderOffset; }
    public int    getFolderIndex()  { return folderIndex; }
    public long   getLastModified() { return lastModified; }
    public String getName()         { return name; }
    public int    getAttributes()   { return attributes; }
    public boolean isDirectory()    { return (attributes & 0x10) != 0; }

    @Override
    public String toString() { return "CabEntry[" + name + " size=" + size + "]"; }
}
