/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/* Ported from SevenZEntry. Apache License 2.0. ASF copyright. Ported by Stef 2025. */
package be.stef.arcana.formats.sevenz;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Objects;


/**
 * An entry in a 7z archive.
 *
 * @NotThreadSafe
 * @since 1.6
 */
public class SevenZEntry {

    static final SevenZEntry[] EMPTY_SEVEN_Z_ARCHIVE_ENTRY_ARRAY = {};

    /**
     * Converts Java time to NTFS time.
     *
     * @param date the Java time
     * @return the NTFS time
     * @deprecated Use {@link FileTimes#toNtfsTime(Date)} instead.
     * @see FileTimes#toNtfsTime(Date)
     */
    @Deprecated
    public static long javaTimeToNtfsTime(final Date date) {
        return epochSecondsToNtfsTime(date.getTime() / 1000L);
    }

    /**
     * Converts NTFS time (100 nanosecond units since 1 January 1601) to Java time.
     *
     * @param ntfsTime the NTFS time in 100 nanosecond units
     * @return the Java time
     * @deprecated Use {@link FileTimes#ntfsTimeToDate(long)} instead.
     * @see FileTimes#ntfsTimeToDate(long)
     */
    @Deprecated
    public static Date ntfsTimeToJavaTime(final long ntfsTime) {
        return new java.util.Date(ntfsTimeToEpochSeconds(ntfsTime) * 1000L);
    }

    private String name;
    private boolean hasStream;
    private boolean isDirectory;
    private boolean isAntiItem;
    private boolean hasCreationDate;
    private boolean hasLastModifiedDate;
    private boolean hasAccessDate;
    private long creationDate = -1L;
    private long lastModifiedDate = -1L;
    private long accessDate = -1L;
    private boolean hasWindowsAttributes;
    private int windowsAttributes;
    private boolean hasCrc;
    private long crc;
    private long compressedCrc;
    private long size;
    private long compressedSize;
    private Iterable<? extends SevenZMethodConfiguration> contentMethods;

    /**
     * Constructs a new instance.
     */
    public SevenZEntry() {
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final SevenZEntry other = (SevenZEntry) obj;
        return Objects.equals(name, other.name) && hasStream == other.hasStream && isDirectory == other.isDirectory && isAntiItem == other.isAntiItem
                && hasCreationDate == other.hasCreationDate && hasLastModifiedDate == other.hasLastModifiedDate && hasAccessDate == other.hasAccessDate
                && Objects.equals(creationDate, other.creationDate) && Objects.equals(lastModifiedDate, other.lastModifiedDate)
                && Objects.equals(accessDate, other.accessDate) && hasWindowsAttributes == other.hasWindowsAttributes
                && windowsAttributes == other.windowsAttributes && hasCrc == other.hasCrc && crc == other.crc && compressedCrc == other.compressedCrc
                && size == other.size && compressedSize == other.compressedSize && equalSevenZMethods(contentMethods, other.contentMethods);
    }

    private boolean equalSevenZMethods(final Iterable<? extends SevenZMethodConfiguration> c1, final Iterable<? extends SevenZMethodConfiguration> c2) {
        if (c1 == null) {
            return c2 == null;
        }
        if (c2 == null) {
            return false;
        }
        final Iterator<? extends SevenZMethodConfiguration> i2 = c2.iterator();
        for (final SevenZMethodConfiguration element : c1) {
            if (!i2.hasNext() || !element.equals(i2.next())) {
                return false;
            }
        }
        return !i2.hasNext();
    }

    /**
     * Gets the access date. This is equivalent to {@link SevenZEntry#getAccessTime()}, but precision is truncated to milliseconds.
     *
     * @throws UnsupportedOperationException if the entry hasn't got an access date.
     * @return the access date
     * @see SevenZEntry#getAccessTime()
     */
    public Date getAccessDate() {
        return new java.util.Date(getAccessTime() * 1000L);
    }

    /**
     * Gets the access time.
     *
     * @throws UnsupportedOperationException if the entry hasn't got an access time.
     * @return the access time
     * @since 1.23
     */
    public long getAccessTime() {
        if (hasAccessDate) {
            return accessDate;
        }
        throw new UnsupportedOperationException("The entry doesn't have this timestamp");
    }

    /**
     * Gets the compressed CRC.
     *
     * @return the compressed CRC
     * @deprecated Use {@link #getCompressedCrcValue()} instead.
     */
    @Deprecated
    int getCompressedCrc() {
        return (int) compressedCrc;
    }

    /**
     * Gets the compressed CRC.
     *
     * @return the CRC
     * @since 1.7
     */
    long getCompressedCrcValue() {
        return compressedCrc;
    }

    /**
     * Gets this entry's compressed file size.
     *
     * @return This entry's compressed file size.
     */
    public long getCompressedSize() {
        return compressedSize;
    }

    /**
     * Gets the (compression) methods to use for entry's content - the default is LZMA2.
     *
     * <p>
     * Currently only {@link SevenZMethod#COPY}, {@link SevenZMethod#LZMA2}, {@link SevenZMethod#BZIP2} and {@link SevenZMethod#DEFLATE} are supported when
     * writing archives.
     * </p>
     *
     * <p>
     * The methods will be consulted in iteration order to create the final output.
     * </p>
     *
     * @return the methods to use for the content
     * @since 1.8
     */
    public Iterable<? extends SevenZMethodConfiguration> getContentMethods() {
        return contentMethods;
    }

    /**
     * Gets the CRC.
     *
     * @deprecated use getCrcValue instead.
     * @return the CRC
     */
    @Deprecated
    public int getCrc() {
        return (int) crc;
    }

    /**
     * Gets the CRC.
     *
     * @return the CRC
     * @since 1.7
     */
    public long getCrcValue() {
        return crc;
    }

    /**
     * Gets the creation date. This is equivalent to {@link SevenZEntry#getCreationTime()}, but precision is truncated to milliseconds.
     *
     * @throws UnsupportedOperationException if the entry hasn't got a creation date.
     * @return the new creation date
     * @see SevenZEntry#getCreationTime()
     */
    public Date getCreationDate() {
        return new java.util.Date(getCreationTime() * 1000L);
    }

    /**
     * Gets the creation time.
     *
     * @throws UnsupportedOperationException if the entry hasn't got a creation time.
     * @return the creation time
     * @since 1.23
     */
    public long getCreationTime() {
        if (hasCreationDate) {
            return creationDate;
        }
        throw new UnsupportedOperationException("The entry doesn't have this timestamp");
    }

    /**
     * Gets whether this entry has got an access date at all.
     *
     * @return whether this entry has got an access date at all.
     */
    public boolean getHasAccessDate() {
        return hasAccessDate;
    }

    /**
     * Gets whether this entry has got a CRC.
     *
     * <p>
     * In general entries without streams don't have a CRC either.
     * </p>
     *
     * @return whether this entry has got a CRC.
     */
    public boolean getHasCrc() {
        return hasCrc;
    }

    /**
     * Gets whether this entry has got a creation date at all.
     *
     * @return whether the entry has got a creation date
     */
    public boolean getHasCreationDate() {
        return hasCreationDate;
    }

    /**
     * Gets whether this entry has got a last modified date at all.
     *
     * @return whether this entry has got a last modified date at all
     */
    public boolean getHasLastModifiedDate() {
        return hasLastModifiedDate;
    }

    /**
     * Gets whether this entry has windows attributes.
     *
     * @return whether this entry has windows attributes.
     */
    public boolean getHasWindowsAttributes() {
        return hasWindowsAttributes;
    }

    /**
     * Gets the last modified date. This is equivalent to {@link SevenZEntry#getLastModifiedTime()}, but precision is truncated to milliseconds.
     *
     * @throws UnsupportedOperationException if the entry hasn't got a last modified date.
     * @return the last modified date
     * @see SevenZEntry#getLastModifiedTime()
     */
    public Date getLastModifiedDate() {
        return new java.util.Date(getLastModifiedTime() * 1000L);
    }

    /**
     * Gets the last modified time.
     *
     * @throws UnsupportedOperationException if the entry hasn't got a last modified time.
     * @return the last modified time
     * @since 1.23
     */
    public long getLastModifiedTime() {
        if (hasLastModifiedDate) {
            return lastModifiedDate;
        }
        throw new UnsupportedOperationException("The entry doesn't have this timestamp");
    }

    /**
     * Gets this entry's name.
     *
     * <p>
     * This method returns the raw name as it is stored inside of the archive.
     * </p>
     *
     * @return This entry's name.
     */
    public String getName() {
        return name;
    }

    /**
     * Gets this entry's file size.
     *
     * @return This entry's file size.
     */
    public long getSize() {
        return size;
    }

    /**
     * Gets the windows attributes.
     *
     * @return the windows attributes
     */
    public int getWindowsAttributes() {
        return windowsAttributes;
    }

    @Override
    public int hashCode() {
        final String n = getName();
        return n == null ? 0 : n.hashCode();
    }

    /**
     * Tests whether there is any content associated with this entry.
     * <p>
     * Returns true if a content is present.
     * </p>
     *
     * @return whether there is any content associated with this entry.
     */
    public boolean hasStream() {
        return hasStream;
    }

    /**
     * Tests whether this is an "anti-item" used in differential backups, meaning it should delete the same file from a previous backup.
     *
     * @return true if it is an anti-item, false otherwise
     */
    public boolean isAntiItem() {
        return isAntiItem;
    }

    /**
     * Tests whether or not this entry represents a directory.
     *
     * @return True if this entry is a directory.
     */
    public boolean isDirectory() {
        return isDirectory;
    }

    /**
     * Tests whether there is any content associated with this entry.
     * <p>
     * Returns true if a content is absent.
     * </p>
     *
     * @return whether there is any content associated with this entry.
     * @since 1.28.0
     */
    public boolean isEmptyStream() {
        return !hasStream;
    }

    /**
     * Sets the access date.
     *
     * @param accessDate the new access date
     * @see SevenZEntry#setAccessTime(FileTime)
     */
    public void setAccessDate(final Date accessDate) {
        setAccessTime(accessDate != null ? accessDate.getTime() / 1000L : -1L);
    }

    /**
     * Sets the access date using NTFS time (100 nanosecond units since 1 January 1601)
     *
     * @param ntfsAccessDate the access date
     */
    public void setAccessDate(final long ntfsAccessDate) {
        this.accessDate = ntfsTimeToEpochSeconds(ntfsAccessDate);
    }

    /**
     * Sets the access time.
     *
     * @param time the new access time
     * @since 1.23
     */

    /** Sets the access time as Unix epoch seconds. */
    public void setAccessTime(final long time) {
        hasAccessDate = (time != -1L);
        this.accessDate = time;
    }

    /** Sets the creation time as Unix epoch seconds. */
    public void setCreationTime(final long time) {
        hasCreationDate = (time != -1L);
        this.creationDate = time;
    }

    /** Sets the last-modified time as Unix epoch seconds. */
    public void setLastModifiedTime(final long time) {
        hasLastModifiedDate = (time != -1L);
        this.lastModifiedDate = time;
    }

    public void setAccessTime(final java.nio.file.attribute.FileTime time) {
        hasAccessDate = time != null;
        if (hasAccessDate) {
            this.accessDate = time.toInstant().getEpochSecond();
        }
    }

    /**
     * Sets whether this is an "anti-item" used in differential backups, meaning it should delete the same file from a previous backup.
     *
     * @param isAntiItem true if it is an anti-item, false otherwise
     */
    public void setAntiItem(final boolean isAntiItem) {
        this.isAntiItem = isAntiItem;
    }

    /**
     * Sets the compressed CRC.
     *
     * @deprecated use setCompressedCrcValue instead.
     * @param crc the CRC
     */
    @Deprecated
    void setCompressedCrc(final int crc) {
        this.compressedCrc = crc;
    }

    /**
     * Sets the compressed CRC.
     *
     * @param crc the CRC
     * @since 1.7
     */
    void setCompressedCrcValue(final long crc) {
        this.compressedCrc = crc;
    }

    /**
     * Sets this entry's compressed file size.
     *
     * @param size This entry's new compressed file size.
     */
    void setCompressedSize(final long size) {
        this.compressedSize = size;
    }

    /**
     * Sets the (compression) methods to use for entry's content - the default is LZMA2.
     *
     * <p>
     * Currently only {@link SevenZMethod#COPY}, {@link SevenZMethod#LZMA2}, {@link SevenZMethod#BZIP2} and {@link SevenZMethod#DEFLATE} are supported when
     * writing archives.
     * </p>
     *
     * <p>
     * The methods will be consulted in iteration order to create the final output.
     * </p>
     *
     * @param methods the methods to use for the content
     * @since 1.8
     */
    public void setContentMethods(final Iterable<? extends SevenZMethodConfiguration> methods) {
        if (methods != null) {
            final LinkedList<SevenZMethodConfiguration> l = new LinkedList<>();
            methods.forEach(l::addLast);
            contentMethods = Collections.unmodifiableList(l);
        } else {
            contentMethods = null;
        }
    }

    /**
     * Sets the (compression) methods to use for entry's content - the default is LZMA2.
     *
     * <p>
     * Currently only {@link SevenZMethod#COPY}, {@link SevenZMethod#LZMA2}, {@link SevenZMethod#BZIP2} and {@link SevenZMethod#DEFLATE} are supported when
     * writing archives.
     * </p>
     *
     * <p>
     * The methods will be consulted in iteration order to create the final output.
     * </p>
     *
     * @param methods the methods to use for the content
     * @since 1.22
     */
    public void setContentMethods(final SevenZMethodConfiguration... methods) {
        setContentMethods(Arrays.asList(methods));
    }

    /**
     * Sets the CRC.
     *
     * @deprecated use setCrcValue instead.
     * @param crc the CRC
     */
    @Deprecated
    public void setCrc(final int crc) {
        this.crc = crc;
    }

    /**
     * Sets the CRC.
     *
     * @param crc the CRC
     * @since 1.7
     */
    public void setCrcValue(final long crc) {
        this.crc = crc;
    }

    /**
     * Sets the creation date.
     *
     * @param creationDate the new creation date
     * @see SevenZEntry#setCreationTime(FileTime)
     */
    public void setCreationDate(final Date creationDate) {
        setCreationTime(creationDate != null ? creationDate.getTime() / 1000L : -1L);
    }

    /**
     * Sets the creation date using NTFS time (100 nanosecond units since 1 January 1601)
     *
     * @param ntfsCreationDate the creation date
     */
    public void setCreationDate(final long ntfsCreationDate) {
        this.creationDate = ntfsTimeToEpochSeconds(ntfsCreationDate);
    }

    /**
     * Sets the creation time.
     *
     * @param time the new creation time
     * @since 1.23
     */
    public void setCreationTime(final java.nio.file.attribute.FileTime time) {
        hasCreationDate = time != null;
        if (hasCreationDate) {
            this.creationDate = time.toInstant().getEpochSecond();
        }
    }

    /**
     * Sets whether or not this entry represents a directory.
     *
     * @param isDirectory True if this entry is a directory.
     */
    public void setDirectory(final boolean isDirectory) {
        this.isDirectory = isDirectory;
    }

    /**
     * Sets whether this entry has got an access date at all.
     *
     * @param hasAcessDate whether this entry has got an access date at all.
     */
    public void setHasAccessDate(final boolean hasAcessDate) {
        this.hasAccessDate = hasAcessDate;
    }

    /**
     * Sets whether this entry has got a CRC.
     *
     * @param hasCrc whether this entry has got a CRC.
     */
    public void setHasCrc(final boolean hasCrc) {
        this.hasCrc = hasCrc;
    }

    /**
     * Sets whether this entry has got a creation date at all.
     *
     * @param hasCreationDate whether the entry has got a creation date
     */
    public void setHasCreationDate(final boolean hasCreationDate) {
        this.hasCreationDate = hasCreationDate;
    }

    /**
     * Sets whether this entry has got a last modified date at all.
     *
     * @param hasLastModifiedDate whether this entry has got a last modified date at all
     */
    public void setHasLastModifiedDate(final boolean hasLastModifiedDate) {
        this.hasLastModifiedDate = hasLastModifiedDate;
    }

    /**
     * Sets whether there is any content associated with this entry.
     *
     * @param hasStream whether there is any content associated with this entry.
     */
    public void setHasStream(final boolean hasStream) {
        this.hasStream = hasStream;
    }

    /**
     * Sets whether this entry has windows attributes.
     *
     * @param hasWindowsAttributes whether this entry has windows attributes.
     */
    public void setHasWindowsAttributes(final boolean hasWindowsAttributes) {
        this.hasWindowsAttributes = hasWindowsAttributes;
    }

    /**
     * Sets the last modified date.
     *
     * @param lastModifiedDate the new last modified date
     * @see SevenZEntry#setLastModifiedTime(FileTime)
     */
    public void setLastModifiedDate(final Date lastModifiedDate) {
        setLastModifiedTime(lastModifiedDate != null ? lastModifiedDate.getTime() / 1000L : -1L);
    }

    /**
     * Sets the last modified date using NTFS time (100 nanosecond units since 1 January 1601)
     *
     * @param ntfsLastModifiedDate the last modified date
     */
    public void setLastModifiedDate(final long ntfsLastModifiedDate) {
        this.lastModifiedDate = ntfsTimeToEpochSeconds(ntfsLastModifiedDate);
    }

    /**
     * Sets the last modified time.
     *
     * @param time the new last modified time
     * @since 1.23
     */
    public void setLastModifiedTime(final java.nio.file.attribute.FileTime time) {
        hasLastModifiedDate = time != null;
        if (hasLastModifiedDate) {
            this.lastModifiedDate = time.toInstant().getEpochSecond();
        }
    }

    /**
     * Sets this entry's name.
     *
     * @param name This entry's new name.
     */
    public void setName(final String name) {
        this.name = name;
    }

    /**
     * Sets this entry's file size.
     *
     * @param size This entry's new file size.
     */
    public void setSize(final long size) {
        this.size = size;
    }

    /**
     * Sets the windows attributes.
     *
     * @param windowsAttributes the windows attributes
     */
    public void setWindowsAttributes(final int windowsAttributes) {
        this.windowsAttributes = windowsAttributes;
    }
    private static long ntfsTimeToEpochSeconds(final long ntfsTime) { return (ntfsTime - 116444736000000000L) / 10_000_000L; }
    private static long epochSecondsToNtfsTime(final long epochSeconds) { return epochSeconds * 10_000_000L + 116444736000000000L; }

}
