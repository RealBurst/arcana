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
/* Inspired by org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
 * (Apache Commons Compress 1.28.0). Apache License 2.0. Original copyright: ASF.
 * Rewritten to match the JUnpack port style, using TarEntry.writeEntryHeader()
 * and TarConstants from the existing port. No external dependency. */
package be.stef.arcana.formats.tar;

import java.io.File;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Writes TAR archives to an {@link OutputStream}.
 *
 * <p>Usage pattern:</p>
 * <pre>
 *   try (TarOutputStream tos = new TarOutputStream(new FileOutputStream("out.tar"))) {
 *       tos.putNextEntry(new TarEntry(someFile, "relativeName.txt"));
 *       // write file content to tos
 *       tos.closeEntry();
 *   }
 * </pre>
 *
 * <p>Entries whose names exceed 100 bytes are handled via GNU LongName extension
 * (identical to what GNU tar and Commons Compress produce).</p>
 *
 * <p>Call {@link #finish()} before closing if you do not want to close the
 * underlying stream (e.g. when chaining with a GZIPOutputStream).</p>
 *
 * @author Stef
 * @since 1.0
 */
public class TarOutputStream extends FilterOutputStream implements TarConstants {

    /** Size of a single TAR header block (512 bytes). */
    private static final int RECORD_SIZE = DEFAULT_RCDSIZE;

    /** Two consecutive zero-filled 512-byte blocks that mark the end of a TAR archive. */
    private static final byte[] EOF_BLOCK = new byte[RECORD_SIZE * 2];

    /** Reusable header buffer. */
    private final byte[] header = new byte[RECORD_SIZE];

    /** Number of bytes written for the current entry (used to compute padding). */
    private long currentEntrySize;

    /** Number of bytes actually sent for the current entry. */
    private long bytesWrittenForCurrentEntry;

    private boolean finished = false;

    // =========================================================================
    // Constructors
    // =========================================================================

    /**
     * Creates a TarOutputStream wrapping the given stream.
     *
     * @param out underlying output stream
     */
    public TarOutputStream(OutputStream out) {
        super(out);
    }

    // =========================================================================
    // Entry lifecycle
    // =========================================================================

    /**
     * Starts a new TAR entry.
     *
     * <p>If the entry name is longer than 100 bytes, a GNU LongName extension
     * entry is written first so that the archive is readable by all standard tools.</p>
     *
     * @param entry the entry to write
     * @throws IOException on I/O error
     */
    public void putNextEntry(TarEntry entry) throws IOException {
        String name = entry.getName();
        if (name.length() > NAMELEN) {
            writeLongNameEntry(name);
            // Truncate the name in the main header to 100 chars - readers use the LongName
            entry = cloneWithTruncatedName(entry, name.substring(0, NAMELEN));
        }
        java.util.Arrays.fill(header, (byte) 0);
        entry.writeEntryHeader(header);
        out.write(header);
        currentEntrySize = entry.getSize();
        bytesWrittenForCurrentEntry = 0L;
    }

    /**
     * Closes the current entry, padding the data to the next 512-byte boundary.
     *
     * @throws IOException on I/O error or if the number of bytes written does not
     *                     match the size declared in {@link #putNextEntry}
     */
    public void closeEntry() throws IOException {
        if (bytesWrittenForCurrentEntry != currentEntrySize) {
            throw new IOException("Entry data size mismatch: declared " + currentEntrySize + " bytes, wrote " + bytesWrittenForCurrentEntry);
        }
        int remainder = (int) (currentEntrySize % RECORD_SIZE);
        if (remainder != 0) {
            int padding = RECORD_SIZE - remainder;
            out.write(new byte[padding]);
        }
        currentEntrySize = 0L;
        bytesWrittenForCurrentEntry = 0L;
    }

    // =========================================================================
    // Write methods - delegate to underlying stream, track byte count
    // =========================================================================

    @Override
    public void write(int b) throws IOException {
        out.write(b);
        bytesWrittenForCurrentEntry++;
    }

    @Override
    public void write(byte[] b) throws IOException {
        out.write(b, 0, b.length);
        bytesWrittenForCurrentEntry += b.length;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        out.write(b, off, len);
        bytesWrittenForCurrentEntry += len;
    }

    // =========================================================================
    // Finish / close
    // =========================================================================

    /**
     * Writes the two zero-filled end-of-archive records.
     *
     * <p>Call this instead of {@link #close()} when the underlying stream must
     * remain open (e.g. when this TarOutputStream wraps a GZIPOutputStream that
     * is not yet finished).</p>
     *
     * @throws IOException on I/O error
     */
    public void finish() throws IOException {
        if (!finished) {
            out.write(EOF_BLOCK);
            finished = true;
        }
    }

    /**
     * Finishes the archive and closes the underlying stream.
     */
    @Override
    public void close() throws IOException {
        try {
            finish();
        } finally {
            out.close();
        }
    }

    // =========================================================================
    // GNU LongName extension
    // =========================================================================

    /**
     * Writes a GNU LongName extension entry that carries the full entry name.
     * This entry precedes the actual header when the name exceeds 100 bytes.
     */
    private void writeLongNameEntry(String fullName) throws IOException {
        byte[] nameBytes = fullName.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        // Build the LongName header - use the constructor that accepts linkFlag directly
        TarEntry longNameEntry = new TarEntry(GNU_LONGLINK, LF_GNUTYPE_LONGNAME);
        longNameEntry.setSize(nameBytes.length + 1L); // +1 for NUL terminator
        java.util.Arrays.fill(header, (byte) 0);
        longNameEntry.writeEntryHeader(header);
        out.write(header);
        // Write the name bytes followed by NUL and padding
        out.write(nameBytes);
        out.write(0); // NUL terminator
        int written = nameBytes.length + 1;
        int remainder = written % RECORD_SIZE;
        if (remainder != 0) {
            out.write(new byte[RECORD_SIZE - remainder]);
        }
    }

    /**
     * Returns a copy of {@code entry} whose name is replaced by {@code newName}.
     * Only the name field matters here; all other fields are preserved.
     */
    private static TarEntry cloneWithTruncatedName(TarEntry entry, String newName) {
        // Use the constructor that accepts a linkFlag to preserve the entry type
        TarEntry clone = new TarEntry(newName, entry.getLinkFlag());
        clone.setSize(entry.getSize());
        clone.setModTime(entry.getModTime());
        clone.setMode(entry.getMode());
        clone.setUserId(entry.getUserId());
        clone.setGroupId(entry.getGroupId());
        clone.setUserName(entry.getUserName());
        clone.setGroupName(entry.getGroupName());
        return clone;
    }

    // =========================================================================
    // Factory helper - creates a TarEntry ready for writing from a File
    // =========================================================================

    /**
     * Convenience factory: creates a TarEntry for a file using the given
     * entry name (relative path inside the archive).
     *
     * @param file      source file
     * @param entryName path inside the archive (forward slashes, no leading slash)
     * @return ready-to-use entry with size and mtime set
     */
    public static TarEntry createEntry(File file, String entryName) {
        TarEntry entry = new TarEntry(file, entryName);
        return entry;
    }
}
