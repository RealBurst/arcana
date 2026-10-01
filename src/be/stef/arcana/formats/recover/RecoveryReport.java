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
package be.stef.arcana.formats.recover;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Result of a forced extraction ({@link ForceUnpacker}): what was recovered, and
 * how reliable each file is.
 *
 * @author Stef
 * @since 1.3
 */
public final class RecoveryReport {

    /** Reliability of a recovered file. */
    public enum Status {
        /** Decoded completely and its checksum (when the format has one) is correct. */
        OK,
        /** Decoded completely but no checksum could confirm the content. */
        UNVERIFIED,
        /** Decoded completely but the checksum does not match: the content is damaged. */
        BAD_CHECKSUM,
        /** Decoding stopped on an error: only the beginning of the file was written. */
        PARTIAL,
        /** Nothing could be decoded (encrypted, unsupported method, destroyed data). */
        LOST
    }

    /** One file of the damaged archive. */
    public static final class Entry {
        public final String name;
        public final Status status;
        public final long bytesWritten;
        public final long expectedSize; // -1 = unknown
        public final String message;

        Entry(final String name, final Status status, final long bytesWritten, final long expectedSize, final String message) {
            this.name = name;
            this.status = status;
            this.bytesWritten = bytesWritten;
            this.expectedSize = expectedSize;
            this.message = message;
        }

        @Override
        public String toString() {
            return String.format("%-12s %12d / %-12s %s%s", status, bytesWritten, expectedSize >= 0 ? String.valueOf(expectedSize) : "?", name, message != null ? "  (" + message + ")" : "");
        }
    }

    /** File written by {@link #writeTo(File)} in the destination directory. */
    public static final String REPORT_FILE = "_ARCANA_RECOVERY_REPORT.txt";

    public static final String WARNING = "WARNING: forced extraction of a damaged archive. The recovered files may be incomplete or contain garbage: check every file before using it (see the status of each file).";

    private final String archiveName;
    private final String method;
    private final List<Entry> entries = new ArrayList<Entry>();
    private final List<String> notes = new ArrayList<String>();

    RecoveryReport(final String archiveName, final String method) {
        this.archiveName = archiveName;
        this.method = method;
    }

    void add(final String name, final Status status, final long written, final long expected, final String message) {
        entries.add(new Entry(name, status, written, expected, message));
    }

    /** Index of the last entry, -1 if none. */
    int lastIndex() {
        return entries.size() - 1;
    }

    /** Replaces the status of entry {@code index} (a later finding shows it is damaged). */
    void downgrade(final int index, final Status status, final String message) {
        final Entry e = entries.get(index);
        entries.set(index, new Entry(e.name, status, e.bytesWritten, e.expectedSize, message));
    }

    /** Replaces status, written size and message of entry {@code index}. */
    void set(final int index, final Status status, final long written, final String message) {
        final Entry e = entries.get(index);
        entries.set(index, new Entry(e.name, status, written, e.expectedSize, message));
    }

    void note(final String text) {
        notes.add(text);
    }

    public List<Entry> getEntries() {
        return Collections.unmodifiableList(entries);
    }

    public List<String> getNotes() {
        return Collections.unmodifiableList(notes);
    }

    public int count(final Status s) {
        int n = 0;
        for (final Entry e : entries) if (e.status == s) n++;
        return n;
    }

    /** One-line summary. */
    public String summary() {
        return entries.size() + " file(s): " + count(Status.OK) + " OK, " + count(Status.UNVERIFIED) + " unverified, " + count(Status.BAD_CHECKSUM) + " bad checksum, " + count(Status.PARTIAL) + " partial, " + count(Status.LOST) + " lost";
    }

    /** Full text of the report. */
    public String toText() {
        final StringBuilder sb = new StringBuilder();
        sb.append(WARNING).append('\n').append('\n');
        sb.append("Archive : ").append(archiveName).append('\n');
        sb.append("Method  : ").append(method).append('\n');
        sb.append("Result  : ").append(summary()).append('\n');
        for (final String n : notes) sb.append("Note    : ").append(n).append('\n');
        sb.append('\n').append(String.format("%-12s %12s / %-12s %s%n", "Status", "Written", "Expected", "Name"));
        for (final Entry e : entries) sb.append(e).append('\n');
        return sb.toString();
    }

    /** Writes the report into {@code dir}/{@value #REPORT_FILE}. */
    public void writeTo(final File dir) throws IOException {
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(dir, REPORT_FILE)), StandardCharsets.UTF_8))) {
            w.print(toText());
        }
    }
}
