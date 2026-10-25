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
package be.stef.arcana.formats.rar;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.util.ExtractionGuard;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Where the RAR 4 and RAR 5 extractors send what they decode.
 *
 * <p>By default (no sink), files and folders are created on the disk, as
 * before. When a {@link Sink} is set for the current thread (the per-entry
 * reader of {@code Arcana.read}), every entry goes to the sink instead, in
 * archive order, and nothing is written to the disk. The extractors then run
 * sequentially (no parallel RAR 5 extraction) and show no progress bar.</p>
 *
 * @author Stef
 * @since 1.1.0
 */
public final class RarOutput {

    /** Receives the entries of the archive being extracted. */
    public interface Sink {
        /** A folder entry. */
        void directory(ArcanaEntry entry) throws IOException;

        /** A file entry: the decoded content is written to the returned stream (closed by the extractor). */
        OutputStream file(ArcanaEntry entry) throws IOException;

        /** An error recorded by the extractor (an entry or the whole archive). */
        void error(ExtractionError error);
    }

    private static final ThreadLocal<Sink> SINK = new ThreadLocal<Sink>();

    private RarOutput() {
    }

    /** Sends the entries extracted by the current thread to {@code sink} ({@code null} = back to the disk). */
    public static void setSink(final Sink sink) {
        if (sink == null) SINK.remove();
        else SINK.set(sink);
    }

    /** @return true when the entries go to a sink instead of the disk */
    public static boolean active() {
        return SINK.get() != null;
    }

    /** Output of a file entry: the sink's stream, or the file (counted by {@link ExtractionGuard}). */
    public static OutputStream open(final File target, final ArcanaEntry entry) throws IOException {
        final Sink s = SINK.get();
        return s != null ? s.file(entry) : ExtractionGuard.open(target);
    }

    /** @return true if the sink took this empty file (the caller then creates nothing) */
    public static boolean emptyFile(final ArcanaEntry entry) throws IOException {
        final Sink s = SINK.get();
        if (s == null) return false;
        s.file(entry).close();
        return true;
    }

    /** @return true if the sink took this folder (the caller then creates nothing) */
    public static boolean directory(final ArcanaEntry entry) throws IOException {
        final Sink s = SINK.get();
        if (s == null) return false;
        s.directory(entry);
        return true;
    }

    /** Creates the folder, unless the entries go to a sink. */
    public static void mkdirs(final File dir) {
        if (dir != null && SINK.get() == null) dir.mkdirs();
    }

    /** Reports an error to the sink, if any (called for every error added to an {@link ExtractionResult}). */
    static void error(final ExtractionError error) {
        final Sink s = SINK.get();
        if (s != null) s.error(error);
    }
}
