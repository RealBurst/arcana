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
package be.stef.arcana.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;
import be.stef.arcana.exceptions.ArcanaLimitExceededException;

/**
 * Counts the bytes written by an extraction and enforces {@link ExtractionLimits}.
 *
 * <p>Every extractor creates its output files with {@link #open(File)}. When the
 * extraction runs inside a {@link #begin(File)} scope (the {@link be.stef.arcana.Arcana}
 * facade opens one), all files share one counter and the ratio against the archive
 * size is checked. Without a scope (an extractor used directly) each file has its
 * own counter and only the free-space and total-size limits apply.</p>
 *
 * <p>The scope is inherited by threads created inside it (RAR5 extracts non-solid
 * archives in parallel).</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class ExtractionGuard {

    private static final InheritableThreadLocal<ExtractionGuard> CURRENT = new InheritableThreadLocal<ExtractionGuard>();

    private final long archiveSize;
    private final AtomicLong written = new AtomicLong();
    private final AtomicLong nextSpaceCheck = new AtomicLong();

    private ExtractionGuard(final long archiveSize) {
        this.archiveSize = archiveSize;
    }

    /** Scope of one extraction; close it (try-with-resources) when the extraction ends. */
    public static final class Scope implements AutoCloseable {
        private final boolean owner;

        private Scope(final boolean owner) {
            this.owner = owner;
        }

        @Override
        public void close() {
            if (owner) CURRENT.remove();
        }
    }

    /** Starts an extraction scope for an archive file (nested scopes join the outer one). */
    public static Scope begin(final File archive) {
        return begin(archive != null && archive.isFile() ? archive.length() : 0L);
    }

    /** Starts an extraction scope; {@code archiveSize} 0 = unknown (ratio not checked). */
    public static Scope begin(final long archiveSize) {
        if (CURRENT.get() != null) return new Scope(false);
        CURRENT.set(new ExtractionGuard(archiveSize));
        return new Scope(true);
    }

    /** Opens an output file whose writes are counted and checked. */
    public static FileOutputStream open(final File target) throws FileNotFoundException {
        final ExtractionGuard g = CURRENT.get();
        return new GuardedFileOutputStream(target, g != null ? g : new ExtractionGuard(0L));
    }

    private void account(final long n, final File target) throws ArcanaLimitExceededException {
        final long total = written.addAndGet(n);
        final long maxTotal = ExtractionLimits.maxTotalBytes;
        if (maxTotal > 0 && total > maxTotal) throw new ArcanaLimitExceededException("Extraction stopped: more than " + maxTotal + " bytes written (ExtractionLimits.maxTotalBytes) - possible decompression bomb, at " + target.getName());
        final long maxRatio = ExtractionLimits.maxRatio;
        if (maxRatio > 0 && archiveSize > 0 && total > ExtractionLimits.ratioThreshold && total / archiveSize > maxRatio) {
            throw new ArcanaLimitExceededException("Extraction stopped: " + total + " bytes written from a " + archiveSize + "-byte archive, ratio above " + maxRatio + ":1 (ExtractionLimits.maxRatio) - possible decompression bomb, at " + target.getName());
        }
        final long minFree = ExtractionLimits.minFreeSpace;
        if (minFree > 0 && total >= nextSpaceCheck.get()) {
            nextSpaceCheck.set(total + Math.max(1L, ExtractionLimits.freeSpaceCheckInterval));
            final File dir = target.getAbsoluteFile().getParentFile();
            final long free = dir != null ? dir.getUsableSpace() : 0L;
            if (free > 0 && free < minFree) throw new ArcanaLimitExceededException("Extraction stopped: only " + free + " bytes left on the destination disk (ExtractionLimits.minFreeSpace = " + minFree + "), at " + target.getName());
        }
    }

    /** FileOutputStream that reports every write to its guard; deletes the file when a limit is hit. */
    private static final class GuardedFileOutputStream extends FileOutputStream {
        private final ExtractionGuard guard;
        private final File target;

        GuardedFileOutputStream(final File target, final ExtractionGuard guard) throws FileNotFoundException {
            super(target);
            this.guard = guard;
            this.target = target;
        }

        private void check(final long n) throws IOException {
            try {
                guard.account(n, target);
            } catch (final ArcanaLimitExceededException e) {
                try { close(); } catch (final IOException ignored) { /* already failing */ }
                if (!target.delete()) target.deleteOnExit();
                throw e;
            }
        }

        @Override
        public void write(final int b) throws IOException {
            check(1);
            super.write(b);
        }

        @Override
        public void write(final byte[] b) throws IOException {
            check(b.length);
            super.write(b, 0, b.length);
        }

        @Override
        public void write(final byte[] b, final int off, final int len) throws IOException {
            check(len);
            super.write(b, off, len);
        }
    }
}
