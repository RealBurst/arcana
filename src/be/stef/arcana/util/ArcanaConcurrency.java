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

/**
 * Global settings for the multithreaded code paths (parallel compression of
 * gzip / bzip2 / xz / 7z blocks, parallel ZIP extraction, read-ahead pipeline).
 *
 * <p>The number of worker threads is also capped by the free heap, so that
 * memory-hungry encoders (LZMA2 preset 9 needs ~700 MB each) never cause an
 * {@link OutOfMemoryError}: when only one worker fits, the classic sequential
 * code is used and the output is byte-for-byte the same as before.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class ArcanaConcurrency {

    /**
     * Maximum worker threads. 1 = everything sequential (same output as before 1.3).
     * Default: system property {@code -Darcana.threads=N}, otherwise the number of processors.
     */
    public static volatile int threads = Math.max(1, Integer.getInteger("arcana.threads", Runtime.getRuntime().availableProcessors()));

    /**
     * Enables the read-ahead thread that decompresses while the caller writes files.
     * Default: system property {@code -Darcana.readAhead=false} disables it.
     */
    public static volatile boolean readAhead = !"false".equalsIgnoreCase(System.getProperty("arcana.readAhead"));

    /** Share of the free heap the workers may use together. */
    private static final double HEAP_SHARE = 0.5;

    private ArcanaConcurrency() {}

    /**
     * Number of workers for tasks needing {@code bytesPerTask} of memory each:
     * between 1 and {@link #threads}, limited by the free heap.
     */
    public static int workersFor(final long bytesPerTask) {
        final int max = Math.max(1, threads);
        if (max == 1) return 1;
        final Runtime rt = Runtime.getRuntime();
        final long used = rt.totalMemory() - rt.freeMemory();
        final long free = rt.maxMemory() - used;
        final long fit = (long) (free * HEAP_SHARE) / Math.max(1L, bytesPerTask);
        return (int) Math.max(1, Math.min(max, fit));
    }
}
