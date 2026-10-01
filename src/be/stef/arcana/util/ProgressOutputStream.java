/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.util;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * An {@link OutputStream} wrapper that displays a single-line ASCII progress
 * bar on the console as bytes flow through it.
 *
 * <p>The bar is reprinted in place on the same line via {@code \r}.  When the
 * transfer finishes, call {@link #finish()} to append the elapsed time and
 * move to the next console line:</p>
 * <pre>
 *   [==============================] 4.2 MB 100% (setup.exe) -> 5 sec
 *   [==============================] 1.8 GB 100% (image.iso) -> 3 min 24 sec
 * </pre>
 *
 * <p>If {@code totalSize <= 0} the percentage is omitted and only the byte
 * count is shown (useful when the uncompressed size is not known in advance).</p>
 *
 * <p>Used by extractors to report per-file extraction progress.  The symmetric
 * {@link ProgressInputStream} serves the same purpose for compressors that
 * read source files.</p>
 *
 * @author Stef
 * @since 1.2
 */
public class ProgressOutputStream extends FilterOutputStream {

    private static final int BAR_WIDTH = 30;

    private final long   totalSize;
    private final String fileName;
    private final long   startTime;
    private long bytesWritten = 0;
    private int  lastPercent  = -1;

    /**
     * Creates a ProgressOutputStream.
     *
     * @param out       the underlying stream that receives the bytes
     * @param totalSize expected total bytes to be written; use <= 0 if unknown
     * @param fileName  label displayed in the progress line (truncated if long)
     */
    public ProgressOutputStream(final OutputStream out, final long totalSize, final String fileName) {
        super(out);
        this.totalSize = totalSize;
        this.fileName  = fileName;
        this.startTime = System.nanoTime();
    }

    @Override
    public void write(final int b) throws IOException {
        out.write(b);
        bytesWritten++;
        updateProgress();
    }

    @Override
    public void write(final byte[] b, final int off, final int len) throws IOException {
        out.write(b, off, len);
        bytesWritten += len;
        updateProgress();
    }

    private void updateProgress() {
        if (totalSize <= 0) {
            // Size unknown: just print byte count, no percentage
            System.out.printf("\r  %s  %s", formatSize(bytesWritten), truncate(fileName, 40));
            return;
        }
        final int percent = (int) ((bytesWritten * 100) / totalSize);
        if (percent != lastPercent) {
            lastPercent = percent;
            printBar(percent, null);
        }
    }

    private void printBar(final int percent, final String duration) {
        final int filled = (percent * BAR_WIDTH) / 100;
        final StringBuilder bar = new StringBuilder("[");
        for (int i = 0; i < BAR_WIDTH; i++) bar.append(i < filled ? '=' : ' ');
        bar.append(']');
        System.out.printf("\r%s %s %3d%% (%s)",
                bar, formatSize(bytesWritten), percent, truncate(fileName, 30));
        if (duration != null) System.out.print(" -> " + duration);
    }

    /**
     * Reprints the final progress line with the elapsed time, then prints a
     * newline.  Must be called explicitly before the stream is closed.
     */
    public void finish() {
        if (totalSize > 0) {
            printBar(Math.max(lastPercent, 0), formatDuration(elapsedMillis()));
        } else {
            System.out.printf("\r  %s  %s", formatSize(bytesWritten), truncate(fileName, 40));
        }
        System.out.println();
    }

    /** Returns the number of milliseconds elapsed since this stream was created. */
    public long elapsedMillis() {
        return (System.nanoTime() - startTime) / 1_000_000L;
    }

    // ---- shared formatting helpers (also used by ProgressInputStream) -------

    /** Formats a byte count as "512 B", "4.2 KB", "1.8 MB", "3.14 GB". */
    public static String formatSize(final long bytes) {
        if (bytes < 1024L)                return bytes + " B ";
        if (bytes < 1024L * 1024)         return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024L * 1024 * 1024)  return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    /**
     * Formats a duration as "48 ms", "5 sec", "3 min 24 sec", "1 h 5 min 3 sec".
     */
    public static String formatDuration(final long millis) {
        if (millis < 1000L) return millis + " ms";
        final long s = millis / 1000;
        final long h = s / 3600;
        final long m = (s % 3600) / 60;
        final long sec = s % 60;
        if (h > 0)   return h + " h " + m + " min " + sec + " sec";
        if (m > 0)   return m + " min " + sec + " sec";
        return sec + " sec";
    }

    static String truncate(final String name, final int max) {
        if (name == null || name.length() <= max) return name;
        return "..." + name.substring(name.length() - max + 3);
    }
}
