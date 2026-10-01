/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.util;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * An {@link InputStream} wrapper that displays a single-line ASCII progress
 * bar on the console as bytes are read through it.
 *
 * <p>Symmetric to {@link ProgressOutputStream}: while that class is used by
 * <em>extractors</em> (bytes flow out to disk), this class is used by
 * <em>compressors</em> (bytes flow in from source files).  The display format
 * is identical:</p>
 * <pre>
 *   [==============================] 4.2 MB 100% (BigFile.dat) -> 2 sec
 * </pre>
 *
 * <p>Call {@link #finish()} after all bytes have been read to append the
 * elapsed time and move to the next console line.</p>
 *
 * @author Stef
 * @see ProgressOutputStream
 * @since 1.2
 */
public class ProgressInputStream extends FilterInputStream {

    private static final int BAR_WIDTH = 30;

    private final long   totalSize;
    private final String fileName;
    private final long   startTime;
    private long bytesRead   = 0;
    private int  lastPercent = -1;

    /**
     * Creates a ProgressInputStream.
     *
     * @param in        the underlying stream that supplies the bytes
     * @param totalSize expected total bytes to be read; use <= 0 if unknown
     * @param fileName  label displayed in the progress line (truncated if long)
     */
    public ProgressInputStream(final InputStream in, final long totalSize, final String fileName) {
        super(in);
        this.totalSize = totalSize;
        this.fileName  = fileName;
        this.startTime = System.nanoTime();
    }

    @Override
    public int read() throws IOException {
        final int b = in.read();
        if (b != -1) { bytesRead++; updateProgress(); }
        return b;
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        final int n = in.read(b, off, len);
        if (n > 0) { bytesRead += n; updateProgress(); }
        return n;
    }

    @Override
    public long skip(final long n) throws IOException {
        final long skipped = in.skip(n);
        if (skipped > 0) { bytesRead += skipped; updateProgress(); }
        return skipped;
    }

    private void updateProgress() {
        if (totalSize <= 0) {
            System.out.printf("\r  %s  %s", ProgressOutputStream.formatSize(bytesRead), ProgressOutputStream.truncate(fileName, 40));
            return;
        }
        final int percent = (int) ((bytesRead * 100) / totalSize);
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
                bar, ProgressOutputStream.formatSize(bytesRead), percent, ProgressOutputStream.truncate(fileName, 30));
        if (duration != null) System.out.print(" -> " + duration);
    }

    /**
     * Reprints the final progress line with the elapsed time, then prints a
     * newline.  Must be called explicitly after all bytes have been read.
     */
    public void finish() {
        if (totalSize > 0) {
            printBar(Math.max(lastPercent, 0), ProgressOutputStream.formatDuration(elapsedMillis()));
        } else {
            System.out.printf("\r  %s  %s",
                    ProgressOutputStream.formatSize(bytesRead), ProgressOutputStream.truncate(fileName, 40));
        }
        System.out.println();
    }

    /** Returns the number of milliseconds elapsed since this stream was created. */
    public long elapsedMillis() {
        return (System.nanoTime() - startTime) / 1_000_000L;
    }
}
