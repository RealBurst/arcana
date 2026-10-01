/*
 * Copyright 2025 Stephane Bury - Derived from Apache Commons Compress
 * (CircularBuffer.java, Apache License 2.0).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.lha;

/**
 * Circular byte buffer used as the sliding-window dictionary in LZH decompression.
 *
 * <p>The buffer has a fixed size and supports two operations: writing a new byte
 * ({@link #put}) and copying a back-reference ({@link #copy}).  The copied bytes
 * are read with {@link #get}, one byte at a time, before more data is written.</p>
 *
 * <p>Derived from {@code org.apache.commons.compress.archivers.lha.CircularBuffer}
 * (Apache License 2.0).</p>
 */
final class LhaCircularBuffer {

    private final int    size;
    private final byte[] buffer;
    private int readIndex;
    private int writeIndex;
    private int bytesAvailable;

    /**
     * Creates a new circular buffer.
     *
     * @param size total buffer capacity in bytes
     */
    LhaCircularBuffer(final int size) {
        this.size       = size;
        this.buffer     = new byte[size];
        this.bytesAvailable = 0;
    }

    /** Returns {@code true} if at least one byte is ready to be read. */
    boolean available() { return bytesAvailable > 0; }

    /**
     * Writes one byte to the buffer.
     *
     * @param value byte value (0-255)
     * @throws IllegalStateException if the buffer is already full
     */
    void put(final int value) {
        if (bytesAvailable == size) throw new IllegalStateException("Buffer overflow");
        buffer[writeIndex] = (byte) value;
        writeIndex = (writeIndex + 1) % size;
        bytesAvailable++;
    }

    /**
     * Reads and removes the next byte from the buffer.
     *
     * @return byte value (0-255), or -1 if the buffer is empty
     */
    int get() {
        if (!available()) return -1;
        final int value = buffer[readIndex] & 0xFF;
        readIndex = (readIndex + 1) % size;
        bytesAvailable--;
        return value;
    }

    /**
     * Copies a back-reference from within the sliding window into the current
     * write position.  Because the copy can overlap the source (producing a
     * "run-length" repetition when {@code distance == 1}), bytes are always
     * copied one at a time.
     *
     * @param distance distance from the current write position (must be >= 1)
     * @param length   number of bytes to copy
     * @throws IllegalArgumentException if {@code distance} is out of range
     */
    void copy(final int distance, final int length) {
        if (distance < 1) throw new IllegalArgumentException("Distance must be >= 1");
        if (distance > size) throw new IllegalArgumentException("Distance exceeds buffer size");
        final int pos = writeIndex - distance;
        for (int i = 0; i < length; i++) {
            put(buffer[(pos + i + size) % size]);
        }
    }
}
