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
package be.stef.arcana.formats.rar.util;

/**
 * Simple byte buffer with lazy allocation.
 * 
 * <p>This class provides a growable byte buffer that allocates memory
 * only when needed and can be reused across multiple operations.</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class ByteBuffer {
    private byte[] buffer;
    private int capacity;
    
    /**
     * Creates an empty byte buffer.
     */
    public ByteBuffer() {
        this.buffer = null;
        this.capacity = 0;
    }
    
    /**
     * Creates a byte buffer with initial capacity.
     * 
     * @param initialCapacity the initial buffer size
     */
    public ByteBuffer(int initialCapacity) {
        this.buffer = new byte[initialCapacity];
        this.capacity = initialCapacity;
    }
    
    /**
     * Checks if the buffer has been allocated.
     * 
     * @return true if buffer is allocated
     */
    public boolean isAllocated() {
        return buffer != null;
    }
    
    /**
     * Returns the underlying byte array.
     * 
     * @return the buffer, or null if not allocated
     */
    public byte[] getBuffer() {
        return buffer;
    }
    
    /**
     * Ensures the buffer has at least the specified capacity.
     * 
     * @param size required minimum size
     * @param maxSize maximum allowed size
     * @return true if allocation succeeded, false if size exceeds maxSize
     */
    public boolean allocAtLeastMax(int size, int maxSize) {
        if (size > maxSize) {
            return false;
        }
        
        if (buffer == null || capacity < size) {
            buffer = new byte[size];
            capacity = size;
        }
        return true;
    }
    
    /**
     * Frees the buffer memory.
     */
    public void free() {
        buffer = null;
        capacity = 0;
    }
}
