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
 * Represents a Variable Integer (VInt) read from a RAR5 archive.
 * 
 * <p>RAR5 uses variable-length integer encoding where each byte contains
 * 7 bits of data and 1 continuation bit. The high bit (0x80) indicates
 * whether more bytes follow.</p>
 * 
 * <p>This class is immutable and stores both the decoded value and
 * the number of bytes consumed during decoding.</p>
 * 
 * @author Stef
 * @since 1.0
 */
public final class VInt {
    public final long value;  //The decoded integer value
    public final int length;  //The number of bytes consumed to decode this value
    
    /**
     * Constructs a new VInt with the specified value and byte length.
     * 
     * @param value the decoded value
     * @param length the number of bytes consumed
     */
    public VInt(long value, int length) {
        this.value = value;
        this.length = length;
    }
    
    /**
     * Returns the value as an int, truncating if necessary.
     * 
     * @return the value as int
     */
    public int intValue() {
        return (int) value;
    }
    
    @Override
    public String toString() {
        return String.format("VInt[value=%d, length=%d]", value, length);
    }
}
