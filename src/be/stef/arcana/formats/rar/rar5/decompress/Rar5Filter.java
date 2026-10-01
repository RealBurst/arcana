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
package be.stef.arcana.formats.rar.rar5.decompress;

/**
 * Represents a RAR5 post-processing filter.
 * 
 * <p>RAR5 supports several filter types for improving compression of specific
 * data types:</p>
 * <ul>
 *   <li>DELTA (0) - For audio data with multiple channels</li>
 *   <li>E8 (1) - For x86 executables (CALL instructions)</li>
 *   <li>E8E9 (2) - For x86 executables (CALL and JMP instructions)</li>
 *   <li>ARM (3) - For ARM executables</li>
 * </ul>
 * 
 * @author Stef
 * @since 1.0
 * @see Rar5Constants#FILTER_DELTA
 * @see Rar5Constants#FILTER_E8
 * @see Rar5Constants#FILTER_E8E9
 * @see Rar5Constants#FILTER_ARM
 */
public class Rar5Filter {
    public long startPos;   // Start position in the output stream
    public int size;       // Size of the data to filter
    public int type;       // Filter type (DELTA, E8, E8E9, ARM)
    public int channels;   // Number of channels (for DELTA filter)
    
    /**
     * Creates an empty filter.
     */
    public Rar5Filter() {
    }
    
    /**
     * Creates a copy of another filter.
     * 
     * @param other the filter to copy
     */
    public Rar5Filter(Rar5Filter other) {
        this.startPos = other.startPos;
        this.size = other.size;
        this.type = other.type;
        this.channels = other.channels;
    }
}
