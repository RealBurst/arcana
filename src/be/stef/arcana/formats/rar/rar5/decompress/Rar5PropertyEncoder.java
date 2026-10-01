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
 * Encoder for RAR5 decoder properties.
 * 
 * <p>This class converts window size and compression flags into the 2-byte
 * property format expected by {@link Rar5LZDecoder#setDecoderProperties2}.</p>
 * 
 * <p>Property format:</p>
 * <ul>
 *   <li>Byte 0: pow (power value for window size)</li>
 *   <li>Byte 1: [frac:5 bits][v7:1 bit][solid:1 bit]</li>
 * </ul>
 * 
 * <p>Window size formula: {@code (frac + 32) << (pow + 12)}</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5PropertyEncoder {
    
    /**
     * Encodes window size and flags into decoder properties.
     * 
     * @param windowSize the dictionary window size
     * @param solid true if solid compression is used
     * @param v7 true if v7 algorithm is used
     * @return 2-byte property array for setDecoderProperties2
     */
    public static byte[] encodeWindowSize(long windowSize, boolean solid, boolean v7) {
        // Find best pow and frac values that match the window size
        int bestPow = 0;
        int bestFrac = 0;
        long minDiff = Long.MAX_VALUE;
        
        for (int pow = 0; pow <= 31; pow++) {
            for (int frac = 0; frac <= 31; frac++) {
                long calculatedSize = (long) (frac + 32) << (pow + 12);
                long diff = Math.abs(calculatedSize - windowSize);
                
                if (diff < minDiff) {
                    minDiff = diff;
                    bestPow = pow;
                    bestFrac = frac;
                }
                
                // Exact match found
                if (diff == 0) {
                    break;
                }
            }
        }
        
        // Build property bytes
        byte[] properties = new byte[2];
        properties[0] = (byte) bestPow;
        
        // Second byte: [frac:5 bits][v7:1 bit][solid:1 bit]
        int secondByte = (bestFrac << 3) | (v7 ? 0x02 : 0x00) | (solid ? 0x01 : 0x00);
        properties[1] = (byte) secondByte;
        
        return properties;
    }
    
    /**
     * Checks if a compression method is supported.
     * 
     * <p>RAR5 compression methods:</p>
     * <ul>
     *   <li>0 = Store (no compression)</li>
     *   <li>1 = Fastest</li>
     *   <li>2 = Fast</li>
     *   <li>3 = Normal</li>
     *   <li>4 = Good</li>
     *   <li>5 = Best</li>
     * </ul>
     * 
     * @param compressionMethod the method to check
     * @return true if supported (0-5)
     */
    public static boolean isCompressionMethodSupported(int compressionMethod) {
        // RAR5 supports methods 0 (store) through 5 (best)
        return compressionMethod >= 0 && compressionMethod <= 5;
    }
}
