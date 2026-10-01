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
 * Information about a file to be decoded from a RAR5 archive.
 * 
 * <p>This class holds all the metadata needed to decompress a single file,
 * including the compressed data, unpack size, window size, and compression
 * parameters.</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5FileDecodeInfo {
    private final byte[] compressedData;
    private final long unpackedSize;
    private final long windowSize;
    private final boolean solid;
    private final boolean v7;
    private final int compressionMethod;
    
    /**
     * Creates a new file decode info object.
     * 
     * @param compressedData the compressed file data
     * @param unpackedSize the expected unpacked size
     * @param windowSize the dictionary window size
     * @param solid true if this file uses solid compression
     * @param v7 true if this file uses v7 algorithm
     * @param compressionMethod the compression method (0-5)
     */
    public Rar5FileDecodeInfo(byte[] compressedData, long unpackedSize, long windowSize, boolean solid, boolean v7, int compressionMethod) {
        this.compressedData = compressedData;
        this.unpackedSize = unpackedSize;
        this.windowSize = windowSize;
        this.solid = solid;
        this.v7 = v7;
        this.compressionMethod = compressionMethod;
    }
    
    /**
     * @return the compressed file data
     */
    public byte[] getCompressedData() {
        return compressedData;
    }
    
    /**
     * @return the expected unpacked size in bytes
     */
    public long getUnpackedSize() {
        return unpackedSize;
    }
    
    /**
     * @return the dictionary window size
     */
    public long getWindowSize() {
        return windowSize;
    }
    
    /**
     * @return true if this file uses solid compression
     */
    public boolean isSolid() {
        return solid;
    }
    
    /**
     * @return true if this file uses v7 algorithm
     */
    public boolean isV7() {
        return v7;
    }
    
    /**
     * @return the compression method (0=store, 1-5=compressed)
     */
    public int getCompressionMethod() {
        return compressionMethod;
    }
}
