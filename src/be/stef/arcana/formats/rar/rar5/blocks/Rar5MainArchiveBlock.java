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
package be.stef.arcana.formats.rar.rar5.blocks;

import java.nio.charset.StandardCharsets;
import be.stef.arcana.formats.rar.util.Utils;
import be.stef.arcana.formats.rar.util.VInt;
import be.stef.arcana.formats.rar.util.VIntReader;
import be.stef.arcana.formats.rar.rar5.Rar5Constants;

/**
 * Main Archive Header block for RAR5 archives.
 * 
 * <p>This is the first block after the signature (or after the encryption
 * block if headers are encrypted). It contains archive-wide settings.</p>
 * 
 * <p>Structure:</p>
 * <ul>
 *   <li>ArchiveFlags (VInt)</li>
 *   <li>VolumeNumber (VInt, optional)</li>
 *   <li>Extra area (optional) - contains Locator and/or Metadata</li>
 * </ul>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5MainArchiveBlock extends Rar5Block {
    private long archiveFlags;
    private long volumeNumber;
    private Locator locator;
    private Metadata metadata;
    
    @Override
    public boolean parseSpecificData(byte[] data, int offset, int endExclusive) {
        try {
            int pos = offset;
            
            // Archive flags (VInt)
            VInt flagsVInt = VIntReader.read(data, pos, endExclusive);
            if (flagsVInt == null) {
                return false;
            }
            archiveFlags = flagsVInt.value;
            pos += flagsVInt.length;
            
            // Volume number (VInt, optional)
            if (hasVolumeNumber()) {
                VInt volVInt = VIntReader.read(data, pos, endExclusive);
                if (volVInt == null) {
                    return false;
                }
                volumeNumber = volVInt.value;
                pos += volVInt.length;
            }
            
            // Parse extra area if present
            if (hasExtra() && pos + extraSize <= endExclusive) {
                parseExtraArea(data, pos, (int) extraSize);
                pos += (int) extraSize;
            }
            
            return pos == endExclusive;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    @Override
    protected boolean parseExtraArea(byte[] data, int offset, int size) {
        try {
            int pos = offset;
            int end = offset + size;
            
            while (pos < end) {
                // Record size (VInt)
                VInt sizeVInt = VIntReader.read(data, pos, end);
                if (sizeVInt == null) {
                    break;
                }
                int recordSize = (int) sizeVInt.value;
                pos += sizeVInt.length;
                
                // Record ID (VInt)
                VInt idVInt = VIntReader.read(data, pos, end);
                if (idVInt == null) {
                    break;
                }
                int id = (int) idVInt.value;
                pos += idVInt.length;
                
                int dataSize = recordSize - idVInt.length;
                if (pos + dataSize > end) {
                    break;
                }
                
                if (id == Rar5Constants.ARC_EXTRA_LOCATOR) {
                    locator = new Locator();
                    locator.parse(data, pos, dataSize);
                } else if (id == Rar5Constants.ARC_EXTRA_METADATA) {
                    metadata = new Metadata();
                    metadata.parse(data, pos, dataSize);
                }
                
                pos += dataSize;
            }
            
            return true;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    // ========== Archive Flags ==========
    
    /**
     * @return true if this is part of a multi-volume set
     */
    public boolean isVolume() {
        return (archiveFlags & Rar5Constants.ARC_FLAG_VOLUME) != 0;
    }
    
    /**
     * @return true if volume number is present
     */
    public boolean hasVolumeNumber() {
        return (archiveFlags & Rar5Constants.ARC_FLAG_VOLUME_NUMBER) != 0;
    }
    
    // Legacy method name
    public boolean hasVolNumber() {
        return hasVolumeNumber();
    }
    
    /**
     * @return true if archive uses solid compression
     */
    public boolean isSolid() {
        return (archiveFlags & Rar5Constants.ARC_FLAG_SOLID) != 0;
    }
    
    /**
     * @return true if archive contains recovery record
     */
    public boolean hasRecoveryRecord() {
        return (archiveFlags & Rar5Constants.ARC_FLAG_RECOVERY) != 0;
    }
    
    /**
     * @return true if archive is locked
     */
    public boolean isLocked() {
        return (archiveFlags & Rar5Constants.ARC_FLAG_LOCKED) != 0;
    }
    
    /**
     * @return true if headers are encrypted
     */
    public boolean areHeadersEncrypted() {
        return (flags & 0x0004) != 0;
    }
    
    // ========== Getters ==========
    
    public long getArchiveFlags() {
        return archiveFlags;
    }
    
    // Legacy getter
    public long getArcFlags() {
        return archiveFlags;
    }
    
    public long getVolumeNumber() {
        return volumeNumber;
    }
    
    // Legacy getter
    public long getVolNumber() {
        return volumeNumber;
    }
    
    public Locator getLocator() {
        return locator;
    }
    
    public Metadata getMetadata() {
        return metadata;
    }
    
    // ========== Inner Classes ==========
    
    /**
     * Locator extra record - contains offsets to quick open and recovery records.
     */
    public static class Locator {
        private long flags;
        private long quickOpenOffset;
        private long recoveryOffset;
        
        public boolean parse(byte[] data, int offset, int size) {
            try {
                int pos = offset;
                int end = offset + size;
                
                // Flags (VInt)
                VInt flagsVInt = VIntReader.read(data, pos, end);
                if (flagsVInt == null) {
                    return false;
                }
                flags = flagsVInt.value;
                pos += flagsVInt.length;
                
                // Quick open offset (VInt, optional)
                if ((flags & Rar5Constants.LOCATOR_FLAG_QUICK_OPEN) != 0) {
                    VInt qoVInt = VIntReader.read(data, pos, end);
                    if (qoVInt == null) {
                        return false;
                    }
                    quickOpenOffset = qoVInt.value;
                    pos += qoVInt.length;
                }
                
                // Recovery offset (VInt, optional)
                if ((flags & Rar5Constants.LOCATOR_FLAG_RECOVERY) != 0) {
                    VInt recVInt = VIntReader.read(data, pos, end);
                    if (recVInt == null) {
                        return false;
                    }
                    recoveryOffset = recVInt.value;
                    pos += recVInt.length;
                }
                
                return true;
                
            } catch (Exception e) {
                return false;
            }
        }
        
        public long getFlags() {
            return flags;
        }
        
        public long getQuickOpenOffset() {
            return quickOpenOffset;
        }
        
        // Legacy getter
        public long getQuickOpen() {
            return quickOpenOffset;
        }
        
        public long getRecoveryOffset() {
            return recoveryOffset;
        }
        
        // Legacy getter
        public long getRecovery() {
            return recoveryOffset;
        }
    }
    
    /**
     * Metadata extra record - contains archive name and creation time.
     */
    public static class Metadata {
        private long flags;
        private String archiveName;
        private long creationTime;
        
        public boolean parse(byte[] data, int offset, int size) {
            try {
                int pos = offset;
                int end = offset + size;
                
                // Flags (VInt)
                VInt flagsVInt = VIntReader.read(data, pos, end);
                if (flagsVInt == null) {
                    return false;
                }
                flags = flagsVInt.value;
                pos += flagsVInt.length;
                
                // Archive name (optional)
                if ((flags & Rar5Constants.METADATA_FLAG_ARC_NAME) != 0) {
                    VInt lenVInt = VIntReader.read(data, pos, end);
                    if (lenVInt == null) {
                        return false;
                    }
                    int nameLen = (int) lenVInt.value;
                    pos += lenVInt.length;
                    
                    if (pos + nameLen > end) {
                        return false;
                    }
                    archiveName = new String(data, pos, nameLen, StandardCharsets.UTF_8);
                    pos += nameLen;
                }
                
                // Creation time (optional)
                if ((flags & Rar5Constants.METADATA_FLAG_CREATION_TIME) != 0) {
                    boolean unixTime = (flags & Rar5Constants.METADATA_FLAG_UNIX_TIME) != 0;
                    boolean nanoSec = (flags & Rar5Constants.METADATA_FLAG_NANOSECOND) != 0;
                    int timeSize = (unixTime && !nanoSec) ? 4 : 8;
                    
                    if (pos + timeSize > end) {
                        return false;
                    }
                    
                    if (timeSize == 4) {
                        creationTime = Utils.readUInt32LE(data, pos);
                    } else {
                        creationTime = Utils.readUInt64LE(data, pos);
                    }
                    pos += timeSize;
                }
                
                return true;
                
            } catch (Exception e) {
                return false;
            }
        }
        
        public long getFlags() {
            return flags;
        }
        
        public String getArchiveName() {
            return archiveName;
        }
        
        // Legacy getter
        public String getArcName() {
            return archiveName;
        }
        
        public long getCreationTime() {
            return creationTime;
        }
        
        // Legacy getter
        public long getCtime() {
            return creationTime;
        }
    }
}
