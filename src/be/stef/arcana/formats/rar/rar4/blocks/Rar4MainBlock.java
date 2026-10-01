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
package be.stef.arcana.formats.rar.rar4.blocks;

import be.stef.arcana.formats.rar.rar4.Rar4Constants;

/**
 * RAR4 main archive header block (type 0x73).
 *
 * <p>Structure after common header:</p>
 * <pre>
 *   2 bytes : reserved1
 *   4 bytes : reserved2
 * </pre>
 *
 * @author Stef
 * @since 1.0
 */
public class Rar4MainBlock extends Rar4Block {
    private int  reserved1;
    private long reserved2;

    @Override
    public boolean parseSpecificData(byte[] buf, int offset, int length) {
        if (length - offset < 6) return false;
        reserved1 = readUInt16LE(buf, offset);
        reserved2 = readUInt32LE(buf, offset + 2);
        return true;
    }

    public boolean isVolume()            { return (flags & Rar4Constants.ARC_FLAG_VOLUME)            != 0; }
    public boolean isSolid()             { return (flags & Rar4Constants.ARC_FLAG_SOLID)             != 0; }
    public boolean isLocked()            { return (flags & Rar4Constants.ARC_FLAG_LOCKED)            != 0; }
    public boolean hasComment()          { return (flags & Rar4Constants.ARC_FLAG_HAS_COMMENT)       != 0; }
    public boolean hasAuthInfo()         { return (flags & Rar4Constants.ARC_FLAG_AUTH_INFO)         != 0; }
    public boolean hasRecovery()         { return (flags & Rar4Constants.ARC_FLAG_RECOVERY)          != 0; }
    public boolean hasEncryptedHeaders() { return (flags & Rar4Constants.ARC_FLAG_ENCRYPTED_HEADERS) != 0; }
    public boolean isFirstVolume()       { return (flags & Rar4Constants.ARC_FLAG_FIRST_VOLUME)      != 0; }
    public boolean usesNewNaming()       { return (flags & Rar4Constants.ARC_FLAG_NEW_NAMING)        != 0; }
}