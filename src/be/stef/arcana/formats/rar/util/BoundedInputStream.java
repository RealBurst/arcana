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

import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;

/**
 * InputStream that limits reads to a specific region of a RandomAccessFile.
 */
public class BoundedInputStream extends InputStream {
    private final RandomAccessFile file;
    private final long end;
    private long pos;

    public BoundedInputStream(RandomAccessFile file, long length) throws IOException {
        this.file = file;
        this.pos = file.getFilePointer();
        this.end = pos + length;
    }

    @Override
    public int read() throws IOException {
        if (pos >= end) return -1;
        if (file.getFilePointer() != pos) {
            file.seek(pos);
        }
        int b = file.read();
        if (b != -1) pos++;
        return b;
    }
    
    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (pos >= end) return -1;
        long canRead = end - pos;
        if (len > canRead) len = (int) canRead;
        
        if (file.getFilePointer() != pos) {
            file.seek(pos);
        }
        int bytesRead = file.read(b, off, len);
        if (bytesRead != -1) pos += bytesRead;
        return bytesRead;
    }
    
    @Override
    public int available() {
        return (int) Math.max(0, end - pos);
    }
}
