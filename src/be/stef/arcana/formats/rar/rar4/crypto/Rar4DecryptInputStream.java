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
package be.stef.arcana.formats.rar.rar4.crypto;

import java.io.IOException;
import java.io.InputStream;
import javax.crypto.Cipher;

/**
 * InputStream that decrypts an AES-128 CBC stream on the fly, block by block.
 *
 * <p>RAR4 encrypts file data in 16-byte AES-CBC blocks. This stream reads the
 * encrypted bytes from the underlying stream, decrypts them in bulk, and serves
 * the plaintext to the consumer (the LZ decompressor).</p>
 *
 * @author Stef
 * @since 1.0
 */
public class Rar4DecryptInputStream extends InputStream {

    private final InputStream in;
    private final Cipher      cipher;
    private final byte[]      encBuf = new byte[8192]; // multiple of 16
    private byte[]            outBuf = new byte[0];
    private int               outPos;
    private boolean           eof;

    public Rar4DecryptInputStream(InputStream in, Cipher cipher) {
        this.in     = in;
        this.cipher = cipher;
    }

    private boolean fill() throws IOException {
        if (eof) return false;
        int got = 0;
        while (got < encBuf.length) {
            int r = in.read(encBuf, got, encBuf.length - got);
            if (r == -1) { eof = true; break; }
            got += r;
        }
        if (got == 0) { eof = true; return false; }
        int blocks = got / 16; // ignore any sub-16 remainder (shouldn't occur)
        if (blocks == 0) { eof = true; return false; }
        outBuf = cipher.update(encBuf, 0, blocks * 16);
        outPos = 0;
        return outBuf != null && outBuf.length > 0;
    }

    @Override
    public int read() throws IOException {
        while (outPos >= outBuf.length) {
            if (!fill()) return -1;
        }
        return outBuf[outPos++] & 0xFF;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            if (outPos >= outBuf.length) {
                if (!fill()) break;
            }
            int n = Math.min(len - total, outBuf.length - outPos);
            System.arraycopy(outBuf, outPos, b, off + total, n);
            outPos += n;
            total  += n;
        }
        return total == 0 ? -1 : total;
    }
}