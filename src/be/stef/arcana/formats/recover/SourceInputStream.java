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
package be.stef.arcana.formats.recover;

import be.stef.arcana.formats.carve.ByteSource;
import java.io.IOException;
import java.io.InputStream;

/** InputStream over a range of a {@link ByteSource} (the source is not closed). */
final class SourceInputStream extends InputStream {

    private final ByteSource s;
    private long pos;
    private final long end;

    SourceInputStream(final ByteSource s, final long start, final long length) {
        this.s = s;
        this.pos = start;
        this.end = Math.min(s.length(), start + Math.max(0, length));
    }

    @Override
    public int read() throws IOException {
        if (pos >= end) return -1;
        return s.u8(pos++);
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        if (len == 0) return 0;
        if (pos >= end) return -1;
        final int n = s.read(pos, b, off, (int) Math.min(len, end - pos));
        if (n <= 0) return -1;
        pos += n;
        return n;
    }

    @Override
    public long skip(final long n) {
        final long k = Math.max(0, Math.min(n, end - pos));
        pos += k;
        return k;
    }
}
