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
package be.stef.arcana.util;

import java.io.OutputStream;

/**
 * An {@link OutputStream} that discards all bytes written to it.
 *
 * <p>Used by extractors when the caller wants to validate or skip an entry
 * without writing any data to disk (e.g. CRC verification without extraction,
 * or skipping solid-archive entries to reach a target file).</p>
 *
 * @author Stef
 * @since 1.0
 */
public final class NullOutputStream extends OutputStream {

    @Override
    public void write(int b) {
        // discard
    }

    @Override
    public void write(byte[] b, int off, int len) {
        // discard
    }

    @Override
    public void write(byte[] b) {
        // discard
    }
}
