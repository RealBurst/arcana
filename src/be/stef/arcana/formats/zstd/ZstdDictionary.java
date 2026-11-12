/*
 * Copyright 2026 Stephane Bury
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
package be.stef.arcana.formats.zstd;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;

/**
 * A Zstandard dictionary (RFC 8878, section 5), used to decode the frames
 * whose header gives its ID.
 *
 * <p>Two forms: a dictionary made by {@code zstd --train} (magic
 * {@code 37 A4 30 EC}, ID, entropy tables, repeated offsets, then the
 * content), or raw content (any other bytes: ID 0, no tables). The content
 * stands before the first byte of the frame: matches may copy from it.</p>
 *
 * @author Stef
 * @since 1.2.0
 */
public final class ZstdDictionary {

    private static final int MAGIC = 0xEC30A437;

    /** Gives the dictionary of an ID, or null when it is not known. */
    public interface Provider {
        ZstdDictionary get(long id);
    }

    private final byte[] data;
    private final long id;
    private final boolean hasTables;
    private final int contentStart;

    private ZstdDictionary(final byte[] data) throws IOException {
        this.data = data;
        if (data.length >= 8 && le32(data, 0) == MAGIC) {
            id = le32(data, 4) & 0xFFFFFFFFL;
            hasTables = true;
            final ZstdFrameDecompressor check = new ZstdFrameDecompressor();
            check.reset();
            try {
                contentStart = check.loadDictionary(data);
            } catch (final RuntimeException e) {
                throw new IOException("Invalid Zstandard dictionary: " + e.getMessage(), e);
            }
        } else {
            id = 0;
            hasTables = false;
            contentStart = 0;
        }
    }

    /** Dictionary from its bytes (copied). */
    public static ZstdDictionary of(final byte[] bytes) throws IOException {
        return new ZstdDictionary(Arrays.copyOf(bytes, bytes.length));
    }

    /** Dictionary from a file (".zsdic", output of zstd --train...). */
    public static ZstdDictionary of(final File file) throws IOException {
        return new ZstdDictionary(Files.readAllBytes(file.toPath()));
    }

    /** ID of the dictionary; 0 for raw content. */
    public long getId() {
        return id;
    }

    /** Size of the content (the bytes that frames may copy). */
    public int getContentSize() {
        return data.length - contentStart;
    }

    /** Provider of a list of dictionaries, by ID. */
    public static Provider provider(final Iterable<ZstdDictionary> dictionaries) {
        final java.util.Map<Long, ZstdDictionary> map = new java.util.HashMap<Long, ZstdDictionary>();
        for (final ZstdDictionary d : dictionaries) map.put(d.getId(), d);
        return map::get;
    }

    /** Loads the tables in {@code decoder} (after reset) and returns the content start. */
    int load(final ZstdFrameDecompressor decoder) {
        return hasTables ? decoder.loadDictionary(data) : 0;
    }

    /** Copies the content to {@code dst}. */
    void copyContent(final byte[] dst, final int off) {
        System.arraycopy(data, contentStart, dst, off, data.length - contentStart);
    }

    private static int le32(final byte[] b, final int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8) | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
    }
}
