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
package be.stef.arcana.formats.rar.rar5;

import be.stef.arcana.formats.rar.util.SafePathBuilder;
import be.stef.arcana.formats.rar.rar5.decompress.Rar5LZDecoder;

/**
 * Per-thread extraction context: groups the mutable objects that must NOT be
 * shared between concurrent extraction tasks.
 *
 * <p>In sequential mode one instance is reused for all files. In parallel mode
 * each task gets its own instance so there is no shared mutable state between
 * threads.</p>
 *
 * <ul>
 *   <li>{@link #decoder} - the LZ sliding-window decoder; its state carries
 *       over between files only for solid archives, which are always sequential.</li>
 *   <li>{@link #pathBuilder} - tracks written paths for collision avoidance;
 *       its internal {@code HashSet} is not thread-safe.</li>
 * </ul>
 *
 * @author Stef
 * @since 2.0.2
 */
public final class ExtractionContext {

    /** LZ decoder; may be null (lazily created on first use). */
    public Rar5LZDecoder decoder;

    /** Safe path builder; never null after construction. */
    public final SafePathBuilder pathBuilder;

    /**
     * Creates a context with a fresh decoder and the given path builder.
     *
     * @param pathBuilder the safe path builder for this context
     */
    public ExtractionContext(SafePathBuilder pathBuilder) {
        this.pathBuilder = pathBuilder;
    }
}
