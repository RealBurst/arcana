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
package be.stef.arcana.exceptions;

import java.io.IOException;

/**
 * Root exception for all Arcana errors.
 *
 * <p>Extends {@link IOException} so callers that already handle I/O exceptions
 * do not need an additional catch block.  More specific conditions are
 * represented by subclasses:</p>
 * <ul>
 *   <li>{@link ArcanaUnsupportedFormatException} - format not recognised or not supported</li>
 *   <li>{@link ArcanaCorruptedException}          - archive data is corrupted</li>
 *   <li>{@link ArcanaEncryptedException}          - archive or entry is password-protected</li>
 * </ul>
 *
 * @author Stef
 * @since 1.0
 */
public class ArcanaException extends IOException {

    private static final long serialVersionUID = 1L;

    public ArcanaException(String message) {
        super(message);
    }

    public ArcanaException(String message, Throwable cause) {
        super(message, cause);
    }

    public ArcanaException(Throwable cause) {
        super(cause);
    }
}
