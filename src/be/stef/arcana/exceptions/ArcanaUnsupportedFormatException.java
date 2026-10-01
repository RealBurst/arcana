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

/**
 * Thrown when the archive format is not recognised or not supported by Arcana.
 *
 * @author Stef
 * @since 1.0
 */
public class ArcanaUnsupportedFormatException extends ArcanaException {

    private static final long serialVersionUID = 1L;

    public ArcanaUnsupportedFormatException(String message) {
        super(message);
    }

    public ArcanaUnsupportedFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
