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
 * Thrown when an extraction is stopped by a limit of
 * {@link be.stef.arcana.util.ExtractionLimits} (probable decompression bomb, or not
 * enough free disk space). The file being written is deleted.
 *
 * @author Stef
 * @since 1.3
 */
public class ArcanaLimitExceededException extends ArcanaException {

    private static final long serialVersionUID = 1L;

    public ArcanaLimitExceededException(String message) {
        super(message);
    }
}
