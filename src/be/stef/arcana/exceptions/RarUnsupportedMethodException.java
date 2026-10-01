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

public class RarUnsupportedMethodException extends IOException {

    private static final long serialVersionUID = 1L;

    private final int method;
    private final int version;

    public RarUnsupportedMethodException(int method, int version) {
        super(String.format("Unsupported compression method 0x%02X (version %d)", method, version));
        this.method = method;
        this.version = version;
    }

    public int getMethod()  { return method; }
    public int getVersion() { return version; }
}