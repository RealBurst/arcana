/*
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
/*
 * Derived from io.airlift.compress.IncompatibleJvmException (aircompressor 0.27).
 * Ported to package be.stef.arcana.formats.zstd to avoid any external dependency.
 */
package be.stef.arcana.formats.zstd;

/**
 * Thrown at class-loading time when the JVM does not meet the requirements
 * of the Zstandard decompressor (little-endian platform required;
 * sun.misc.Unsafe is used when available, with automatic fallback to
 * pure-Java array reads via {@link MemoryAccess}).
 *
 * <p>This is a port of {@code io.airlift.compress.IncompatibleJvmException} from
 * the aircompressor library (v0.27), relocated to eliminate the external dependency.</p>
 *
 * @author aircompressor contributors (original), ported by Stef
 * @since 2.0
 */
public class ZstdIncompatibleJvmException extends RuntimeException
{
    public ZstdIncompatibleJvmException(String message)
    {
        super(message);
    }
}
