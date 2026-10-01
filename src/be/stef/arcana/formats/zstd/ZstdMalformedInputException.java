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
 * Derived from io.airlift.compress.MalformedInputException (aircompressor 0.27).
 * Ported to package be.stef.arcana.formats.zstd to avoid any external dependency.
 */
package be.stef.arcana.formats.zstd;

/**
 * Thrown when the Zstandard decompressor encounters malformed or corrupted input data.
 *
 * <p>This is a port of {@code io.airlift.compress.MalformedInputException} from
 * the aircompressor library (v0.27), relocated to eliminate the external dependency.</p>
 *
 * @author aircompressor contributors (original), ported by Stef
 * @since 2.0
 */
public class ZstdMalformedInputException extends RuntimeException
{
    private final long offset;

    public ZstdMalformedInputException(long offset)
    {
        this(offset, "Malformed input");
    }

    public ZstdMalformedInputException(long offset, String reason)
    {
        super(reason + ": offset=" + offset);
        this.offset = offset;
    }

    public long getOffset()
    {
        return offset;
    }
}
