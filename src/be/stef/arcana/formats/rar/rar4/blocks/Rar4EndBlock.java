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
package be.stef.arcana.formats.rar.rar4.blocks;

/**
 * RAR4 end of archive block (type 0x7B).
 *
 * <p>No specific data beyond the common header.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class Rar4EndBlock extends Rar4Block {

    @Override
    public boolean parseSpecificData(byte[] buf, int offset, int length) {
        // No specific data in end block
        return true;
    }

}