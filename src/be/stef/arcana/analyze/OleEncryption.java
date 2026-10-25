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
package be.stef.arcana.analyze;

import be.stef.arcana.formats.ole.CompoundFile;
import java.io.File;
import java.io.IOException;

/**
 * Recognizes an encrypted Office Open XML document: a password-protected
 * .docx / .xlsx / .pptx is not a ZIP but an OLE compound file holding the
 * streams "EncryptionInfo" and "EncryptedPackage" ([MS-OFFCRYPTO] 2.3.4).
 * The version of EncryptionInfo gives the kind of encryption.
 *
 * @author Stef
 * @since 1.1.0
 */
public final class OleEncryption {

    private OleEncryption() {
    }

    /**
     * @return the kind of encryption ("ECMA-376 agile encryption", "ECMA-376
     *         standard encryption"...) if {@code file} is an encrypted OOXML
     *         document, else null (also when the file cannot be read)
     */
    public static String ooxml(final File file) {
        if (file == null) return null;
        try (CompoundFile cf = new CompoundFile(file)) {
            CompoundFile.Node info = null;
            boolean pkg = false;
            for (final CompoundFile.Node n : cf.getRoot().children) {
                if (n.storage) continue;
                if (n.name.equals("EncryptionInfo")) info = n;
                else if (n.name.equals("EncryptedPackage")) pkg = true;
            }
            if (info == null || !pkg || info.size < 4) return null;
            if (info.size > (1 << 20)) return "ECMA-376 encryption";
            final byte[] b = cf.read(info);
            final int major = (b[0] & 0xFF) | ((b[1] & 0xFF) << 8);
            final int minor = (b[2] & 0xFF) | ((b[3] & 0xFF) << 8);
            final String v = " (EncryptionInfo " + major + "." + minor + ")";
            if (major == 4 && minor == 4) return "ECMA-376 agile encryption" + v;
            if ((major == 3 || major == 4) && minor == 2) return "ECMA-376 standard encryption" + v;
            if ((major == 3 || major == 4) && minor == 3) return "ECMA-376 extensible encryption" + v;
            return "ECMA-376 encryption" + v;
        } catch (final IOException | RuntimeException e) {
            return null;
        }
    }
}
