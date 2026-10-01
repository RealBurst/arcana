// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: The XZ for Java authors and contributors
// SPDX-FileContributor: Lasse Collin <lasse.collin@tukaani.org>

/* Ported from org.tukaani.xz.check (XZ for Java). Original licence: 0BSD. Changes: package only. */
package be.stef.arcana.formats.xz.check;

import be.stef.arcana.formats.xz.common.ByteArrayView;

public class CRC32 extends Check {
    private final java.util.zip.CRC32 state = new java.util.zip.CRC32();

    public CRC32() {
        size = 4;
        name = "CRC32";
    }

    @Override
    public void update(byte[] buf, int off, int len) {
        state.update(buf, off, len);
    }

    @Override
    public byte[] finish() {
        byte[] buf = new byte[4];
        ByteArrayView.setIntLE(buf, 0, (int)state.getValue());
        state.reset();
        return buf;
    }
}
