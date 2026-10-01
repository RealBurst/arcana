// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: The XZ for Java authors and contributors
// SPDX-FileContributor: Lasse Collin <lasse.collin@tukaani.org>
// SPDX-FileContributor: Igor Pavlov <https://7-zip.org/>

/* Ported from org.tukaani.xz.rangecoder (XZ for Java). Original licence: 0BSD. Changes: package only. */
package be.stef.arcana.formats.xz.rangecoder;

import java.io.InputStream;
import be.stef.arcana.formats.xz.CorruptedInputException;
import java.io.DataInputStream;
import java.io.IOException;

public final class RangeDecoderFromStream extends RangeDecoder {
    private final DataInputStream inData;

    public RangeDecoderFromStream(InputStream in) throws IOException {
        inData = new DataInputStream(in);

        if (inData.readUnsignedByte() != 0x00)
            throw new CorruptedInputException();

        code = inData.readInt();
        range = 0xFFFFFFFF;
    }

    public boolean isFinished() {
        return code == 0;
    }

    @Override
    public void normalize() throws IOException {
        if ((range & TOP_MASK) == 0) {
            code = (code << SHIFT_BITS) | inData.readUnsignedByte();
            range <<= SHIFT_BITS;
        }
    }
}
