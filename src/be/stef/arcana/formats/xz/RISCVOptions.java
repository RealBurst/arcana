// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: The XZ for Java authors and contributors
// SPDX-FileContributor: Lasse Collin <lasse.collin@tukaani.org>

/* Ported from org.tukaani.xz (XZ for Java). Original licence: 0BSD. Changes: package only. */
package be.stef.arcana.formats.xz;

import java.io.InputStream;
import be.stef.arcana.formats.xz.simple.RISCVDecoder;

/**
 * BCJ filter for RISC-V instructions.
 *
 * @since 1.10
 */
public final class RISCVOptions extends BCJOptions {
    private static final int ALIGNMENT = 2;

    public RISCVOptions() {
        super(ALIGNMENT);
    }

    @Override
    public InputStream getInputStream(InputStream in, ArrayCache arrayCache) {
        return new SimpleInputStream(in, new RISCVDecoder(startOffset));
    }


}
