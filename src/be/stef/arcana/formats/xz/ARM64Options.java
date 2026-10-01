// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: The XZ for Java authors and contributors
// SPDX-FileContributor: Lasse Collin <lasse.collin@tukaani.org>

/* Ported from org.tukaani.xz (XZ for Java). Original licence: 0BSD. Changes: package only. */
package be.stef.arcana.formats.xz;

import java.io.InputStream;
import be.stef.arcana.formats.xz.simple.ARM64;

/**
 * BCJ filter for ARM64 (AArch64) instructions.
 *
 * @since 1.10
 */
public final class ARM64Options extends BCJOptions {
    private static final int ALIGNMENT = 4;

    public ARM64Options() {
        super(ALIGNMENT);
    }

    @Override
    public FinishableOutputStream getOutputStream(FinishableOutputStream out,
                                                  ArrayCache arrayCache) {
        return new SimpleOutputStream(out, new ARM64(true, startOffset));
    }

    @Override
    public InputStream getInputStream(InputStream in, ArrayCache arrayCache) {
        return new SimpleInputStream(in, new ARM64(false, startOffset));
    }

}
