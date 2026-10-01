// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: The XZ for Java authors and contributors
// SPDX-FileContributor: Lasse Collin <lasse.collin@tukaani.org>

/* Ported from org.tukaani.xz.simple (XZ for Java). Original licence: 0BSD. Changes: package only. */
package be.stef.arcana.formats.xz.simple;

public interface SimpleFilter {
    int code(byte[] buf, int off, int len);
}
