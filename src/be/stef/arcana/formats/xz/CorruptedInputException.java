// SPDX-License-Identifier: 0BSD
// SPDX-FileCopyrightText: The XZ for Java authors and contributors
// SPDX-FileContributor: Lasse Collin <lasse.collin@tukaani.org>

/* Ported from org.tukaani.xz (XZ for Java). Original licence: 0BSD. Changes: package only. */
package be.stef.arcana.formats.xz;

/**
 * Thrown when the compressed input data is corrupt.
 * However, it is possible that some or all of the data
 * already read from the input stream was corrupt too.
 */
public class CorruptedInputException extends XZIOException {
    private static final long serialVersionUID = 3L;

    /**
     * Creates a new CorruptedInputException with
     * the default error detail message.
     */
    public CorruptedInputException() {
        super("Compressed data is corrupt");
    }

    /**
     * Creates a new CorruptedInputException with
     * the specified error detail message.
     *
     * @param       s           error detail message
     */
    public CorruptedInputException(String s) {
        super(s);
    }
}
