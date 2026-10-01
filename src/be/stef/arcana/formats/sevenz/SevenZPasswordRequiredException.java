/* Copyright 2025 Stephane Bury. Apache License 2.0. */
package be.stef.arcana.formats.sevenz;
import java.io.IOException;
public class SevenZPasswordRequiredException extends IOException {
    private static final long serialVersionUID = 1L;
    public SevenZPasswordRequiredException(String archiveName) {
        super("Archive is encrypted but no password was specified: " + archiveName);
    }
}
