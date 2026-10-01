/* Copyright 2025 Stephane Bury. Apache License 2.0. */
package be.stef.arcana.formats.sevenz;
import java.io.IOException;
public class SevenZMemoryLimitException extends IOException {
    private static final long serialVersionUID = 1L;
    private final long needed;
    private final int limit;
    public SevenZMemoryLimitException(int needed, int limit) {
        super("Memory limit " + limit + " KiB exceeded (need " + needed + " KiB)");
        this.needed = needed; this.limit = limit;
    }
    public SevenZMemoryLimitException(long needed, int limit) {
        super("Memory limit " + limit + " KiB exceeded (need " + needed + " KiB)");
        this.needed = needed; this.limit = limit;
    }
    public long getMemoryNeededInKiB() { return needed; }
    public int getMemoryLimitInKiB() { return limit; }
}
