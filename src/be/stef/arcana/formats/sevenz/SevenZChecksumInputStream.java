/* Copyright 2025 Stephane Bury. Apache License 2.0. */
package be.stef.arcana.formats.sevenz;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.CRC32;
/** Replaces commons-io ChecksumInputStream for 7z CRC32 verification. */
final class SevenZChecksumInputStream extends InputStream {
    private final InputStream in;
    private final CRC32 crc;
    private final long countThreshold;
    private final long expectedChecksum;
    private long count = 0;
    private long remaining;
    SevenZChecksumInputStream(InputStream in, CRC32 crc, long countThreshold, long expectedChecksum) {
        this.in = in; this.crc = crc != null ? crc : new CRC32();
        this.countThreshold = countThreshold; this.expectedChecksum = expectedChecksum;
        this.remaining = countThreshold >= 0 ? countThreshold : Long.MAX_VALUE;
    }
    @Override public int read() throws IOException {
        int b = in.read();
        if (b >= 0) { crc.update(b); count++; if (remaining != Long.MAX_VALUE) remaining--; verifyIfDone(); }
        return b;
    }
    @Override public int read(byte[] buf, int off, int len) throws IOException {
        int n = in.read(buf, off, len);
        if (n > 0) { crc.update(buf, off, n); count += n; if (remaining != Long.MAX_VALUE) remaining -= n; verifyIfDone(); }
        return n;
    }
    @Override public void close() throws IOException { in.close(); }
    long getRemaining() { return remaining == Long.MAX_VALUE ? 0 : remaining; }
    long getCount() { return count; }
    private void verifyIfDone() throws IOException {
        if (countThreshold >= 0 && count >= countThreshold && expectedChecksum >= 0) {
            long actual = crc.getValue();
            if (actual != expectedChecksum) throw new IOException("7z CRC32 mismatch: expected 0x" + Long.toHexString(expectedChecksum) + " got 0x" + Long.toHexString(actual));
        }
    }
}
