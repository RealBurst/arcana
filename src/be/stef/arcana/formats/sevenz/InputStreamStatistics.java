/* Copyright 2025 Stephane Bury. Apache License 2.0. */
/* Ported from org.apache.commons.compress.utils.InputStreamStatistics. Apache License 2.0. */
package be.stef.arcana.formats.sevenz;

/**
 * Provides statistics on the number of bytes compressed and uncompressed
 * for the current entry being read from a 7z archive.
 */
public interface InputStreamStatistics {
    /**
     * Returns the number of compressed bytes read from the current entry.
     * @return compressed byte count
     */
    long getCompressedCount();

    /**
     * Returns the number of uncompressed bytes read from the current entry.
     * @return uncompressed byte count
     */
    long getUncompressedCount();
}
