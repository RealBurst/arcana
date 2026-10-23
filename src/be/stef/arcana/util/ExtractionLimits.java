/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.stef.arcana.util;

/**
 * Global limits against decompression bombs, enforced by {@link ExtractionGuard}
 * on the bytes <b>actually written</b> during an extraction (sizes declared in
 * archive headers can be forged, so they are never trusted).
 *
 * <p>Defaults are chosen so that legitimate archives are not blocked - highly
 * compressible data (logs, PPMd text, sparse images) routinely exceeds 1000:1 on
 * small files:</p>
 * <ul>
 *   <li>{@link #minFreeSpace}: 256 MB always kept free on the destination disk - this
 *       is the protection that matters (a bomb's harm is filling the disk);</li>
 *   <li>{@link #maxRatio} 1000:1 (bytes written / archive size), enforced only once
 *       {@link #ratioThreshold} (1 GB) has been written - a 176 KB archive may give
 *       241 MB, not 1 GB and more;</li>
 *   <li>{@link #maxTotalBytes}: no absolute limit by default.</li>
 * </ul>
 *
 * <p>Set a value to 0 to disable that check. The static fields are the global
 * defaults, read at each check, so they can be changed at any time.</p>
 *
 * <p>An extraction can also use its own limits, without touching the global
 * ones (an ingestion pipeline running several extractions at once):</p>
 * <pre>
 *     ExtractionLimits.Values limits = ExtractionLimits.current().maxTotalBytes(10L &lt;&lt; 30).minFreeSpace(0);
 *     Arcana.withLimits(limits).extract(archive, destination);
 *     Arcana.withPassword(pwd).limits(ExtractionLimits.none()).extract(archive, destination);
 * </pre>
 *
 * @author Stef
 * @since 1.3
 */
public final class ExtractionLimits {

    /** Maximum bytes written by one extraction (all entries together). 0 = unlimited. */
    public static volatile long maxTotalBytes = 0;

    /** Maximum ratio bytes written / archive size. 0 = disabled. */
    public static volatile long maxRatio = 1000;

    /** The ratio is only enforced once this many bytes have been written. */
    public static volatile long ratioThreshold = 1L << 30;

    /** Minimum free space to keep on the destination disk. 0 = disabled. */
    public static volatile long minFreeSpace = 256L << 20;

    /** Free space is re-checked every this many bytes written. */
    public static volatile long freeSpaceCheckInterval = 16L << 20;

    private ExtractionLimits() {}

    /** Copy of the current global limits, to adjust for one extraction. */
    public static Values current() {
        return new Values(maxTotalBytes, maxRatio, ratioThreshold, minFreeSpace, freeSpaceCheckInterval);
    }

    /** No limit at all (every check disabled). */
    public static Values none() {
        return new Values(0, 0, 0, 0, freeSpaceCheckInterval);
    }

    /**
     * Limits of one extraction (see {@link be.stef.arcana.Arcana#limits(Values)}).
     * Same meaning as the static fields; 0 disables a check. The setters change
     * this object and return it, for chaining.
     */
    public static final class Values {
        private long maxTotalBytes;
        private long maxRatio;
        private long ratioThreshold;
        private long minFreeSpace;
        private long freeSpaceCheckInterval;

        private Values(final long maxTotalBytes, final long maxRatio, final long ratioThreshold, final long minFreeSpace, final long freeSpaceCheckInterval) {
            this.maxTotalBytes = maxTotalBytes;
            this.maxRatio = maxRatio;
            this.ratioThreshold = ratioThreshold;
            this.minFreeSpace = minFreeSpace;
            this.freeSpaceCheckInterval = freeSpaceCheckInterval;
        }

        /** Independent copy. */
        public Values copy() {
            return new Values(maxTotalBytes, maxRatio, ratioThreshold, minFreeSpace, freeSpaceCheckInterval);
        }

        public Values maxTotalBytes(final long v) { maxTotalBytes = v; return this; }
        public Values maxRatio(final long v) { maxRatio = v; return this; }
        public Values ratioThreshold(final long v) { ratioThreshold = v; return this; }
        public Values minFreeSpace(final long v) { minFreeSpace = v; return this; }
        public Values freeSpaceCheckInterval(final long v) { freeSpaceCheckInterval = v; return this; }

        public long getMaxTotalBytes() { return maxTotalBytes; }
        public long getMaxRatio() { return maxRatio; }
        public long getRatioThreshold() { return ratioThreshold; }
        public long getMinFreeSpace() { return minFreeSpace; }
        public long getFreeSpaceCheckInterval() { return freeSpaceCheckInterval; }

        @Override
        public String toString() {
            return "maxTotalBytes=" + maxTotalBytes + ", maxRatio=" + maxRatio + ", ratioThreshold=" + ratioThreshold + ", minFreeSpace=" + minFreeSpace + ", freeSpaceCheckInterval=" + freeSpaceCheckInterval;
        }
    }
}
