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
package be.stef.arcana.plugin;

import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.compressor.ArchiveCompressor;
import be.stef.arcana.detector.ArchiveDetector;
import be.stef.arcana.extractor.ArchiveExtractor;
import java.io.IOException;

/**
 * A format built into Arcana, exposed through the same interface as the
 * plugins ({@link ArcanaPlugin}). The instances are created by
 * {@link FormatRegistry}; the content detection of the built-in formats stays
 * in {@link ArchiveDetector} (order-sensitive magic bytes, ISO, extensions).
 *
 * @author Stef
 * @since 1.3
 */
public final class BuiltinFormat implements ArcanaPlugin {

    /** Group of the format in the listings. */
    public enum Category { ARCHIVE, SINGLE_FILE, OTHER }

    /** Creates the extractor of the format. */
    interface ExtractorFactory {
        ArchiveExtractor create(byte[] password) throws IOException;
    }

    /** Creates the compressor of the format. */
    interface CompressorFactory {
        ArchiveCompressor create(int level, byte[] password) throws IOException;
    }

    private final ArcanaFormat format;
    private final Category category;
    private final String[] names;
    private final String display;
    private final String description;
    private final String compressDescription;
    private final ExtractorFactory extractor;
    private final CompressorFactory compressor;

    BuiltinFormat(final ArcanaFormat format, final Category category, final String[] names, final String display, final String description, final ExtractorFactory extractor, final String compressDescription, final CompressorFactory compressor) {
        this.format = format;
        this.category = category;
        this.names = names;
        this.display = display;
        this.description = description;
        this.extractor = extractor;
        this.compressDescription = compressDescription;
        this.compressor = compressor;
    }

    /** The format constant of the public API. */
    public ArcanaFormat getFormat() {
        return format;
    }

    public Category getCategory() {
        return category;
    }

    /** Extensions shown in the listings (may include detection-only extensions: jar, cbr...). */
    public String getDisplayExtensions() {
        return display;
    }

    /** Description of the extraction support. */
    public String getDescription() {
        return description;
    }

    /** Description of the compression support, or null if Arcana cannot create this format. */
    public String getCompressDescription() {
        return compressor != null ? compressDescription : null;
    }

    public boolean canCompress() {
        return compressor != null;
    }

    @Override public String getId() { return "arcana." + names[0]; }
    @Override public String getName() { return format.getLabel(); }
    @Override public String getVersion() { return "built-in"; }
    @Override public String getAuthor() { return "Arcana"; }
    @Override public String getSourceUrl() { return "(built into Arcana)"; }
    @Override public String getLicense() { return "Apache-2.0"; }

    /** Names accepted by -f / -t (e.g. "tar.gz", "tgz"). */
    @Override
    public String[] getExtensions() {
        return names.clone();
    }

    @Override
    public int getProbeSize() {
        return 264;
    }

    /** Content detection by magic bytes (the ISO signature at 32 KB is not visible here). */
    @Override
    public boolean matches(final byte[] header, final String fileName) {
        return ArchiveDetector.detectByMagic(header) == format;
    }

    @Override
    public ArchiveExtractor createExtractor(final byte[] password) throws IOException {
        return extractor.create(password);
    }

    @Override
    public ArchiveCompressor createCompressor(final int level) throws IOException {
        return createCompressor(level, null);
    }

    @Override
    public ArchiveCompressor createCompressor(final int level, final byte[] password) throws IOException {
        return compressor != null ? compressor.create(level, password) : null;
    }

    @Override
    public String toString() {
        return getId();
    }
}
