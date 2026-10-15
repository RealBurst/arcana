/*
 * Copyright 2026 Stephane Bury
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
package be.stef.arcana.extractor;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.dmg.DmgContent;
import be.stef.arcana.formats.dmg.UdifImage;
import be.stef.arcana.formats.hfs.HfsPlusReader;
import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Extractor for Apple disk images (.dmg, UDIF): the files of the HFS+ / HFSX
 * volumes, and a raw image of the other partitions (APFS, FAT...), see
 * {@link DmgContent}.
 *
 * <p>Symbolic links are extracted as empty files, like the CPIO, TAR and
 * SquashFS extractors; resource forks are skipped. The data fork CRC32 is
 * checked before the extraction and the CRC32 of each extracted partition
 * at the end. A disk image needs random access, so
 * {@link #extract(InputStream, File)} is not supported.</p>
 *
 * @author Stef
 * @since 1.5
 */
public class DmgExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return false;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (UdifImage img = UdifImage.open(archive)) {
            img.verifyDataFork();
            // one reader per partition (its cache and chunk checksums are shared by the items of a "whole disk" partition)
            final Map<UdifImage.Partition, UdifImage.PartitionReader> readers = new LinkedHashMap<UdifImage.Partition, UdifImage.PartitionReader>();
            for (final DmgContent.Item it : DmgContent.plan(img)) {
                if (it.kind != DmgContent.HFS && it.kind != DmgContent.RAW) continue;
                UdifImage.PartitionReader pr = readers.get(it.partition);
                if (pr == null) {
                    pr = img.openPartition(it.partition);
                    readers.put(it.partition, pr);
                }
                final HfsPlusReader.Source src = DmgContent.view(pr, it);
                if (it.kind == DmgContent.HFS) {
                    final HfsPlusReader reader = new HfsPlusReader(src);
                    reader.walk(e -> {
                        final File target = SafePathBuilder.buildSafePath(destination, join(it.target, e.path));
                        if (e.kind == HfsPlusReader.DIRECTORY) {
                            IOHelper.mkdirs(target);
                            return;
                        }
                        IOHelper.mkdirs(target.getParentFile());
                        try (BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                            reader.copyFile(e, out);
                        }
                        if (e.mtime > 0) target.setLastModified(e.mtime * 1000L);
                    });
                } else {
                    final File target = SafePathBuilder.buildSafePath(destination, it.target);
                    try (BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                        DmgContent.copy(src, out);
                    }
                }
            }
            for (final UdifImage.PartitionReader pr : readers.values()) pr.verifyChecksum();
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        throw new ArcanaUnsupportedFormatException("DMG requires random file access - use extract(File,File).");
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (UdifImage img = UdifImage.open(archive)) {
            for (final DmgContent.Item it : DmgContent.plan(img)) {
                if (it.kind == DmgContent.HFS) {
                    if (!it.target.isEmpty()) result.add(new ArcanaEntry.Builder(it.target).directory(true).format(ArcanaFormat.DMG).build());
                    new HfsPlusReader(DmgContent.view(img.openPartition(it.partition), it)).walk(e -> result.add(new ArcanaEntry.Builder(join(it.target, e.path)).uncompressedSize(e.size).lastModifiedTime(e.mtime).directory(e.kind == HfsPlusReader.DIRECTORY).format(ArcanaFormat.DMG).build()));
                } else if (it.kind == DmgContent.RAW) {
                    result.add(new ArcanaEntry.Builder(it.target).uncompressedSize(it.length).format(ArcanaFormat.DMG).build());
                }
            }
        }
        return result;
    }

    private static String join(final String prefix, final String path) {
        return prefix.isEmpty() ? path : prefix + "/" + path;
    }
}
