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
package be.stef.arcana.analyze;

import be.stef.arcana.formats.carve.ByteSource;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Identifies databases and structured data files: SQLite, OLE2 compound files
 * (legacy Office, MSI), and a few common data signatures.
 *
 * @author Stef
 * @since 1.4
 */
public final class DataAnalyzer implements ArcanaAnalyzer {

    @Override
    public String getId() {
        return "arcana.data";
    }

    @Override
    public Identification analyze(final ByteSource s, final String fileName) throws IOException {
        if (s.matches(0, "SQLite format 3\0".getBytes(StandardCharsets.US_ASCII))) return sqlite(s);
        if (s.u8(0) == 0xD0 && s.u8(1) == 0xCF && s.u8(2) == 0x11 && s.u8(3) == 0xE0) return ole(s, fileName);
        if (s.matches(0, "SQLite".getBytes(StandardCharsets.US_ASCII))) return simple("database", "SQLite", "SQLite database (older format)");
        if (s.matches(4, "Standard Jet DB".getBytes(StandardCharsets.US_ASCII)) || s.matches(4, "Standard ACE DB".getBytes(StandardCharsets.US_ASCII))) return simple("database", "Access", "Microsoft Access (Jet/ACE) database");
        if (s.matches(0, "regf".getBytes(StandardCharsets.US_ASCII))) return simple("data", "Registry", "Windows registry hive");
        if (s.u8(0) == 0xEF && s.u8(1) == 0xBB && s.u8(2) == 0xBF) return simple("document", "text (UTF-8)", "UTF-8 text (with byte-order mark)");
        if (s.u8(0) == 0xFF && s.u8(1) == 0xFE) return simple("document", "text (UTF-16 LE)", "UTF-16 little-endian text");
        if (s.u8(0) == 0xFE && s.u8(1) == 0xFF) return simple("document", "text (UTF-16 BE)", "UTF-16 big-endian text");
        return null;
    }

    private static Identification sqlite(final ByteSource s) throws IOException {
        // Header fields (big-endian): page size at 16, write/read version at 18/19, app id at 68, user version at 60.
        int pageSize = s.u16be(16);
        if (pageSize == 1) pageSize = 65536; // stored as 1 for a 64 KB page
        final long userVersion = s.u32be(60);
        final long appId = s.u32be(68);
        final Identification.Builder b = Identification.of("database", "SQLite")
                .version("3")
                .description("SQLite 3 database")
                .detail("page size", pageSize + " bytes");
        if (userVersion != 0) b.detail("user_version", userVersion);
        if (appId != 0) b.detail("application_id", String.format("0x%08X", appId));
        return b.build();
    }

    private static Identification ole(final ByteSource s, final String fileName) throws IOException {
        // OLE2 / Compound File Binary: legacy Office, MSI, MSG... Subtype needs the directory; use the name as a hint.
        final String n = fileName != null ? fileName.toLowerCase() : "";
        String type = "OLE2", desc = "OLE2 compound file (legacy Office document, MSI, or similar)";
        if (n.endsWith(".doc")) { type = "DOC"; desc = "Word 97-2003 document (OLE2)"; }
        else if (n.endsWith(".xls")) { type = "XLS"; desc = "Excel 97-2003 workbook (OLE2)"; }
        else if (n.endsWith(".ppt")) { type = "PPT"; desc = "PowerPoint 97-2003 presentation (OLE2)"; }
        else if (n.endsWith(".msi")) { type = "MSI"; desc = "Windows Installer package (OLE2)"; }
        else if (n.endsWith(".msg")) { type = "MSG"; desc = "Outlook message (OLE2)"; }
        return Identification.of(type.equals("MSI") ? "data" : "document", type).description(desc).build();
    }

    private static Identification simple(final String cat, final String type, final String desc) {
        return Identification.of(cat, type).description(desc).build();
    }
}
