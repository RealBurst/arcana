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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Result of identifying a file: what it is, its version when known, and a few
 * details. Produced by an {@link ArcanaAnalyzer}.
 *
 * @author Stef
 * @since 1.4
 */
public final class Identification {

    /** Broad family: "archive", "executable", "image", "document", "database", "audio", "video", "font", "data". */
    public final String category;
    /** Short type name, e.g. "ZIP", "PE32+", "PNG", "PDF", "SQLite". */
    public final String type;
    /** Version of the format or of the file, or null if unknown. */
    public final String version;
    /** One-line human description. */
    public final String description;
    /** Confidence 0-100 (100 = certain from a strong signature). */
    public final int confidence;
    private final Map<String, String> details;

    private Identification(final Builder b) {
        this.category = b.category;
        this.type = b.type;
        this.version = b.version;
        this.description = b.description != null ? b.description : b.type;
        this.confidence = b.confidence;
        this.details = Collections.unmodifiableMap(new LinkedHashMap<String, String>(b.details));
    }

    /** Ordered detail fields (architecture, dimensions, entry count...). */
    public Map<String, String> getDetails() {
        return details;
    }

    /** "TYPE version (description)" on one line. */
    public String oneLine() {
        final StringBuilder sb = new StringBuilder(type);
        if (version != null && !version.isEmpty()) sb.append(' ').append(version);
        if (description != null && !description.equals(type)) sb.append(" - ").append(description);
        return sb.toString();
    }

    public static Builder of(final String category, final String type) {
        return new Builder(category, type);
    }

    /** Fluent builder. */
    public static final class Builder {
        private final String category;
        private String type;
        private String version;
        private String description;
        private int confidence = 100;
        private final Map<String, String> details = new LinkedHashMap<String, String>();

        Builder(final String category, final String type) {
            this.category = category;
            this.type = type;
        }

        /** Refines the type name (e.g. ZIP -> DOCX once the container is inspected). */
        public Builder type(final String t) {
            this.type = t;
            return this;
        }

        public Builder version(final String v) {
            this.version = v;
            return this;
        }

        public Builder description(final String d) {
            this.description = d;
            return this;
        }

        public Builder confidence(final int c) {
            this.confidence = c;
            return this;
        }

        /** Adds a detail; a null or empty value is ignored. */
        public Builder detail(final String key, final String value) {
            if (value != null && !value.isEmpty()) details.put(key, value);
            return this;
        }

        public Builder detail(final String key, final long value) {
            details.put(key, String.valueOf(value));
            return this;
        }

        public Identification build() {
            return new Identification(this);
        }
    }
}
