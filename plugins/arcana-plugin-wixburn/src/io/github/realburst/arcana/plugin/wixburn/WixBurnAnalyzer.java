/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.wixburn;

import be.stef.arcana.analyze.ArcanaAnalyzer;
import be.stef.arcana.analyze.Identification;
import be.stef.arcana.formats.carve.ByteSource;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** "arcana i": identifies WiX Burn bundles (bundle, WiX version, packages) instead of a plain PE executable. */
public final class WixBurnAnalyzer implements ArcanaAnalyzer {

    @Override public String getId() { return "io.github.realburst.wixburn"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-wixburn"; }
    @Override public String getLicense() { return "Apache-2.0"; }

    @Override
    public Identification analyze(final ByteSource s, final String fileName) throws IOException {
        if (BurnBundle.findSection(s) < 0) return null;
        final BurnBundle b;
        try {
            b = BurnBundle.open(s);
        } catch (final IOException e) {
            return Identification.of("archive", "WiX Burn").description("WiX Burn bundle (not readable: " + e.getMessage() + ")").confidence(70).build();
        }
        try {
            final String app = ((b.bundleName != null ? b.bundleName : "") + (b.bundleVersion != null && (b.bundleName == null || !b.bundleName.contains(b.bundleVersion)) ? " " + b.bundleVersion : "")).trim();
            final List<BurnBundle.Payload> missing = b.missingPayloads();
            final StringBuilder d = new StringBuilder("WiX Burn bundle");
            if (!app.isEmpty()) d.append(" of ").append(app);
            d.append(" (").append(b.packageIds.size()).append(b.packageIds.size() == 1 ? " package" : " packages");
            if (!missing.isEmpty()) d.append(", ").append(missing.size()).append(missing.size() == 1 ? " payload" : " payloads").append(" not in the bundle");
            d.append(')');
            final Map<String, Integer> types = new LinkedHashMap<String, Integer>();
            for (final String t : b.packageTypes) types.put(t, types.containsKey(t) ? types.get(t) + 1 : 1);
            final StringBuilder kinds = new StringBuilder();
            for (final Map.Entry<String, Integer> e : types.entrySet()) kinds.append(kinds.length() > 0 ? ", " : "").append(e.getValue()).append(' ').append(e.getKey());
            final StringBuilder notIn = new StringBuilder();
            for (final BurnBundle.Payload p : missing) notIn.append(notIn.length() > 0 ? ", " : "").append(p.outName).append(" (").append(p.whereLabel()).append(')');
            final Identification.Builder r = Identification.of("archive", "WiX Burn").description(d.toString()).detail("bundle", app).detail("publisher", b.publisher).detail("bundle id", b.registrationId != null ? b.registrationId : b.bundleGuid).detail("WiX engine", b.wixVersion()).detail("packages", b.packageIds.size() + (kinds.length() > 0 ? " (" + kinds + ")" : "")).detail("package ids", String.join(", ", b.packageIds)).detail("payloads", b.payloads.size()).detail("containers", b.sizes.length + " in the file (UX + " + (b.sizes.length - 1) + " attached)").detail("not in the bundle", notIn.toString());
            if (b.wixVersion() != null) r.version(b.wixVersion());
            if (b.damage != null) r.description(d + " - damaged: " + b.damage).detail("damage", b.damage);
            return r.confidence(b.damage != null ? 80 : 95).build();
        } finally {
            b.close();
        }
    }
}
