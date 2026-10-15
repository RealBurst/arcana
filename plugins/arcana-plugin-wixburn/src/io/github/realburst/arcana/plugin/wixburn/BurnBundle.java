/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.wixburn;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.cab.CabEntry;
import be.stef.arcana.formats.cab.CabReader;
import be.stef.arcana.formats.carve.ByteSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A WiX Burn bundle: the ".wixburn" section of the engine stub, the containers
 * attached after the stub (cabinets) and the manifest (BurnManifest.xml) that
 * gives every payload its real path.
 *
 * <p>Layout (from the WiX documentation and the analysis of real bundles):</p>
 * <ul>
 *   <li>".wixburn" PE section: magic 0x00F14300, version, bundle GUID (16 bytes),
 *       stub size, original PE checksum, offset and size of the signature of the
 *       engine (stub + UX container), container format (1 = cabinet), number of
 *       containers, then one 32-bit size per container;</li>
 *   <li>the UX container starts at the stub size: a cabinet holding the manifest
 *       (named "0") and the bootstrapper application files ("u0", "u1"...);</li>
 *   <li>the attached containers follow the engine signature (or the UX container
 *       when the engine was not signed): cabinets holding the payloads ("a0"...).</li>
 * </ul>
 */
final class BurnBundle implements Closeable {

    static final long SECTION_MAGIC = 0x00F14300L;
    static final String MANIFEST_NAME = "ux/BurnManifest.xml";
    private static final byte[] MSCF = {'M', 'S', 'C', 'F', 0, 0, 0, 0};
    private static final int MAX_CONTAINERS = 1024;
    private static final int MAX_MANIFEST = 64 << 20;

    /** A container of the bundle: the UX one, attached ones (in the file) and detached ones (next to it or downloaded). */
    static final class Container {
        String id;
        String filePath;
        String downloadUrl;
        long size = -1;
        String hash;
        boolean attached;
        int index;
        long offset = -1;
    }

    /** A payload of the manifest. */
    static final class Payload {
        String id;
        String filePath;
        String sourcePath;
        String containerId;
        String packaging;
        String downloadUrl;
        String hash;
        long size = -1;
        boolean ux;
        Container container;
        String outName;

        /** True when the payload is inside the bundle file (UX or attached container). */
        boolean embedded() {
            return ux || (container != null && container.attached);
        }

        /** Why the payload is not extracted. */
        String whereLabel() {
            if (container != null) return "detached container " + (container.filePath != null ? container.filePath : container.id);
            return downloadUrl != null ? "external, downloaded" : "external";
        }
    }

    final ByteSource src;
    private final boolean ownsSource;
    final String bundleGuid;
    final int sectionVersion;
    final long stubSize;
    final long[] sizes;
    final long[] offsets;
    final Container ux = new Container();
    final List<Container> containers = new ArrayList<Container>();
    final List<Payload> payloads = new ArrayList<Payload>();
    final List<String> packageIds = new ArrayList<String>();
    final List<String> packageTypes = new ArrayList<String>();
    byte[] manifest;
    /** Why some attached containers could not be located (truncated or damaged file), or null. */
    String damage;
    String engineVersion;
    boolean wix3;
    String bundleName;
    String bundleVersion;
    String publisher;
    String registrationId;
    private File uxTemp;

    private BurnBundle(final ByteSource src, final boolean ownsSource, final long sectionPos) throws IOException {
        this.src = src;
        this.ownsSource = ownsSource;
        this.sectionVersion = (int) src.u32le(sectionPos + 4);
        this.bundleGuid = guid(src.bytes(sectionPos + 8, 16));
        this.stubSize = src.u32le(sectionPos + 24);
        final long format = src.u32le(sectionPos + 40);
        final long count = src.u32le(sectionPos + 44);
        if (format != 1) throw new ArcanaUnsupportedFormatException("WiX Burn bundle with container format " + format + " (only cabinets are supported)");
        if (count < 1 || count > MAX_CONTAINERS) throw new ArcanaCorruptedException("WiX Burn section damaged (" + count + " containers)");
        sizes = new long[(int) count];
        for (int i = 0; i < sizes.length; i++) sizes[i] = src.u32le(sectionPos + 48 + 4L * i);
        ux.id = "WixUXContainer";
        ux.attached = true;
        ux.size = sizes[0];
        ux.offset = findCabinet(stubSize, sizes[0], "UX container");
        final long sigOffset = src.u32le(sectionPos + 32);
        final long sigSize = src.u32le(sectionPos + 36);
        long next = ux.offset + ux.size;
        if (sigOffset > 0 && sigSize > 0 && sigOffset >= next && sigOffset - next < 4096) next = sigOffset + sigSize;
        offsets = new long[sizes.length];
        offsets[0] = ux.offset;
        for (int i = 1; i < sizes.length; i++) {
            try {
                offsets[i] = findCabinet(next, sizes[i], "attached container " + i);
                next = offsets[i] + sizes[i];
            } catch (final ArcanaCorruptedException e) {
                for (int k = i; k < sizes.length; k++) offsets[k] = -1;
                damage = e.getMessage();
                break;
            }
        }
        try {
            readManifest();
            parseManifest();
        } catch (final IOException | RuntimeException e) {
            if (uxTemp != null) delete(uxTemp);
            throw e;
        }
    }

    /** Opens the bundle in {@code f}; throws if it is not a WiX Burn bundle. */
    static BurnBundle open(final File f) throws IOException {
        final ByteSource s = new ByteSource(f);
        try {
            final long pos = findSection(s);
            if (pos < 0) throw new ArcanaUnsupportedFormatException(f.getName() + " is not a WiX Burn bundle (no .wixburn section)");
            return new BurnBundle(s, true, pos);
        } catch (final IOException | RuntimeException e) {
            s.close();
            throw e;
        }
    }

    /** Opens the bundle behind {@code s} (owned by the caller), or returns null if it is not one. */
    static BurnBundle open(final ByteSource s) throws IOException {
        final long pos = findSection(s);
        return pos < 0 ? null : new BurnBundle(s, false, pos);
    }

    /** File position of the ".wixburn" section data, or -1. */
    static long findSection(final ByteSource s) throws IOException {
        if (s.length() < 1024 || s.u8(0) != 'M' || s.u8(1) != 'Z') return -1;
        final long pe = s.u32le(0x3c);
        if (pe < 64 || pe > s.length() - 24 || s.u32le(pe) != 0x4550) return -1;
        final int sections = s.u16le(pe + 6);
        final long table = pe + 24 + s.u16le(pe + 20);
        for (int i = 0; i < sections && i < 96; i++) {
            final long h = table + 40L * i;
            final byte[] name = s.bytes(h, 8);
            if (name == null) return -1;
            if (!".wixburn".equals(new String(name, "US-ASCII"))) continue;
            final long rawSize = s.u32le(h + 16);
            final long rawPos = s.u32le(h + 20);
            if (rawSize < 52 || rawPos + rawSize > s.length() || s.u32le(rawPos) != SECTION_MAGIC) return -1;
            final long count = s.u32le(rawPos + 44);
            if (48 + 4 * count > rawSize) return -1;
            return rawPos;
        }
        return -1;
    }

    /** True if the PE header in {@code h} has a ".wixburn" section (probe of the plugin). */
    static boolean hasSection(final byte[] h) {
        if (h.length < 512 || h[0] != 'M' || h[1] != 'Z') return false;
        final int pe = le32(h, 0x3c);
        if (pe < 64 || pe > h.length - 24 || le32(h, pe) != 0x4550) return false;
        final int sections = (h[pe + 6] & 0xff) | (h[pe + 7] & 0xff) << 8;
        final int table = pe + 24 + ((h[pe + 20] & 0xff) | (h[pe + 21] & 0xff) << 8);
        for (int i = 0; i < sections && table + 40 * i + 8 <= h.length; i++) {
            final int o = table + 40 * i;
            if (h[o] == '.' && h[o + 1] == 'w' && h[o + 2] == 'i' && h[o + 3] == 'x' && h[o + 4] == 'b' && h[o + 5] == 'u' && h[o + 6] == 'r' && h[o + 7] == 'n') return true;
        }
        return false;
    }

    static int le32(final byte[] b, final int o) {
        return (b[o] & 0xff) | (b[o + 1] & 0xff) << 8 | (b[o + 2] & 0xff) << 16 | (b[o + 3] & 0xff) << 24;
    }

    /** Position of a cabinet of {@code size} bytes expected at {@code pos} (an alignment gap is accepted). */
    private long findCabinet(final long pos, final long size, final String what) throws IOException {
        long p = pos;
        final long end = Math.min(src.length(), pos + 65536);
        while (p >= 0 && p < end) {
            if (src.matches(p, MSCF) && src.u32le(p + 8) == size) {
                if (p + size > src.length()) throw new ArcanaCorruptedException("WiX Burn bundle truncated (" + what + " incomplete)");
                return p;
            }
            p = src.indexOf(MSCF, p + 1, end + MSCF.length);
        }
        throw new ArcanaCorruptedException("WiX Burn bundle damaged or truncated (" + what + " not found)");
    }

    /** Copies a container to a temporary cabinet file (the payloads are checked one by one when extracted). */
    File copyContainer(final Container c) throws IOException {
        if (c == ux && uxTemp != null) return uxTemp;
        final File tmp = File.createTempFile("arcana-wixburn", ".cab");
        boolean ok = false;
        try {
            try (OutputStream out = new FileOutputStream(tmp)) {
                final byte[] buf = new byte[65536];
                long pos = c.offset;
                long left = c.size;
                while (left > 0) {
                    final int n = src.read(pos, buf, 0, (int) Math.min(buf.length, left));
                    if (n <= 0) throw new ArcanaCorruptedException("WiX Burn bundle truncated (container " + c.id + ")");
                    out.write(buf, 0, n);
                    pos += n;
                    left -= n;
                }
            }
            ok = true;
            if (c == ux) uxTemp = tmp;
            return tmp;
        } finally {
            if (!ok) delete(tmp);
        }
    }

    /** Deletes a temporary cabinet returned by {@link #copyContainer} (the UX one is kept until close). */
    void release(final File tmp) {
        if (tmp != null && tmp != uxTemp) delete(tmp);
    }

    private static void delete(final File f) {
        if (!f.delete()) f.deleteOnExit();
    }

    private void readManifest() throws IOException {
        final File tmp = copyContainer(ux);
        try (CabReader cab = new CabReader(tmp.getPath())) {
            for (final CabEntry e : cab.getEntries()) {
                if (!"0".equals(e.getName())) continue;
                if (e.getSize() > MAX_MANIFEST) throw new ArcanaCorruptedException("WiX Burn manifest too large");
                final ByteArrayOutputStream out = new ByteArrayOutputStream((int) e.getSize());
                cab.extract(e, out);
                manifest = out.toByteArray();
                return;
            }
        }
        throw new ArcanaCorruptedException("WiX Burn UX container without manifest");
    }

    private void parseManifest() throws IOException {
        final Document doc;
        try {
            final DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setXIncludeAware(false);
            f.setExpandEntityReferences(false);
            final DocumentBuilder b = f.newDocumentBuilder();
            b.setErrorHandler(new DefaultHandler());
            doc = b.parse(new ByteArrayInputStream(manifest));
        } catch (final Exception e) {
            throw new ArcanaCorruptedException("WiX Burn manifest not readable (" + e.getMessage() + ")", e);
        }
        final Element root = doc.getDocumentElement();
        final String ns = root.getAttribute("xmlns");
        wix3 = ns.contains("schemas.microsoft.com/wix/");
        engineVersion = attr(root, "EngineVersion");
        final Map<String, Container> byId = new HashMap<String, Container>();
        int nextIndex = 1;
        final NodeList all = root.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            final Element e = (Element) all.item(i);
            final String tag = local(e);
            if ("Container".equals(tag)) {
                final Container c = new Container();
                c.id = attr(e, "Id");
                c.filePath = attr(e, "FilePath");
                c.downloadUrl = attr(e, "DownloadUrl");
                c.hash = attr(e, "Hash");
                c.size = number(attr(e, "FileSize"));
                c.attached = "yes".equals(attr(e, "Attached"));
                if (c.attached) {
                    final long idx = number(attr(e, "AttachedIndex"));
                    c.index = idx > 0 ? (int) idx : nextIndex;
                    nextIndex = c.index + 1;
                    if (c.index < offsets.length) {
                        c.offset = offsets[c.index];
                        if (c.size < 0) c.size = sizes[c.index];
                        else if (c.size != sizes[c.index]) throw new ArcanaCorruptedException("WiX Burn container " + c.id + ": size " + c.size + " in the manifest, " + sizes[c.index] + " in the bundle");
                    }
                }
                containers.add(c);
                if (c.id != null) byId.put(c.id, c);
            } else if ("Payload".equals(tag)) {
                final Payload p = new Payload();
                p.id = attr(e, "Id");
                p.filePath = attr(e, "FilePath");
                p.sourcePath = attr(e, "SourcePath");
                p.containerId = attr(e, "Container");
                p.packaging = attr(e, "Packaging");
                p.downloadUrl = attr(e, "DownloadUrl");
                p.hash = attr(e, "Hash");
                p.size = number(attr(e, "FileSize"));
                p.ux = isUnder(e, "UX");
                payloads.add(p);
            } else if ("Registration".equals(tag)) {
                registrationId = attr(e, "Id");
                bundleVersion = attr(e, "Version");
            } else if ("Arp".equals(tag)) {
                bundleName = attr(e, "DisplayName");
                publisher = attr(e, "Publisher");
                if (bundleVersion == null) bundleVersion = attr(e, "DisplayVersion");
            } else if (tag.endsWith("Package") && e.getParentNode() instanceof Element && "Chain".equals(local((Element) e.getParentNode()))) {
                packageIds.add(attr(e, "Id"));
                packageTypes.add(tag.substring(0, tag.length() - "Package".length()));
            }
        }
        for (final Payload p : payloads) {
            if (!p.ux && p.containerId != null) p.container = byId.get(p.containerId);
            if (!p.ux && p.container != null && p.container.attached && p.container.offset < 0 && damage == null) damage = "WiX Burn bundle damaged: container " + p.container.id + " is not in the file";
        }
        assignNames();
    }

    /** Output names: UX files under "ux/", packages at their FilePath, unique (case-insensitive). */
    private void assignNames() {
        final Set<String> used = new HashSet<String>();
        used.add(MANIFEST_NAME.toLowerCase(Locale.ROOT));
        for (final Payload p : payloads) {
            final String path = clean(p.filePath != null ? p.filePath : p.sourcePath != null ? p.sourcePath : p.id);
            p.outName = unique(used, p.ux ? "ux/" + path : path);
        }
    }

    /** Name for a cabinet entry that no payload of the manifest describes. */
    String orphanName(final Container c, final String entryName, final Set<String> used) {
        final String dir = c == ux ? "ux" : c.id != null ? clean(c.id) : "container" + c.index;
        return unique(used, dir + "/" + clean(entryName));
    }

    /** Names already given to payloads (for {@link #orphanName}). */
    Set<String> usedNames() {
        final Set<String> used = new HashSet<String>();
        used.add(MANIFEST_NAME.toLowerCase(Locale.ROOT));
        for (final Payload p : payloads) used.add(p.outName.toLowerCase(Locale.ROOT));
        return used;
    }

    static String unique(final Set<String> used, final String name) {
        String n = name;
        int k = 2;
        while (!used.add(n.toLowerCase(Locale.ROOT))) {
            final int slash = name.lastIndexOf('/');
            final int dot = name.lastIndexOf('.');
            n = dot > slash + 1 ? name.substring(0, dot) + " (" + k + ")" + name.substring(dot) : name + " (" + k + ")";
            k++;
        }
        return n;
    }

    private static String clean(final String s) {
        String n = s.replace('\\', '/');
        while (n.startsWith("/")) n = n.substring(1);
        return n.isEmpty() ? "_" : n;
    }

    /** Payloads stored in container {@code c} under the cabinet name {@code entryName}. */
    List<Payload> payloadsOf(final Container c, final String entryName) {
        final List<Payload> r = new ArrayList<Payload>();
        for (final Payload p : payloads) {
            if (!entryName.equals(p.sourcePath)) continue;
            if (c == ux ? p.ux : !p.ux && p.container == c) r.add(p);
        }
        return r;
    }

    /** The containers stored in the bundle file, UX first. */
    List<Container> embeddedContainers() {
        final List<Container> r = new ArrayList<Container>();
        r.add(ux);
        for (int i = 1; i < sizes.length; i++) {
            Container found = null;
            for (final Container c : containers) {
                if (c.attached && c.index == i) found = c;
            }
            if (found == null) {
                found = new Container();
                found.id = "container" + i;
                found.attached = true;
                found.index = i;
                found.size = sizes[i];
                found.offset = offsets[i];
            }
            if (found.offset >= 0) r.add(found);
        }
        return r;
    }

    /** A file of a container cabinet, as listed by its directory. */
    static final class CabFile {
        String name;
        long size;
    }

    /** Reads the file table of the cabinet of container {@code c} directly from the bundle (no copy). */
    List<CabFile> cabFiles(final Container c) throws IOException {
        final long table = c.offset + src.u32le(c.offset + 16);
        final int n = src.u16le(c.offset + 28);
        final List<CabFile> r = new ArrayList<CabFile>();
        long p = table;
        for (int i = 0; i < n; i++) {
            final CabFile f = new CabFile();
            f.size = src.u32le(p);
            final int attributes = src.u16le(p + 14);
            p += 16;
            final ByteArrayOutputStream name = new ByteArrayOutputStream();
            int x;
            while ((x = src.u8(p++)) > 0 && name.size() < 1024) name.write(x);
            if (x != 0 || p > c.offset + c.size) throw new ArcanaCorruptedException("WiX Burn container " + c.id + ": cabinet file table damaged");
            f.name = new String(name.toByteArray(), (attributes & 0x80) != 0 ? "UTF-8" : "ISO-8859-1");
            r.add(f);
        }
        return r;
    }

    /** Payloads that are not in the bundle file (external, downloaded, detached containers). */
    List<Payload> missingPayloads() {
        final List<Payload> r = new ArrayList<Payload>();
        for (final Payload p : payloads) if (!p.embedded()) r.add(p);
        return r;
    }

    /** WiX version label: the engine version of WiX 4 and later, "3.x" for the WiX 3 manifest. */
    String wixVersion() {
        if (engineVersion != null) return engineVersion;
        return wix3 ? "3.x" : null;
    }

    /** Digest for a manifest hash (SHA-1, SHA-256 or SHA-512 by its length), or null. */
    static MessageDigest digest(final String hash) {
        if (hash == null) return null;
        final String alg = hash.length() == 40 ? "SHA-1" : hash.length() == 64 ? "SHA-256" : hash.length() == 128 ? "SHA-512" : null;
        if (alg == null) return null;
        try {
            return MessageDigest.getInstance(alg);
        } catch (final NoSuchAlgorithmException e) {
            return null;
        }
    }

    static String hex(final byte[] b) {
        final StringBuilder sb = new StringBuilder(b.length * 2);
        for (final byte x : b) sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        return sb.toString();
    }

    private static String guid(final byte[] b) {
        if (b == null) return null;
        return String.format("{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}", b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    }

    private static String local(final Element e) {
        final String t = e.getTagName();
        final int colon = t.indexOf(':');
        return colon >= 0 ? t.substring(colon + 1) : t;
    }

    private static boolean isUnder(final Element e, final String tag) {
        for (Node n = e.getParentNode(); n instanceof Element; n = n.getParentNode()) {
            if (tag.equals(local((Element) n))) return true;
        }
        return false;
    }

    private static String attr(final Element e, final String name) {
        final String v = e.getAttribute(name);
        return v == null || v.isEmpty() ? null : v;
    }

    private static long number(final String s) {
        if (s == null) return -1;
        try {
            return Long.parseLong(s.trim());
        } catch (final NumberFormatException e) {
            return -1;
        }
    }

    @Override
    public void close() throws IOException {
        if (uxTemp != null) {
            delete(uxTemp);
            uxTemp = null;
        }
        if (ownsSource) src.close();
    }
}
