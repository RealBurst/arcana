/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.extractor;

import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.InflaterInputStream;
import be.stef.arcana.formats.bzip2.BZip2InputStream;
import be.stef.arcana.formats.xz.LZMAInputStream;
import be.stef.arcana.formats.xz.XZInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Extractor for XAR archives (.xar, Apple eXtensible ARchive).
 * Format: 28-byte header + zlib-compressed XML TOC + heap of file data blocks.
 */
public class XarExtractor implements ArchiveExtractor {

    private static final int[] MAGIC      = {0x78,0x61,0x72,0x21};
    private static final int   HDR_SIZE   = 28;

    @Override public boolean supportsStream() { return false; }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final Xar xar = Xar.open(archive);
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        // getDocumentElement() = <xar>; files are under <xar><toc>
        final Element toc = firstChild(xar.toc.getDocumentElement(), "toc");
        if (toc != null) collectEntries(toc, "", result);
        return result;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final Xar xar = Xar.open(archive);
        try (RandomAccessFile raf = new RandomAccessFile(archive, "r")) {
            final Element toc = firstChild(xar.toc.getDocumentElement(), "toc");
            if (toc != null) {
                final Map<String, Element> dataById = new HashMap<String, Element>();
                collectData(toc, dataById);
                extractEntries(toc, "", destination, raf, xar.heapOffset, dataById);
            }
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        throw new ArcanaUnsupportedFormatException("XAR requires random file access - use extract(File,File).");
    }

    // ---- traversal ----

    private static void collectEntries(final Element parent, final String path, final List<ArcanaEntry> out) {
        final NodeList children = parent.getChildNodes();
        for (int i=0;i<children.getLength();i++) {
            final Node n = children.item(i);
            if (!(n instanceof Element)) continue;
            final Element el = (Element) n;
            if (!"file".equals(el.getTagName())) continue;
            final String name = childText(el,"name");
            if (name==null||name.isEmpty()) continue;
            final String fullPath = path.isEmpty() ? name : path+"/"+name;
            final boolean isDir = "directory".equals(childText(el,"type"));
            final ArcanaEntry.Builder b = new ArcanaEntry.Builder(fullPath).directory(isDir).format(ArcanaFormat.XAR);
            if (!isDir) { final String sz=childText(el,"size"); if(sz!=null)try{b.uncompressedSize(Long.parseLong(sz.trim()));}catch(NumberFormatException ignored){} }
            out.add(b.build());
            collectEntries(el, fullPath, out);
        }
    }

    /** Data of every file by id: a hard link refers to the file holding the data ("link" attribute of its type). */
    private static void collectData(final Element parent, final Map<String, Element> out) {
        final NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            final Node n = children.item(i);
            if (!(n instanceof Element) || !"file".equals(((Element) n).getTagName())) continue;
            final Element el = (Element) n;
            final Element data = firstChild(el, "data");
            if (data != null && el.hasAttribute("id")) out.put(el.getAttribute("id"), data);
            collectData(el, out);
        }
    }

    private static void extractEntries(final Element parent, final String path, final File dest, final RandomAccessFile raf, final long heapOffset, final Map<String, Element> dataById) throws IOException {
        final NodeList children = parent.getChildNodes();
        for (int i=0;i<children.getLength();i++) {
            final Node n = children.item(i);
            if (!(n instanceof Element)) continue;
            final Element el = (Element) n;
            if (!"file".equals(el.getTagName())) continue;
            final String name = childText(el,"name");
            if (name==null||name.isEmpty()) continue;
            final String fullPath = path.isEmpty() ? name : path+"/"+name;
            final File outFile = SafePathBuilder.buildSafePath(dest, fullPath.replace("/",File.separator));
            if ("directory".equals(childText(el,"type"))) {
                IOHelper.mkdirs(outFile);
            } else {
                IOHelper.mkdirs(outFile.getParentFile());
                Element data = firstChild(el,"data");
                final Element type = firstChild(el, "type");
                if (data == null && type != null && "hardlink".equals(type.getTextContent().trim())) data = dataById.get(type.getAttribute("link"));
                try (BufferedOutputStream bos = new BufferedOutputStream(ExtractionGuard.open(outFile), 65536)) {
                    // no data: empty file, symbolic link (written empty, like TAR and CPIO)
                    if (data != null) copyData(data, raf, heapOffset, bos, fullPath);
                }
            }
            extractEntries(el, fullPath, dest, raf, heapOffset, dataById);
        }
    }

    /**
     * Copies the data of a file: heap range "offset"/"length", decoded according to
     * the "style" attribute of "encoding", checked against "extracted-checksum".
     */
    private static void copyData(final Element data, final RandomAccessFile raf, final long heapOffset, final OutputStream out, final String name) throws IOException {
        final String offStr = childText(data, "offset");
        final String lenStr = childText(data, "length");
        final String sizeStr = childText(data, "size");
        if (offStr == null || lenStr == null) throw new ArcanaCorruptedException("XAR data without offset or length: " + name);
        final long offset;
        final long length;
        try {
            offset = Long.parseLong(offStr.trim());
            length = Long.parseLong(lenStr.trim());
        } catch (final NumberFormatException e) {
            throw new ArcanaCorruptedException("Invalid XAR data location: " + name);
        }
        if (offset < 0 || length < 0 || heapOffset + offset + length > raf.length()) throw new ArcanaCorruptedException("XAR data outside the archive: " + name);
        final Element checksum = firstChild(data, "extracted-checksum");
        MessageDigest digest = null;
        if (checksum != null) {
            final String alg = checksum.getAttribute("style").trim().toLowerCase();
            try {
                if (alg.equals("sha1")) digest = MessageDigest.getInstance("SHA-1");
                else if (alg.equals("md5")) digest = MessageDigest.getInstance("MD5");
                else if (alg.equals("sha256")) digest = MessageDigest.getInstance("SHA-256");
                else if (alg.equals("sha512")) digest = MessageDigest.getInstance("SHA-512");
            } catch (final NoSuchAlgorithmException e) {
                digest = null;
            }
        }
        long written = 0;
        try (InputStream src = decode(new RangeInputStream(raf, heapOffset + offset, length), encoding(data), name)) {
            final byte[] buf = new byte[65536];
            int n;
            while ((n = src.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (digest != null) digest.update(buf, 0, n);
                written += n;
            }
        }
        if (sizeStr != null) {
            try {
                if (Long.parseLong(sizeStr.trim()) != written) throw new ArcanaCorruptedException("XAR size mismatch: " + name);
            } catch (final NumberFormatException ignored) {
                // size not checked
            }
        }
        if (digest != null && !toHex(digest.digest()).equalsIgnoreCase(checksum.getTextContent().trim())) throw new ArcanaCorruptedException("XAR checksum mismatch: " + name);
    }

    /** The encoding is given by the "style" attribute: {@code <encoding style="application/x-gzip"/>}. */
    private static String encoding(final Element data) {
        final Element e = firstChild(data, "encoding");
        if (e == null) return "application/octet-stream";
        final String style = e.getAttribute("style").trim();
        return style.isEmpty() ? e.getTextContent().trim() : style;
    }

    private static InputStream decode(final InputStream in, final String enc, final String name) throws IOException {
        if (enc.isEmpty() || enc.equals("application/octet-stream")) return in;
        // "application/x-gzip" is a zlib stream (with the zlib header), not a gzip file
        if (enc.equals("application/x-gzip") || enc.equals("application/zlib")) return new InflaterInputStream(in, new java.util.zip.Inflater(false), 65536);
        if (enc.equals("application/x-bzip2")) return new BZip2InputStream(in);
        if (enc.equals("application/x-xz")) return new XZInputStream(in);
        if (enc.equals("application/x-lzma")) {
            // xar writes an .xz stream under this name; older writers used the .lzma ("alone") format
            final BufferedInputStream b = new BufferedInputStream(in, 65536);
            b.mark(6);
            final byte[] head = new byte[6];
            int n = 0;
            while (n < 6) {
                final int k = b.read(head, n, 6 - n);
                if (k < 0) break;
                n += k;
            }
            b.reset();
            final boolean xz = n == 6 && (head[0] & 0xff) == 0xFD && head[1] == '7' && head[2] == 'z' && head[3] == 'X' && head[4] == 'Z' && head[5] == 0;
            return xz ? new XZInputStream(b) : new LZMAInputStream(b);
        }
        throw new ArcanaUnsupportedFormatException("XAR encoding '" + enc + "' is not supported (" + name + ")");
    }

    private static String toHex(final byte[] b) {
        final StringBuilder sb = new StringBuilder(b.length * 2);
        for (final byte x : b) sb.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        return sb.toString();
    }

    /** Sequential view of [pos, pos + len) of the archive. */
    private static final class RangeInputStream extends InputStream {
        private final RandomAccessFile raf;
        private long pos;
        private long left;

        RangeInputStream(final RandomAccessFile raf, final long pos, final long len) {
            this.raf = raf;
            this.pos = pos;
            this.left = len;
        }

        @Override
        public int read() throws IOException {
            final byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            if (left <= 0) return -1;
            raf.seek(pos);
            final int n = raf.read(b, off, (int) Math.min(len, left));
            if (n > 0) {
                pos += n;
                left -= n;
            }
            return n;
        }
    }

    // ---- XML helpers ----

    private static String childText(final Element p, final String tag) {
        final NodeList nl=p.getChildNodes();
        for(int i=0;i<nl.getLength();i++){final Node n=nl.item(i);if(n instanceof Element&&tag.equals(((Element)n).getTagName()))return n.getTextContent();}
        return null;
    }
    private static Element firstChild(final Element p, final String tag) {
        final NodeList nl=p.getChildNodes();
        for(int i=0;i<nl.getLength();i++){final Node n=nl.item(i);if(n instanceof Element&&tag.equals(((Element)n).getTagName()))return(Element)n;}
        return null;
    }

    // ---- XAR header parsing ----

    private static final class Xar {
        final Document toc;
        final long heapOffset;
        Xar(Document toc, long heapOffset){this.toc=toc;this.heapOffset=heapOffset;}

        static Xar open(final File f) throws IOException {
            try (InputStream in = new BufferedInputStream(new FileInputStream(f))) {
                final byte[] hdr = new byte[HDR_SIZE]; readFully(in, hdr);
                for(int i=0;i<4;i++) if((hdr[i]&0xFF)!=MAGIC[i]) throw new ArcanaCorruptedException("Not a XAR archive");
                // header size (bytes 4-5): 28, or more when a checksum algorithm name follows
                final int hdrSize = (hdr[4] & 0xFF) << 8 | (hdr[5] & 0xFF);
                if (hdrSize < HDR_SIZE || hdrSize > 4096) throw new ArcanaCorruptedException("Invalid XAR header size " + hdrSize);
                for (int skip = hdrSize - HDR_SIZE; skip > 0; skip--) if (in.read() < 0) throw new ArcanaCorruptedException("XAR header truncated");
                final long tocCLen = readLong8BE(hdr,8);
                if (tocCLen <= 0 || tocCLen > 256L * 1024 * 1024 || tocCLen > f.length()) throw new ArcanaCorruptedException("Invalid XAR table of contents size");
                final byte[] tocBuf = new byte[(int)tocCLen]; readFully(in, tocBuf);
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try (InflaterInputStream zlib = new InflaterInputStream(new ByteArrayInputStream(tocBuf), new java.util.zip.Inflater(false))) {
                    final byte[] tmp=new byte[8192]; int nr; while((nr=zlib.read(tmp))>=0) baos.write(tmp,0,nr);
                }
                final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
                final DocumentBuilder db = dbf.newDocumentBuilder();
                final Document doc = db.parse(new ByteArrayInputStream(baos.toByteArray()));
                return new Xar(doc, hdrSize+tocCLen);
            } catch (javax.xml.parsers.ParserConfigurationException|org.xml.sax.SAXException e) {
                throw new ArcanaCorruptedException("Failed to parse XAR TOC: "+e.getMessage());
            }
        }
    }

    private static long readLong8BE(final byte[] b, final int off) { long v=0; for(int i=0;i<8;i++) v=(v<<8)|(b[off+i]&0xFF); return v; }
    private static void readFully(final InputStream in, final byte[] buf) throws IOException { int o=0; while(o<buf.length){int n=in.read(buf,o,buf.length-o);if(n<0)throw new IOException("EOF");o+=n;} }
}