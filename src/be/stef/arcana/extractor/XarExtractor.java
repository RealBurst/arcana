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
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.InflaterInputStream;
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
            if (toc != null) extractEntries(toc, "", destination, raf, xar.heapOffset);
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        throw new UnsupportedOperationException("XAR extraction requires seekable file");
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

    private static void extractEntries(final Element parent, final String path, final File dest, final RandomAccessFile raf, final long heapOffset) throws IOException {
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
                final Element data = firstChild(el,"data");
                if (data!=null) {
                    final String offStr=childText(data,"offset"), lenStr=childText(data,"length");
                    if (offStr!=null&&lenStr!=null) {
                        raf.seek(heapOffset+Long.parseLong(offStr.trim()));
                        final long compLen = Long.parseLong(lenStr.trim());
                        final byte[] buf = new byte[(int)compLen]; raf.readFully(buf,0,(int)compLen);
                        try (InputStream src = wrapEncoding(new ByteArrayInputStream(buf), childText(data,"encoding"));
                             BufferedOutputStream bos = new BufferedOutputStream(ExtractionGuard.open(outFile))) {
                            IOHelper.copy(src, bos);
                        }
                    }
                }
            }
            extractEntries(el, fullPath, dest, raf, heapOffset);
        }
    }

    private static InputStream wrapEncoding(final InputStream in, final String enc) throws IOException {
        if (enc==null||enc.contains("octet-stream")) return in;
        if (enc.contains("gzip")||enc.contains("zlib")) return new InflaterInputStream(in, new java.util.zip.Inflater(false));
        if (enc.contains("bzip2")) return new be.stef.arcana.formats.bzip2.BZip2InputStream(in);
        if (enc.contains("xz"))    return new be.stef.arcana.formats.xz.XZInputStream(in);
        return in;
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
                final long tocCLen = readLong8BE(hdr,8);
                final byte[] tocBuf = new byte[(int)tocCLen]; readFully(in, tocBuf);
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try (InflaterInputStream zlib = new InflaterInputStream(new ByteArrayInputStream(tocBuf), new java.util.zip.Inflater(false))) {
                    final byte[] tmp=new byte[8192]; int nr; while((nr=zlib.read(tmp))>=0) baos.write(tmp,0,nr);
                }
                final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
                final DocumentBuilder db = dbf.newDocumentBuilder();
                final Document doc = db.parse(new ByteArrayInputStream(baos.toByteArray()));
                return new Xar(doc, HDR_SIZE+tocCLen);
            } catch (javax.xml.parsers.ParserConfigurationException|org.xml.sax.SAXException e) {
                throw new ArcanaCorruptedException("Failed to parse XAR TOC: "+e.getMessage());
            }
        }
    }

    private static long readLong8BE(final byte[] b, final int off) { long v=0; for(int i=0;i<8;i++) v=(v<<8)|(b[off+i]&0xFF); return v; }
    private static void readFully(final InputStream in, final byte[] buf) throws IOException { int o=0; while(o<buf.length){int n=in.read(buf,o,buf.length-o);if(n<0)throw new IOException("EOF");o+=n;} }
}