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
 * Identifies images, documents (PDF) and RIFF/ISO-BMFF media containers, with
 * their dimensions or version when cheaply available.
 *
 * @author Stef
 * @since 1.4
 */
public final class MediaAnalyzer implements ArcanaAnalyzer {

    @Override
    public String getId() {
        return "arcana.media";
    }

    @Override
    public Identification analyze(final ByteSource s, final String fileName) throws IOException {
        final int c0 = s.u8(0), c1 = s.u8(1);
        if (c0 == 0x89 && c1 == 'P' && s.u8(2) == 'N' && s.u8(3) == 'G') return png(s);
        if (c0 == 0xFF && c1 == 0xD8 && s.u8(2) == 0xFF) return jpeg(s);
        if (c0 == 'G' && c1 == 'I' && s.u8(2) == 'F') return gif(s);
        if (c0 == 'B' && c1 == 'M') return bmp(s);
        if (c0 == '%' && c1 == 'P' && s.u8(2) == 'D' && s.u8(3) == 'F') return pdf(s);
        if (c0 == 'R' && c1 == 'I' && s.u8(2) == 'F' && s.u8(3) == 'F') return riff(s);
        if ((c0 == 'I' && c1 == 'I' && s.u8(2) == 42) || (c0 == 'M' && c1 == 'M' && s.u8(3) == 42)) return tiff(s, c0 == 'I');
        if (matchAt(s, 4, "ftyp")) return isoBmff(s);
        if (c0 == 'O' && c1 == 'g' && s.u8(2) == 'g' && s.u8(3) == 'S') return simple("audio", "Ogg", "Ogg container (Vorbis/Opus/Theora)");
        if (c0 == 'f' && c1 == 'L' && s.u8(2) == 'a' && s.u8(3) == 'C') return simple("audio", "FLAC", "FLAC audio");
        if (c0 == 'I' && c1 == 'D' && s.u8(2) == '3') return simple("audio", "MP3", "MP3 audio (with ID3 tag)");
        if (matchAt(s, 0, "OTTO") || (c0 == 0x00 && c1 == 0x01 && s.u8(2) == 0x00 && s.u8(3) == 0x00)) return simple("font", "OpenType/TrueType", "OpenType or TrueType font");
        if (matchAt(s, 0, "wOF2")) return simple("font", "WOFF2", "Web font (WOFF2)");
        if (matchAt(s, 0, "wOFF")) return simple("font", "WOFF", "Web font (WOFF)");
        return null;
    }

    private static Identification png(final ByteSource s) throws IOException {
        // IHDR follows the 8-byte signature + 4-byte length + "IHDR": width/height at offset 16/20.
        final long w = s.u32be(16), h = s.u32be(20);
        final int depth = s.u8(24), colorType = s.u8(25);
        return Identification.of("image", "PNG")
                .description("PNG image, " + w + "x" + h)
                .detail("dimensions", w + " x " + h)
                .detail("bit depth", String.valueOf(depth))
                .detail("color type", pngColor(colorType))
                .build();
    }

    private static String pngColor(final int t) {
        switch (t) {
            case 0: return "grayscale";
            case 2: return "truecolor (RGB)";
            case 3: return "palette";
            case 4: return "grayscale + alpha";
            case 6: return "truecolor + alpha (RGBA)";
            default: return "type " + t;
        }
    }

    private static Identification jpeg(final ByteSource s) throws IOException {
        // Scan the segments for a start-of-frame marker (SOFn) to read the dimensions.
        long p = 2;
        final long len = s.length();
        while (p + 4 < len) {
            if (s.u8(p) != 0xFF) { p++; continue; }
            final int marker = s.u8(p + 1);
            if (marker == 0xD8 || marker == 0xD9 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0x01) { p += 2; continue; }
            final int segLen = s.u16be(p + 2);
            if (segLen < 2) break;
            if ((marker >= 0xC0 && marker <= 0xCF) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC) {
                final int h = s.u16be(p + 5), w = s.u16be(p + 7);
                return Identification.of("image", "JPEG").description("JPEG image, " + w + "x" + h).detail("dimensions", w + " x " + h).build();
            }
            p += 2 + segLen;
        }
        return Identification.of("image", "JPEG").description("JPEG image").build();
    }

    private static Identification gif(final ByteSource s) throws IOException {
        final byte[] ver = s.bytes(3, 3);
        final String v = ver != null ? new String(ver, StandardCharsets.US_ASCII) : "";
        final int w = s.u16le(6), h = s.u16le(8);
        return Identification.of("image", "GIF")
                .version(v)
                .description("GIF image (" + (v.equals("89a") ? "GIF89a" : "GIF87a") + "), " + w + "x" + h)
                .detail("dimensions", w + " x " + h)
                .build();
    }

    private static Identification bmp(final ByteSource s) throws IOException {
        final long w = s.u32le(18), h = s.u32le(22);
        return Identification.of("image", "BMP").description("Windows BMP image, " + w + "x" + Math.abs((int) h)).detail("dimensions", w + " x " + Math.abs((int) h)).build();
    }

    private static Identification tiff(final ByteSource s, final boolean le) throws IOException {
        return Identification.of("image", "TIFF").description("TIFF image (" + (le ? "little" : "big") + "-endian)").detail("byte order", le ? "little-endian (II)" : "big-endian (MM)").build();
    }

    private static Identification pdf(final ByteSource s) throws IOException {
        // "%PDF-1.x" or "%PDF-2.x"
        final byte[] v = s.bytes(5, 3);
        final String version = v != null ? new String(v, StandardCharsets.US_ASCII).trim() : null;
        return Identification.of("document", "PDF")
                .version(version)
                .description("PDF document" + (version != null ? " (version " + version + ")" : ""))
                .build();
    }

    private static Identification riff(final ByteSource s) throws IOException {
        final byte[] f = s.bytes(8, 4);
        final String form = f != null ? new String(f, StandardCharsets.US_ASCII) : "";
        if (form.equals("WAVE")) return simple("audio", "WAV", "WAV audio (RIFF)");
        if (form.equals("AVI ")) return simple("video", "AVI", "AVI video (RIFF)");
        if (form.equals("WEBP")) return simple("image", "WebP", "WebP image (RIFF)");
        return Identification.of("data", "RIFF").description("RIFF container (" + form.trim() + ")").build();
    }

    private static Identification isoBmff(final ByteSource s) throws IOException {
        final byte[] b = s.bytes(8, 4);
        final String brand = b != null ? new String(b, StandardCharsets.US_ASCII).trim() : "";
        String desc = "ISO base media file";
        String type = "MP4";
        if (brand.startsWith("hei") || brand.equals("mif1")) { type = "HEIF/HEIC"; desc = "HEIF/HEIC image"; return Identification.of("image", type).description(desc).detail("brand", brand).build(); }
        if (brand.equals("qt")) { type = "MOV"; desc = "QuickTime movie"; }
        else if (brand.startsWith("M4A")) { type = "M4A"; desc = "M4A audio"; return Identification.of("audio", type).description(desc).detail("brand", brand).build(); }
        else desc = "MP4 / ISO base media video (brand " + brand + ")";
        return Identification.of("video", type).description(desc).detail("brand", brand).build();
    }

    private static Identification simple(final String cat, final String type, final String desc) {
        return Identification.of(cat, type).description(desc).build();
    }

    private static boolean matchAt(final ByteSource s, final long pos, final String text) throws IOException {
        return s.matches(pos, text.getBytes(StandardCharsets.US_ASCII));
    }
}
