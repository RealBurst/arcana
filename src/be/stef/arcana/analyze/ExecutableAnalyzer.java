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
import be.stef.arcana.formats.carve.DotNetBundle;
import be.stef.arcana.formats.carve.PeImage;
import java.io.IOException;

/**
 * Identifies executables and shared libraries: Windows PE (EXE/DLL/SYS/EFI),
 * Linux/Unix ELF, Mach-O (macOS), Java class files and WebAssembly.
 *
 * <p>For a PE, the version is read from its VERSIONINFO resource when present,
 * and a .NET single-file bundle is signalled.</p>
 *
 * @author Stef
 * @since 1.4
 */
public final class ExecutableAnalyzer implements ArcanaAnalyzer {

    @Override
    public String getId() {
        return "arcana.executable";
    }

    @Override
    public Identification analyze(final ByteSource s, final String fileName) throws IOException {
        final int c0 = s.u8(0), c1 = s.u8(1);
        if (c0 == 'M' && c1 == 'Z') return pe(s);
        if (c0 == 0x7F && c1 == 'E' && s.u8(2) == 'L' && s.u8(3) == 'F') return elf(s);
        if (c0 == 0xCA && c1 == 0xFE && s.u8(2) == 0xBA && s.u8(3) == 0xBE) {
            // shared magic: a Java class file has a major version >= 45 at offset 6; a Mach-O fat binary has a small architecture count there
            return s.u16be(6) >= 45 ? javaClass(s) : macho(s);
        }
        if (isMachO(s)) return macho(s);
        if (c0 == 0x00 && c1 == 'a' && s.u8(2) == 's' && s.u8(3) == 'm') return wasm(s);
        return null;
    }

    // =========================================================================
    // PE (Windows)
    // =========================================================================

    private static Identification pe(final ByteSource s) throws IOException {
        final PeImage pe = PeImage.parse(s, 0);
        if (pe == null) {
            // "MZ" but not a valid PE: a real-mode MS-DOS program
            return Identification.of("executable", "MS-DOS").description("MS-DOS executable (MZ)").confidence(60).build();
        }
        final Identification.Builder b = Identification.of("executable", pe.pe64 ? "PE32+" : "PE32")
                .description(pe.describe())
                .detail("kind", pe.dll ? "DLL (dynamic library)" : "EXE (application)")
                .detail("architecture", arch(pe.machine))
                .detail("subsystem", subsystem(pe.subsystem));
        if (pe.name != null) b.detail("internal name", pe.name);
        final DotNetBundle.Manifest bundle = DotNetBundle.findInExecutable(s);
        if (bundle != null) {
            b.detail("runtime", ".NET single-file bundle (" + bundle.entries.size() + " files, format v" + bundle.major + ")");
        } else if (hasCliHeader(s, pe)) {
            b.detail("runtime", ".NET / CLI assembly (managed)");
        }
        final String version = peVersion(s, pe);
        if (version != null) b.version(version);
        if (pe.certSize > 0) b.detail("signature", "Authenticode signature present (" + pe.certSize + " bytes)");
        return b.build();
    }

    private static String arch(final int machine) {
        switch (machine) {
            case 0x014C: return "x86 (32-bit)";
            case 0x8664: return "x64 (64-bit)";
            case 0xAA64: return "ARM64";
            case 0x01C0: case 0x01C4: return "ARM";
            case 0x0200: return "IA-64";
            default: return String.format("machine 0x%04X", machine);
        }
    }

    private static String subsystem(final int sub) {
        switch (sub) {
            case 1: return "native / driver";
            case 2: return "Windows GUI";
            case 3: return "Windows console";
            case 5: return "OS/2 console";
            case 7: return "POSIX console";
            case 9: return "Windows CE GUI";
            case 10: return "EFI application";
            case 11: return "EFI boot driver";
            case 12: return "EFI runtime driver";
            case 13: return "EFI ROM";
            case 14: return "Xbox";
            case 16: return "boot application";
            default: return "subsystem " + sub;
        }
    }

    /** True if the PE has a non-empty CLI (.NET) data directory (index 14). */
    private static boolean hasCliHeader(final ByteSource s, final PeImage pe) throws IOException {
        // The COM descriptor directory lives at a fixed offset from the optional header.
        // Reusing PeImage would be cleaner, but its directory table is not exposed; scan is enough here.
        final long peSig = s.u32le(0x3C);
        if (peSig <= 0 || !s.matches(peSig, new byte[] {'P', 'E', 0, 0})) return false;
        final int opt = (int) peSig + 24;
        final int magic = s.u16le(opt);
        final int dirBase = opt + (magic == 0x20B ? 112 : 96); // data directories
        final long comRva = s.u32le(dirBase + 14 * 8);
        final long comSize = s.u32le(dirBase + 14 * 8 + 4);
        return comRva > 0 && comSize > 0;
    }

    /**
     * File version from the VERSIONINFO resource: locate the "VS_VERSION_INFO"
     * UTF-16 marker, then the VS_FIXEDFILEINFO signature 0xFEEF04BD, and read the
     * file version dwords. Returns "a.b.c.d" or null.
     */
    private static String peVersion(final ByteSource s, final PeImage pe) throws IOException {
        final long end = Math.min(s.length(), pe.size);
        final byte[] marker = utf16("VS_VERSION_INFO");
        long at = s.indexOf(marker, 0, end);
        while (at >= 0) {
            // VS_FIXEDFILEINFO starts a little after the marker, aligned on 4 bytes; search a small window.
            final long sig = s.indexOf(new byte[] {(byte) 0xBD, 0x04, (byte) 0xEF, (byte) 0xFE}, at, Math.min(end, at + 64));
            if (sig >= 0) {
                final long ms = s.u32le(sig + 8), ls = s.u32le(sig + 12); // dwFileVersionMS, dwFileVersionLS
                final int a = (int) (ms >>> 16), b = (int) (ms & 0xFFFF), c = (int) (ls >>> 16), d = (int) (ls & 0xFFFF);
                if ((a | b | c | d) != 0) return a + "." + b + "." + c + "." + d;
            }
            at = s.indexOf(marker, at + 2, end);
        }
        return null;
    }

    private static byte[] utf16(final String s) {
        final byte[] b = new byte[s.length() * 2];
        for (int i = 0; i < s.length(); i++) b[i * 2] = (byte) s.charAt(i);
        return b;
    }

    // =========================================================================
    // ELF (Linux / Unix)
    // =========================================================================

    private static Identification elf(final ByteSource s) throws IOException {
        final boolean is64 = s.u8(4) == 2;
        final boolean le = s.u8(5) == 1;
        final int type = read16(s, 16, le);
        final int machine = read16(s, 18, le);
        final String kind;
        switch (type) {
            case 1: kind = "relocatable object (.o)"; break;
            case 2: kind = "executable"; break;
            case 3: kind = "shared object (.so) or PIE executable"; break;
            case 4: kind = "core dump"; break;
            default: kind = "type " + type;
        }
        return Identification.of("executable", "ELF")
                .description("ELF " + (is64 ? "64-bit" : "32-bit") + " " + kind + " - " + elfMachine(machine))
                .detail("class", is64 ? "64-bit" : "32-bit")
                .detail("endianness", le ? "little-endian" : "big-endian")
                .detail("kind", kind)
                .detail("architecture", elfMachine(machine))
                .build();
    }

    private static String elfMachine(final int m) {
        switch (m) {
            case 3: return "x86";
            case 62: return "x86-64";
            case 40: return "ARM";
            case 183: return "AArch64 (ARM64)";
            case 243: return "RISC-V";
            case 8: return "MIPS";
            case 20: return "PowerPC";
            case 21: return "PowerPC64";
            default: return "machine " + m;
        }
    }

    // =========================================================================
    // Mach-O (macOS)
    // =========================================================================

    private static boolean isMachO(final ByteSource s) throws IOException {
        final long m = s.u32be(0);
        return m == 0xFEEDFACEL || m == 0xFEEDFACFL || m == 0xCEFAEDFEL || m == 0xCFFAEDFEL || m == 0xBEBAFECAL;
    }

    private static Identification macho(final ByteSource s) throws IOException {
        final long m = s.u32be(0);
        if (m == 0xCAFEBABEL || m == 0xBEBAFECAL) {
            return Identification.of("executable", "Mach-O")
                    .description("Mach-O universal (fat) binary")
                    .detail("format", "universal (multiple architectures)")
                    .build();
        }
        final boolean is64 = m == 0xFEEDFACFL || m == 0xCFFAEDFEL;
        return Identification.of("executable", "Mach-O")
                .description("Mach-O " + (is64 ? "64-bit" : "32-bit") + " executable (macOS)")
                .detail("class", is64 ? "64-bit" : "32-bit")
                .build();
    }

    // =========================================================================
    // Java class / WebAssembly
    // =========================================================================

    private static Identification javaClass(final ByteSource s) throws IOException {
        final int major = s.u16be(6);
        // 45 = Java 1.1, 52 = Java 8, 61 = Java 17, 65 = Java 21...
        final String java = major >= 45 ? (major <= 48 ? "1." + (major - 44) : String.valueOf(major - 44)) : null;
        return Identification.of("executable", "Java class")
                .description("Java compiled class file" + (java != null ? " (Java " + java + ")" : ""))
                .version(java)
                .detail("class file version", major + ".0")
                .build();
    }

    private static Identification wasm(final ByteSource s) throws IOException {
        final long version = s.u32le(4);
        return Identification.of("executable", "WebAssembly")
                .description("WebAssembly binary module")
                .version(String.valueOf(version))
                .build();
    }

    private static int read16(final ByteSource s, final long p, final boolean le) throws IOException {
        return le ? s.u16le(p) : s.u16be(p);
    }
}
