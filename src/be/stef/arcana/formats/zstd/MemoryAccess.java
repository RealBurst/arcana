/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.zstd;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Field;
import java.nio.ByteOrder;

/**
 * Low-level memory accessor for the Zstandard decompressor.
 *
 * <p>Replaces the original {@code UnsafeUtil} / {@code sun.misc.Unsafe} dependency
 * with a self-selecting dual-mode implementation:</p>
 *
 * <ul>
 *   <li><strong>Fast path (Unsafe available)</strong>: delegates to
 *       {@code sun.misc.Unsafe} - zero-overhead multi-byte reads and
 *       direct {@code copyMemory}.  Active on JDK 8 to 21 at least.
 *       Unsafe is reached by reflection and called through {@code static final}
 *       MethodHandles, which the JIT inlines like direct calls: the source has
 *       <b>no compile-time reference to sun.misc</b>, so it compiles everywhere
 *       (Eclipse access rules, {@code javac --release 8}, future JDKs).</li>
 *   <li><strong>Safe path (Unsafe blocked or absent)</strong>: pure-Java
 *       little-endian reads via array indexing.  Activated automatically
 *       whenever the Unsafe path fails for any reason (module restriction,
 *       security manager, class removal in a future JDK).
 *       About 1.5x slower on pure ZSTD decoding (measured JDK 8 and 21),
 *       10-15 % on a whole extraction.</li>
 * </ul>
 *
 * <p>The selection happens once in the static initialiser - no per-call
 * branching overhead when the JIT inlines these small methods.</p>
 *
 * <p>All methods use the same address convention as the original engine:
 * {@code address = BASE + arrayIndex}.  In Unsafe mode {@code BASE} equals
 * the actual array-base offset reported by the JVM (typically 16 on HotSpot
 * x86-64); in safe mode {@code BASE = 0} so addresses are plain indices.</p>
 *
 * <h3>Byte order</h3>
 * <p>The Zstandard algorithm is inherently little-endian.  Both paths
 * produce little-endian results.  A {@link ZstdIncompatibleJvmException}
 * is thrown at class-load time on big-endian platforms.</p>
 *
 * @author Stef
 * @since 1.3 (replaces UnsafeUtil, no external API change)
 */
final class MemoryAccess
{
    // -------------------------------------------------------------------------
    // Selection
    // -------------------------------------------------------------------------

    /** true when sun.misc.Unsafe is accessible; false = safe-path active. */
    static final boolean USE_UNSAFE;

    /**
     * Array base offset used to convert between array indices and addresses.
     * <ul>
     *   <li>Unsafe mode: {@code Unsafe.arrayBaseOffset(byte[].class)}, typically 16.</li>
     *   <li>Safe mode: 0 - addresses <em>are</em> array indices.</li>
     * </ul>
     */
    static final long BASE;

    // sun.misc.Unsafe methods, reached through MethodHandles bound to the Unsafe
    // instance: the source has NO compile-time reference to sun.misc (compiles with
    // javac --release 8 and with Eclipse's default access rules), while the JIT
    // inlines "static final" MethodHandles like direct calls (same speed).
    // null when USE_UNSAFE is false.
    private static final MethodHandle GET_BYTE, GET_SHORT, GET_INT, GET_LONG;
    private static final MethodHandle PUT_BYTE, PUT_SHORT, PUT_INT, PUT_LONG;
    private static final MethodHandle COPY_MEMORY;
    private static final Object UNSAFE; // the sun.misc.Unsafe instance, typed Object

    static {
        // Zstandard requires little-endian byte ordering
        if (!ByteOrder.nativeOrder().equals(ByteOrder.LITTLE_ENDIAN)) {
            throw new ZstdIncompatibleJvmException("Zstandard requires a little-endian platform (found: " + ByteOrder.nativeOrder() + ")");
        }

        Object uo = null;
        MethodHandle gb = null, gs = null, gi = null, gl = null, pb = null, ps = null, pi = null, pl = null, cm = null;
        long base = 0L;
        // Allow forcing safe mode for testing or diagnostics:
        //   java -Darcana.zstd.safe=true -jar Arcana.jar ...
        final boolean forceSafe = Boolean.getBoolean("arcana.zstd.safe");
        if (!forceSafe) {
            try {
                final Class<?> c = Class.forName("sun.misc.Unsafe");
                final Field f = c.getDeclaredField("theUnsafe");
                f.setAccessible(true);
                final Object u = f.get(null);
                uo = u;
                final MethodHandles.Lookup l = MethodHandles.lookup();
                gb = objectReceiver(l.unreflect(c.getMethod("getByte", Object.class, long.class)));
                gs = objectReceiver(l.unreflect(c.getMethod("getShort", Object.class, long.class)));
                gi = objectReceiver(l.unreflect(c.getMethod("getInt", Object.class, long.class)));
                gl = objectReceiver(l.unreflect(c.getMethod("getLong", Object.class, long.class)));
                pb = objectReceiver(l.unreflect(c.getMethod("putByte", Object.class, long.class, byte.class)));
                ps = objectReceiver(l.unreflect(c.getMethod("putShort", Object.class, long.class, short.class)));
                pi = objectReceiver(l.unreflect(c.getMethod("putInt", Object.class, long.class, int.class)));
                pl = objectReceiver(l.unreflect(c.getMethod("putLong", Object.class, long.class, long.class)));
                cm = objectReceiver(l.unreflect(c.getMethod("copyMemory", Object.class, long.class, Object.class, long.class, long.class)));
                base = ((Number) c.getMethod("arrayBaseOffset", Class.class).invoke(u, byte[].class)).longValue(); // typically 16 on HotSpot x86/x64
            } catch (Throwable ignored) {
                // Unsafe blocked (module/security restrictions) or removed in a future JDK:
                // fall back to safe pure-Java mode with BASE = 0.
                gb = gs = gi = gl = pb = ps = pi = pl = cm = null;
                uo = null;
                base = 0L;
            }
        }
        GET_BYTE = gb; GET_SHORT = gs; GET_INT = gi; GET_LONG = gl;
        PUT_BYTE = pb; PUT_SHORT = ps; PUT_INT = pi; PUT_LONG = pl;
        COPY_MEMORY = cm;
        UNSAFE = uo;
        BASE       = base;
        USE_UNSAFE = (cm != null);
    }

    /** Handle whose receiver (the Unsafe instance) is typed Object. */
    private static MethodHandle objectReceiver(final MethodHandle m) {
        return m.asType(m.type().changeParameterType(0, Object.class));
    }

    /** A MethodHandle call cannot fail here (same types as the Unsafe methods). */
    private static RuntimeException rethrow(final Throwable t) {
        if (t instanceof RuntimeException) return (RuntimeException) t;
        if (t instanceof Error) throw (Error) t;
        return new IllegalStateException(t);
    }

    private MemoryAccess() {}

    // =========================================================================
    // Read methods (byte[] variants - used by most ZSTD classes)
    // =========================================================================

    static byte getByte(final byte[] buf, final long addr) {
        if (USE_UNSAFE) { try { return (byte) GET_BYTE.invokeExact(UNSAFE, (Object) buf, addr); } catch (Throwable t) { throw rethrow(t); } }
        return buf[(int) addr];
    }

    static short getShort(final byte[] buf, final long addr) {
        if (USE_UNSAFE) { try { return (short) GET_SHORT.invokeExact(UNSAFE, (Object) buf, addr); } catch (Throwable t) { throw rethrow(t); } }
        final int i = (int) addr;
        return (short) ((buf[i] & 0xFF) | ((buf[i + 1] & 0xFF) << 8));
    }

    static int getInt(final byte[] buf, final long addr) {
        if (USE_UNSAFE) { try { return (int) GET_INT.invokeExact(UNSAFE, (Object) buf, addr); } catch (Throwable t) { throw rethrow(t); } }
        final int i = (int) addr;
        return (buf[i] & 0xFF)
             | ((buf[i + 1] & 0xFF) << 8)
             | ((buf[i + 2] & 0xFF) << 16)
             | ((buf[i + 3] & 0xFF) << 24);
    }

    static long getLong(final byte[] buf, final long addr) {
        if (USE_UNSAFE) { try { return (long) GET_LONG.invokeExact(UNSAFE, (Object) buf, addr); } catch (Throwable t) { throw rethrow(t); } }
        final int i = (int) addr;
        return  (buf[i]     & 0xFFL)
             | ((buf[i + 1] & 0xFFL) <<  8)
             | ((buf[i + 2] & 0xFFL) << 16)
             | ((buf[i + 3] & 0xFFL) << 24)
             | ((buf[i + 4] & 0xFFL) << 32)
             | ((buf[i + 5] & 0xFFL) << 40)
             | ((buf[i + 6] & 0xFFL) << 48)
             | ((buf[i + 7] & 0xFFL) << 56);
    }

    // =========================================================================
    // Read methods (Object variants - used by Util.java which types base as Object)
    // =========================================================================

    static byte getByte(final Object buf, final long addr) {
        if (USE_UNSAFE) { try { return (byte) GET_BYTE.invokeExact(UNSAFE, (Object) buf, addr); } catch (Throwable t) { throw rethrow(t); } }
        return getByte((byte[]) buf, addr);
    }

    static short getShort(final Object buf, final long addr) {
        if (USE_UNSAFE) { try { return (short) GET_SHORT.invokeExact(UNSAFE, (Object) buf, addr); } catch (Throwable t) { throw rethrow(t); } }
        return getShort((byte[]) buf, addr);
    }

    static int getInt(final Object buf, final long addr) {
        if (USE_UNSAFE) { try { return (int) GET_INT.invokeExact(UNSAFE, (Object) buf, addr); } catch (Throwable t) { throw rethrow(t); } }
        return getInt((byte[]) buf, addr);
    }

    static long getLong(final Object buf, final long addr) {
        if (USE_UNSAFE) { try { return (long) GET_LONG.invokeExact(UNSAFE, (Object) buf, addr); } catch (Throwable t) { throw rethrow(t); } }
        return getLong((byte[]) buf, addr);
    }

    // =========================================================================
    // Write methods (byte[] variants)
    // =========================================================================

    static void putByte(final byte[] buf, final long addr, final byte val) {
        if (USE_UNSAFE) { try { PUT_BYTE.invokeExact(UNSAFE, (Object) buf, addr, val); return; } catch (Throwable t) { throw rethrow(t); } }
        buf[(int) addr] = val;
    }

    static void putShort(final byte[] buf, final long addr, final short val) {
        if (USE_UNSAFE) { try { PUT_SHORT.invokeExact(UNSAFE, (Object) buf, addr, val); return; } catch (Throwable t) { throw rethrow(t); } }
        final int i = (int) addr;
        buf[i]     = (byte)  val;
        buf[i + 1] = (byte) (val >>> 8);
    }

    static void putLong(final byte[] buf, final long addr, final long val) {
        if (USE_UNSAFE) { try { PUT_LONG.invokeExact(UNSAFE, (Object) buf, addr, val); return; } catch (Throwable t) { throw rethrow(t); } }
        final int i = (int) addr;
        buf[i]     = (byte)  val;
        buf[i + 1] = (byte) (val >>>  8);
        buf[i + 2] = (byte) (val >>> 16);
        buf[i + 3] = (byte) (val >>> 24);
        buf[i + 4] = (byte) (val >>> 32);
        buf[i + 5] = (byte) (val >>> 40);
        buf[i + 6] = (byte) (val >>> 48);
        buf[i + 7] = (byte) (val >>> 56);
    }

    static void putInt(final byte[] buf, final long addr, final int val) {
        if (USE_UNSAFE) { try { PUT_INT.invokeExact(UNSAFE, (Object) buf, addr, val); return; } catch (Throwable t) { throw rethrow(t); } }
        final int i = (int) addr;
        buf[i]     = (byte)  val;
        buf[i + 1] = (byte) (val >>>  8);
        buf[i + 2] = (byte) (val >>> 16);
        buf[i + 3] = (byte) (val >>> 24);
    }

    // =========================================================================
    // Write methods (Object variants - used by Util.java and ZstdFrameDecompressor)
    // =========================================================================

    static void putByte(final Object buf, final long addr, final byte val) {
        if (USE_UNSAFE) { try { PUT_BYTE.invokeExact(UNSAFE, (Object) buf, addr, val); return; } catch (Throwable t) { throw rethrow(t); } }
        putByte((byte[]) buf, addr, val);
    }

    static void putShort(final Object buf, final long addr, final short val) {
        if (USE_UNSAFE) { try { PUT_SHORT.invokeExact(UNSAFE, (Object) buf, addr, val); return; } catch (Throwable t) { throw rethrow(t); } }
        putShort((byte[]) buf, addr, val);
    }

    static void putInt(final Object buf, final long addr, final int val) {
        if (USE_UNSAFE) { try { PUT_INT.invokeExact(UNSAFE, (Object) buf, addr, val); return; } catch (Throwable t) { throw rethrow(t); } }
        putInt((byte[]) buf, addr, val);
    }

    static void putLong(final Object buf, final long addr, final long val) {
        if (USE_UNSAFE) { try { PUT_LONG.invokeExact(UNSAFE, (Object) buf, addr, val); return; } catch (Throwable t) { throw rethrow(t); } }
        putLong((byte[]) buf, addr, val);
    }

    // =========================================================================
    // Copy
    // =========================================================================

    /**
     * Copies {@code len} bytes from {@code src[srcAddr..]} to {@code dst[dstAddr..]}.
     *
     * <p>Handles the overlapping-copy case required by LZ77 back-references:
     * when {@code src == dst} and the source and destination windows overlap,
     * a forward byte-by-byte copy is used so that already-written output
     * bytes can be re-read ("repeat" pattern).</p>
     */
    static void copyMemory(final byte[] src, final long srcAddr,
                           final byte[] dst, final long dstAddr, final long len) {
        if (USE_UNSAFE) { try { COPY_MEMORY.invokeExact(UNSAFE, (Object) src, srcAddr, (Object) dst, dstAddr, len); return; } catch (Throwable t) { throw rethrow(t); } }
        final int s = (int) srcAddr;
        final int d = (int) dstAddr;
        final int l = (int) len;
        if (src != dst) {
            System.arraycopy(src, s, dst, d, l);
        } else {
            // Forward byte-by-byte: deliberately copies already-written bytes
            // to implement LZ77 overlap repeat (e.g. distance=1 repeats last byte).
            for (int k = 0; k < l; k++) dst[d + k] = src[s + k];
        }
    }

    /** Object-typed variant for callers that use {@code Object} as base type. */
    static void copyMemory(final Object src, final long srcAddr,
                           final Object dst, final long dstAddr, final long len) {
        if (USE_UNSAFE) { try { COPY_MEMORY.invokeExact(UNSAFE, (Object) src, srcAddr, (Object) dst, dstAddr, len); return; } catch (Throwable t) { throw rethrow(t); } }
        copyMemory((byte[]) src, srcAddr, (byte[]) dst, dstAddr, len);
    }
}