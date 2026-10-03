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
package be.stef.arcana.formats.sevenz;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Read-only channel over the volumes of a split 7z archive (name.7z.001,
 * name.7z.002...), seen as one file. 7-Zip splits an archive byte by byte, so
 * the volumes only need to be concatenated.
 *
 * @author Stef
 * @since 1.0.3
 */
public final class MultiVolumeChannel implements SeekableByteChannel {

    private static final Pattern FIRST_VOLUME = Pattern.compile("(?i)(.*\\.7z\\.)(0*1)");

    private final RandomAccessFile[] parts;
    private final long[] starts; // starts[i] = position of part i; starts[n] = total size
    private long position;
    private boolean open = true;

    private MultiVolumeChannel(final List<File> files) throws IOException {
        parts = new RandomAccessFile[files.size()];
        starts = new long[files.size() + 1];
        try {
            for (int i = 0; i < parts.length; i++) {
                parts[i] = new RandomAccessFile(files.get(i), "r");
                starts[i + 1] = starts[i] + parts[i].length();
            }
        } catch (final IOException e) {
            closeParts();
            throw e;
        }
    }

    /**
     * The volumes of a split archive whose first volume is {@code first}
     * ("x.7z.001", "x.7z.01"...), in order, or null if the name is not the one of
     * a first volume. The list stops at the first missing number.
     */
    public static List<File> volumes(final File first) {
        final Matcher m = FIRST_VOLUME.matcher(first.getName());
        if (!m.matches()) return null;
        final String base = m.group(1);
        final int width = m.group(2).length();
        final File dir = first.getAbsoluteFile().getParentFile();
        final List<File> files = new ArrayList<File>();
        for (int n = 1; n < 100000; n++) {
            String num = Integer.toString(n);
            while (num.length() < width) num = "0" + num;
            final File f = new File(dir, base + num);
            if (!f.isFile()) break;
            files.add(f);
        }
        return files.isEmpty() ? null : files;
    }

    /** Total size of the volumes of a split archive, or the size of the file itself. */
    public static long totalSize(final File file) {
        final List<File> v = volumes(file);
        if (v == null) return file.length();
        long total = 0;
        for (final File f : v) total += f.length();
        return total;
    }

    /** Opens the volumes of a split archive; null if {@code first} is not a first volume. */
    public static MultiVolumeChannel open(final File first) throws IOException {
        final List<File> v = volumes(first);
        return v == null ? null : new MultiVolumeChannel(v);
    }

    /** Number of volumes. */
    public int getVolumeCount() {
        return parts.length;
    }

    @Override
    public int read(final ByteBuffer dst) throws IOException {
        if (!open) throw new ClosedChannelException();
        if (!dst.hasRemaining()) return 0;
        if (position >= starts[parts.length]) return -1;
        int total = 0;
        while (dst.hasRemaining() && position < starts[parts.length]) {
            int i = 0;
            while (position >= starts[i + 1]) i++;
            final RandomAccessFile f = parts[i];
            final long inPart = position - starts[i];
            final int n = (int) Math.min(dst.remaining(), starts[i + 1] - position);
            final int k = f.getChannel().read((ByteBuffer) dst.duplicate().limit(dst.position() + n), inPart);
            if (k <= 0) break;
            dst.position(dst.position() + k);
            position += k;
            total += k;
        }
        return total == 0 ? -1 : total;
    }

    @Override
    public int write(final ByteBuffer src) {
        throw new NonWritableChannelException();
    }

    @Override
    public long position() throws IOException {
        if (!open) throw new ClosedChannelException();
        return position;
    }

    @Override
    public SeekableByteChannel position(final long newPosition) throws IOException {
        if (!open) throw new ClosedChannelException();
        if (newPosition < 0) throw new IOException("Negative position");
        position = newPosition;
        return this;
    }

    @Override
    public long size() throws IOException {
        if (!open) throw new ClosedChannelException();
        return starts[parts.length];
    }

    @Override
    public SeekableByteChannel truncate(final long size) {
        throw new NonWritableChannelException();
    }

    @Override
    public boolean isOpen() {
        return open;
    }

    @Override
    public void close() throws IOException {
        open = false;
        closeParts();
    }

    private void closeParts() throws IOException {
        IOException first = null;
        for (final RandomAccessFile f : parts) {
            if (f == null) continue;
            try {
                f.close();
            } catch (final IOException e) {
                if (first == null) first = e;
            }
        }
        if (first != null) throw first;
    }
}
