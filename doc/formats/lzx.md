# LZX codec

| | |
|---|---|
| Extensions | none (a codec, not a file format) |
| Signature | none; selected by the container: CAB folder method 3, CHM "MSCompressed" section ("LZXC" control data), WIM compression flag 0x40000 |
| Arcana support | decode only |
| Main classes | `be.stef.arcana.formats.lzx.LzxDecoder` (CAB, CHM), `be.stef.arcana.formats.wim.WimLzxDecoder` (WIM) |
| Test samples | `test/samples/chm/help.chm` (64 KiB window, reset every 2 frames), `test/samples/wim/lzx.wim`; no LZX cabinet in `test/samples/cab` |

## Overview

LZX is an LZ77 + Huffman compression method designed by Jonathan Forbes and
Tomi Poutanen in the mid-1990s and acquired by Microsoft. It is used in
Cabinet files, Compiled HTML Help files, Windows Imaging (WIM) files, and in
other Microsoft formats that Arcana does not read (for example patch files
using the LZX DELTA extension). Its window is 32 KiB to 2 MiB; the output
is produced in frames of 32 KiB; an optional filter turns the relative target
of x86 CALL instructions into absolute addresses before compression.

## Detection

LZX is not a file format and has no signature. It is used by:

- **CAB**: a folder whose `typeCompress` has method 3 in its low 4 bits; bits
  8-12 give the window size (log2). See [cab.md](cab.md).
- **CHM**: section 1 ("MSCompressed") of a help file, described by the
  "LZXC" control data and the reset table. See [chm.md](chm.md).
- **WIM**: a WIM whose header flags have 0x40000, or a solid resource whose
  chunk header gives LZX. Decoded by the separate `WimLzxDecoder` (see
  Variants).

## Structure

### Bit stream

The compressed data is read as 16-bit little-endian words; inside a word, bits
are taken from the most significant one. Past the end of the input, both
decoders feed zero words (no error is raised at that point; a corrupted stream
fails later on an invalid code, offset or block).

### Stream header (CAB, CHM)

At the start of the stream, and again after every CHM reset, one bit tells
whether the x86 CALL translation is used; when it is 1, a 32-bit translation
size follows (read as two 16-bit fields, high part first).

### Blocks

| Field | Bits | Notes |
|---|---|---|
| block type | 3 | 1 verbatim, 2 aligned offset, 3 uncompressed; any other value is an error |
| block size | 24 | uncompressed bytes of the block (16 bits then 8 bits); 0 is an error |

Then, depending on the type:

| Type | Content after the header |
|---|---|
| aligned offset | 8 code lengths of 3 bits (aligned offset tree), then the same trees as verbatim |
| verbatim | main tree lengths for the 256 literals, main tree lengths for the match symbols, length tree lengths; then the symbols |
| uncompressed | 1 to 16 bits of padding up to a 16-bit boundary, R0, R1, R2 (3 x 32 bits little-endian), the raw bytes, and one padding byte when the size is odd |

A block may span several frames; a frame may contain several blocks.

### Trees

| Tree | Symbols | Notes |
|---|---|---|
| pretree | 20 | 20 lengths of 4 bits, sent before each run of code lengths |
| main | 256 + 8 x position slots | literals, then (slot, length header) pairs |
| length | 249 | extra length when the length header is 7 |
| aligned offset | 8 | aligned blocks only |

Position slots: 30, 32, 34, 36 and 38 for windows of 2^15 to 2^19, 42 for
2^20, 50 for 2^21 (`2 * windowBits`, except 20 and 21).

Code lengths are sent through the pretree as differences with the lengths of
the previous block (`LzxDecoder.readLengths`), which start at 0:

| Pretree symbol | Meaning |
|---|---|
| 0-16 | new length = (previous - symbol + 17) mod 17 |
| 17 | 4 + (4 bits) zero lengths |
| 18 | 20 + (5 bits) zero lengths |
| 19 | 4 + (1 bit) equal lengths; their value comes from the next pretree symbol (0-16) applied to the first previous length |

The main tree is sent in two runs (256 literals, then the match symbols), each
with its own pretree. All codes are canonical Huffman codes of at most 16 bits.

### Matches

A main symbol `s >= 256` is a match: `slot = (s - 256) >> 3`, length header
`= (s - 256) & 7`. When the header is 7, a length tree symbol is added. The
match length is header (+ length symbol) + 2, so 2 to 257 bytes.

| Slot | Offset |
|---|---|
| 0 | R0 |
| 1 | R1, swapped with R0 |
| 2 | R2, swapped with R0 |
| 3 and more | base(slot) + footer bits - 2; R2 = R1, R1 = R0, R0 = offset |

Footer bits per slot: 0 for slots 0-3, then `min(slot / 2 - 1, 17)`; the
bases are the running sum of `2^footer`. In an aligned offset block, when a
slot has 3 or more footer bits, the top `footer - 3` bits are read verbatim and
the low 3 bits are an aligned offset tree symbol. R0, R1 and R2 start at 1.

## Compression and encryption

### Frames (`LzxDecoder.decompress`)

`LzxDecoder` decodes one frame per call: the caller gives the compressed byte
range of the frame and its output size (32768, or less for the last frame;
more than 32768 is an error). The window, R0-R2, the code lengths, the
current block and the translation header carry over from one call to the next.
The bit buffer is restarted at every call, since each frame starts on its own
byte range (a CAB `CFDATA`, a CHM reset table entry).

A match may end after the end of the frame; the extra bytes are kept in the
window and counted as the start of the next frame (`overrun`). A match that
goes past the end of its block is an error ("LZX match past the end of its
block").

### x86 CALL translation (`undoE8`)

When the stream header enabled it, every frame is post-processed after
decoding: for each `E8` byte (except in the last 10 bytes of the frame), the
following 32-bit value `abs` is converted back when `-pos <= abs < size`
(`pos` = position of the `E8` byte in the whole output, `size` = translation
size): `abs - pos` when `abs >= 0`, `abs + size` otherwise; the 4 bytes are
then skipped. Frames of 10 bytes or less are not processed, and the
translation stops after the first 32768 frames (1 GiB of output).

### Resets

- `reset()`: everything, including the window position and the translation
  position. Used at the start of a CAB folder (one decoder per folder) and at
  the start of a CHM section.
- `resetState()`: R0-R2 = 1, code lengths to 0, current block dropped, stream
  header (translation bit) read again. The window content and the output
  position go on. Used at each CHM reset interval.

Arcana has no LZX encoder; there is no encryption.

## Variants and versions

| | CAB | CHM | WIM |
|---|---|---|---|
| Decoder | `LzxDecoder` | `LzxDecoder` | `WimLzxDecoder` |
| Window | 2^15 to 2^21 from `typeCompress` (0 means 15) | 2^15 to 2^21 from the control data | the chunk size (32 KiB by default), rounded up to a power of two, at most 2^21 |
| Frame input | one `CFDATA` block | reset table entry i to entry i+1 | one chunk (an independent stream) |
| State between frames | kept for the whole folder | kept; `resetState()` every reset interval | none: lengths and R0-R2 reset at each chunk |
| Translation header | 1 bit (+ 32-bit size) at stream start | same, after every reset | none: always on, size 12000000 |
| Translation position | output offset in the folder | output offset in the section | offset in the chunk |
| Block size field | 24 bits | 24 bits | 1 bit "default" (32768), else 16 bits, plus 8 bits when the window is 64 KiB or more |

`WimLzxDecoder` also clamps a block size larger than what remains of the chunk
to the remaining size, refuses matches that reach before the start of the
chunk ("LZX match before the start of the output") or past its end, and
decodes straight into the output buffer (no separate window). It uses a 64-bit
bit buffer instead of 32 bits.

LZX DELTA ([MS-PATCH]) extends LZX with windows up to 32 MiB and a reference
data; neither decoder supports it (`LzxDecoder` refuses window sizes outside
15-21: "LZX invalid window size 2^n").

## Limits

- Windows larger than 2 MiB (LZX DELTA, some WIM chunk sizes) are refused.
- No encoder: Arcana cannot create LZX cabinets, CHM or WIM files.
- A truncated frame is not detected as such (zero bits are read past the
  end): the error, if any, is the first invalid structure met ("Invalid LZX
  Huffman code", "Invalid LZX match offset n", "LZX uncompressed block
  truncated", "LZX stream truncated"). An `ArrayIndexOutOfBoundsException`
  during decoding is reported as "LZX stream corrupted". All of these are
  `ArcanaCorruptedException`.
- The decoder does not check that a frame consumed exactly its input bytes.

## Implementation notes

- Huffman decoding (`Huffman.build`, `decode`) uses a 1024-entry table for
  codes of up to 10 bits; longer codes (up to 16) are found by walking the
  canonical code length by length. Lengths whose short codes (10 bits or
  less) overflow the table are refused ("Invalid LZX Huffman lengths").
- Match offsets larger than the window, or 0 and below, are refused.
- The window is a ring buffer of `2^windowBits` bytes; the frame is copied out
  of it after decoding, so the caller's output buffer only needs the frame size.
- For an uncompressed block, the padding rule depends on the bits left in the
  32-bit buffer after the header: none left means a whole 16-bit word of
  padding is skipped; more than 16 means one word was read ahead and is given
  back; otherwise the rest of the current word is the padding.
- `LzxDecoder` and `WimLzxDecoder` share the same tree and slot logic but are
  separate classes; a fix in one must be checked in the other.

## Sources

- Microsoft, [MS-PATCH] LZX DELTA Compression and Decompression (LZX block
  types, trees, position slots, x86 translation):
  https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/cc78752a-b4af-4eee-88cb-01f4d8a4c2bf
- Microsoft, "Microsoft Cabinet Format" (LZX folders, window size in
  `typeCompress`): https://learn.microsoft.com/en-us/previous-versions/bb267310(v=vs.85)
- CHM format description, chmspec project (LZXC control data and reset table):
  https://www.nongnu.org/chmspec/latest/ITSF.html

License: `LzxDecoder` and `WimLzxDecoder` are Copyright 2026 Stephane Bury,
Apache-2.0 (file headers); both state that they were written from the
Microsoft LZX documentation ([MS-PATCH] LZX DELTA and the Cabinet LZX format).
