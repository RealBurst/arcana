# Format name

| | |
|---|---|
| Extensions | `.ext`, `.ext2` |
| Signature | `XX YY` at offset 0 (or how the format is recognized when it has none) |
| Arcana support | list, extract (and create, encrypt, recover when available) |
| Main classes | `be.stef.arcana.formats.xxx.XxxReader`, `be.stef.arcana.extractor.XxxExtractor` |
| Test samples | `test/samples/xxx/` |

## Overview

What the format is, who made it, when, where it is met today.

## Detection

How Arcana recognizes the format: signature and offset, extra checks,
extension fallback, conflicts with other formats.

## Structure

Layout of the file: headers, tables, records. Offset tables where useful:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | signature | |

## Compression and encryption

Methods and encryption schemes of the format, and which ones Arcana decodes
(and encodes).

## Variants and versions

Versions, dialects and extensions met in the wild, and how Arcana handles them.

## Limits

What Arcana does not support, and what happens then (error message).

## Implementation notes

Choices made in Arcana: performance, memory, safety checks (path traversal,
size limits), integrity checks (CRC, hashes), pitfalls met and fixed.

## Sources

Public specifications and documents the implementation is based on, and the
license status of the code (from the file headers). The core of Arcana is
Apache-2.0: it is written from public specifications and documentation.
