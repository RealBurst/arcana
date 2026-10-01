/*
 * Copyright 2025 Stephane Bury - Derived from Apache Commons Compress
 * (BinaryTree.java, Apache License 2.0).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.lha;

import java.io.IOException;
import java.util.Arrays;

/**
 * Canonical binary Huffman tree used by the LZH decompressor.
 *
 * <p>The tree is built from an array of code lengths.  Each array index is a
 * symbol value; the array element is the Huffman code length (depth) assigned
 * to that symbol.  Once built, {@link #read(LhaBitInputStream)} walks the tree
 * one bit at a time and returns the symbol at the reached leaf.</p>
 *
 * <p>Special case: if the array has exactly one element it represents a single
 * value (root-only tree) and no bits are consumed on each read.</p>
 *
 * <p>Derived from {@code org.apache.commons.compress.archivers.lha.BinaryTree}
 * (Apache License 2.0).  Main change: uses {@link LhaBitInputStream} instead of
 * {@code BitInputStream} and {@code IOException} instead of
 * {@code CompressorException}.</p>
 */
final class LhaBinaryTree {

    /** Marks an unassigned node. */
    private static final int UNDEFINED = -1;
    /** Marks an internal (branching) node. */
    private static final int NODE      = -2;

    /** Flat array representing the complete binary tree.
     *  Root at index 0; left child of node i at 2i+1; right child at 2i+2. */
    private final int[] tree;

    /**
     * Builds a binary tree from an array of code lengths.
     *
     * <p>If the array contains a single element, a root-only tree is created with
     * that element as the constant return value.</p>
     *
     * @param codeLengths array where {@code codeLengths[symbol] = depth in tree}
     * @throws IOException if the code-length table is invalid
     */
    LhaBinaryTree(final int... codeLengths) throws IOException {
        if (codeLengths.length == 1) {
            tree = new int[]{codeLengths[0]};
            return;
        }
        int maxDepth = 0;
        for (final int len : codeLengths) if (len > maxDepth) maxDepth = len;
        if (maxDepth == 0) throw new IOException("LHA: Huffman tree contains no leaf nodes");
        if (maxDepth > 16)  throw new IOException("LHA: Huffman tree depth exceeds 16 (" + maxDepth + ")");

        final int arraySize = (int)((1L << (maxDepth + 1)) - 1);
        tree = new int[arraySize];
        Arrays.fill(tree, UNDEFINED);

        int treePos = 0;
        tree[treePos++] = NODE;

        for (int depth = 1; depth <= maxDepth; depth++) {
            final int startPos   = (1 << depth) - 1;
            final int maxAtDepth = 1 << depth;
            int numAtDepth = treePos - startPos;

            // Add leaves for symbols at this depth
            for (int sym = 0; sym < codeLengths.length; sym++) {
                if (codeLengths[sym] == depth) {
                    if (numAtDepth == maxAtDepth) throw new IOException("LHA: too many Huffman leaf nodes at depth " + depth);
                    tree[treePos++] = sym;
                    numAtDepth++;
                }
            }

            // Fill remaining slots with internal nodes that point to the next depth
            int skipTo = -1;
            while (depth < maxDepth && numAtDepth < maxAtDepth) {
                if (skipTo < 0) skipTo = 2 * treePos + 1;
                tree[treePos++] = NODE;
                numAtDepth++;
            }
            if (skipTo >= 0) treePos = skipTo;
        }
    }

    /**
     * Reads one symbol from the bit stream by traversing the tree.
     *
     * @param stream bit input stream
     * @return decoded symbol value, or -1 if the stream is exhausted
     * @throws IOException if the bit stream is malformed
     */
    int read(final LhaBitInputStream stream) throws IOException {
        int idx = 0;
        while (true) {
            final int val = tree[idx];
            if (val == UNDEFINED) throw new IOException("LHA: invalid Huffman bitstream at tree index " + idx);
            if (val != NODE) return val;  // leaf node
            // Root-only tree has exactly one element
            if (tree.length == 1) return val;
            final int bit = stream.readBit();
            if (bit < 0) return -1;
            idx = 2 * idx + 1 + bit;
        }
    }
}
