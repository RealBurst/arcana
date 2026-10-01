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
package be.stef.arcana.formats.rar.rar5;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import be.stef.arcana.exceptions.RarDecryptException;
import be.stef.arcana.formats.rar.util.Utils;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Decryptor for RAR5 archives with encrypted headers.
 * 
 * <p>When a RAR5 archive has encrypted headers (file names are encrypted),
 * the entire archive structure after the encryption block is AES-encrypted.
 * This class decrypts the headers while preserving the encrypted file data.</p>
 * 
 * <h3>Usage:</h3>
 * <pre>
 * Rar5HeaderDecryptor decryptor = new Rar5HeaderDecryptor("password");
 * 
 * // Decrypt to a new file
 * decryptor.decryptToFile("encrypted.rar", "decrypted.rar");
 * 
 * // Or decrypt to byte array
 * byte[] decrypted = decryptor.decrypt(encryptedData);
 * </pre>
 * 
 * <p><b>Note:</b> After header decryption, file data remains encrypted.
 * Use {@link Rar5Reader#decryptFileData} to decrypt individual files.</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5HeaderDecryptor {
    private final String password;
    private byte[] salt;
    private int kdfIterationExponent;
    private byte[] checkValue;
    private byte[] aesKey;
    private byte[] passwordCheckBytes;
    
    /**
     * Creates a header decryptor with the specified password.
     * 
     * @param password the archive password
     * @throws IllegalArgumentException if password is null or empty
     */
    public Rar5HeaderDecryptor(String password) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        this.password = password;
    }
    
    /**
     * Decrypts a RAR5 archive from a byte array.
     * 
     * @param encryptedData the encrypted archive data
     * @return the decrypted archive data
     * @throws RarDecryptException if decryption fails
     */
    public byte[] decrypt(byte[] encryptedData) throws RarDecryptException {
        try {
            return decryptInternal(encryptedData);
        } catch (RarDecryptException e) {
            throw e;
        } catch (Exception e) {
            throw new RarDecryptException("Decryption error: " + e.getMessage(), e);
        }
    }
    
    /**
     * Decrypts a RAR5 archive file and writes the result to a new file.
     * 
     * @param inputPath path to the encrypted archive
     * @param outputPath path for the decrypted archive
     * @throws RarDecryptException if decryption fails
     */
    public void decryptToFile(String inputPath, String outputPath) throws RarDecryptException {
        try {
            byte[] encrypted = Files.readAllBytes(new File(inputPath).toPath());
            
            byte[] decrypted = decrypt(encrypted);
            
            try (FileOutputStream fos = new FileOutputStream(outputPath)) {
                fos.write(decrypted);
            }
        } catch (IOException e) {
            throw new RarDecryptException("I/O error: " + e.getMessage(), e);
        }
    }
    
    /**
     * Checks if an archive has encrypted headers.
     * 
     * @param data the archive data
     * @return true if headers are encrypted
     */
    public static boolean isEncrypted(byte[] data) {
        if (data == null || data.length < Rar5Constants.RAR5_SIGNATURE.length + 10) {
            return false;
        }
        
        // Verify RAR5 signature
        for (int i = 0; i < Rar5Constants.RAR5_SIGNATURE.length; i++) {
            if (data[i] != Rar5Constants.RAR5_SIGNATURE[i]) {
                return false;
            }
        }
        
        // Read first block type
        try {
            int offset = Rar5Constants.RAR5_SIGNATURE.length + 4; // Skip signature + CRC
            long[] result = readVIntArray(data, offset);
            offset += (int) result[1]; // Skip header size
            result = readVIntArray(data, offset);
            return result[0] == Rar5Constants.BLOCK_TYPE_ARC_ENCRYPT;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Returns encryption information for display purposes.
     * 
     * @param data the archive data
     * @return description of encryption parameters, or error message
     */
    public static String getEncryptionInfo(byte[] data) {
        if (!isEncrypted(data)) {
            return "Archive is not encrypted or has invalid format";
        }
        
        try {
            Rar5HeaderDecryptor temp = new Rar5HeaderDecryptor("dummy");
            temp.parseEncryptionHeader(data);
            
            StringBuilder sb = new StringBuilder();
            sb.append("Encrypted RAR5 Archive:\n");
            sb.append("  Algorithm: AES-256-CBC\n");
            sb.append("  KDF: PBKDF2-HMAC-SHA256\n");
            sb.append("  Iterations: 2^").append(temp.kdfIterationExponent);
            sb.append(" = ").append(1 << temp.kdfIterationExponent).append("\n");
            sb.append("  Salt: ").append(Utils.bytesToHexCompact(temp.salt)).append("\n");
            return sb.toString();
        } catch (Exception e) {
            return "Error reading encryption info: " + e.getMessage();
        }
    }
    
    private byte[] decryptInternal(byte[] data) throws Exception {
        // Verify signature
        if (!checkSignature(data)) {
            throw new RarDecryptException("Invalid RAR5 signature");
        }
        
        // Parse encryption header
        int encHeaderEnd = parseEncryptionHeader(data);
        
        // Derive key
        deriveKey();
        
        // Decrypt archive
        return decryptArchive(data, encHeaderEnd);
    }
    
    private boolean checkSignature(byte[] data) {
        if (data.length < Rar5Constants.RAR5_SIGNATURE.length) {
            return false;
        }
        for (int i = 0; i < Rar5Constants.RAR5_SIGNATURE.length; i++) {
            if (data[i] != Rar5Constants.RAR5_SIGNATURE[i]) {
                return false;
            }
        }
        return true;
    }
    
    private int parseEncryptionHeader(byte[] data) throws RarDecryptException {
        int offset = Rar5Constants.RAR5_SIGNATURE.length;
        
        // CRC (4 bytes)
        offset += 4;
        
        // Header size (VInt)
        long[] sizeResult = readVIntArray(data, offset);
        long headerSize = sizeResult[0];
        offset += (int) sizeResult[1];
        
        // Type (VInt)
        long[] typeResult = readVIntArray(data, offset);
        if (typeResult[0] != Rar5Constants.BLOCK_TYPE_ARC_ENCRYPT) {
            throw new RarDecryptException("Archive does not have encrypted headers");
        }
        offset += (int) typeResult[1];
        
        // Flags (VInt)
        long[] flagsResult = readVIntArray(data, offset);
        offset += (int) flagsResult[1];
        
        // Encryption version (VInt)
        long[] versionResult = readVIntArray(data, offset);
        int version = (int) versionResult[0];
        offset += (int) versionResult[1];
        if (version != 0) {
            throw new RarDecryptException("Unsupported encryption version: " + version);
        }
        
        // Encryption flags (VInt)
        long[] encFlagsResult = readVIntArray(data, offset);
        boolean hasCheck = (encFlagsResult[0] & 0x01) != 0;
        offset += (int) encFlagsResult[1];
        
        // KDF IterationExponent (1 byte)
        kdfIterationExponent = data[offset++] & 0xFF;
        
        // Salt (16 bytes)
        salt = new byte[Rar5Constants.SALT_SIZE];
        System.arraycopy(data, offset, salt, 0, Rar5Constants.SALT_SIZE);
        offset += Rar5Constants.SALT_SIZE;
        
        // Note: IV is NOT in Archive Encryption Header
        // IV is placed before each encrypted block
        
        // Check value (12 bytes, optional)
        if (hasCheck) {
            checkValue = new byte[Rar5Constants.CHECK_VALUE_SIZE];
            System.arraycopy(data, offset, checkValue, 0, Rar5Constants.CHECK_VALUE_SIZE);
            offset += Rar5Constants.CHECK_VALUE_SIZE;
        }
        
        // Return end offset
        int vintLen = (int) readVIntArray(data, Rar5Constants.RAR5_SIGNATURE.length + 4)[1];
        return Rar5Constants.RAR5_SIGNATURE.length + 4 + vintLen + (int) headerSize;
    }
    
    private void deriveKey() throws Exception {
        int iterations = 1 << kdfIterationExponent;
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // 64 bytes: 32 for AES key, 32 for password check
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 64 * 8);
        byte[] fullKey = factory.generateSecret(spec).getEncoded();
        
        // Bytes 0-31: AES key
        aesKey = Arrays.copyOf(fullKey, 32);
        
        // Bytes 32-63: Password check value
        passwordCheckBytes = Arrays.copyOfRange(fullKey, 32, 64);
    }
    
    private byte[] decryptArchive(byte[] data, int startPos) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        
        // Write RAR5 signature
        output.write(Rar5Constants.RAR5_SIGNATURE);
        
        int pos = startPos;
        
        while (pos < data.length) {
            // Each block is preceded by a 16-byte IV
            if (pos + Rar5Constants.AES_BLOCK_SIZE > data.length) {
                break;
            }
            
            // Read IV
            byte[] iv = new byte[Rar5Constants.AES_BLOCK_SIZE];
            System.arraycopy(data, pos, iv, 0, Rar5Constants.AES_BLOCK_SIZE);
            pos += Rar5Constants.AES_BLOCK_SIZE;
            
            if (pos + Rar5Constants.AES_BLOCK_SIZE > data.length) {
                break;
            }
            
            // Decrypt first block to get header size
            byte[] firstBlock = new byte[Rar5Constants.AES_BLOCK_SIZE];
            System.arraycopy(data, pos, firstBlock, 0, Rar5Constants.AES_BLOCK_SIZE);
            byte[] decFirst = decryptAES(firstBlock, iv);
            
            // Parse header size (skip CRC - 4 bytes)
            long[] sizeResult = readVIntArray(decFirst, 4);
            long headerSize = sizeResult[0];
            long totalSize = 4 + sizeResult[1] + headerSize;
            long encSize = Utils.alignToAesBlock(totalSize);
            
            if (pos + encSize > data.length) {
                encSize = Utils.alignToAesBlock(data.length - pos);
                if (encSize == 0) {
                    break;
                }
            }
            
            // Read and decrypt complete header
            byte[] encHeader = new byte[(int) encSize];
            System.arraycopy(data, pos, encHeader, 0, (int) encSize);
            pos += encSize;
            
            byte[] decHeader = decryptAES(encHeader, iv);
            
            // Write decrypted header (without padding)
            int writeSize = (int) Math.min(totalSize, decHeader.length);
            output.write(decHeader, 0, writeSize);
            
            // Get block type and flags
            int parsePos = 4 + (int) sizeResult[1];
            long[] typeResult = readVIntArray(decHeader, parsePos);
            int blockType = (int) typeResult[0];
            parsePos += (int) typeResult[1];
            
            long[] flagsResult = readVIntArray(decHeader, parsePos);
            int flags = (int) flagsResult[0];
            parsePos += (int) flagsResult[1];
            
            // Handle data area if present
            if ((flags & Rar5Constants.HEADER_FLAG_DATA) != 0) {
                // Skip extra size if present
                if ((flags & Rar5Constants.HEADER_FLAG_EXTRA) != 0) {
                    long[] extraResult = readVIntArray(decHeader, parsePos);
                    parsePos += (int) extraResult[1];
                }
                
                // Read data size
                long[] dataResult = readVIntArray(decHeader, parsePos);
                long dataSize = dataResult[0];
                
                // Copy file data (stays encrypted)
                if (dataSize > 0 && pos + dataSize <= data.length) {
                    byte[] fileData = new byte[(int) dataSize];
                    System.arraycopy(data, pos, fileData, 0, (int) dataSize);
                    output.write(fileData);
                    pos += dataSize;
                }
            }
            
            // Stop at END block
            if (blockType == Rar5Constants.BLOCK_TYPE_END_OF_ARC) {
                break;
            }
        }
        
        return output.toByteArray();
    }
    
    private byte[] decryptAES(byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,
            new SecretKeySpec(aesKey, "AES"),
            new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }
    
    
    /**
     * Reads a VInt and returns [value, bytesRead].
     */
    private static long[] readVIntArray(byte[] data, int offset) {
        long value = 0;
        int bytesRead = 0;
        int shift = 0;
        
        while (offset + bytesRead < data.length && bytesRead < 10) {
            int b = data[offset + bytesRead] & 0xFF;
            bytesRead++;
            value |= (long) (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                break;
            }
            shift += 7;
        }
        
        return new long[]{value, bytesRead};
    }
}
