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
package be.stef.arcana.formats.rar;

/**
  * Represents an extraction error for a single file.
  */
 public class ExtractionError {
     public final String fileName;           // Name of the file that failed
     public final long unpackedSize;         // Expected unpacked size
     public final int compressionMethod;     // Compression method used
     public final boolean isV7;              // Whether file uses V7 algorithm
     public final boolean isSolid;           // Whether file uses solid compression
     public final boolean isEncryptedBlock;  // Whether file is encrypted
     public final String errorMessage;       // Error description
     public final Exception exception;       // Exception that caused the error, if any

     
     public ExtractionError(String fileName, long unpackedSize, int compressionMethod,
                            boolean isV7, boolean isSolid, boolean isEncryptedBlock,
                            String error, Exception ex) {
         this.fileName = fileName;
         this.unpackedSize = unpackedSize;
         this.compressionMethod = compressionMethod;
         this.isV7 = isV7;
         this.isSolid = isSolid;
         this.isEncryptedBlock = isEncryptedBlock;
         this.errorMessage = error;
         this.exception = ex;
     }
     
     public ExtractionError(String fileName, String error) {
         this(fileName, error, null);
     }

     public ExtractionError(String fileName, String error, Exception ex) {
         this.fileName = fileName;
         this.unpackedSize = -1;
         this.compressionMethod = -1;
         this.isV7 = false;
         this.isSolid = false;
         this.isEncryptedBlock = false;
         this.errorMessage = error;
         this.exception = ex;
     }
     
     @Override
     public String toString() {
         StringBuilder sb = new StringBuilder();
         sb.append("Error: ").append(fileName).append("\n");
         sb.append("  Size: ").append(unpackedSize).append(" bytes\n");
         sb.append("  Method: ").append(compressionMethod).append("\n");
         sb.append("  V7: ").append(isV7).append("\n");
         sb.append("  Solid: ").append(isSolid).append("\n");
         sb.append("  Encrypted: ").append(isEncryptedBlock).append("\n");
         sb.append("  Message: ").append(errorMessage);
         if (exception != null) {
             sb.append("\n  Exception: ").append(exception.getMessage());
         }
         return sb.toString();
     }
 }
