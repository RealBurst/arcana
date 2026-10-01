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

import java.util.ArrayList;
import java.util.List;

/**
  * Result of an extraction operation.
  */
 public class ExtractionResult {
     public String archiveName; 
     public ArrayList<String> unpackedFiles = new ArrayList<>();
     public ArrayList<String> failedFiles = new ArrayList<>();
     public int totalFiles;         //Total number of files in the archive
     public int successCount;       //Number of successfully extracted files
     public int errorCount;         //Number of files that failed to extract
     public int passwordStatus = 0;                                  
     public final List<ExtractionError> errors = new ArrayList<>(); //List of extraction errors
     
     /**
      * Prints a summary of the extraction result.
      */
     public void print() {
         System.out.println("\n=== Extraction Result ===");
         System.out.println("Archive Name: " + archiveName);
         if(passwordStatus > 0) {
            System.out.println("File encrypted !");
            System.out.println("Password check: "+(passwordStatus==1?"OK":"BAD PASSWORD !"));
         }
         System.out.println("Total files: " + totalFiles+" :");
         System.out.println("Successful: " + successCount);
         for(String file:unpackedFiles) {
            System.out.println("  => " + file);
         }
         System.out.println("Errors: " + errorCount);
         for(String file:failedFiles) {
            System.out.println("  => error " + file);
         }
         
         if (!errors.isEmpty()) {
             System.out.println("\n=== Error Details ===");
             for (int i = 0; i < errors.size(); i++) {
                 System.out.println("\n[" + (i + 1) + "] " + errors.get(i));
             }
         }
     }
     
     /**
      * Merges results of a parallel sub-task. Must be called under synchronized.
      */
     public void merge(ExtractionResult other) {
         successCount += other.successCount;
         errorCount   += other.errorCount;
         unpackedFiles.addAll(other.unpackedFiles);
         failedFiles.addAll(other.failedFiles);
         errors.addAll(other.errors);
         if (other.passwordStatus > passwordStatus) passwordStatus = other.passwordStatus;
     }

     /**
      * @return true if all files were extracted successfully
      */
     public boolean isSuccess() {
         return errorCount == 0 && errors.isEmpty(); // RAR4 fills errors without errorCount
     }
 }
