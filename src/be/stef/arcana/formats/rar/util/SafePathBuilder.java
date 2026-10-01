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
package be.stef.arcana.formats.rar.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public class SafePathBuilder {
    private static final Pattern ILLEGAL_CHARS = Pattern.compile("[<>:\"|?*\\u0000-\\u001F]");
    private final Set<String> writtenPaths = new HashSet<>();
    private final File baseDir;
    private final boolean isCaseSensitiveFS;
    
    private static final List<String> RESERVED_NAMES = Arrays.asList(
       "CON", "PRN", "AUX", "NUL", 
       "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
       "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    );


    public SafePathBuilder(File outputDirectory) { //throws IOException {
        this.baseDir = outputDirectory;
        if (!baseDir.exists()) baseDir.mkdirs();
        
        // --- PHYSICAL FILE-SYSTEM DETECTION ---
        this.isCaseSensitiveFS = detectCaseSensitivity(outputDirectory);
//        System.out.println("  [FS INFO] Case-Sensitive FS: " + this.isCaseSensitiveFS);
    }

    /**
     * Actually tests whether the target disk is case-sensitive.
     */
    private boolean detectCaseSensitivity(File dir) {
        try {
            Path testFile = Files.createTempFile(dir.toPath(), ".case_test_", ".tmp");
            boolean sensitive = !Files.exists(Paths.get(testFile.toString().toUpperCase()));
            Files.delete(testFile);
            return sensitive;
        } catch (IOException e) {
            // Fall back to OS-based detection if the test fails
            String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
            return !(os.contains("win") || os.contains("mac"));
        }
    }

    public File buildSafePath(String originalPath) throws IOException {
        // Path normalization and hardening
        String normalized = originalPath.replace("\\", "/"); 
        Path p = Paths.get(normalized);
        Path safePath = Paths.get("");

        for (Path component : p) {
            String sanitizedName = sanitizeComponent(component.toString());
            safePath = safePath.resolve(sanitizedName);
        }

        File destFile = new File(baseDir, safePath.toString());
        
        // Protection Path Traversal
        if (!destFile.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
            throw new IOException("Security Error: Path traversal attempt: " + originalPath);
        }

        return resolveCollision(destFile);
    }

    /**
     * Builds a safe directory path with sanitization and path traversal protection,
     * but WITHOUT collision detection. Directories that already exist are normal
     * (created by mkdirs() during file extraction) and should not be renamed.
     */
    public File buildSafeDirPath(String originalPath) throws IOException {
        String normalized = originalPath.replace("\\", "/"); 
        Path p = Paths.get(normalized);
        Path safePath = Paths.get("");

        for (Path component : p) {
            String sanitizedName = sanitizeComponent(component.toString());
            safePath = safePath.resolve(sanitizedName);
        }

        File destFile = new File(baseDir, safePath.toString());
        
        // Protection Path Traversal
        if (!destFile.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
            throw new IOException("Security Error: Path traversal attempt: " + originalPath);

        }

        return destFile;
    }

    private String sanitizeComponent(String name) {
        // 1. Illegal characters
        String clean = ILLEGAL_CHARS.matcher(name).replaceAll("_");
        
        // 2. Trim trailing dots/spaces (critical on Windows)
        clean = clean.trim();
        while (clean.endsWith(".")) {
            clean = clean.substring(0, clean.length() - 1) + "_";
        }
        
        if (clean.isEmpty()) clean = "_empty_";

        // 3. Handle RESERVED_NAMES (e.g. AUX.txt -> _AUX_.txt)
        String nameNoExt = clean.contains(".") ? clean.substring(0, clean.lastIndexOf('.')) : clean;
        if (RESERVED_NAMES.contains(nameNoExt.toUpperCase(Locale.ROOT))) {
            clean = "_" + clean + "_";
        }
        
        return clean;
    }

    private File resolveCollision(File file) {
        File finalFile = file;
        String parent = file.getParent();
        String name = file.getName();
        
        String baseName = name;
        String extension = "";
        int dotIndex = name.lastIndexOf('.');
        if (dotIndex > 0) {
            baseName = name.substring(0, dotIndex);
            extension = name.substring(dotIndex);
        }

        int counter = 1;
        String checkKey = getCollisionKey(finalFile);

        // Loop while there is a "logical" collision (within our session)
        // or "physical" (the file already exists on disk)
        while (writtenPaths.contains(checkKey) || finalFile.exists()) {
            String newName = baseName + "_" + counter + extension;
            finalFile = new File(parent, newName);
            checkKey = getCollisionKey(finalFile);
            counter++;
        }

        writtenPaths.add(checkKey);
        return finalFile;
    }

    private String getCollisionKey(File f) {
        String path = f.getAbsolutePath();
        return isCaseSensitiveFS ? path : path.toLowerCase(Locale.ROOT);
    }

    public File getBaseDir() {
       return baseDir;
    }
}

