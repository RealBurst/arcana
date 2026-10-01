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
package be.stef.arcana.formats.recover;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Optional recovery strategy of a format plugin, used by forced extraction
 * ({@code arcana r}) when the archive is damaged. A plugin returns one from
 * {@code ArcanaPlugin.createRecoverer} to do better than the default (which
 * simply keeps whatever a normal extraction wrote before the error).
 *
 * <p>The implementation writes the recovered files into {@code destination}
 * (create the output with {@code PluginSupport.openOutput} for safe names and
 * limits) and returns a {@link RecoveredFile} for each, describing how reliable
 * it is. It should catch its own decoding errors and return what it managed to
 * recover rather than throwing.</p>
 *
 * @author Stef
 * @since 1.4
 */
public interface ArchiveRecoverer {

    /**
     * Recovers as much as possible from {@code archive} into {@code destination}.
     *
     * @return the files recovered (their names, status, sizes); never null
     */
    List<RecoveredFile> recover(File archive, File destination) throws IOException;
}
