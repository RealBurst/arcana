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

/**
 * One file recovered by a plugin's {@link ArchiveRecoverer}: its name, how
 * reliable it is, how many bytes were written, and an optional note. Arcana
 * turns these into the recovery report.
 *
 * @author Stef
 * @since 1.4
 */
public final class RecoveredFile {

    public final String name;
    public final RecoveryReport.Status status;
    public final long bytesWritten;
    public final String message;

    public RecoveredFile(final String name, final RecoveryReport.Status status, final long bytesWritten, final String message) {
        this.name = name;
        this.status = status;
        this.bytesWritten = bytesWritten;
        this.message = message;
    }

    /** Convenience for a file recovered completely (its own checksum, if any, was correct). */
    public static RecoveredFile ok(final String name, final long bytes) {
        return new RecoveredFile(name, RecoveryReport.Status.OK, bytes, null);
    }

    /** Convenience for a file that could only be recovered in part. */
    public static RecoveredFile partial(final String name, final long bytes, final String message) {
        return new RecoveredFile(name, RecoveryReport.Status.PARTIAL, bytes, message);
    }
}
