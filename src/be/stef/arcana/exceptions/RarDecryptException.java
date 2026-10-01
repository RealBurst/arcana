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
package be.stef.arcana.exceptions;

/**
 * Exception thrown when RAR5 decryption fails.
 * 
 * <p>This exception is thrown in the following situations:</p>
 * <ul>
 *   <li>Invalid or incorrect password</li>
 *   <li>Unsupported encryption algorithm</li>
 *   <li>Corrupted encryption data</li>
 *   <li>CRC verification failure after decryption</li>
 * </ul>
 * 
 * @author Stef
 * @since 1.0
 */
public class RarDecryptException extends Exception {
    private static final long serialVersionUID = 1L;
    
    /**
     * Constructs a new decryption exception with the specified message.
     * 
     * @param message the detail message
     */
    public RarDecryptException(String message) {
        super(message);
    }
    
    /**
     * Constructs a new decryption exception with the specified message and cause.
     * 
     * @param message the detail message
     * @param cause the cause of this exception
     */
    public RarDecryptException(String message, Throwable cause) {
        super(message, cause);
    }
}
