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
package be.stef.arcana.formats.rar.rar5.blocks;

/**
 * Service block for RAR5 archives.
 * 
 * <p>Service blocks use the same structure as file blocks but contain
 * archive metadata rather than user files. Common service blocks:</p>
 * <ul>
 *   <li>CMT - Archive comment</li>
 *   <li>ACL - NTFS Access Control List</li>
 *   <li>STM - NTFS Alternate Data Stream</li>
 *   <li>QO - Quick Open data</li>
 *   <li>RR - Recovery Record</li>
 * </ul>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5ServiceBlock extends Rar5FileBlock {
    
    /**
     * @return true if this is an archive comment block
     */
    public boolean isComment() {
        return "CMT".equals(getFileName());
    }
    
    /**
     * @return true if this is an NTFS ACL block
     */
    public boolean isACL() {
        return "ACL".equals(getFileName());
    }
    
    /**
     * @return true if this is an NTFS alternate stream block
     */
    public boolean isStream() {
        return "STM".equals(getFileName());
    }
    
    /**
     * @return true if this is a Quick Open data block
     */
    public boolean isQuickOpen() {
        return "QO".equals(getFileName());
    }
    
    /**
     * @return true if this is a Recovery Record block
     */
    public boolean isRecoveryRecord() {
        return "RR".equals(getFileName());
    }
    
    /**
     * Returns the service type name.
     * 
     * @return service type description
     */
    public String getServiceTypeName() {
        String name = getFileName();
        if (name == null) {
            return "Unknown";
        }
        
        switch (name) {
            case "CMT":
                return "Comment";
                
            case "ACL":
                return "AccessControlList";
                
            case "STM":
                return "AlternateStream";
                
            case "QO":
                return "QuickOpen";
                
            case "RR":
                return "RecoveryRecord";
                
            default:
                return name;
        }
    }
}
