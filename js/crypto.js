/**
 * SecureDocs Cryptographic Module
 * Implements AES-GCM encryption with Argon2 key derivation
 * All operations are performed client-side only
 */

class SecureCrypto {
    constructor() {
        this.VERSION = 1;
        this.SALT_LENGTH = 32; // bytes
        this.IV_LENGTH = 12;   // bytes for AES-GCM
        this.KEY_LENGTH = 32;  // bytes (256-bit key)
        
        // Argon2 parameters (balanced for client-side use)
        this.ARGON2_TIME = 3;      // iterations
        this.ARGON2_MEMORY = 65536; // 64 MB
        this.ARGON2_PARALLELISM = 1;
        
        this.isInitialized = false;
        this.initPromise = null;
    }

    /**
     * Initialize the crypto module (loads libsodium)
     */
    async init() {
        if (this.isInitialized) return;
        
        if (!this.initPromise) {
            this.initPromise = this._doInit();
        }
        
        return this.initPromise;
    }

    async _doInit() {
        try {
            // Try to initialize libsodium for Argon2
            if (typeof sodium !== 'undefined') {
                await sodium.ready;
                this.useArgon2 = true;
                console.log('SecureCrypto initialized with Argon2 support');
            } else {
                // Fallback to PBKDF2 if libsodium is not available
                this.useArgon2 = false;
                console.log('SecureCrypto initialized with PBKDF2 fallback');
            }
            this.isInitialized = true;
        } catch (error) {
            console.warn('Argon2 initialization failed, falling back to PBKDF2:', error);
            this.useArgon2 = false;
            this.isInitialized = true;
        }
    }

    /**
     * Generate a cryptographically secure random salt
     */
    generateSalt() {
        return crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
    }

    /**
     * Generate a cryptographically secure random IV
     */
    generateIV() {
        return crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
    }

    /**
     * Derive encryption key from password using Argon2 or PBKDF2 fallback
     * @param {string} password - User password
     * @param {Uint8Array} salt - Random salt
     * @returns {Promise<Uint8Array>} Derived key
     */
    async deriveKey(password, salt) {
        if (!this.isInitialized) {
            await this.init();
        }

        try {
            if (this.useArgon2 && typeof sodium !== 'undefined') {
                // Use Argon2id for key derivation (most secure variant)
                const passwordBuffer = new TextEncoder().encode(password);
                const derivedKey = sodium.crypto_pwhash(
                    this.KEY_LENGTH,
                    passwordBuffer,
                    salt,
                    this.ARGON2_TIME,
                    this.ARGON2_MEMORY,
                    sodium.crypto_pwhash_ALG_ARGON2ID
                );
                return derivedKey;
            } else {
                // Fallback to PBKDF2 with Web Crypto API
                return await this.deriveKeyPBKDF2(password, salt);
            }
        } catch (error) {
            console.error('Key derivation failed:', error);
            throw new Error('Failed to derive encryption key from password');
        }
    }

    /**
     * Derive key using PBKDF2 (Web Crypto API fallback)
     * @param {string} password - User password
     * @param {Uint8Array} salt - Random salt
     * @returns {Promise<Uint8Array>} Derived key
     */
    async deriveKeyPBKDF2(password, salt) {
        // Import password as key material
        const passwordBuffer = new TextEncoder().encode(password);
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        // Derive key using PBKDF2
        const derivedKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000, // 100k iterations for PBKDF2
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        // Export the key as raw bytes
        const keyBuffer = await crypto.subtle.exportKey('raw', derivedKey);
        return new Uint8Array(keyBuffer);
    }

    /**
     * Encrypt file data using AES-GCM
     * @param {ArrayBuffer} fileData - File content to encrypt
     * @param {string} password - Encryption password
     * @param {string} originalFileName - Original file name
     * @param {Function} progressCallback - Progress callback function
     * @returns {Promise<{encryptedData: Uint8Array, metadata: Object}>}
     */
    async encryptFile(fileData, password, originalFileName = '', progressCallback = null) {
        if (!this.isInitialized) {
            await this.init();
        }

        try {
            if (progressCallback) progressCallback(10, 'Generating cryptographic parameters...');
            
            // Generate random salt and IV
            const salt = this.generateSalt();
            const iv = this.generateIV();
            
            if (progressCallback) progressCallback(20, 'Deriving encryption key...');
            
            // Derive key from password
            const key = await this.deriveKey(password, salt);
            
            if (progressCallback) progressCallback(40, 'Encrypting file data...');
            
            // Import key for Web Crypto API
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                key,
                { name: 'AES-GCM' },
                false,
                ['encrypt']
            );
            
            if (progressCallback) progressCallback(60, 'Performing AES-GCM encryption...');
            
            // Encrypt the file data
            const encryptedBuffer = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                cryptoKey,
                fileData
            );
            
            if (progressCallback) progressCallback(80, 'Creating encrypted file structure...');
            
            // Create metadata
            const metadata = {
                version: this.VERSION,
                algorithm: 'AES-GCM',
                kdf: this.useArgon2 ? 'Argon2id' : 'PBKDF2',
                saltLength: this.SALT_LENGTH,
                ivLength: this.IV_LENGTH,
                originalFileName: originalFileName,
                encryptedSize: encryptedBuffer.byteLength,
                timestamp: Date.now()
            };
            
            // Create the final encrypted file structure
            const encryptedData = this.createEncryptedFileStructure(
                salt,
                iv,
                new Uint8Array(encryptedBuffer),
                metadata
            );
            
            if (progressCallback) progressCallback(100, 'Encryption completed successfully!');
            
            return {
                encryptedData,
                metadata
            };
            
        } catch (error) {
            console.error('Encryption failed:', error);
            throw new Error(`File encryption failed: ${error.message}`);
        }
    }

    /**
     * Decrypt file data using AES-GCM
     * @param {ArrayBuffer} encryptedFileData - Encrypted file content
     * @param {string} password - Decryption password
     * @param {Function} progressCallback - Progress callback function
     * @returns {Promise<{decryptedData: ArrayBuffer, metadata: Object}>}
     */
    async decryptFile(encryptedFileData, password, progressCallback = null) {
        if (!this.isInitialized) {
            await this.init();
        }

        try {
            if (progressCallback) progressCallback(10, 'Parsing encrypted file structure...');
            
            // Parse the encrypted file structure
            const {
                salt,
                iv,
                encryptedData,
                metadata
            } = this.parseEncryptedFileStructure(new Uint8Array(encryptedFileData));
            
            // Validate version compatibility
            if (metadata.version > this.VERSION) {
                throw new Error('This file was encrypted with a newer version of SecureDocs');
            }
            
            if (progressCallback) progressCallback(30, 'Deriving decryption key...');
            
            // Derive key from password
            const key = await this.deriveKey(password, salt);
            
            if (progressCallback) progressCallback(50, 'Importing cryptographic key...');
            
            // Import key for Web Crypto API
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                key,
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );
            
            if (progressCallback) progressCallback(70, 'Decrypting file data...');
            
            // Decrypt the file data
            const decryptedBuffer = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                cryptoKey,
                encryptedData
            );
            
            if (progressCallback) progressCallback(100, 'Decryption completed successfully!');
            
            return {
                decryptedData: decryptedBuffer,
                metadata: metadata
            };
            
        } catch (error) {
            console.error('Decryption failed:', error);
            
            // Provide more specific error messages
            if (error.name === 'OperationError' || error.message.includes('decrypt')) {
                throw new Error('Incorrect password or corrupted file');
            } else if (error.message.includes('Invalid file format')) {
                throw new Error('Invalid encrypted file format');
            } else {
                throw new Error(`File decryption failed: ${error.message}`);
            }
        }
    }

    /**
     * Create the encrypted file structure with metadata header
     */
    createEncryptedFileStructure(salt, iv, encryptedData, metadata) {
        // Create metadata JSON
        const metadataJson = JSON.stringify(metadata);
        const metadataBytes = new TextEncoder().encode(metadataJson);
        
        // Calculate sizes
        const metadataSize = metadataBytes.length;
        const totalHeaderSize = 4 + 4 + metadataSize + salt.length + iv.length; // size markers + metadata + salt + iv
        
        // Create the complete file structure
        const totalSize = totalHeaderSize + encryptedData.length;
        const result = new Uint8Array(totalSize);
        
        let offset = 0;
        
        // Write metadata size (4 bytes)
        const metadataSizeView = new DataView(result.buffer, offset, 4);
        metadataSizeView.setUint32(0, metadataSize, false); // big-endian
        offset += 4;
        
        // Write total header size (4 bytes)
        const headerSizeView = new DataView(result.buffer, offset, 4);
        headerSizeView.setUint32(0, totalHeaderSize, false); // big-endian
        offset += 4;
        
        // Write metadata
        result.set(metadataBytes, offset);
        offset += metadataSize;
        
        // Write salt
        result.set(salt, offset);
        offset += salt.length;
        
        // Write IV
        result.set(iv, offset);
        offset += iv.length;
        
        // Write encrypted data
        result.set(encryptedData, offset);
        
        return result;
    }

    /**
     * Parse the encrypted file structure and extract components
     */
    parseEncryptedFileStructure(fileData) {
        if (fileData.length < 8) {
            throw new Error('Invalid file format: File too small');
        }
        
        let offset = 0;
        
        // Read metadata size (4 bytes)
        const metadataSizeView = new DataView(fileData.buffer, fileData.byteOffset + offset, 4);
        const metadataSize = metadataSizeView.getUint32(0, false); // big-endian
        offset += 4;
        
        // Read total header size (4 bytes)
        const headerSizeView = new DataView(fileData.buffer, fileData.byteOffset + offset, 4);
        const totalHeaderSize = headerSizeView.getUint32(0, false); // big-endian
        offset += 4;
        
        // Validate sizes
        if (metadataSize > fileData.length || totalHeaderSize > fileData.length) {
            throw new Error('Invalid file format: Invalid header sizes');
        }
        
        // Read metadata
        const metadataBytes = fileData.slice(offset, offset + metadataSize);
        const metadataJson = new TextDecoder().decode(metadataBytes);
        let metadata;
        
        try {
            metadata = JSON.parse(metadataJson);
        } catch (e) {
            throw new Error('Invalid file format: Corrupted metadata');
        }
        
        offset += metadataSize;
        
        // Read salt
        const saltLength = metadata.saltLength || this.SALT_LENGTH;
        const salt = fileData.slice(offset, offset + saltLength);
        offset += saltLength;
        
        // Read IV
        const ivLength = metadata.ivLength || this.IV_LENGTH;
        const iv = fileData.slice(offset, offset + ivLength);
        offset += ivLength;
        
        // Validate that we've read the expected header size
        if (offset !== totalHeaderSize) {
            throw new Error('Invalid file format: Header size mismatch');
        }
        
        // Read encrypted data
        const encryptedData = fileData.slice(offset);
        
        return {
            salt,
            iv,
            encryptedData,
            metadata
        };
    }

    /**
     * Validate password strength
     * @param {string} password - Password to validate
     * @returns {Object} Strength information
     */
    validatePasswordStrength(password) {
        const result = {
            score: 0,
            level: 'weak',
            feedback: []
        };
        
        if (!password) {
            result.feedback.push('Password is required');
            return result;
        }
        
        // Length check
        if (password.length >= 8) result.score += 1;
        else result.feedback.push('Use at least 8 characters');
        
        if (password.length >= 12) result.score += 1;
        else if (password.length >= 8) result.feedback.push('Longer passwords are more secure');
        
        // Character variety checks
        if (/[a-z]/.test(password)) result.score += 1;
        else result.feedback.push('Include lowercase letters');
        
        if (/[A-Z]/.test(password)) result.score += 1;
        else result.feedback.push('Include uppercase letters');
        
        if (/[0-9]/.test(password)) result.score += 1;
        else result.feedback.push('Include numbers');
        
        if (/[^a-zA-Z0-9]/.test(password)) result.score += 1;
        else result.feedback.push('Include special characters (!@#$%^&*)');
        
        // Common patterns check
        if (!/(.)\1{2,}/.test(password)) result.score += 1;
        else result.feedback.push('Avoid repeating characters');
        
        if (!/123|abc|qwe|asd|zxc/i.test(password)) result.score += 1;
        else result.feedback.push('Avoid common sequences');
        
        // Determine level
        if (result.score >= 7) {
            result.level = 'strong';
        } else if (result.score >= 5) {
            result.level = 'good';
        } else if (result.score >= 3) {
            result.level = 'fair';
        } else {
            result.level = 'weak';
        }
        
        return result;
    }

    /**
     * Format file size for display
     */
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    /**
     * Generate a secure random filename for encrypted files
     */
    generateSecureFileName(originalName, extension = 'enc') {
        const timestamp = Date.now();
        const randomSuffix = Math.random().toString(36).substring(2, 8);
        const baseName = originalName ? originalName.replace(/\.[^/.]+$/, '') : 'document';
        return `${baseName}_encrypted_${timestamp}_${randomSuffix}.${extension}`;
    }
}

// Create global instance
window.secureCrypto = new SecureCrypto();