/**
 * SecureDocs UI Management Module
 * Handles all user interface interactions and state management
 */

class SecureUI {
    constructor() {
        this.selectedEncryptFile = null;
        this.selectedDecryptFile = null;
        this.isProcessing = false;
        
        // File size limits (50MB for chunking recommendation)
        this.MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
        this.CHUNK_SIZE = 1024 * 1024; // 1MB chunks for progress updates
        
        this.init();
    }

    init() {
        this.initializeEventListeners();
        this.initializeDragAndDrop();
        this.initializePasswordToggles();
        this.initializePasswordStrength();
    }

    /**
     * Initialize all event listeners
     */
    initializeEventListeners() {
        // File input listeners
        document.getElementById('encryptFileInput').addEventListener('change', (e) => {
            this.handleFileSelect(e, 'encrypt');
        });
        
        document.getElementById('decryptFileInput').addEventListener('change', (e) => {
            this.handleFileSelect(e, 'decrypt');
        });
        
        // File removal listeners
        document.getElementById('removeEncryptFile').addEventListener('click', () => {
            this.removeSelectedFile('encrypt');
        });
        
        document.getElementById('removeDecryptFile').addEventListener('click', () => {
            this.removeSelectedFile('decrypt');
        });
        
        // Password input listeners
        document.getElementById('encryptPassword').addEventListener('input', (e) => {
            this.updatePasswordStrength(e.target.value);
            this.updateButtonState('encrypt');
        });
        
        document.getElementById('decryptPassword').addEventListener('input', () => {
            this.updateButtonState('decrypt');
        });
        
        // Action button listeners
        document.getElementById('encryptBtn').addEventListener('click', () => {
            this.handleEncrypt();
        });
        
        document.getElementById('decryptBtn').addEventListener('click', () => {
            this.handleDecrypt();
        });
    }

    /**
     * Initialize drag and drop functionality
     */
    initializeDragAndDrop() {
        const encryptArea = document.getElementById('encryptFileArea');
        const decryptArea = document.getElementById('decryptFileArea');
        
        // Prevent default drag behaviors
        [encryptArea, decryptArea].forEach(area => {
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                area.addEventListener(eventName, this.preventDefaults, false);
            });
        });
        
        // Highlight drop area when item is dragged over it
        [encryptArea, decryptArea].forEach(area => {
            ['dragenter', 'dragover'].forEach(eventName => {
                area.addEventListener(eventName, () => area.classList.add('drag-over'), false);
            });
            
            ['dragleave', 'drop'].forEach(eventName => {
                area.addEventListener(eventName, () => area.classList.remove('drag-over'), false);
            });
        });
        
        // Handle dropped files
        encryptArea.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.handleFileSelect({ target: { files } }, 'encrypt');
            }
        }, false);
        
        decryptArea.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.handleFileSelect({ target: { files } }, 'decrypt');
            }
        }, false);
        
        // Make upload areas clickable
        encryptArea.addEventListener('click', () => {
            if (!this.isProcessing) {
                document.getElementById('encryptFileInput').click();
            }
        });
        
        decryptArea.addEventListener('click', () => {
            if (!this.isProcessing) {
                document.getElementById('decryptFileInput').click();
            }
        });
    }

    /**
     * Initialize password visibility toggles
     */
    initializePasswordToggles() {
        document.getElementById('toggleEncryptPassword').addEventListener('click', (e) => {
            this.togglePasswordVisibility('encryptPassword', e.target);
        });
        
        document.getElementById('toggleDecryptPassword').addEventListener('click', (e) => {
            this.togglePasswordVisibility('decryptPassword', e.target);
        });
    }

    /**
     * Initialize password strength indicator
     */
    initializePasswordStrength() {
        const passwordInput = document.getElementById('encryptPassword');
        const strengthIndicator = document.getElementById('passwordStrength');
        
        // Initial state
        this.updatePasswordStrength('');
    }

    /**
     * Prevent default drag behaviors
     */
    preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    /**
     * Handle file selection
     */
    handleFileSelect(event, type) {
        const files = event.target.files;
        if (!files || files.length === 0) return;
        
        const file = files[0];
        
        // Validate file for decrypt operation
        if (type === 'decrypt') {
            if (!this.isValidEncryptedFile(file)) {
                this.showAlert('Please select a valid encrypted file (.enc or .secured)', 'error');
                return;
            }
        }
        
        // Check file size
        if (file.size > this.MAX_FILE_SIZE) {
            this.showAlert(`Large file detected (${secureCrypto.formatFileSize(file.size)}). Processing may take longer.`, 'info');
        }
        
        // Store file reference
        if (type === 'encrypt') {
            this.selectedEncryptFile = file;
        } else {
            this.selectedDecryptFile = file;
        }
        
        // Update UI
        this.displayFileInfo(file, type);
        this.updateButtonState(type);
        
        // Clear file input to allow re-selection of the same file
        event.target.value = '';
    }

    /**
     * Check if file appears to be an encrypted file
     */
    isValidEncryptedFile(file) {
        const validExtensions = ['.enc', '.secured'];
        const fileName = file.name.toLowerCase();
        return validExtensions.some(ext => fileName.endsWith(ext));
    }

    /**
     * Display file information in the UI
     */
    displayFileInfo(file, type) {
        const fileInfo = document.getElementById(`${type}FileInfo`);
        const fileName = document.getElementById(`${type}FileName`);
        const fileSize = document.getElementById(`${type}FileSize`);
        const uploadArea = document.getElementById(`${type}FileArea`);
        
        fileName.textContent = file.name;
        fileSize.textContent = secureCrypto.formatFileSize(file.size);
        
        uploadArea.style.display = 'none';
        fileInfo.style.display = 'block';
    }

    /**
     * Remove selected file
     */
    removeSelectedFile(type) {
        if (type === 'encrypt') {
            this.selectedEncryptFile = null;
        } else {
            this.selectedDecryptFile = null;
        }
        
        const fileInfo = document.getElementById(`${type}FileInfo`);
        const uploadArea = document.getElementById(`${type}FileArea`);
        
        fileInfo.style.display = 'none';
        uploadArea.style.display = 'block';
        
        this.updateButtonState(type);
    }

    /**
     * Toggle password visibility
     */
    togglePasswordVisibility(inputId, buttonElement) {
        const input = document.getElementById(inputId);
        const icon = buttonElement.querySelector('i') || buttonElement;
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            input.type = 'password';
            icon.className = 'fas fa-eye';
        }
    }

    /**
     * Update password strength indicator
     */
    updatePasswordStrength(password) {
        const strengthElement = document.getElementById('passwordStrength');
        const strengthResult = secureCrypto.validatePasswordStrength(password);
        
        // Remove existing strength classes
        strengthElement.classList.remove('strength-weak', 'strength-fair', 'strength-good', 'strength-strong');
        
        // Add appropriate class
        if (password) {
            strengthElement.classList.add(`strength-${strengthResult.level}`);
        }
        
        // Update text
        const strengthText = strengthElement.querySelector('.strength-text');
        if (password) {
            strengthText.textContent = `Password strength: ${strengthResult.level}`;
            if (strengthResult.feedback.length > 0) {
                strengthText.title = strengthResult.feedback.join(', ');
            }
        } else {
            strengthText.textContent = 'Enter password to see strength';
            strengthText.title = '';
        }
    }

    /**
     * Update button enabled state
     */
    updateButtonState(type) {
        const button = document.getElementById(`${type}Btn`);
        const password = document.getElementById(`${type}Password`).value;
        const hasFile = type === 'encrypt' ? this.selectedEncryptFile : this.selectedDecryptFile;
        
        button.disabled = !hasFile || !password.trim() || this.isProcessing;
    }

    /**
     * Handle file encryption
     */
    async handleEncrypt() {
        if (!this.selectedEncryptFile || this.isProcessing) return;
        
        const password = document.getElementById('encryptPassword').value;
        if (!password.trim()) {
            this.showAlert('Please enter a password for encryption', 'error');
            return;
        }
        
        // Check password strength
        const strengthResult = secureCrypto.validatePasswordStrength(password);
        if (strengthResult.level === 'weak') {
            const proceed = confirm('Your password is weak. This may make your file easier to crack. Do you want to continue anyway?');
            if (!proceed) return;
        }
        
        try {
            this.setProcessingState(true, 'encrypt');
            this.showProgress('encrypt', 0, 'Starting encryption...');
            
            // Read file data
            const fileData = await this.readFileAsArrayBuffer(this.selectedEncryptFile);
            
            // Encrypt the file
            const result = await secureCrypto.encryptFile(
                fileData,
                password,
                this.selectedEncryptFile.name,
                (progress, status) => this.showProgress('encrypt', progress, status)
            );
            
            // Generate filename for encrypted file
            const encryptedFileName = secureCrypto.generateSecureFileName(this.selectedEncryptFile.name);
            
            // Download encrypted file
            this.downloadFile(result.encryptedData, encryptedFileName, 'application/octet-stream');
            
            this.showAlert(`File encrypted successfully! Download: ${encryptedFileName}`, 'success');
            
            // Reset form
            this.removeSelectedFile('encrypt');
            document.getElementById('encryptPassword').value = '';
            this.updatePasswordStrength('');
            
        } catch (error) {
            console.error('Encryption error:', error);
            this.showAlert(`Encryption failed: ${error.message}`, 'error');
        } finally {
            this.setProcessingState(false, 'encrypt');
            this.hideProgress('encrypt');
        }
    }

    /**
     * Handle file decryption
     */
    async handleDecrypt() {
        if (!this.selectedDecryptFile || this.isProcessing) return;
        
        const password = document.getElementById('decryptPassword').value;
        if (!password.trim()) {
            this.showAlert('Please enter the decryption password', 'error');
            return;
        }
        
        try {
            this.setProcessingState(true, 'decrypt');
            this.showProgress('decrypt', 0, 'Starting decryption...');
            
            // Read encrypted file data
            const encryptedData = await this.readFileAsArrayBuffer(this.selectedDecryptFile);
            
            // Decrypt the file
            const result = await secureCrypto.decryptFile(
                encryptedData,
                password,
                (progress, status) => this.showProgress('decrypt', progress, status)
            );
            
            // Determine original filename and type
            let fileName = result.metadata.originalFileName || 'decrypted_file';
            const mimeType = this.getMimeTypeFromFileName(fileName) || 'application/octet-stream';
            
            // Download decrypted file
            this.downloadFile(result.decryptedData, fileName, mimeType);
            
            this.showAlert(`File decrypted successfully! Download: ${fileName}`, 'success');
            
            // Reset form
            this.removeSelectedFile('decrypt');
            document.getElementById('decryptPassword').value = '';
            
        } catch (error) {
            console.error('Decryption error:', error);
            this.showAlert(`Decryption failed: ${error.message}`, 'error');
        } finally {
            this.setProcessingState(false, 'decrypt');
            this.hideProgress('decrypt');
        }
    }

    /**
     * Set processing state for UI elements
     */
    setProcessingState(processing, type) {
        this.isProcessing = processing;
        
        const button = document.getElementById(`${type}Btn`);
        const btnText = button.querySelector('.btn-text');
        const btnLoader = button.querySelector('.btn-loader');
        
        if (processing) {
            button.disabled = true;
            btnText.style.display = 'none';
            btnLoader.style.display = 'flex';
        } else {
            btnText.style.display = 'flex';
            btnLoader.style.display = 'none';
            this.updateButtonState(type);
        }
    }

    /**
     * Show progress bar with status
     */
    showProgress(type, percentage, status) {
        const progressContainer = document.getElementById(`${type}Progress`);
        const progressFill = progressContainer.querySelector('.progress-fill');
        const progressText = progressContainer.querySelector('.progress-text');
        
        progressContainer.style.display = 'block';
        progressFill.style.width = `${percentage}%`;
        progressText.textContent = status;
    }

    /**
     * Hide progress bar
     */
    hideProgress(type) {
        const progressContainer = document.getElementById(`${type}Progress`);
        progressContainer.style.display = 'none';
    }

    /**
     * Read file as ArrayBuffer
     */
    readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = e => resolve(e.target.result);
            reader.onerror = e => reject(new Error('Failed to read file'));
            reader.readAsArrayBuffer(file);
        });
    }

    /**
     * Download file to user's device
     */
    downloadFile(data, fileName, mimeType) {
        const blob = new Blob([data], { type: mimeType });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = fileName;
        link.style.display = 'none';
        
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        // Clean up the URL object
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    /**
     * Get MIME type from file extension
     */
    getMimeTypeFromFileName(fileName) {
        const extension = fileName.toLowerCase().split('.').pop();
        const mimeTypes = {
            // Documents
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls': 'application/vnd.ms-excel',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'ppt': 'application/vnd.ms-powerpoint',
            'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'txt': 'text/plain',
            'rtf': 'application/rtf',
            
            // Images
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'svg': 'image/svg+xml',
            'webp': 'image/webp',
            'bmp': 'image/bmp',
            
            // Audio
            'mp3': 'audio/mpeg',
            'wav': 'audio/wav',
            'ogg': 'audio/ogg',
            'aac': 'audio/aac',
            
            // Video
            'mp4': 'video/mp4',
            'avi': 'video/x-msvideo',
            'mov': 'video/quicktime',
            'wmv': 'video/x-ms-wmv',
            
            // Archives
            'zip': 'application/zip',
            'rar': 'application/x-rar-compressed',
            '7z': 'application/x-7z-compressed',
            'tar': 'application/x-tar',
            'gz': 'application/gzip',
            
            // Other
            'json': 'application/json',
            'xml': 'application/xml',
            'csv': 'text/csv',
            'html': 'text/html',
            'css': 'text/css',
            'js': 'application/javascript'
        };
        
        return mimeTypes[extension];
    }

    /**
     * Show alert notification
     */
    showAlert(message, type = 'info', duration = 5000) {
        const alertContainer = document.getElementById('alertContainer');
        
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        
        const icon = this.getAlertIcon(type);
        
        alert.innerHTML = `
            <i class="fas fa-${icon}"></i>
            <span class="alert-message">${message}</span>
            <button class="alert-close">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        alertContainer.appendChild(alert);
        
        // Auto remove after duration
        setTimeout(() => {
            if (alert.parentNode) {
                this.removeAlert(alert);
            }
        }, duration);
        
        // Manual close
        const closeBtn = alert.querySelector('.alert-close');
        closeBtn.addEventListener('click', () => this.removeAlert(alert));
        
        return alert;
    }

    /**
     * Get appropriate icon for alert type
     */
    getAlertIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            info: 'info-circle',
            warning: 'exclamation-triangle'
        };
        return icons[type] || icons.info;
    }

    /**
     * Remove alert with animation
     */
    removeAlert(alert) {
        alert.style.transform = 'translateX(100%)';
        alert.style.opacity = '0';
        setTimeout(() => {
            if (alert.parentNode) {
                alert.parentNode.removeChild(alert);
            }
        }, 300);
    }
}

// Create global UI instance
window.secureUI = new SecureUI();