/**
 * SecureDocs Main Application Entry Point
 * Initializes the application and handles global functionality
 */

class SecureDocsApp {
    constructor() {
        this.isInitialized = false;
        this.init();
    }

    /**
     * Initialize the application
     */
    async init() {
        try {
            // Show loading state
            this.showLoadingState();

            // Initialize crypto module
            await window.secureCrypto.init();

            // Initialize UI (already done by SecureUI constructor)
            // UI is initialized automatically when the script loads

            // Hide loading state and show main content
            this.hideLoadingState();

            // Show welcome message
            this.showWelcomeMessage();

            this.isInitialized = true;
            console.log('SecureDocs application initialized successfully');

        } catch (error) {
            console.error('Failed to initialize SecureDocs:', error);
            this.showInitializationError(error);
        }
    }

    /**
     * Show loading state during initialization
     */
    showLoadingState() {
        // We could add a loading overlay here if needed
        // For now, the app loads quickly enough that it's not necessary
    }

    /**
     * Hide loading state after initialization
     */
    hideLoadingState() {
        // Hide any loading overlays
        const main = document.querySelector('.main');
        if (main) {
            main.style.opacity = '1';
        }
    }

    /**
     * Show welcome message to users
     */
    showWelcomeMessage() {
        // Only show welcome message on first visit (using sessionStorage)
        if (!sessionStorage.getItem('securedocs-welcome-shown')) {
            setTimeout(() => {
                if (window.secureUI) {
                    window.secureUI.showAlert(
                        'Welcome to SecureDocs! Your files are encrypted locally and never leave your device.',
                        'info',
                        7000
                    );
                }
                sessionStorage.setItem('securedocs-welcome-shown', 'true');
            }, 1000);
        }
    }

    /**
     * Show initialization error
     */
    showInitializationError(error) {
        const errorMessage = `
            <div style="
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: white;
                padding: 2rem;
                border-radius: 8px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                max-width: 400px;
                text-align: center;
                z-index: 9999;
            ">
                <i class="fas fa-exclamation-triangle" style="color: #ef4444; font-size: 3rem; margin-bottom: 1rem;"></i>
                <h3 style="margin-bottom: 1rem; color: #1f2937;">Initialization Failed</h3>
                <p style="color: #6b7280; margin-bottom: 1.5rem;">
                    SecureDocs failed to initialize. This might be due to:
                </p>
                <ul style="text-align: left; color: #6b7280; margin-bottom: 1.5rem;">
                    <li>Unsupported browser</li>
                    <li>Network connection issues</li>
                    <li>Missing JavaScript features</li>
                </ul>
                <button onclick="location.reload()" style="
                    background: #3b82f6;
                    color: white;
                    border: none;
                    padding: 0.75rem 1.5rem;
                    border-radius: 6px;
                    cursor: pointer;
                    font-weight: 500;
                ">
                    Retry
                </button>
                <div style="margin-top: 1rem; font-size: 0.75rem; color: #9ca3af;">
                    Error: ${error.message}
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', errorMessage);
    }

    /**
     * Handle browser compatibility warnings
     */
    checkBrowserCompatibility() {
        const warnings = [];

        // Check for Web Crypto API
        if (!window.crypto || !window.crypto.subtle) {
            warnings.push('Web Crypto API not supported');
        }

        // Check for FileReader API
        if (!window.FileReader) {
            warnings.push('FileReader API not supported');
        }

        // Check for Blob API
        if (!window.Blob) {
            warnings.push('Blob API not supported');
        }

        // Check for modern JavaScript features
        try {
            // Test for async/await support
            eval('(async () => {})');
        } catch (e) {
            warnings.push('Modern JavaScript features not supported');
        }

        if (warnings.length > 0) {
            const warningMessage = `
                Your browser may not fully support SecureDocs. Missing features:
                ${warnings.map(w => `• ${w}`).join('\n')}
                
                Please use a modern browser like Chrome, Firefox, Safari, or Edge.
            `;

            if (window.secureUI) {
                window.secureUI.showAlert(warningMessage, 'warning', 10000);
            } else {
                alert(warningMessage);
            }
        }
    }

    /**
     * Handle global keyboard shortcuts
     */
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Escape key to cancel operations or close modals
            if (e.key === 'Escape') {
                // Close any open alerts
                const alerts = document.querySelectorAll('.alert');
                alerts.forEach(alert => {
                    if (window.secureUI) {
                        window.secureUI.removeAlert(alert);
                    }
                });
            }

            // Ctrl/Cmd + Enter to trigger encryption if form is ready
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                const encryptBtn = document.getElementById('encryptBtn');
                const decryptBtn = document.getElementById('decryptBtn');

                if (!encryptBtn.disabled && document.activeElement.closest('.encrypt-section')) {
                    e.preventDefault();
                    encryptBtn.click();
                } else if (!decryptBtn.disabled && document.activeElement.closest('.decrypt-section')) {
                    e.preventDefault();
                    decryptBtn.click();
                }
            }
        });
    }

    /**
     * Setup performance monitoring
     */
    setupPerformanceMonitoring() {
        // Monitor memory usage for large files
        if ('memory' in performance) {
            setInterval(() => {
                const memInfo = performance.memory;
                if (memInfo.usedJSHeapSize > memInfo.totalJSHeapSize * 0.9) {
                    console.warn('High memory usage detected');
                    if (window.secureUI && !window.secureUI.isProcessing) {
                        window.secureUI.showAlert(
                            'Memory usage is high. Consider processing smaller files.',
                            'warning'
                        );
                    }
                }
            }, 30000); // Check every 30 seconds
        }
    }

    /**
     * Setup error handling for uncaught errors
     */
    setupGlobalErrorHandling() {
        window.addEventListener('error', (e) => {
            console.error('Global error:', e.error);
            
            if (window.secureUI && this.isInitialized) {
                window.secureUI.showAlert(
                    'An unexpected error occurred. Please refresh the page if issues persist.',
                    'error'
                );
            }
        });

        window.addEventListener('unhandledrejection', (e) => {
            console.error('Unhandled promise rejection:', e.reason);
            
            if (window.secureUI && this.isInitialized) {
                window.secureUI.showAlert(
                    'An operation failed. Please try again.',
                    'error'
                );
            }
        });
    }

    /**
     * Setup offline detection
     */
    setupOfflineDetection() {
        const handleOnline = () => {
            if (window.secureUI) {
                window.secureUI.showAlert('You\'re back online!', 'success');
            }
        };

        const handleOffline = () => {
            if (window.secureUI) {
                window.secureUI.showAlert(
                    'You\'re offline. SecureDocs works offline - all encryption happens locally!',
                    'info',
                    8000
                );
            }
        };

        window.addEventListener('online', handleOnline);
        window.addEventListener('offline', handleOffline);
    }

    /**
     * Initialize analytics (privacy-friendly, no personal data)
     */
    setupAnalytics() {
        // Simple usage analytics without personal data
        const sessionStart = Date.now();
        
        // Track basic usage patterns
        const trackEvent = (event) => {
            const sessionData = {
                event,
                timestamp: Date.now(),
                sessionDuration: Date.now() - sessionStart,
                userAgent: navigator.userAgent.substring(0, 100), // Truncated for privacy
                // No personal identifying information
            };
            
            // Store locally for debugging (could be removed in production)
            const logs = JSON.parse(localStorage.getItem('securedocs-logs') || '[]');
            logs.push(sessionData);
            
            // Keep only last 50 events
            if (logs.length > 50) {
                logs.splice(0, logs.length - 50);
            }
            
            localStorage.setItem('securedocs-logs', JSON.stringify(logs));
        };

        // Track app initialization
        trackEvent('app_initialized');

        // Track encryption/decryption events (no file details)
        document.getElementById('encryptBtn')?.addEventListener('click', () => {
            trackEvent('encrypt_started');
        });

        document.getElementById('decryptBtn')?.addEventListener('click', () => {
            trackEvent('decrypt_started');
        });
    }
}

/**
 * Initialize the application when DOM is ready
 */
function initializeApp() {
    // Check browser compatibility first
    const app = new SecureDocsApp();
    app.checkBrowserCompatibility();
    app.setupKeyboardShortcuts();
    app.setupPerformanceMonitoring();
    app.setupGlobalErrorHandling();
    app.setupOfflineDetection();
    app.setupAnalytics();
    
    // Store global reference
    window.secureDocsApp = app;
}

// Initialize when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    initializeApp();
}

// Additional utility functions for debugging and development
window.SecureDocsDebug = {
    /**
     * Clear all stored data
     */
    clearAllData() {
        localStorage.removeItem('securedocs-logs');
        sessionStorage.removeItem('securedocs-welcome-shown');
        console.log('All SecureDocs data cleared');
    },

    /**
     * Get performance logs
     */
    getLogs() {
        return JSON.parse(localStorage.getItem('securedocs-logs') || '[]');
    },

    /**
     * Test encryption/decryption with sample data
     */
    async testCrypto() {
        try {
            const testData = new TextEncoder().encode('Hello, SecureDocs!');
            const password = 'test123';
            
            console.log('Testing encryption...');
            const encrypted = await secureCrypto.encryptFile(testData, password, 'test.txt');
            
            console.log('Testing decryption...');
            const decrypted = await secureCrypto.decryptFile(encrypted.encryptedData, password);
            
            const originalText = new TextDecoder().decode(testData);
            const decryptedText = new TextDecoder().decode(decrypted.decryptedData);
            
            if (originalText === decryptedText) {
                console.log('✅ Crypto test passed!');
                return true;
            } else {
                console.error('❌ Crypto test failed - data mismatch');
                return false;
            }
        } catch (error) {
            console.error('❌ Crypto test failed:', error);
            return false;
        }
    }
};