// client/js/config.js
// This file centralizes configuration settings for the client-side application.

// Define a configuration object to hold settings.
const config = {
    /**
     * The full URL for the WebSocket server connection.
     * - Use 'wss://' for secure connections (required for Web Crypto API on non-localhost domains).
     * - Use 'ws://' for insecure connections (only for local testing, not recommended for deployment).
     * - Replace 'localhost' with the actual hostname or IP address of your server if deployed.
     * - Ensure the port number (e.g., 5678) matches the port the Python WebSocket server is listening on.
     */
    // Use wss:// and the actual hostname/IP of your server
    // Ensure the port matches the WebSocket server port (e.g., 5678)
    webSocketUrl: 'wss://localhost:5678',

    /**
     * Debug Flag for Console Logging.
     * - Set to `true` to enable detailed console logging for development and debugging.
     *   This will output internal states, cryptographic steps, and other verbose information.
     * - Set to `false` for production deployments to minimize information leakage
     *   and keep the console cleaner. Essential errors (`console.error`, `console.warn`)
     *   will still be logged regardless of this flag.
     */
    DEBUG: false,    // Default to false for production

    /**
     * Application Version String.
     * - Used by the /version command.
     */
    APP_VERSION: "0.1 beta test", // NEW: Application version string
};

// Make the config object globally accessible (if not using modules)
// If using ES modules, you would export this object instead.
// window.config = config; // Uncomment if needed in a non-module environment
