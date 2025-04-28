// client/js/config.js
// This file centralizes configuration settings for the client-side application.

// Define a configuration object to hold settings.
const config = {
    /**
     * The port number for the WebSocket server connection.
     * - This value should match the port the Python WebSocket server (server/main.py) is listening on.
     * - This value is intended to be updated by the helix_manager.py script based on user configuration.
     * - The client will dynamically construct the full WebSocket URL (e.g., wss://<hostname>:<port>)
     *   using window.location.hostname and this port number.
     */
    webSocketPort: 5678,      // Default WSS port, updated by helix_manager

    /**
     * Debug Flag for Console Logging.
     * - Set to `true` to enable detailed console logging for development and debugging.
     *   This will output internal states, cryptographic steps, and other verbose information.
     * - Set to `false` for production deployments to minimize information leakage
     *   and keep the console cleaner. Essential errors (`console.error`, `console.warn`)
     *   will still be logged regardless of this flag.
     * - This value is intended to be updated by the helix_manager.py script.
     */
    DEBUG: false, // Default to false for production

    /**
     * Application Version String.
     * - Used by the /version command.
     */
    APP_VERSION: "0.1 beta test", // Application version string
};

// Make the config object globally accessible (if not using modules)
// If using ES modules, you would export this object instead.
// window.config = config; // Uncomment if needed in a non-module environment