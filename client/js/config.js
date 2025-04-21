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
    webSocketUrl: 'wss://localhost:5678'
};
