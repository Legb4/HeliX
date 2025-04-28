// client/js/WebSocketClient.js

/**
 * Manages the WebSocket connection to the server.
 * Handles connecting, sending messages, receiving messages,
 * monitoring connection status, and implementing automatic reconnection logic.
 * Dynamically determines the WebSocket URL based on the current hostname and configured port.
 */
class WebSocketClient {
    /**
     * Creates a new WebSocketClient instance.
     * Note: The URL is now determined dynamically in the connect() method.
     */
    constructor() {
        // Holds the WebSocket object instance when connected. Null otherwise.
        this.websocket = null;
        // Callback function to handle incoming messages. Set via setMessageListener.
        this.messageListener = null;
        // Callback function to report status changes. Set via setStatusListener.
        this.statusListener = null;
        // Tracks if the 'onopen' event was ever successfully triggered for the current connection attempt cycle.
        // Used to differentiate between initial connection failures and later disconnections.
        this.wasConnected = false;

        // --- Reconnection Logic ---
        // Counter for reconnection attempts after an unexpected disconnection.
        this.reconnectAttempts = 0;
        // Maximum number of times to try reconnecting before giving up.
        this.maxReconnectAttempts = 5;
        // Delay (in milliseconds) before attempting the next reconnect.
        this.reconnectDelay = 10000; // 10 seconds
        // Stores the timeout ID for the scheduled reconnect attempt. Null if no reconnect is scheduled.
        this.reconnectTimeoutId = null;
        // --------------------------

        // Bind handlers once in the constructor
        this.bindHandlers();
    }

    /**
     * Initiates a WebSocket connection attempt.
     * Dynamically constructs the URL using the current page hostname and the port from config.js.
     * Handles closing existing connections and manages initial state for reconnection logic.
     * @param {boolean} [isReconnectAttempt=false] - Internal flag set to true when called during the reconnect sequence.
     */
    connect(isReconnectAttempt = false) {
        // Clear any previously scheduled reconnect attempt.
        this.clearReconnectTimeout();

        // --- Dynamically Construct WebSocket URL ---
        // Use 'wss://' protocol (required for Web Crypto API).
        // Use window.location.hostname to get the hostname the user accessed the page with (e.g., localhost, 192.168.x.x).
        // Use config.webSocketPort (read from client/js/config.js, updated by manager) for the port.
        const dynamicUrl = `wss://${window.location.hostname}:${config.webSocketPort}`;
        // --- End Dynamic URL Construction ---

        // Log connection attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Attempting to connect to WebSocket server at ${dynamicUrl}... (Reconnect: ${isReconnectAttempt})`);
        }

        // If this is a fresh connection attempt (not a reconnect), reset state.
        if (!isReconnectAttempt) {
            this.wasConnected = false; // Reset flag indicating if connection was ever established.
            this.reconnectAttempts = 0; // Reset reconnect counter.
        }

        // Update the status immediately to "Connecting...".
        this.updateStatus('Connecting...');

        // If a WebSocket object already exists and isn't closed, close it cleanly first.
        if (this.websocket && this.websocket.readyState !== WebSocket.CLOSED) {
            // Log closure only if DEBUG is enabled.
            if (config.DEBUG) console.log("Closing existing WebSocket connection before connecting.");
            // IMPORTANT: Remove listeners from the old socket *before* closing it
            // to prevent its handleClose method firing unexpectedly.
            this.removeListeners();
            // Close with a normal closure code.
            this.websocket.close(1000, "Client initiated new connection");
        }

        try {
            // Create the new WebSocket object using the dynamically constructed URL.
            this.websocket = new WebSocket(dynamicUrl);
            // Attach the event listeners ('open', 'message', 'error', 'close') to the new socket.
            this.addListeners(); // Handlers are already bound in constructor

        } catch (error) {
            // Catch errors during WebSocket object creation (e.g., invalid URL format - less likely now).
            // Always log these errors.
            console.error(`Error creating WebSocket connection to ${dynamicUrl}:`, error);
            this.updateStatus('Failed to connect (Initialization Error)');
            this.websocket = null; // Ensure websocket is null on failure.
            // Reset connection state fully if creation failed.
            this.wasConnected = false;
            this.reconnectAttempts = 0;
        }
    }

    // --- Listener Management ---

    /**
     * Binds the 'this' context to the event handler methods.
     * This ensures that 'this' refers to the WebSocketClient instance
     * when the handlers are called by the WebSocket object. Called once in constructor.
     */
    bindHandlers() {
        this.handleOpen = this.handleOpen.bind(this);
        this.handleMessage = this.handleMessage.bind(this);
        this.handleError = this.handleError.bind(this);
        this.handleClose = this.handleClose.bind(this);
    }

    /**
     * Adds the standard WebSocket event listeners to the current WebSocket object.
     */
    addListeners() {
        if (!this.websocket) return; // Don't add listeners if socket doesn't exist.
        this.websocket.addEventListener('open', this.handleOpen);
        this.websocket.addEventListener('message', this.handleMessage);
        this.websocket.addEventListener('error', this.handleError);
        this.websocket.addEventListener('close', this.handleClose);
    }

    /**
     * Removes the standard WebSocket event listeners from the current WebSocket object.
     * Important to call before closing a socket manually or replacing it.
     */
    removeListeners() {
         if (!this.websocket) return; // Don't remove if socket doesn't exist.
         try {
            // Use try-catch as removing listeners from an already closed/null socket might throw errors in some environments.
            this.websocket.removeEventListener('open', this.handleOpen);
            this.websocket.removeEventListener('message', this.handleMessage);
            this.websocket.removeEventListener('error', this.handleError);
            this.websocket.removeEventListener('close', this.handleClose);
         } catch(e) {
             // Always log warnings about listener removal errors.
             console.warn("Error removing listeners (socket might be null or already closed):", e);
         }
    }
    // -------------------------


    // --- Event Handlers ---

    /**
     * Called when the WebSocket connection is successfully established ('open' event).
     * Updates status, resets reconnection attempts, and sets the wasConnected flag.
     * @param {Event} event - The 'open' event object.
     */
    handleOpen(event) {
        // Log connection established (not wrapped in DEBUG as it's significant).
        // Log the actual URL used for the connection.
        const connectedUrl = event.target?.url || this.websocket?.url || 'N/A';
        console.log(`WebSocket connection established to ${connectedUrl}.`);
        this.wasConnected = true; // Mark that we successfully connected at least once.
        this.reconnectAttempts = 0; // Reset reconnect counter on successful connection.
        this.clearReconnectTimeout(); // Clear any pending reconnect attempts.
        this.updateStatus('Connected'); // Notify listeners of the connected status.
    }

    /**
     * Called when a message is received from the server ('message' event).
     * Passes the message data to the registered message listener.
     * @param {MessageEvent} event - The 'message' event object, containing data property.
     */
    handleMessage(event) {
        if (this.messageListener) {
            // Pass the received data (event.data) to the callback function.
            this.messageListener(event.data);
        } else {
            // Always log warning if no listener is set.
            console.warn('No message listener registered for incoming message.');
        }
    }

    /**
     * Called when a WebSocket error occurs ('error' event).
     * Note: This event often precedes the 'close' event, especially for connection failures.
     * @param {Event} event - The 'error' event object.
     */
    handleError(event) {
        // Log the error event for debugging. Detailed handling is often done in handleClose.
        // Always log WebSocket errors.
        const targetUrl = event.target?.url || this.websocket?.url || 'N/A';
        console.error(`WebSocket error observed for connection to ${targetUrl}:`, event);
        // Potential enhancement: Update status based on specific error types if possible.
    }

    /**
     * Called when the WebSocket connection is closed ('close' event).
     * Determines if the closure was clean or unexpected, attempts reconnection
     * if appropriate, and updates the status accordingly.
     * @param {CloseEvent} event - The 'close' event object containing code, reason, wasClean.
     */
    handleClose(event) {
        // Log closure details (not wrapped in DEBUG as it's significant).
        const targetUrl = event.target?.url || 'N/A'; // Get URL from event if possible
        console.log(`WebSocket connection to ${targetUrl} closed. Code: ${event.code}, Reason: "${event.reason}", Clean: ${event.wasClean}`);

        // Determine if the close was unexpected (abnormal).
        // !event.wasClean is the primary indicator. Code 1006 is a common abnormal close code.
        const abnormalClose = !event.wasClean || event.code === 1006;
        // Determine if we should attempt to reconnect based on the closure type and attempt count.
        const shouldAttemptReconnect = abnormalClose && this.reconnectAttempts < this.maxReconnectAttempts;

        // --- Cleanup ---
        // Remove listeners from the socket that just closed.
        this.removeListeners();
        // Nullify the main websocket reference *after* removing listeners.
        this.websocket = null;
        // --- End Cleanup ---

        if (shouldAttemptReconnect) {
            // If reconnection is needed, schedule the next attempt.
            this.attemptReconnect();
        } else {
            // --- Final Disconnect Status ---
            // Determine the final status message based on why we're not reconnecting.
            let statusMessage;
            if (this.reconnectAttempts >= this.maxReconnectAttempts) {
                // Max attempts reached.
                statusMessage = "Connection Lost. Failed to reconnect.";
                // Always log this error.
                console.error("Max reconnect attempts reached. Giving up.");
            } else if (event.code === 1000) {
                // Normal, clean closure (e.g., server shutdown, client disconnect).
                statusMessage = "Disconnected";
            } else if (event.code === 1001) {
                // Client or server is "going away" (e.g., page navigation).
                statusMessage = "Disconnected (Client navigating away)";
            } else if (event.code === 1006 && !this.wasConnected) {
                // Abnormal close (1006) *and* we never successfully connected in the first place.
                // Likely indicates the server was unreachable or refused connection.
                statusMessage = `Connection Failed (Server at ${targetUrl} Unreachable/Refused?)`;
            } else if (event.code === 1015) {
                 // TLS handshake failure (SSL/TLS error).
                 statusMessage = `Connection Failed (TLS/SSL Error to ${targetUrl})`;
            } else if (abnormalClose && this.wasConnected) {
                 // Abnormal close after having been connected, but retries are exhausted or not applicable.
                 statusMessage = "Connection Lost";
            } else {
                 // Fallback for other close codes or scenarios.
                 statusMessage = `Disconnected (Code: ${event.code})`;
            }

            // Update status to the final determined state.
            this.updateStatus(statusMessage);
            // Reset connection state fully as we are stopping.
            this.wasConnected = false;
            this.reconnectAttempts = 0;
            this.clearReconnectTimeout(); // Ensure no lingering timeout.
            // --- End Final Disconnect Status ---
        }
    }
    // -----------------------------

    // --- Reconnect Attempt Logic ---

    /**
     * Increments the reconnect counter, updates the status, and schedules the next
     * connection attempt using setTimeout.
     */
    attemptReconnect() {
        this.reconnectAttempts++;
        // Log reconnect attempt (not wrapped in DEBUG as it's significant).
        console.log(`Connection lost/failed. Reconnect attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts}.`);

        // Calculate delay in seconds for the status message.
        const delaySeconds = this.reconnectDelay / 1000;
        // Update status to indicate reconnection attempt is pending.
        this.updateStatus(`Connection Lost. Retrying in ${delaySeconds}s... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

        // Schedule the actual connect() call after the delay.
        this.reconnectTimeoutId = setTimeout(() => {
            // Log execution of attempt only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Executing reconnect attempt ${this.reconnectAttempts}...`);
            // Call connect again, marking it as a reconnect attempt.
            this.connect(true);
        }, this.reconnectDelay);
    }

    /**
     * Clears any pending reconnection timeout.
     * Called when a connection is established, manually disconnected, or max retries are reached.
     */
    clearReconnectTimeout() {
        if (this.reconnectTimeoutId) {
            // Log clearing only if DEBUG is enabled.
            if (config.DEBUG) console.log("Clearing pending reconnect attempt.");
            clearTimeout(this.reconnectTimeoutId);
            this.reconnectTimeoutId = null;
        }
    }
    // ---------------------------

    /**
     * Sends a message object to the server over the WebSocket connection.
     * The object is automatically stringified to JSON.
     * @param {object} messageObject - The JavaScript object to send.
     * @returns {boolean} True if the message was sent successfully, false otherwise (e.g., not connected, error).
     */
    sendMessage(messageObject) {
        // Check if the WebSocket exists and is currently open.
        if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
            try {
                // Convert the JavaScript object to a JSON string.
                const messageString = JSON.stringify(messageObject);
                // Send the JSON string.
                this.websocket.send(messageString);
                return true; // Indicate success.
            } catch (error) {
                // Handle potential errors during stringification or sending.
                if (error instanceof DOMException && error.name === 'InvalidStateError') {
                    // This specific error often means the connection closed unexpectedly between the readyState check and send().
                    // Always log this error.
                    console.error('Failed to send message: WebSocket connection closed unexpectedly.', messageObject, error);
                    this.updateStatus("Error: Send Failed (Connection Lost?)");
                    // Manually trigger close handling logic if the 'close' event hasn't fired yet.
                    // Check if websocket still exists before calling handleClose on it.
                    const currentSocket = this.websocket;
                    if (currentSocket) {
                         // Simulate an abnormal close event to potentially trigger reconnection or final status update.
                         this.handleClose({ code: 1006, reason: "Send failed", wasClean: false });
                    }
                } else {
                    // Handle other errors (e.g., JSON stringification error).
                    // Always log these errors.
                    console.error('Failed to stringify or send message:', messageObject, error);
                    this.updateStatus("Error: Failed to send message");
                }
                return false; // Indicate failure.
            }
        } else {
            // WebSocket is not connected or doesn't exist.
            // Always log this error.
            console.error('WebSocket is not connected. Cannot send message.');
            this.updateStatus('Error: Not connected');
            return false; // Indicate failure.
        }
    }

    /**
     * Manually closes the WebSocket connection.
     * Clears any pending reconnect attempts and updates the status.
     * @param {string} [reason="User initiated disconnect"] - Optional reason string for the closure.
     */
    disconnect(reason = "User initiated disconnect") {
        // Stop any scheduled reconnection attempts.
        this.clearReconnectTimeout();
        this.reconnectAttempts = 0; // Reset counter on manual disconnect.

        if (this.websocket) {
            // Log manual closure only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Closing WebSocket connection manually. Reason: ${reason}`);
            // Remove listeners *before* calling close on manual disconnect
            // to prevent the automatic reconnect logic in handleClose from firing.
            this.removeListeners();
            // Only call close if the socket is in a state where it can be closed.
            if (this.websocket.readyState === WebSocket.OPEN || this.websocket.readyState === WebSocket.CONNECTING) {
                 this.websocket.close(1000, reason); // Use normal closure code (1000).
                 // Manually update status after initiating close, as handleClose might not fire now
                 // due to listener removal, or might fire with the wrong context if called later.
                 this.updateStatus("Disconnected");
            } else {
                 // Log already closed state only if DEBUG is enabled.
                 if (config.DEBUG) console.log("WebSocket already closing or closed.");
                 // Status might have already been updated by handleClose.
            }
            // Nullify the reference after initiating close or confirming it's already closed/closing.
            this.websocket = null;
            this.wasConnected = false; // Ensure state reflects disconnect.
        } else {
            // Log attempt to disconnect non-existent socket only if DEBUG is enabled.
            if (config.DEBUG) console.log("Manual disconnect called but WebSocket does not exist.");
            // Ensure status reflects disconnected state if called when already null/disconnected.
             if (this.statusListener) {
                 this.updateStatus("Disconnected");
             }
        }
    }

    /**
     * Registers a callback function to be called when a message is received.
     * @param {function(string): void} listener - The callback function that takes message data (string) as an argument.
     */
    setMessageListener(listener) {
        this.messageListener = listener;
    }

    /**
     * Registers a callback function to be called when the connection status changes.
     * @param {function(string): void} listener - The callback function that takes a status string as an argument.
     */
    setStatusListener(listener) {
        this.statusListener = listener;
    }

    /**
     * Updates the connection status and notifies the registered status listener.
     * @param {string} status - The new status message.
     */
    updateStatus(status) {
        if (this.statusListener) {
            // Call the registered callback function.
            this.statusListener(status);
        } else {
            // Fallback to console logging if no listener is registered.
            // Log status only if DEBUG is enabled (as UIController also logs it).
            if (config.DEBUG) {
                console.log(`WebSocket Status: ${status}`);
            }
        }
    }
}