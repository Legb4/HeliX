// client/js/WebSocketClient.js

/**
 * Manages the WebSocket connection to the server specified by the URL.
 * Handles the entire lifecycle: connecting, sending messages (as JSON strings),
 * receiving messages, monitoring the connection status (connecting, connected, disconnected, errors),
 * and implementing an automatic reconnection strategy with exponential backoff (though currently linear)
 * upon unexpected disconnections.
 */
class WebSocketClient {
    /**
     * Creates a new WebSocketClient instance.
     * @param {string} url - The WebSocket server URL (e.g., 'wss://localhost:5678').
     */
    constructor(url) {
        // The target WebSocket server URL (e.g., 'wss://example.com:5678').
        this.url = url;
        // Holds the native WebSocket object instance when connected or attempting connection. Null otherwise.
        this.websocket = null;
        // Callback function provided by the SessionManager to handle incoming message data strings.
        this.messageListener = null;
        // Callback function provided by the SessionManager to report status changes (e.g., 'Connecting...', 'Connected').
        this.statusListener = null;
        // Tracks if the 'open' event was ever successfully triggered for the current connection attempt cycle.
        // Used by handleClose to differentiate between initial connection failures (server unreachable) and later disconnections.
        this.wasConnected = false;

        // --- Reconnection Logic State ---
        // Counter for automatic reconnection attempts after an unexpected disconnection.
        this.reconnectAttempts = 0;
        // Maximum number of times to try reconnecting automatically before giving up.
        this.maxReconnectAttempts = 5;
        // Delay (in milliseconds) before attempting the next reconnect. (Currently fixed, could be exponential).
        this.reconnectDelay = 10000; // 10 seconds.
        // Stores the JavaScript timeout ID (from setTimeout) for the scheduled reconnect attempt. Null if no reconnect is scheduled.
        this.reconnectTimeoutId = null;
        // --------------------------
    }

    /**
     * Initiates a WebSocket connection attempt to the configured URL.
     * If an existing connection is present, it's closed first.
     * Resets reconnection state if this is a fresh connection attempt (not an automatic retry).
     * @param {boolean} [isReconnectAttempt=false] - Internal flag set to true when this method is called by the automatic reconnection logic.
     */
    connect(isReconnectAttempt = false) {
        // Clear any previously scheduled reconnect attempt timer.
        this.clearReconnectTimeout();

        // Log connection attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Attempting to connect to WebSocket server at ${this.url}... (Reconnect: ${isReconnectAttempt})`);
        }

        // If this is a fresh connection attempt (initiated by user/app start, not an automatic retry), reset state flags.
        if (!isReconnectAttempt) {
            this.wasConnected = false; // Reset flag indicating if connection was ever successfully established in this cycle.
            this.reconnectAttempts = 0; // Reset reconnect counter.
        }

        // Update the status immediately to "Connecting...".
        this.updateStatus('Connecting...');

        // If a WebSocket object already exists and isn't closed, close it cleanly first before creating a new one.
        if (this.websocket && this.websocket.readyState !== WebSocket.CLOSED) {
            // Log closure only if DEBUG is enabled.
            if (config.DEBUG) console.log("Closing existing WebSocket connection before connecting.");
            // IMPORTANT: Remove event listeners from the old socket *before* closing it
            // to prevent its handleClose method firing unexpectedly and potentially triggering incorrect logic.
            this.removeListeners();
            // Close with a normal closure code (1000) indicating a planned closure.
            this.websocket.close(1000, "Client initiated new connection");
        }

        try {
            // Create the new native WebSocket object. This action initiates the connection attempt asynchronously.
            this.websocket = new WebSocket(this.url);
            // Ensure event handler methods (`handleOpen`, `handleMessage`, etc.) have the correct 'this' context when called.
            this.bindHandlers(); // Needs to be called only once, typically in constructor, but safe here too.
            // Attach the event listeners ('open', 'message', 'error', 'close') to the new WebSocket object.
            this.addListeners();

        } catch (error) {
            // Catch errors during WebSocket object creation itself (e.g., invalid URL format).
            // Always log these critical errors.
            console.error("Error creating WebSocket connection:", error);
            this.updateStatus('Failed to connect (Initialization Error)');
            this.websocket = null; // Ensure websocket reference is null on creation failure.
            // Reset connection state fully if creation failed.
            this.wasConnected = false;
            this.reconnectAttempts = 0;
        }
    }

    // --- Listener Management ---

    /**
     * Binds the 'this' context to the event handler methods (handleOpen, handleMessage, etc.).
     * This ensures that 'this' refers to the WebSocketClient instance inside these handlers
     * when they are invoked by the WebSocket object's events. Should ideally be called once in the constructor.
     */
    bindHandlers() {
        // Ensure each handler method is bound to the current instance context.
        this.handleOpen = this.handleOpen.bind(this);
        this.handleMessage = this.handleMessage.bind(this);
        this.handleError = this.handleError.bind(this);
        this.handleClose = this.handleClose.bind(this);
    }

    /**
     * Adds the standard WebSocket event listeners ('open', 'message', 'error', 'close')
     * to the current WebSocket object instance (`this.websocket`).
     */
    addListeners() {
        if (!this.websocket) return; // Don't add listeners if the socket object doesn't exist.
        this.websocket.addEventListener('open', this.handleOpen);
        this.websocket.addEventListener('message', this.handleMessage);
        this.websocket.addEventListener('error', this.handleError);
        this.websocket.addEventListener('close', this.handleClose);
    }

    /**
     * Removes the standard WebSocket event listeners from the current WebSocket object instance.
     * This is crucial before closing a socket manually or replacing it with a new one
     * to prevent handlers from being called on the old, potentially defunct, socket.
     */
    removeListeners() {
         if (!this.websocket) return; // Don't attempt removal if the socket object doesn't exist.
         try {
            // Use try-catch as removing listeners from an already closed/null socket might throw errors in some environments.
            this.websocket.removeEventListener('open', this.handleOpen);
            this.websocket.removeEventListener('message', this.handleMessage);
            this.websocket.removeEventListener('error', this.handleError);
            this.websocket.removeEventListener('close', this.handleClose);
         } catch(e) {
             // Always log warnings about listener removal errors, but don't stop execution.
             console.warn("Error removing listeners (socket might be null or already closed):", e);
         }
    }
    // -------------------------


    // --- Event Handlers ---

    /**
     * WebSocket 'open' event handler. Called when the connection is successfully established.
     * Updates status to 'Connected', resets reconnection attempts, sets the `wasConnected` flag,
     * and clears any pending reconnect timeout.
     * @param {Event} event - The 'open' event object (not typically used).
     */
    handleOpen(event) {
        // Log connection established (significant event, not wrapped in DEBUG).
        console.log('WebSocket connection established.');
        this.wasConnected = true; // Mark that we successfully connected at least once in this cycle.
        this.reconnectAttempts = 0; // Reset reconnect counter on a successful connection.
        this.clearReconnectTimeout(); // Clear any pending reconnect attempt timer.
        this.updateStatus('Connected'); // Notify listeners (e.g., SessionManager) of the connected status.
    }

    /**
     * WebSocket 'message' event handler. Called when a message is received from the server.
     * Passes the received message data (string) to the registered message listener (SessionManager).
     * @param {MessageEvent} event - The 'message' event object, containing the received data in `event.data`.
     */
    handleMessage(event) {
        if (this.messageListener) {
            // Pass the received data string (event.data) to the callback function set by SessionManager.
            this.messageListener(event.data);
        } else {
            // Always log warning if no listener is registered, as messages would be lost.
            console.warn('No message listener registered for incoming message.');
        }
    }

    /**
     * WebSocket 'error' event handler. Called when a WebSocket error occurs.
     * Note: This event often precedes the 'close' event, especially for connection failures.
     * Detailed error handling and status updates are typically managed in `handleClose`.
     * @param {Event} event - The 'error' event object (often generic, specific details may be limited).
     */
    handleError(event) {
        // Log the error event for debugging purposes.
        // Always log WebSocket errors.
        console.error('WebSocket error observed:', event);
        // Status updates related to connection failures are usually handled in handleClose based on wasConnected flag.
    }

    /**
     * WebSocket 'close' event handler. Called when the connection is closed, either cleanly or due to an error.
     * Determines if the closure was unexpected (abnormal).
     * Initiates the automatic reconnection logic if the closure was abnormal and max attempts haven't been reached.
     * Updates the status to reflect the final disconnection state (e.g., Disconnected, Connection Lost, Failed).
     * Performs cleanup by removing listeners and nullifying the websocket reference.
     * @param {CloseEvent} event - The 'close' event object containing `code`, `reason`, and `wasClean` properties.
     */
    handleClose(event) {
        // Log closure details (significant event, not wrapped in DEBUG).
        console.log(`WebSocket connection closed. Code: ${event.code}, Reason: "${event.reason}", Clean: ${event.wasClean}`);

        // Determine if the close was unexpected (abnormal).
        // !event.wasClean is the primary indicator. Code 1006 (Abnormal Closure) is common for network issues.
        const abnormalClose = !event.wasClean || event.code === 1006;
        // Determine if we should attempt to reconnect based on the closure type and attempt count.
        const shouldAttemptReconnect = abnormalClose && this.reconnectAttempts < this.maxReconnectAttempts;

        // --- Cleanup ---
        // Remove event listeners from the socket that just closed.
        this.removeListeners();
        // Nullify the main websocket reference *after* removing listeners to prevent race conditions.
        this.websocket = null;
        // --- End Cleanup ---

        if (shouldAttemptReconnect) {
            // If reconnection is needed and possible, schedule the next attempt.
            this.attemptReconnect();
        } else {
            // --- Final Disconnect Status Determination ---
            // Determine the final status message based on why we're not reconnecting.
            let statusMessage;
            if (this.reconnectAttempts >= this.maxReconnectAttempts) {
                // Max reconnect attempts reached.
                statusMessage = "Connection Lost. Failed to reconnect.";
                // Always log this error.
                console.error("Max reconnect attempts reached. Giving up.");
            } else if (event.code === 1000) {
                // Normal, clean closure (e.g., server shutdown initiated cleanly, client called disconnect()).
                statusMessage = "Disconnected";
            } else if (event.code === 1001) {
                // Client or server is "going away" (e.g., browser tab closing, server process stopping).
                statusMessage = "Disconnected (Client navigating away)";
            } else if (event.code === 1006 && !this.wasConnected) {
                // Abnormal close (1006) *and* we never successfully connected in the first place ('open' event never fired).
                // This strongly suggests the server was unreachable or refused the initial connection.
                statusMessage = "Connection Failed (Server Unreachable?)";
            } else if (event.code === 1015) {
                 // TLS handshake failure (e.g., certificate issue, SSL/TLS protocol mismatch).
                 statusMessage = "Connection Failed (TLS/SSL Error)";
            } else if (abnormalClose && this.wasConnected) {
                 // Abnormal close after having been connected, but retries are exhausted or not applicable (e.g., specific error code).
                 statusMessage = "Connection Lost";
            } else {
                 // Fallback for other close codes or scenarios.
                 statusMessage = `Disconnected (Code: ${event.code})`;
            }

            // Update status to the final determined state.
            this.updateStatus(statusMessage);
            // Reset connection state fully as we are stopping connection attempts.
            this.wasConnected = false;
            this.reconnectAttempts = 0;
            this.clearReconnectTimeout(); // Ensure no lingering reconnect timer.
            // --- End Final Disconnect Status Determination ---
        }
    }
    // -----------------------------

    // --- Reconnect Attempt Logic ---

    /**
     * Handles the logic for scheduling the next reconnection attempt.
     * Increments the reconnect counter, updates the status to indicate a retry is pending,
     * and uses `setTimeout` to schedule the `connect(true)` call after the configured delay.
     */
    attemptReconnect() {
        this.reconnectAttempts++;
        // Log reconnect attempt (significant event, not wrapped in DEBUG).
        console.log(`Connection lost/failed. Reconnect attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts}.`);

        // Calculate delay in seconds for the status message.
        const delaySeconds = this.reconnectDelay / 1000;
        // Update status to indicate reconnection attempt is pending and show progress.
        this.updateStatus(`Connection Lost. Retrying in ${delaySeconds}s... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

        // Schedule the actual connect() call after the delay.
        // Pass 'true' to connect() to indicate this is a reconnect attempt.
        this.reconnectTimeoutId = setTimeout(() => {
            // Log execution of the scheduled attempt only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Executing reconnect attempt ${this.reconnectAttempts}...`);
            this.connect(true); // Call connect again, marking it as a reconnect.
        }, this.reconnectDelay);
    }

    /**
     * Clears any pending reconnection timeout scheduled by `attemptReconnect`.
     * Called when a connection is successfully established, manually disconnected,
     * or when max reconnect attempts are reached.
     */
    clearReconnectTimeout() {
        if (this.reconnectTimeoutId) {
            // Log clearing only if DEBUG is enabled.
            if (config.DEBUG) console.log("Clearing pending reconnect attempt.");
            clearTimeout(this.reconnectTimeoutId);
            this.reconnectTimeoutId = null; // Clear the stored timeout ID.
        }
    }
    // ---------------------------

    /**
     * Sends a message object to the server over the WebSocket connection.
     * The object is automatically stringified to JSON before sending.
     * Checks if the connection is open before attempting to send.
     * Includes error handling for send failures, especially due to unexpected closures.
     *
     * @param {object} messageObject - The JavaScript object to be serialized and sent.
     * @returns {boolean} True if the message was successfully queued for sending, false otherwise (e.g., not connected, error during send).
     */
    sendMessage(messageObject) {
        // Check if the WebSocket object exists and its readyState is OPEN.
        if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
            try {
                // Convert the JavaScript object to a JSON string.
                const messageString = JSON.stringify(messageObject);
                // Send the JSON string over the WebSocket.
                this.websocket.send(messageString);
                // Log sent message only if DEBUG is enabled (can be verbose).
                // if (config.DEBUG) console.log("WebSocket message sent:", messageString);
                return true; // Indicate success (message queued by browser).
            } catch (error) {
                // Handle potential errors during stringification or sending.
                if (error instanceof DOMException && error.name === 'InvalidStateError') {
                    // This specific error often means the connection closed unexpectedly
                    // between the readyState check and the actual send() call.
                    // Always log this critical error.
                    console.error('Failed to send message: WebSocket connection closed unexpectedly.', messageObject, error);
                    this.updateStatus("Error: Send Failed (Connection Lost?)");
                    // Manually trigger close handling logic if the 'close' event hasn't fired yet,
                    // as the state is clearly inconsistent.
                    const currentSocket = this.websocket; // Capture current socket reference.
                    if (currentSocket) {
                         // Simulate an abnormal close event to potentially trigger reconnection or final status update.
                         // Use a local reference as this.websocket might be nulled by handleClose itself.
                         this.handleClose({ code: 1006, reason: "Send failed due to InvalidStateError", wasClean: false });
                    }
                } else {
                    // Handle other errors (e.g., JSON stringification error if object is invalid).
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
     * Manually closes the WebSocket connection with a normal closure code (1000).
     * Clears any pending reconnect attempts and updates the status to 'Disconnected'.
     * Removes listeners before closing to prevent automatic reconnection attempts.
     * @param {string} [reason="User initiated disconnect"] - Optional reason string for the closure, sent to the server.
     */
    disconnect(reason = "User initiated disconnect") {
        // Stop any scheduled reconnection attempts immediately.
        this.clearReconnectTimeout();
        this.reconnectAttempts = 0; // Reset counter on manual disconnect.

        if (this.websocket) {
            // Log manual closure only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Closing WebSocket connection manually. Reason: ${reason}`);
            // Remove listeners *before* calling close on manual disconnect
            // to prevent the automatic reconnect logic in handleClose from firing.
            this.removeListeners();
            // Only call close if the socket is in a state where it can be closed (CONNECTING or OPEN).
            if (this.websocket.readyState === WebSocket.OPEN || this.websocket.readyState === WebSocket.CONNECTING) {
                 this.websocket.close(1000, reason); // Use normal closure code (1000).
                 // Manually update status after initiating close, as handleClose might not fire now
                 // due to listener removal, or might fire with the wrong context if called later.
                 this.updateStatus("Disconnected");
            } else {
                 // Log if already closed/closing only if DEBUG is enabled.
                 if (config.DEBUG) console.log("WebSocket already closing or closed when manual disconnect called.");
                 // Status might have already been updated by a previous handleClose call.
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
     * Registers a callback function to be called when a message is received from the server.
     * @param {function(string): void} listener - The callback function that takes the raw message data string as an argument.
     */
    setMessageListener(listener) {
        this.messageListener = listener;
    }

    /**
     * Registers a callback function to be called when the WebSocket connection status changes.
     * @param {function(string): void} listener - The callback function that takes a status string (e.g., 'Connecting...', 'Connected') as an argument.
     */
    setStatusListener(listener) {
        this.statusListener = listener;
    }

    /**
     * Updates the connection status internally and notifies the registered status listener callback.
     * @param {string} status - The new status message string.
     */
    updateStatus(status) {
        if (this.statusListener) {
            // Call the registered callback function (likely in SessionManager) with the new status.
            this.statusListener(status);
        } else {
            // Fallback to console logging if no listener is registered (should not happen in normal operation).
            // Log status only if DEBUG is enabled (as UIController also logs it via SessionManager).
            if (config.DEBUG) {
                console.log(`WebSocket Status: ${status}`);
            }
        }
    }
}
