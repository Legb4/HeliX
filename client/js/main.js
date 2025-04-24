// client/js/main.js

/**
 * Main entry point for the HeliX client-side application.
 * This script runs after the DOM is fully loaded. It initializes the core components
 * (UIController, WebSocketClient, SessionManager), connects them, binds UI events
 * to application logic, and starts the WebSocket connection.
 */
document.addEventListener('DOMContentLoaded', () => {
    // Log DOM loaded (not wrapped in DEBUG as it's fundamental)
    console.log('DOM fully loaded.');

    // --- 1. Initialize Core Components ---

    // Create an instance of the UIController to manage DOM interactions.
    const uiController = new UIController();

    // Create an instance of the WebSocketClient, passing the server URL from config.js.
    const webSocketClient = new WebSocketClient(config.webSocketUrl);

    // Create an instance of the SessionManager.
    // Pass it the WebSocket client (for sending messages), the UI controller (for updating the view),
    // and the CryptoModule CLASS itself (not an instance), so SessionManager can create
    // new CryptoModule instances for each session.
    const sessionManager = new SessionManager(webSocketClient, uiController, CryptoModule);

    // --- 2. Wire Components Together ---

    // Set up a listener for WebSocket status changes (Connecting, Connected, Disconnected, etc.).
    webSocketClient.setStatusListener((status) => {
        // Always update the visual status bar in the UI.
        uiController.updateStatus(status);

        // --- UPDATED Disconnect Handling ---
        // Determine if the status represents a final, unrecoverable disconnection or failure state.
        const isFinalDisconnect = status === "Disconnected" ||
                                  status === "Disconnected (Client navigating away)" ||
                                  status.startsWith("Connection Failed") || // Covers Unreachable, TLS, Init Error
                                  status === "Connection Lost. Failed to reconnect."; // Max retries reached

        if (isFinalDisconnect) {
            // If it's a final disconnect state, tell the SessionManager to clean up all sessions
            // and reset the application state (e.g., show registration).
            // Log disconnect handling only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`StatusListener: Detected final disconnect/failure state: "${status}". Calling handleDisconnection.`);
            }
            sessionManager.handleDisconnection();
        } else if (status === 'Connected' && sessionManager.managerState !== sessionManager.STATE_REGISTERED) {
            // If the WebSocket connects (or reconnects) but the user isn't registered yet
            // (e.g., initial connection, or reconnect after server restart), show the registration screen.
            uiController.showRegistration();
        }
        // Note: Explicit handling for intermediate "Connection Lost" is removed here,
        // as WebSocketClient now manages the retry loop internally and updates the status
        // accordingly. Only the final failure state triggers the full SessionManager reset.
        // ---------------------------------
    });

    // Set up a listener for incoming WebSocket messages.
    webSocketClient.setMessageListener((messageData) => {
        // Pass the raw message data to the SessionManager for parsing and handling.
        sessionManager.handleIncomingMessage(messageData);
    });

    // --- 3. Bind UI Actions to SessionManager/UIController Methods ---
    // Connect user interface elements (buttons, inputs) to their corresponding
    // actions within the SessionManager or UIController.

    // Registration: Bind the register button click.
    uiController.bindRegisterButton(() => {
        const id = uiController.getIdentifierInput(); // Get ID from input field
        if (id) {
            sessionManager.attemptRegistration(id); // Call SessionManager method
        } else {
            alert("Please enter an identifier."); // Basic validation
        }
    });
    // Registration: Allow pressing Enter in the identifier input field to trigger registration.
    if (uiController.identifierInput) {
        uiController.identifierInput.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') {
                event.preventDefault(); // Prevent default form submission/newline
                if (uiController.registerButton) uiController.registerButton.click(); // Simulate button click
            }
        });
    }

    // Start Chat: Bind the start chat button click.
    uiController.bindStartChatButton(() => {
        const peerId = uiController.getPeerIdInput(); // Get peer ID from input
        if (peerId) {
            sessionManager.initiateSession(peerId); // Call SessionManager method
            uiController.clearPeerIdInput(); // Clear the input field after initiating
        } else {
            alert("Please enter the peer's identifier."); // Basic validation
        }
    });
    // Start Chat: Allow pressing Enter in the peer ID input field to trigger starting a chat.
     if (uiController.peerIdInput) {
        uiController.peerIdInput.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') {
                event.preventDefault(); // Prevent default form submission/newline
                if (uiController.startChatButton) uiController.startChatButton.click(); // Simulate button click
            }
        });
     }

    // Accept/Deny Incoming Request: Bind the accept and deny buttons.
    uiController.bindAcceptButton(() => {
        // SessionManager stores the ID of the peer whose request is currently displayed.
        if (sessionManager.pendingPeerIdForAction) {
            sessionManager.acceptRequest(sessionManager.pendingPeerIdForAction);
        } else {
            // Should not happen in normal flow, but log if it does.
            // Always log this error.
            console.error("UIController: Accept clicked, but no pendingPeerIdForAction set.");
        }
    });

    uiController.bindDenyButton(() => {
        // SessionManager stores the ID of the peer whose request is currently displayed.
        if (sessionManager.pendingPeerIdForAction) {
            sessionManager.denyRequest(sessionManager.pendingPeerIdForAction);
        } else {
            // Should not happen in normal flow, but log if it does.
            // Always log this error.
            console.error("UIController: Deny clicked, but no pendingPeerIdForAction set.");
        }
    });

    // Close Info Message (Denial/Timeout): Bind the close button in the info pane.
    // The handler receives the peerId associated with the info message (stored in button's dataset).
    uiController.bindCloseInfoButton((peerId) => {
        // Log button click only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Close info button clicked for peer: ${peerId}`);
        sessionManager.closeInfoMessage(peerId); // Tell SessionManager to handle closing this state.
    });

    // Retry Request (After Timeout): Bind the retry button in the info pane.
    // The handler receives the peerId associated with the info message (stored in button's dataset).
    uiController.bindRetryRequestButton((peerId) => {
        // Log button click only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Retry button clicked for peer: ${peerId}`);
        sessionManager.retryRequest(peerId); // Tell SessionManager to retry the request.
    });

    // Bind Cancel Request Button (While waiting for response).
    // The handler receives the peerId associated with the waiting pane (stored in button's dataset).
    uiController.bindCancelRequestButton((peerId) => {
        // Log button click only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Cancel request button clicked for peer: ${peerId}`);
        sessionManager.cancelRequest(peerId); // Tell SessionManager to cancel the outgoing request.
    });

    // Send Message: Define the action for sending a message.
    const sendMessageAction = () => {
        const messageText = uiController.getMessageInput(); // Get text from input
        const activePeerId = sessionManager.getActivePeerId(); // Get the ID of the currently active chat
        if (messageText && activePeerId) {
            // If there's text and an active chat, tell SessionManager to send it.
            sessionManager.sendEncryptedMessage(activePeerId, messageText);
            uiController.clearMessageInput(); // Clear the input field
        } else if (!activePeerId) {
            // Log error if trying to send without an active chat.
            // Always log this error.
            console.error("UIController: Cannot send message, no active chat selected.");
        }
    };
    // Bind the send button click and Enter key press in the message input to the send action.
    uiController.bindSendButton(sendMessageAction);

    // Disconnect Chat: Bind the disconnect button in the active chat header.
    uiController.bindDisconnectButton(() => {
        const activePeerId = sessionManager.getActivePeerId(); // Get the ID of the current chat
        if (activePeerId) {
            sessionManager.endSession(activePeerId); // Tell SessionManager to end the session.
        } else {
            // Should not happen if button is only visible in active chat, but log if it does.
            // Always log this error.
            console.error("UIController: Disconnect clicked, but no active chat selected.");
        }
    });

    // Bind Session List Clicks: Handle clicks on items in the session list (sidebar).
    // The handler receives the peerId associated with the clicked list item (stored in dataset).
    uiController.bindSessionListClick((peerId) => {
        // Log list click only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session list item clicked for peer: ${peerId}`);
        sessionManager.switchToSessionView(peerId); // Tell SessionManager to switch the main view.
    });

    // Bind Message Input Typing: Notify SessionManager when the user types in the message input.
    // This is used to send typing indicators to the peer.
    uiController.bindMessageInput(() => {
        const activePeerId = sessionManager.getActivePeerId(); // Get current chat peer ID
        if (activePeerId) {
            // Tell SessionManager the local user is typing in the context of this chat.
            sessionManager.handleLocalTyping(activePeerId);
        }
    });

    // Bind Mute Button: Toggle mute state in UIController.
    uiController.bindMuteButton(() => {
        // Log mute toggle only if DEBUG is enabled.
        if (config.DEBUG) console.log("Mute button clicked.");
        uiController.toggleMuteState(); // Call the UIController method directly
    });

    // --- NEW: Bind Settings UI Elements ---
    // Bind Settings Button: Show the settings pane.
    uiController.bindSettingsButton(() => {
        // Log settings open only if DEBUG is enabled.
        if (config.DEBUG) console.log("Settings button clicked.");
        uiController.showSettingsPane();
    });

    // Bind Close Settings Button: Hide the settings pane.
    uiController.bindCloseSettingsButton(() => {
        // Log settings close only if DEBUG is enabled.
        if (config.DEBUG) console.log("Close settings button clicked.");
        uiController.hideSettingsPane();
    });

    // Bind Font Family Select: Apply new font family when changed.
    uiController.bindFontFamilyChange((event) => {
        const newFontFamily = event.target.value;
        const currentStyles = uiController.getCurrentChatStyles();
        // Log font change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Font family changed to: ${newFontFamily}`);
        uiController.applyChatStyles(newFontFamily, currentStyles.fontSize);
    });

    // Bind Font Size Input: Apply new font size as it changes.
    uiController.bindFontSizeChange((event) => {
        const newFontSize = event.target.value;
        const currentStyles = uiController.getCurrentChatStyles();
        // Log size change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Font size changed to: ${newFontSize}`);
        uiController.applyChatStyles(currentStyles.fontFamily, newFontSize);
    });
    // ------------------------------------


    // --- 4. Add Page Unload / Hide Event Listeners for Cleanup ---
    // Attempt to gracefully notify peers and close the WebSocket when the user navigates away or closes the tab/browser.
    // Note: Reliability of these events, especially `beforeunload`, can vary across browsers.
    // `pagehide` is generally more reliable for mobile and modern browsers.
    const handlePageUnload = (event) => {
        // Log unload event only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Page unload event triggered (${event.type}). Attempting cleanup.`);
        // Tell SessionManager to send disconnect notifications (Type 9) to active peers.
        // This is a best-effort attempt.
        if (sessionManager) {
            sessionManager.notifyPeersOfDisconnect();
        }
        // Attempt a synchronous close of the WebSocket if it's open.
        // This helps signal the server immediately, though it might not always complete.
        if (webSocketClient.websocket && webSocketClient.websocket.readyState === WebSocket.OPEN) {
             // Log synchronous close attempt only if DEBUG is enabled.
             if (config.DEBUG) console.log("Attempting synchronous WebSocket close during unload.");
             // Use code 1001 (Going Away)
             webSocketClient.websocket.close(1001, "Client navigating away");
        }
    };
    // Listen for both events for broader compatibility.
    window.addEventListener('pagehide', handlePageUnload);
    window.addEventListener('beforeunload', handlePageUnload);

    // --- 5. Start the Application ---
    // Set the initial status message.
    uiController.updateStatus('Initialized. Connecting...');
    // Initiate the first WebSocket connection attempt.
    webSocketClient.connect();

    // --- Optional: Debugging Access ---
    // Expose the sessionManager instance globally for easier debugging in the browser console.
    // Log this message regardless of DEBUG flag, as it's helpful for developers.
    window.sessionManager = sessionManager;
    console.log("Debug: Access 'sessionManager' in the browser console.");

}); // End DOMContentLoaded listener
