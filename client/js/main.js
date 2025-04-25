// client/js/main.js

/**
 * Main entry point for the HeliX client-side application.
 * This script runs after the DOM is fully loaded. It initializes the core components
 * (UIController, WebSocketClient, SessionManager), connects them by setting up listeners,
 * binds UI element events (like button clicks and input changes) to application logic
 * in the SessionManager or UIController, and initiates the WebSocket connection process.
 */
document.addEventListener('DOMContentLoaded', () => {
    // Log DOM loaded confirmation.
    console.log('DOM fully loaded.');

    // --- 1. Initialize Core Components ---

    // Create an instance of the UIController to manage all DOM interactions and updates.
    const uiController = new UIController();

    // Create an instance of the WebSocketClient, passing the server URL from the global config object.
    const webSocketClient = new WebSocketClient(config.webSocketUrl);

    // Create an instance of the SessionManager, which orchestrates the application logic.
    // Pass it the WebSocket client (for sending messages), the UI controller (for updating the view),
    // and the CryptoModule CLASS itself (not an instance). The SessionManager will create
    // new CryptoModule instances for each individual chat session as needed.
    const sessionManager = new SessionManager(webSocketClient, uiController, CryptoModule);

    // --- 2. Wire Components Together (Setup Listeners) ---

    // Set up a listener for WebSocket status changes (e.g., Connecting, Connected, Disconnected).
    // The WebSocketClient will call this function whenever its connection state changes.
    webSocketClient.setStatusListener((status) => {
        // Always update the visual status bar in the UI with the latest status.
        uiController.updateStatus(status);

        // Determine if the status represents a final, unrecoverable disconnection or connection failure state.
        const isFinalDisconnect = status === "Disconnected" ||
                                  status === "Disconnected (Client navigating away)" ||
                                  status.startsWith("Connection Failed") || // Covers Unreachable, TLS, Init Error
                                  status === "Connection Lost. Failed to reconnect."; // Max reconnect retries reached

        if (isFinalDisconnect) {
            // If it's a final disconnect state, inform the SessionManager to clean up all active sessions,
            // reset the application state, and potentially show the registration screen again.
            // Log disconnect handling only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`StatusListener: Detected final disconnect/failure state: "${status}". Calling handleDisconnection.`);
            }
            sessionManager.handleDisconnection(); // SessionManager handles the full reset.
        } else if (status === 'Connected' && sessionManager.managerState !== sessionManager.STATE_REGISTERED) {
            // If the WebSocket connects (or reconnects successfully after a temporary drop)
            // but the user isn't registered yet (e.g., initial connection, or reconnect after server restart),
            // ensure the registration screen is shown.
            uiController.showRegistration();
        }
        // Note: Intermediate "Connection Lost" states are handled internally by WebSocketClient's
        // reconnection logic. Only the final failure state triggers the full SessionManager reset here.
    });

    // Set up a listener for incoming WebSocket messages.
    // The WebSocketClient will call this function whenever a message is received from the server.
    webSocketClient.setMessageListener((messageData) => {
        // Pass the raw message data string directly to the SessionManager for parsing and handling.
        sessionManager.handleIncomingMessage(messageData);
    });

    // --- 3. Bind UI Actions to SessionManager/UIController Methods ---
    // Connect user interface elements (buttons, inputs) to their corresponding
    // actions within the SessionManager (for application logic) or UIController (for UI-only actions).

    // Registration: Bind the register button click event.
    uiController.bindRegisterButton(() => {
        const id = uiController.getIdentifierInput(); // Get identifier from input field.
        if (id) {
            sessionManager.attemptRegistration(id); // Call SessionManager to handle registration logic.
        } else {
            alert("Please enter an identifier."); // Basic validation feedback.
        }
    });
    // Registration: Allow pressing Enter in the identifier input field to trigger registration.
    if (uiController.identifierInput) {
        uiController.identifierInput.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') {
                event.preventDefault(); // Prevent default form submission or newline behavior.
                if (uiController.registerButton) uiController.registerButton.click(); // Simulate button click.
            }
        });
    }

    // Start Chat: Bind the start chat button click event.
    uiController.bindStartChatButton(() => {
        const peerId = uiController.getPeerIdInput(); // Get peer ID from input field.
        if (peerId) {
            sessionManager.initiateSession(peerId); // Call SessionManager to handle session initiation.
            uiController.clearPeerIdInput(); // Clear the input field after initiating.
        } else {
            alert("Please enter the peer's identifier."); // Basic validation feedback.
        }
    });
    // Start Chat: Allow pressing Enter in the peer ID input field to trigger starting a chat.
     if (uiController.peerIdInput) {
        uiController.peerIdInput.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') {
                event.preventDefault(); // Prevent default form submission or newline behavior.
                if (uiController.startChatButton) uiController.startChatButton.click(); // Simulate button click.
            }
        });
     }

    // Accept/Deny Incoming Request: Bind the accept and deny buttons in the incoming request pane.
    uiController.bindAcceptButton(() => {
        // SessionManager stores the ID of the peer whose request is currently displayed and awaiting action.
        if (sessionManager.pendingPeerIdForAction) {
            sessionManager.acceptRequest(sessionManager.pendingPeerIdForAction); // Tell SessionManager to accept.
        } else {
            // This state should not normally occur if the UI is managed correctly.
            // Always log this error.
            console.error("UIController: Accept clicked, but no pendingPeerIdForAction set in SessionManager.");
        }
    });

    uiController.bindDenyButton(() => {
        // SessionManager stores the ID of the peer whose request is currently displayed.
        if (sessionManager.pendingPeerIdForAction) {
            sessionManager.denyRequest(sessionManager.pendingPeerIdForAction); // Tell SessionManager to deny.
        } else {
            // This state should not normally occur.
            // Always log this error.
            console.error("UIController: Deny clicked, but no pendingPeerIdForAction set in SessionManager.");
        }
    });

    // Close Info Message (Denial/Timeout/Error): Bind the close button in the info pane.
    // The handler receives the peerId associated with the info message (stored in the button's dataset).
    uiController.bindCloseInfoButton((peerId) => {
        // Log button click only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Close info button clicked for peer: ${peerId}`);
        sessionManager.closeInfoMessage(peerId); // Tell SessionManager to handle closing this state and potentially resetting the session.
    });

    // Retry Request (After Timeout): Bind the retry button in the info pane.
    // The handler receives the peerId associated with the info message (stored in the button's dataset).
    uiController.bindRetryRequestButton((peerId) => {
        // Log button click only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Retry button clicked for peer: ${peerId}`);
        sessionManager.retryRequest(peerId); // Tell SessionManager to retry the request.
    });

    // Bind Cancel Request Button (While waiting for peer response).
    // The handler receives the peerId associated with the waiting pane (stored in the button's dataset).
    uiController.bindCancelRequestButton((peerId) => {
        // Log button click only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Cancel request button clicked for peer: ${peerId}`);
        sessionManager.cancelRequest(peerId); // Tell SessionManager to cancel the outgoing request.
    });

    // Send Message: Define the action for sending a message or processing a command.
    const sendMessageAction = () => {
        const messageText = uiController.getMessageInput(); // Get text from input field.
        const activePeerId = sessionManager.getActivePeerId(); // Get the ID of the currently active chat session.
        if (messageText && activePeerId) {
            // If there's text and an active chat, tell SessionManager to process and send it.
            sessionManager.sendEncryptedMessage(activePeerId, messageText);
            uiController.clearMessageInput(); // Clear the input field after sending/processing.
        } else if (!activePeerId) {
            // Log error if trying to send without an active chat selected.
            // Always log this error.
            console.error("UIController: Cannot send message, no active chat selected.");
            // Optionally provide UI feedback here if needed.
        }
        // If messageText is empty, do nothing silently.
    };
    // Bind the send button click and the Enter key press (without Shift) in the message input to the send action.
    uiController.bindSendButton(sendMessageAction);

    // Disconnect Chat: Bind the disconnect button in the active chat header.
    uiController.bindDisconnectButton(() => {
        const activePeerId = sessionManager.getActivePeerId(); // Get the ID of the currently active chat.
        if (activePeerId) {
            sessionManager.endSession(activePeerId); // Tell SessionManager to end the session.
        } else {
            // This state should not normally occur if the button is only visible in an active chat.
            // Always log this error.
            console.error("UIController: Disconnect clicked, but no active chat selected.");
        }
    });

    // Bind Session List Clicks: Handle clicks on items in the session list (sidebar).
    // The handler receives the peerId associated with the clicked list item (stored in its dataset).
    uiController.bindSessionListClick((peerId) => {
        // Log list click only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session list item clicked for peer: ${peerId}`);
        sessionManager.switchToSessionView(peerId); // Tell SessionManager to switch the main view to this session.
    });

    // Bind Message Input Typing: Notify SessionManager when the user types in the message input.
    // This is used to send typing indicators ('is typing...') to the peer.
    uiController.bindMessageInput(() => {
        const activePeerId = sessionManager.getActivePeerId(); // Get current chat peer ID.
        if (activePeerId) {
            // Tell SessionManager the local user is typing in the context of this chat.
            sessionManager.handleLocalTyping(activePeerId);
        }
    });

    // Bind Mute Button: Toggle mute state directly in UIController.
    uiController.bindMuteButton(() => {
        // Log mute toggle only if DEBUG is enabled.
        if (config.DEBUG) console.log("Mute button clicked.");
        uiController.toggleMuteState(); // Call the UIController method to toggle mute and update icon.
    });

    // --- Bind Settings UI Elements ---
    // Bind Settings Button: Show the settings pane.
    uiController.bindSettingsButton(() => {
        // Log settings open only if DEBUG is enabled.
        if (config.DEBUG) console.log("Settings button clicked.");
        uiController.showSettingsPane(); // Tell UIController to display the settings pane.
    });

    // Bind Close Settings Button: Hide the settings pane.
    uiController.bindCloseSettingsButton(() => {
        // Log settings close only if DEBUG is enabled.
        if (config.DEBUG) console.log("Close settings button clicked.");
        uiController.hideSettingsPane(); // Tell UIController to hide the settings pane.
    });

    // Bind Font Family Select: Apply new font family when the selection changes.
    uiController.bindFontFamilyChange((event) => {
        const newFontFamily = event.target.value; // Get the selected font family.
        const currentStyles = uiController.getCurrentChatStyles(); // Get current size.
        // Log font change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Font family changed to: ${newFontFamily}`);
        // Apply the new font family while keeping the current font size.
        uiController.applyChatStyles(newFontFamily, currentStyles.fontSize);
    });

    // Bind Font Size Input: Apply new font size as the value changes.
    uiController.bindFontSizeChange((event) => {
        const newFontSize = event.target.value; // Get the entered font size.
        const currentStyles = uiController.getCurrentChatStyles(); // Get current font family.
        // Log size change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Font size changed to: ${newFontSize}`);
        // Apply the new font size while keeping the current font family.
        uiController.applyChatStyles(currentStyles.fontFamily, newFontSize);
    });
    // ------------------------------------

    // --- File Transfer UI Elements ---
    // Bind Attach Button click to trigger the hidden file input element.
    uiController.bindAttachButton(() => {
        // Log attach click only if DEBUG is enabled.
        if (config.DEBUG) console.log("Attach button clicked, triggering file input.");
        uiController.triggerFileInputClick(); // Tell UIController to click the hidden input.
    });

    // Bind File Input change event to the SessionManager handler.
    // This is triggered when the user selects a file in the browser's file dialog.
    uiController.bindFileInputChange((event) => {
        // Log file selection only if DEBUG is enabled.
        if (config.DEBUG) console.log("File input changed, calling SessionManager handler.");
        sessionManager.handleFileSelection(event); // Pass the event to SessionManager.
    });

    // Bind dynamic buttons within file transfer messages using UIController's event delegation methods.
    // These handlers receive the transferId associated with the clicked button.
    uiController.bindFileAccept((transferId) => {
        // Log accept click only if DEBUG is enabled.
        if (config.DEBUG) console.log(`File Accept clicked for transfer: ${transferId}`);
        sessionManager.handleAcceptFile(transferId); // Tell SessionManager to handle acceptance.
    });

    uiController.bindFileReject((transferId) => {
        // Log reject click only if DEBUG is enabled.
        if (config.DEBUG) console.log(`File Reject clicked for transfer: ${transferId}`);
        sessionManager.handleRejectFile(transferId); // Tell SessionManager to handle rejection.
    });

    uiController.bindFileCancel((transferId) => {
        // Log cancel click only if DEBUG is enabled.
        if (config.DEBUG) console.log(`File Cancel clicked for transfer: ${transferId}`);
        sessionManager.handleCancelTransfer(transferId); // Tell SessionManager to handle cancellation.
    });

    uiController.bindFileDownload((transferId) => {
        // Log download click only if DEBUG is enabled.
        if (config.DEBUG) console.log(`File Download clicked for transfer: ${transferId}. Revoking URL.`);
        // The actual download is handled by the browser via the link's href/download attributes.
        // We just need to revoke the temporary Blob URL after the click to free memory.
        // Use a small timeout to allow the browser time to initiate the download before revoking.
        setTimeout(() => {
            uiController.revokeObjectURL(transferId);
        }, 100); // 100ms delay seems reasonable.
    });
    // -----------------------------------------

    // Bind Emoji Picker Button click to toggle the picker's visibility.
    uiController.bindEmojiPickerButton(() => {
        // Log emoji button click only if DEBUG is enabled.
        if (config.DEBUG) console.log("Emoji picker button clicked.");
        uiController.toggleEmojiPicker(); // Tell UIController to show/hide the picker.
    });


    // --- 4. Add Page Unload / Hide Event Listeners for Cleanup ---
    // Attempt to gracefully notify peers and close the WebSocket when the user navigates away
    // or closes the tab/browser. This is a best-effort cleanup.
    // Note: Reliability of 'beforeunload' and 'pagehide' can vary across browsers and scenarios.
    const handlePageUnload = (event) => {
        // Log unload event only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Page unload event triggered (${event.type}). Attempting cleanup.`);
        // Tell SessionManager to send disconnect notifications (Type 9) to active peers.
        if (sessionManager) {
            sessionManager.notifyPeersOfDisconnect();
            // Also attempt to clean up any pending file transfers (cancel/error).
            sessionManager.handleDisconnectionCleanup();
        }
        // Attempt a synchronous close of the WebSocket if it's still open.
        // This helps signal the server immediately, though it might not always complete successfully during unload.
        if (webSocketClient.websocket && webSocketClient.websocket.readyState === WebSocket.OPEN) {
             // Log synchronous close attempt only if DEBUG is enabled.
             if (config.DEBUG) console.log("Attempting synchronous WebSocket close during unload.");
             // Use code 1001 (Going Away) to indicate navigation/closure.
             webSocketClient.websocket.close(1001, "Client navigating away");
        }
    };
    // Listen for both 'pagehide' (more reliable on mobile/modern browsers) and 'beforeunload' for broader compatibility.
    window.addEventListener('pagehide', handlePageUnload);
    window.addEventListener('beforeunload', handlePageUnload);

    // --- 5. Start the Application ---
    // Set the initial status message in the UI.
    uiController.updateStatus('Initialized. Connecting...');
    // Initiate the first WebSocket connection attempt via the WebSocketClient.
    webSocketClient.connect();

    // --- Optional: Debugging Access ---
    // Expose the sessionManager instance globally for easier debugging in the browser console.
    // Log this message regardless of DEBUG flag, as it's helpful for developers.
    window.sessionManager = sessionManager;
    console.log("Debug: Access 'sessionManager' in the browser console.");

}); // End DOMContentLoaded listener
