// client/js/UIController.js

/**
 * Manages all interactions with the HTML Document Object Model (DOM).
 * This class is responsible for getting references to UI elements,
 * showing/hiding different sections of the application, updating text content,
 * enabling/disabling controls, adding/removing items from lists,
 * displaying messages, and binding event listeners to UI elements.
 * It acts as the presentation layer, controlled by the SessionManager.
 */
class UIController {
    /**
     * Initializes the UIController by getting references to all necessary DOM elements.
     * Also sets the initial UI state (showing the registration area).
     */
    constructor() {
        // --- Get References to Elements ---
        // Store references to frequently accessed DOM elements for efficiency.
        // Status Bar
        this.statusElement = document.getElementById('status');

        // Registration Area
        this.registrationArea = document.getElementById('registration-area');
        this.identifierInput = document.getElementById('identifier-input');
        this.registerButton = document.getElementById('register-button');

        // Main App Container (Sidebar + Main Content)
        this.appContainer = document.getElementById('app-container');

        // Sidebar Elements
        this.sidebar = document.getElementById('sidebar');
        this.myIdentifierDisplay = document.getElementById('my-identifier'); // User's ID display in sidebar
        this.initiationArea = document.getElementById('initiation-area'); // Area to start new chat
        this.peerIdInput = document.getElementById('peer-id-input'); // Input for peer's ID
        this.startChatButton = document.getElementById('start-chat-button'); // Button to initiate chat
        this.sessionListContainer = document.getElementById('session-list-container'); // Container for session list
        this.sessionList = document.getElementById('session-list'); // The <ul> element for sessions

        // Main Content Area Panes (different views within the main area)
        this.mainContent = document.getElementById('main-content');
        this.overlay = document.getElementById('overlay'); // Reference to the overlay div
        this.welcomeMessage = document.getElementById('welcome-message'); // Default welcome view
        this.myIdentifierWelcome = document.getElementById('my-identifier-welcome'); // User's ID display in welcome message
        this.incomingRequestArea = document.getElementById('incoming-request-area'); // View for incoming requests
        this.incomingRequestText = document.getElementById('incoming-request-text'); // Text within incoming request view
        this.acceptButton = document.getElementById('accept-button'); // Accept button
        this.denyButton = document.getElementById('deny-button'); // Deny button
        this.infoArea = document.getElementById('info-area'); // View for showing info/errors (denial, timeout)
        this.infoMessage = document.getElementById('info-message'); // Text within info view
        this.closeInfoButton = document.getElementById('close-info-button'); // Close button in info view
        this.retryRequestButton = document.getElementById('retry-request-button'); // Retry button in info view
        this.waitingResponseArea = document.getElementById('waiting-response-area'); // View shown while waiting for peer response
        this.waitingResponseText = document.getElementById('waiting-response-text'); // Text within waiting view
        this.cancelRequestButton = document.getElementById('cancel-request-button'); // Cancel button in waiting view
        this.activeChatArea = document.getElementById('active-chat-area'); // View for an active chat session
        this.chatHeader = document.getElementById('chat-header'); // Header within active chat view
        this.peerIdentifierDisplay = document.getElementById('peer-identifier'); // Peer's ID display in chat header
        this.messageArea = document.getElementById('message-area'); // Area where messages are displayed

        // --- NEW: Typing Indicator Elements ---
        this.typingIndicatorArea = document.getElementById('typing-indicator-area'); // Container below messages
        this.typingIndicatorText = document.getElementById('typing-indicator-text'); // The text span for "is typing..."
        // ------------------------------------

        this.messageInputArea = document.getElementById('message-input-area'); // Container for input and send button
        this.messageInput = document.getElementById('message-input'); // The message text input field
        this.sendButton = document.getElementById('send-button'); // Send message button
        this.disconnectButton = document.getElementById('disconnect-button'); // Disconnect button in chat header

        // --- Initial State ---
        // Set the initial visibility of UI sections.
        this.showRegistration();

        // Log initialization (not wrapped in DEBUG as it's fundamental)
        console.log('UIController initialized.');
        // Validate that all expected elements were found in the DOM.
        if (!this.validateElements()) {
             // Always log validation errors.
             console.error("!!! UIController failed validation - Some elements not found! Check HTML IDs.");
        }
    }

    /**
     * Updates the text content of the status bar element.
     * @param {string} message - The status message to display.
     */
    updateStatus(message) {
        if (this.statusElement) {
            this.statusElement.textContent = `Status: ${message}`;
            // Log status updates only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`UI Status Updated: ${message}`);
            }
        }
    }

    // --- UI State Management ---
    // Methods to control the visibility of different panes/sections.

    /**
     * Hides all major panes within the main content area AND the overlay.
     * Used before showing a specific pane to ensure only one is visible.
     */
    hideAllMainPanes() {
        if (this.welcomeMessage) this.welcomeMessage.style.display = 'none';
        if (this.incomingRequestArea) this.incomingRequestArea.style.display = 'none';
        if (this.activeChatArea) this.activeChatArea.style.display = 'none';
        if (this.infoArea) this.infoArea.style.display = 'none';
        if (this.waitingResponseArea) this.waitingResponseArea.style.display = 'none';
        if (this.overlay) this.overlay.style.display = 'none'; // Hide overlay too
        // Also ensure the typing indicator is hidden when switching panes.
        this.hideTypingIndicator();
    }

    /**
     * Shows the registration area and hides the main application container.
     * Enables registration controls and focuses the identifier input.
     */
    showRegistration() {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Showing Registration");
        if (this.registrationArea) this.registrationArea.style.display = 'flex'; // Use flex for centering
        if (this.appContainer) this.appContainer.style.display = 'none';
        this.setRegistrationControlsEnabled(true); // Enable input/button
        this.setInitiationControlsEnabled(false); // Disable chat initiation
        // Focus input field slightly delayed to ensure visibility.
        if (this.identifierInput) { setTimeout(() => this.identifierInput.focus(), 0); }
    }

    /**
     * Hides the registration area and shows the main application container (sidebar + main content).
     * Displays the user's ID and shows the default welcome message pane.
     * @param {string} myId - The user's registered identifier.
     */
    showMainApp(myId) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Showing Main App");
        if (this.registrationArea) this.registrationArea.style.display = 'none';
        if (this.appContainer) this.appContainer.style.display = 'flex'; // Show the main layout
        if (this.myIdentifierDisplay) this.myIdentifierDisplay.textContent = myId; // Show ID in sidebar
        if (this.myIdentifierWelcome) this.myIdentifierWelcome.textContent = myId; // Show ID in welcome message
        this.showWelcomeMessage(); // Show the default pane
        this.setRegistrationControlsEnabled(false); // Disable registration controls
    }

    /**
     * Shows the welcome message pane in the main content area.
     * Hides other panes and ensures appropriate controls are enabled/disabled.
     */
    showWelcomeMessage() {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Showing Welcome Message Pane");
        this.hideAllMainPanes(); // Hide others (including overlay)
        if (this.welcomeMessage) this.welcomeMessage.style.display = 'block'; // Show welcome
        this.setInitiationControlsEnabled(true); // Allow starting new chats
        this.setChatControlsEnabled(false); // Disable active chat controls
        this.setIncomingRequestControlsEnabled(false); // Disable accept/deny
        this.setInfoControlsEnabled(false); // Disable info pane controls
        this.setWaitingControlsEnabled(false); // Disable waiting pane controls
        this.focusPeerIdInput(); // Focus the input for starting a new chat
    }

    /**
     * Shows the incoming chat request pane with the overlay effect.
     * @param {string} senderId - The identifier of the peer sending the request.
     */
    showIncomingRequest(senderId) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Showing Incoming Request Pane for ${senderId}`);
        this.hideAllMainPanes(); // Hide other panes first
        if (this.welcomeMessage) this.welcomeMessage.style.display = 'block'; // Ensure welcome is visible behind overlay
        if (this.overlay) this.overlay.style.display = 'block'; // Show the overlay
        if (this.incomingRequestArea) this.incomingRequestArea.style.display = 'block'; // Show the request pane on top
        if (this.incomingRequestText) this.incomingRequestText.textContent = `Incoming chat request from ${senderId}. Accept or Deny?`;
        this.setIncomingRequestControlsEnabled(true); // Enable accept/deny buttons
        // Disable other potentially active controls
        this.setChatControlsEnabled(false);
        this.setInfoControlsEnabled(false);
        this.setWaitingControlsEnabled(false);
        this.setInitiationControlsEnabled(true); // Keep initiation enabled
    }

    /**
     * Shows the information pane (for denials, timeouts, errors) with the overlay effect.
     * @param {string} peerId - The peer ID this information relates to.
     * @param {string} message - The message to display in the pane.
     * @param {boolean} showRetry - Whether to show the "Retry" button.
     */
    showInfoMessage(peerId, message, showRetry) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Showing Info Pane for peer ${peerId}. Retry: ${showRetry}`);
        this.hideAllMainPanes(); // Hide other panes first
        if (this.welcomeMessage) this.welcomeMessage.style.display = 'block'; // Ensure welcome is visible behind overlay
        if (this.overlay) this.overlay.style.display = 'block'; // Show the overlay
        if (this.infoArea) this.infoArea.style.display = 'block'; // Show the info pane on top
        if (this.infoMessage) this.infoMessage.textContent = message || `An issue occurred regarding ${peerId}.`;
        // Store peerId in button datasets for event handlers
        if (this.closeInfoButton) this.closeInfoButton.dataset.peerid = peerId;
        if (this.retryRequestButton) {
            this.retryRequestButton.dataset.peerid = peerId;
            // Show or hide the retry button based on the flag
            this.retryRequestButton.style.display = showRetry ? 'inline-block' : 'none';
        }
        this.setInfoControlsEnabled(true); // Enable close/retry buttons
        // Disable other potentially active controls
        this.setChatControlsEnabled(false);
        this.setIncomingRequestControlsEnabled(false);
        this.setWaitingControlsEnabled(false);
        this.setInitiationControlsEnabled(true); // Keep initiation enabled
        // Focus the appropriate button
        const buttonToFocus = showRetry ? this.retryRequestButton : this.closeInfoButton;
        if (buttonToFocus) { setTimeout(() => buttonToFocus.focus(), 0); }
    }

    /**
     * Shows the "waiting for response" pane after initiating a chat, with the overlay effect.
     * @param {string} peerId - The peer ID we are waiting for.
     */
    showWaitingForResponse(peerId) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Showing Waiting for Response Pane for ${peerId}`);
        this.hideAllMainPanes(); // Hide others first
        if (this.welcomeMessage) this.welcomeMessage.style.display = 'block'; // Ensure welcome is visible behind overlay
        if (this.overlay) this.overlay.style.display = 'block'; // Show the overlay
        if (this.waitingResponseArea) this.waitingResponseArea.style.display = 'block'; // Show the waiting pane on top
        if (this.waitingResponseText) this.waitingResponseText.textContent = `Waiting for ${peerId} to respond...`;
        // Store peerId in button dataset for event handler
        if (this.cancelRequestButton) this.cancelRequestButton.dataset.peerid = peerId;
        this.setWaitingControlsEnabled(true); // Enable cancel button
        // Disable other potentially active controls
        this.setChatControlsEnabled(false);
        this.setIncomingRequestControlsEnabled(false);
        this.setInfoControlsEnabled(false);
        this.setInitiationControlsEnabled(true); // Keep initiation enabled
        // Focus the cancel button
        if (this.cancelRequestButton) { setTimeout(() => this.cancelRequestButton.focus(), 0); }
    }

    /**
     * Shows the active chat pane for a specific peer.
     * Clears previous messages and focuses the message input field.
     * (Overlay is not used for this pane).
     * @param {string} peerId - The identifier of the peer for the active chat.
     */
    showActiveChat(peerId) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Showing Active Chat Pane for ${peerId}`);
        this.hideAllMainPanes(); // Hide others (including overlay)
        if (this.activeChatArea) this.activeChatArea.style.display = 'flex'; // Show chat area
        if (this.peerIdentifierDisplay) this.peerIdentifierDisplay.textContent = peerId; // Set peer ID in header
        this.clearMessageInput(); // Clear any old text in input
        this.clearMessages(); // Clear messages from previous chat
        this.setActiveSessionInList(peerId); // Highlight session in sidebar list
        this.setChatControlsEnabled(true); // Enable message input, send, disconnect
        // Disable other potentially active controls
        this.setIncomingRequestControlsEnabled(false);
        this.setInfoControlsEnabled(false);
        this.setWaitingControlsEnabled(false);
        this.setInitiationControlsEnabled(true); // Keep initiation enabled
        this.focusMessageInput(); // Focus the message input field
    }

    /**
     * Shows the default view when registered but no specific session is active
     * (i.e., the welcome message pane). Ensures the main app container is visible.
     * @param {string} myId - The user's registered identifier.
     */
    showDefaultRegisteredView(myId) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Showing Default Registered View (Welcome Pane)");
        // Ensure the main app container is visible if it wasn't already
        if (this.appContainer && this.appContainer.style.display === 'none') {
            this.showMainApp(myId);
        } else {
            // If app container is already visible, just show the welcome pane within it
            this.showWelcomeMessage();
        }
        this.clearActiveSessionInList(); // No session is active in the list
        // Disable controls specific to other panes
        this.setChatControlsEnabled(false);
        this.setIncomingRequestControlsEnabled(false);
        this.setInfoControlsEnabled(false);
        this.setWaitingControlsEnabled(false);
    }

    // --- Focus Helper Methods ---
    /** Sets focus to the peer ID input field if available and enabled. */
    focusPeerIdInput() {
        if (this.peerIdInput && !this.peerIdInput.disabled) {
            // Use setTimeout to ensure focus occurs after potential layout changes.
            setTimeout(() => {
                // Log focus event only if DEBUG is enabled.
                if (config.DEBUG) console.log("UI: Focusing Peer ID Input");
                this.peerIdInput.focus();
            }, 0);
        } else {
            // Log lack of focus only if DEBUG is enabled.
            if (config.DEBUG) console.log("UI: Peer ID Input not available or disabled for focus.");
        }
    }

    /** Sets focus to the message input field if available and enabled. */
    focusMessageInput() {
        if (this.messageInput && !this.messageInput.disabled) {
            // Use setTimeout to ensure focus occurs after potential layout changes.
            setTimeout(() => {
                // Log focus event only if DEBUG is enabled.
                if (config.DEBUG) console.log("UI: Focusing Message Input");
                this.messageInput.focus();
            }, 0);
        } else {
            // Log lack of focus only if DEBUG is enabled.
            if (config.DEBUG) console.log("UI: Message Input not available or disabled for focus.");
        }
    }
    // ---------------------------

    // --- Control Enable/Disable Methods with Loading State ---

    /**
     * Internal helper to set the enabled/disabled and loading state of a button.
     * @param {HTMLButtonElement} button - The button element.
     * @param {boolean} enabled - True to enable, false to disable.
     * @param {boolean} [loadingState=false] - True to show loading text, false otherwise.
     * @param {string} [loadingText="Working..."] - Text to display when loading.
     */
    _setButtonState(button, enabled, loadingState = false, loadingText = "Working...") {
        if (!button) return; // Ignore if button element doesn't exist
        button.disabled = !enabled || loadingState; // Disable if not enabled OR if loading
        if (loadingState && enabled === false) { // Show loading text only when disabled due to loading
            // Store original text if not already stored
            if (!button.dataset.originalText) { button.dataset.originalText = button.textContent; }
            button.textContent = loadingText; // Set loading text
        } else {
            // Restore original text if it was stored
            if (button.dataset.originalText) {
                button.textContent = button.dataset.originalText;
                delete button.dataset.originalText; // Remove stored text
            }
        }
    }

    /** Enables/disables registration input and button, optionally showing loading state. */
    setRegistrationControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Registration Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        if (this.identifierInput) this.identifierInput.disabled = !enabled || loadingState;
        this._setButtonState(this.registerButton, enabled, loadingState, "Registering...");
    }

    /** Enables/disables chat initiation input field and button, optionally showing loading state. */
    setInitiationControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Initiation Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        if (this.peerIdInput) { this.peerIdInput.disabled = !enabled || loadingState; }
        // Apply loading state to the Start Chat button as well
        this._setButtonState(this.startChatButton, enabled, loadingState, "Starting...");
    }

    /** Enables/disables incoming request (Accept/Deny) buttons, optionally showing loading state. */
    setIncomingRequestControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Incoming Request Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        this._setButtonState(this.acceptButton, enabled, loadingState, "Accepting...");
        this._setButtonState(this.denyButton, enabled, loadingState, "Denying...");
    }

    /** Enables/disables active chat controls (input, send, disconnect), optionally showing loading state. */
    setChatControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Chat Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        if (this.messageInput) this.messageInput.disabled = !enabled || loadingState;
        this._setButtonState(this.sendButton, enabled, loadingState, "Sending...");
        this._setButtonState(this.disconnectButton, enabled, loadingState, "Disconnecting...");
    }

    /** Enables/disables info pane controls (Close, Retry), optionally showing loading state. */
    setInfoControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Info Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        this._setButtonState(this.closeInfoButton, enabled, loadingState, "Closing...");
        // Handle retry button only if it's currently visible
        if (this.retryRequestButton && this.retryRequestButton.style.display !== 'none') {
            this._setButtonState(this.retryRequestButton, enabled, loadingState, "Retrying...");
        } else if (this.retryRequestButton) {
            // Ensure retry button is disabled if hidden or parent controls are disabled
             this.retryRequestButton.disabled = !enabled;
        }
    }

    /** Enables/disables waiting pane controls (Cancel), optionally showing loading state. */
    setWaitingControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Waiting Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        this._setButtonState(this.cancelRequestButton, enabled, loadingState, "Cancelling...");
    }
    // -----------------------------------------

    // --- Session List Management ---

    /**
     * Adds a new session entry to the sidebar list if it doesn't already exist.
     * @param {string} peerId - The identifier of the peer for the new session list item.
     */
    addSessionToList(peerId) {
        // Check if list exists and if item already exists
        if (!this.sessionList || this.sessionList.querySelector(`[data-peerid="${peerId}"]`)) {
            return;
        }
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Adding session ${peerId} to list.`);
        const listItem = document.createElement('li');
        listItem.textContent = peerId; // Set text to peer ID
        listItem.dataset.peerid = peerId; // Store peer ID in data attribute for easy retrieval
        // Create and append the notification dot span (initially hidden)
        const dot = document.createElement('span');
        dot.className = 'notification-dot';
        listItem.appendChild(dot);
        this.sessionList.appendChild(listItem); // Add item to the list
    }

    /**
     * Removes a session entry from the sidebar list.
     * @param {string} peerId - The identifier of the peer whose list item should be removed.
     */
    removeSessionFromList(peerId) {
        const listItem = this.sessionList ? this.sessionList.querySelector(`[data-peerid="${peerId}"]`) : null;
        if (listItem) {
            // Log action only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Removing session ${peerId} from list.`);
            listItem.remove(); // Remove the element
        } else {
            // Log missing item only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Session ${peerId} not found in list for removal.`);
        }
    }

    /**
     * Highlights a specific session in the sidebar list as the currently active one.
     * Removes highlighting from any previously active item and clears the unread indicator.
     * @param {string} peerId - The identifier of the peer whose list item should be marked active.
     */
    setActiveSessionInList(peerId) {
        if (!this.sessionList) return;
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting active session in list: ${peerId}`);
        this.clearActiveSessionInList(); // Remove active class from others first
        const listItem = this.sessionList.querySelector(`[data-peerid="${peerId}"]`);
        if (listItem) {
            listItem.classList.add('active-session'); // Add active class
            listItem.classList.remove('has-unread'); // Ensure unread indicator is off
        }
    }

    /** Removes the 'active-session' class from all items in the session list. */
    clearActiveSessionInList() {
         if (!this.sessionList) return;
         this.sessionList.querySelectorAll('li.active-session').forEach(item => {
             item.classList.remove('active-session');
         });
    }

    /**
     * Shows or hides the unread notification dot for a specific session list item.
     * Will not show the dot if the session is currently the active one.
     * @param {string} peerId - The identifier of the peer.
     * @param {boolean} hasUnread - True to show the dot, false to hide it.
     */
    setUnreadIndicator(peerId, hasUnread) {
        if (!this.sessionList) return;
        const listItem = this.sessionList.querySelector(`[data-peerid="${peerId}"]`);
        if (listItem) {
            if (hasUnread) {
                // Only add 'has-unread' if the item isn't already the active one
                if (!listItem.classList.contains('active-session')) {
                    // Log action only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`UI: Setting unread indicator for ${peerId}`);
                    listItem.classList.add('has-unread');
                }
            } else {
                // Always remove 'has-unread' when requested
                // Log action only if DEBUG is enabled.
                if (config.DEBUG) console.log(`UI: Clearing unread indicator for ${peerId}`);
                listItem.classList.remove('has-unread');
            }
        }
    }

    // --- Input/Output Helpers ---
    /** Gets the trimmed value from the identifier input field. */
    getIdentifierInput() { return this.identifierInput ? this.identifierInput.value.trim() : ''; }
    /** Gets the trimmed value from the peer ID input field. */
    getPeerIdInput() { return this.peerIdInput ? this.peerIdInput.value.trim() : ''; }
    /** Clears the peer ID input field. */
    clearPeerIdInput() { if (this.peerIdInput) this.peerIdInput.value = ''; }
    /** Gets the current value from the message input field. */
    getMessageInput() { return this.messageInput ? this.messageInput.value : ''; }
    /** Clears the message input field. */
    clearMessageInput() { if (this.messageInput) this.messageInput.value = ''; }

    // --- Message Display ---

    /**
     * Adds a message (peer, own, or system) to the message display area.
     * Includes timestamp and sender information. Scrolls to bottom if already scrolled down.
     * @param {string} sender - Identifier of the sender ('System', own ID, or peer ID).
     * @param {string} text - The message content.
     * @param {string} [type='peer'] - Type of message ('peer', 'own', 'system').
     */
    addMessage(sender, text, type = 'peer') {
        if (!this.messageArea) return; // Ignore if message area doesn't exist

        // Check if user is scrolled near the bottom before adding the message.
        const wasScrolledToBottom = this.messageArea.scrollHeight - this.messageArea.clientHeight <= this.messageArea.scrollTop + 1;

        // Create message elements
        const messageDiv = document.createElement('div');
        messageDiv.classList.add(`message-${type}`); // Add class based on type

        // Timestamp
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'message-timestamp';
        const now = new Date();
        // Format date and time (adjust locale/options as needed)
        const dateString = now.toLocaleDateString([], { month: '2-digit', day: '2-digit', year: 'numeric' });
        const timeString = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        timestampSpan.textContent = `[${dateString} - ${timeString}]`;

        // Sender
        const senderSpan = document.createElement('span');
        senderSpan.className = 'message-sender';
        let senderDisplay = sender; // Use ID by default
        // Add specific sender class and adjust display format
        if (type === 'own') {
            senderSpan.classList.add('sender-own');
        } else if (type === 'system') {
            senderDisplay = 'System'; // Display 'System' instead of ID
            senderSpan.classList.add('sender-system');
        } else { // 'peer'
            senderSpan.classList.add('sender-peer');
        }
        // Format sender prefix
        senderSpan.textContent = (type !== 'system') ? `<${senderDisplay}>` : `${senderDisplay}:`;

        // Message Text
        const textSpan = document.createElement('span');
        textSpan.className = 'message-text';
        textSpan.textContent = ` ${text}`; // Add leading space for separation

        // Append elements to message container
        messageDiv.appendChild(timestampSpan);
        messageDiv.appendChild(senderSpan);
        // Only add text span if it's not a system message without text (though usually they have text)
        if (type !== 'system' || text) {
            messageDiv.appendChild(textSpan);
        }

        // Add the complete message div to the message area
        this.messageArea.appendChild(messageDiv);

        // Auto-scroll to bottom if the user was already near the bottom.
        if (wasScrolledToBottom) {
            this.messageArea.scrollTop = this.messageArea.scrollHeight;
        }
    }

    /** Convenience method to add a system message. */
    addSystemMessage(text) { this.addMessage('System', text, 'system'); }

    /** Clears all messages from the message display area. */
    clearMessages() { if (this.messageArea) this.messageArea.innerHTML = ''; }

    // --- NEW: Typing Indicator Methods ---

    /**
     * Shows the typing indicator text (e.g., "PeerID is typing...").
     * @param {string} peerId - The ID of the peer who is typing.
     */
    showTypingIndicator(peerId) {
        if (this.typingIndicatorText) {
            this.typingIndicatorText.textContent = `${peerId} is typing...`;
            this.typingIndicatorText.style.display = 'inline'; // Make the text visible
        }
    }

    /** Hides the typing indicator text and clears its content. */
    hideTypingIndicator() {
        if (this.typingIndicatorText) {
            this.typingIndicatorText.style.display = 'none'; // Hide the text element
            this.typingIndicatorText.textContent = ''; // Clear the text content
        }
    }
    // -----------------------------------

    // --- NEW: Info Pane Visibility Checks ---

    /**
     * Checks if the info pane is currently visible and associated with the specified peer.
     * @param {string} peerId - The peer ID to check against the info pane's data.
     * @returns {boolean} True if the info pane is visible and matches the peerId, false otherwise.
     */
    isInfoPaneVisibleFor(peerId) {
        if (!this.infoArea || this.infoArea.style.display === 'none') {
            return false; // Pane is not visible
        }
        // Check the dataset peerid on the close button (or retry button if needed)
        const storedPeerId = this.closeInfoButton?.dataset?.peerid || this.retryRequestButton?.dataset?.peerid;
        return storedPeerId === peerId; // Return true if visible and peerId matches
    }

    /**
     * Checks if the info pane is currently visible, regardless of the associated peer.
     * @returns {boolean} True if the info pane's display style is not 'none', false otherwise.
     */
    isAnyInfoPaneVisible() {
        return this.infoArea ? this.infoArea.style.display !== 'none' : false;
    }
    // --------------------------------------

    // --- Event Listener Setup ---
    // Methods to attach event handlers (provided by main.js/SessionManager) to UI elements.

    /** Binds a handler function to the register button's click event. */
    bindRegisterButton(handler) { if (this.registerButton) this.registerButton.addEventListener('click', handler); }
    /** Binds a handler function to the start chat button's click event. */
    bindStartChatButton(handler) { if (this.startChatButton) this.startChatButton.addEventListener('click', handler); }
    /** Binds a handler function to the accept button's click event. */
    bindAcceptButton(handler) { if (this.acceptButton) this.acceptButton.addEventListener('click', handler); }
    /** Binds a handler function to the deny button's click event. */
    bindDenyButton(handler) { if (this.denyButton) this.denyButton.addEventListener('click', handler); }

    /**
     * Binds a handler function to the send button's click event AND
     * the Enter key press (without Shift) in the message input field.
     */
    bindSendButton(handler) {
        if (this.sendButton) this.sendButton.addEventListener('click', handler);
        if (this.messageInput) {
             this.messageInput.addEventListener('keypress', (event) => {
                 // Check for Enter key (key code 13 or key 'Enter') and ensure Shift key is not pressed
                 if (event.key === 'Enter' && !event.shiftKey) {
                     event.preventDefault(); // Prevent default action (e.g., newline in textarea)
                     handler(); // Call the provided send message handler
                 }
             });
        }
    }

    /** Binds a handler function to the disconnect button's click event. */
    bindDisconnectButton(handler) { if (this.disconnectButton) this.disconnectButton.addEventListener('click', handler); }

    /**
     * Binds a handler function to click events on the session list.
     * Uses event delegation to handle clicks on dynamically added <li> elements.
     * Extracts the peerId from the clicked item's dataset.
     */
    bindSessionListClick(handler) {
         if (this.sessionList) {
             this.sessionList.addEventListener('click', (event) => {
                 // Find the closest ancestor <li> element with a 'data-peerid' attribute
                 const listItem = event.target.closest('li[data-peerid]');
                 // If found, call the handler with the peerId
                 if (listItem && listItem.dataset.peerid) {
                     handler(listItem.dataset.peerid);
                 }
             });
         }
    }

    /**
     * Binds a handler function to the close button in the info pane.
     * Extracts the peerId from the button's dataset.
     */
    bindCloseInfoButton(handler) {
        if (this.closeInfoButton) {
            this.closeInfoButton.addEventListener('click', (event) => {
                const peerId = event.target.dataset.peerid; // Get peerId from data attribute
                if (peerId) {
                    handler(peerId); // Call handler with the ID
                } else {
                    // Always log this error.
                    console.error("Close info button clicked, but no peerId found in dataset.");
                }
            });
        }
    }

    /**
     * Binds a handler function to the retry button in the info pane.
     * Extracts the peerId from the button's dataset.
     */
    bindRetryRequestButton(handler) {
        if (this.retryRequestButton) {
            this.retryRequestButton.addEventListener('click', (event) => {
                const peerId = event.target.dataset.peerid; // Get peerId from data attribute
                if (peerId) {
                    handler(peerId); // Call handler with the ID
                } else {
                    // Always log this error.
                    console.error("Retry button clicked, but no peerId found in dataset.");
                }
            });
        }
    }

    /**
     * Binds a handler function to the cancel request button in the waiting pane.
     * Extracts the peerId from the button's dataset.
     */
    bindCancelRequestButton(handler) {
        if (this.cancelRequestButton) {
            this.cancelRequestButton.addEventListener('click', (event) => {
                 const peerId = event.target.dataset.peerid; // Get peerId from data attribute
                 if (peerId) {
                     handler(peerId); // Call handler with the ID
                 } else {
                     // Always log this error.
                     console.error("Cancel request button clicked, but no peerId found in dataset.");
                 }
            });
        }
    }

    // --- NEW: Bind Message Input Event ---
    /**
     * Attaches an event listener to the message input field for the 'input' event.
     * This event fires immediately whenever the text content changes (typing, pasting, etc.).
     * Used to trigger the local typing indicator logic in SessionManager.
     * @param {function} handler - Function to call when the input value changes.
     */
    bindMessageInput(handler) {
        if (this.messageInput) {
            // 'input' event is generally preferred over 'keydown' or 'keyup' for detecting value changes.
            this.messageInput.addEventListener('input', handler);
        }
    }
    // -----------------------------------

    // --- Utility ---
    /**
     * Validates that all expected DOM element references were successfully found.
     * Logs warnings for any missing elements.
     * @returns {boolean} True if all elements were found, false otherwise.
     */
    validateElements() {
        const elements = [
            // List all element properties stored in the constructor
            this.statusElement, this.registrationArea, this.identifierInput, this.registerButton,
            this.appContainer, this.sidebar, this.myIdentifierDisplay, this.initiationArea,
            this.peerIdInput, this.startChatButton, this.sessionListContainer, this.sessionList,
            this.mainContent, this.overlay, // Added overlay
            this.welcomeMessage, this.myIdentifierWelcome,
            this.incomingRequestArea, this.incomingRequestText,
            this.acceptButton, this.denyButton,
            this.infoArea, this.infoMessage, this.closeInfoButton, this.retryRequestButton,
            this.waitingResponseArea, this.waitingResponseText, this.cancelRequestButton,
            this.activeChatArea, this.chatHeader,
            this.peerIdentifierDisplay, this.messageArea,
            // Add typing indicator elements
            this.typingIndicatorArea, this.typingIndicatorText,
            // Continue existing
            this.messageInputArea, this.messageInput,
            this.sendButton, this.disconnectButton
        ];
        let allFound = true;
        elements.forEach((el) => {
            // Find the property name associated with the element for logging
            const keyName = Object.keys(this).find(key => this[key] === el);
            if (!el) {
                // Always log validation warnings.
                console.warn(`UIController: Element for property '${keyName || 'UNKNOWN'}' not found! Check HTML IDs.`);
                allFound = false;
            }
        });
        return allFound;
    }
}
