// client/js/UIController.js

/**
 * Manages all interactions with the HTML Document Object Model (DOM).
 * This class is responsible for getting references to UI elements,
 * showing/hiding different sections of the application, updating text content,
 * enabling/disabling controls, adding/removing items from lists,
 * displaying messages (including file transfers and actions), playing sounds, managing settings UI,
 * and binding event listeners to UI elements.
 * It acts as the presentation layer, controlled by the SessionManager.
 */
class UIController {
    /**
     * Initializes the UIController by getting references to all necessary DOM elements,
     * preloading notification and UI sounds, setting the initial mute state,
     * applying initial chat styles, and setting the initial UI state.
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
        this.sidebarControls = document.getElementById('sidebar-controls'); // Container for sidebar buttons
        this.muteButton = document.getElementById('mute-button'); // Mute button reference
        this.settingsButton = document.getElementById('settings-button'); // Settings button reference
        this.sessionListContainer = document.getElementById('session-list-container'); // Container for session list
        this.sessionList = document.getElementById('session-list'); // The <ul> element for sessions

        // Main Content Area Panes (different views within the main area)
        this.mainContent = document.getElementById('main-content');
        this.overlay = document.getElementById('overlay'); // Reference to the overlay div
        this.welcomeMessage = document.getElementById('welcome-message'); // Default welcome view
        this.myIdentifierWelcome = document.getElementById('my-identifier-welcome'); // User's ID display in welcome message
        this.appVersionDisplay = document.getElementById('app-version-display'); // NEW: Version display element
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

        // Typing Indicator Elements
        this.typingIndicatorArea = document.getElementById('typing-indicator-area'); // Container below messages
        this.typingIndicatorText = document.getElementById('typing-indicator-text'); // The text span for "is typing..."

        this.messageInputArea = document.getElementById('message-input-area'); // Container for input and send button
        this.attachButton = document.getElementById('attach-button'); // NEW: Attach button reference
        this.messageInput = document.getElementById('message-input'); // The message text input field
        this.sendButton = document.getElementById('send-button'); // Send message button
        this.disconnectButton = document.getElementById('disconnect-button'); // Disconnect button in chat header

        // Settings Pane Elements
        this.settingsPane = document.getElementById('settings-pane');
        this.fontFamilySelect = document.getElementById('font-family-select');
        this.fontSizeInput = document.getElementById('font-size-input');
        this.closeSettingsButton = document.getElementById('close-settings-button');

        // File Input Element (Hidden)
        this.fileInput = document.getElementById('file-input'); // NEW: Hidden file input reference

        // --- Audio Management ---
        // Object to hold preloaded Audio elements.
        this.sounds = {};
        // List of sound names and their file paths.
        const soundFiles = {
            'notification': 'audio/notification.mp3',
            'begin': 'audio/begin.mp3',
            'end': 'audio/end.mp3',
            'error': 'audio/error.mp3',
            'registered': 'audio/registered.mp3',
            'receiverequest': 'audio/receiverequest.mp3',
            'sendrequest': 'audio/sendrequest.mp3',
            // NEW: Add sounds for file transfer
            'file_request': 'audio/receiverequest.mp3', // Reuse request sound
            'file_complete': 'audio/begin.mp3',        // Reuse begin sound
            'file_error': 'audio/error.mp3'            // Reuse error sound
        };

        // Preload each sound file.
        for (const name in soundFiles) {
            try {
                const audio = new Audio(soundFiles[name]);
                audio.preload = 'auto'; // Suggest preloading
                this.sounds[name] = audio; // Store the Audio object
                // Log preloading attempt only if DEBUG is enabled.
                if (config.DEBUG) console.log(`UI: Preloading sound '${name}' from '${soundFiles[name]}'.`);
            } catch (error) {
                // Always log errors related to audio loading.
                console.error(`UI: Failed to create Audio object for sound '${name}':`, error);
                this.sounds[name] = null; // Set to null if creation failed.
            }
        }

        // --- Mute State ---
        // Tracks whether notification sounds should be played.
        this.isMuted = false; // Start unmuted by default.
        // -----------------------

        // --- Object URL Tracking ---
        // Map to store generated Blob Object URLs for file downloads, keyed by transferId.
        // Needed so they can be revoked later to free memory.
        this.objectUrls = new Map();
        // ---------------------------

        // --- Initial State ---
        // Set the initial visibility of UI sections.
        this.showRegistration();
        // Set the initial mute button icon based on the default state.
        this.updateMuteButtonIcon();
        // Apply initial chat styles based on default settings values.
        this.applyInitialChatStyles();

        // Log initialization (not wrapped in DEBUG as it's fundamental)
        console.log('UIController initialized.');
        // Validate that all expected elements were found in the DOM.
        if (!this.validateElements()) {
             // Always log validation errors.
             console.error("!!! UIController failed validation - Some elements not found or sounds failed to load! Check HTML IDs and audio paths.");
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
        if (this.settingsPane) this.settingsPane.style.display = 'none'; // Hide settings pane too
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
     * Sets the application version display.
     * @param {string} myId - The user's registered identifier.
     */
    showMainApp(myId) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Showing Main App");
        if (this.registrationArea) this.registrationArea.style.display = 'none';
        if (this.appContainer) this.appContainer.style.display = 'flex'; // Show the main layout
        if (this.myIdentifierDisplay) this.myIdentifierDisplay.textContent = myId; // Show ID in sidebar
        if (this.myIdentifierWelcome) this.myIdentifierWelcome.textContent = myId; // Show ID in welcome message
        // --- NEW: Set Version Display ---
        if (this.appVersionDisplay && config && config.APP_VERSION) {
            this.appVersionDisplay.textContent = `Version: ${config.APP_VERSION}`;
        } else if (this.appVersionDisplay) {
            this.appVersionDisplay.textContent = 'Version: Unknown'; // Fallback
        }
        // --- END NEW ---
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
        this.setChatControlsEnabled(true); // Enable message input, send, disconnect, attach
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

    // --- Settings Pane Management ---
    /**
     * Shows the settings pane with the overlay effect.
     * Populates the settings controls with current values.
     */
    showSettingsPane() {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Showing Settings Pane");
        this.hideAllMainPanes(); // Hide other panes first
        if (this.welcomeMessage) this.welcomeMessage.style.display = 'block'; // Ensure welcome is visible behind overlay
        if (this.overlay) this.overlay.style.display = 'block'; // Show the overlay
        if (this.settingsPane) this.settingsPane.style.display = 'block'; // Show the settings pane on top

        // Populate settings controls with current values
        const currentStyles = this.getCurrentChatStyles();
        if (this.fontFamilySelect) this.fontFamilySelect.value = currentStyles.fontFamily;
        if (this.fontSizeInput) this.fontSizeInput.value = currentStyles.fontSize;

        // Disable other potentially active controls
        this.setChatControlsEnabled(false);
        this.setIncomingRequestControlsEnabled(false);
        this.setInfoControlsEnabled(false);
        this.setWaitingControlsEnabled(false);
        this.setInitiationControlsEnabled(true); // Keep initiation enabled
        // Focus the close button
        if (this.closeSettingsButton) { setTimeout(() => this.closeSettingsButton.focus(), 0); }
    }

    /**
     * Hides the settings pane and the overlay.
     * Shows the default registered view if no other pane should be active.
     */
    hideSettingsPane() {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Hiding Settings Pane");
        if (this.settingsPane) this.settingsPane.style.display = 'none';
        if (this.overlay) this.overlay.style.display = 'none';
        // Decide which view to show after closing settings
        if (this.displayedPeerId) {
            // If a chat was active before opening settings, show it again
            this.switchToSessionView(this.displayedPeerId);
        } else {
            // Otherwise, show the default welcome view
            this.showDefaultRegisteredView(this.identifier); // Assuming identifier is accessible or passed
        }
    }
    // -----------------------------------

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

    /** Enables/disables active chat controls (input, send, disconnect, attach), optionally showing loading state. */
    setChatControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Chat Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        if (this.messageInput) this.messageInput.disabled = !enabled || loadingState;
        this._setButtonState(this.sendButton, enabled, loadingState, "Sending...");
        this._setButtonState(this.disconnectButton, enabled, loadingState, "Disconnecting...");
        // Also handle the attach button
        if (this.attachButton) this.attachButton.disabled = !enabled || loadingState;
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
        if (!this.sessionList || this.sessionList.querySelector(`li[data-peerid="${peerId}"]`)) {
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
        const listItem = this.sessionList ? this.sessionList.querySelector(`li[data-peerid="${peerId}"]`) : null;
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
        const listItem = this.sessionList.querySelector(`li[data-peerid="${peerId}"]`);
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
        const listItem = this.sessionList.querySelector(`li[data-peerid="${peerId}"]`);
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

    /**
     * Adds a '/me' action message to the message display area.
     * Formats as '* Sender actionText'. Includes timestamp. Scrolls to bottom.
     * @param {string} sender - Identifier of the user performing the action.
     * @param {string} actionText - The text of the action (what follows /me).
     */
    addMeActionMessage(sender, actionText) {
        if (!this.messageArea) return; // Ignore if message area doesn't exist

        // Check if user is scrolled near the bottom before adding the message.
        const wasScrolledToBottom = this.messageArea.scrollHeight - this.messageArea.clientHeight <= this.messageArea.scrollTop + 1;

        // Create message elements
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message-me-action'); // Use a specific class for styling

        // Timestamp
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'message-timestamp';
        const now = new Date();
        const dateString = now.toLocaleDateString([], { month: '2-digit', day: '2-digit', year: 'numeric' });
        const timeString = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        timestampSpan.textContent = `[${dateString} - ${timeString}]`;

        // Action Text (formatted)
        const actionSpan = document.createElement('span');
        actionSpan.className = 'action-text'; // Use a class for the text part
        // Use textContent to prevent potential HTML injection from actionText
        actionSpan.textContent = ` * ${sender} ${actionText}`; // Format: * Sender action

        // Append elements to message container
        messageDiv.appendChild(timestampSpan);
        messageDiv.appendChild(actionSpan);

        // Add the complete message div to the message area
        this.messageArea.appendChild(messageDiv);

        // Auto-scroll to bottom if the user was already near the bottom.
        if (wasScrolledToBottom) {
            this.messageArea.scrollTop = this.messageArea.scrollHeight;
        }
    }

    /**
     * Adds a command error message to the message display area.
     * Formats similarly to a system message but with an error class for styling.
     * @param {string} errorMessage - The error message text to display.
     */
    addCommandError(errorMessage) {
        if (!this.messageArea) return; // Ignore if message area doesn't exist

        // Check if user is scrolled near the bottom before adding the message.
        const wasScrolledToBottom = this.messageArea.scrollHeight - this.messageArea.clientHeight <= this.messageArea.scrollTop + 1;

        // Create message elements
        const messageDiv = document.createElement('div');
        // Apply both system and error classes
        messageDiv.classList.add('message-system', 'message-command-error');

        // Timestamp
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'message-timestamp';
        const now = new Date();
        const dateString = now.toLocaleDateString([], { month: '2-digit', day: '2-digit', year: 'numeric' });
        const timeString = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        timestampSpan.textContent = `[${dateString} - ${timeString}]`;

        // Error Text
        const errorSpan = document.createElement('span');
        errorSpan.className = 'error-text'; // Use a class for the text part
        // Use textContent for safety
        errorSpan.textContent = ` ${errorMessage}`; // Add leading space

        // Append elements to message container
        messageDiv.appendChild(timestampSpan);
        messageDiv.appendChild(errorSpan);

        // Add the complete message div to the message area
        this.messageArea.appendChild(messageDiv);

        // Auto-scroll to bottom if the user was already near the bottom.
        if (wasScrolledToBottom) {
            this.messageArea.scrollTop = this.messageArea.scrollHeight;
        }
    }

    /**
     * Displays the application version information in the chat window.
     * @param {string} versionString - The application version string (from config).
     */
    addVersionInfo(versionString) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Displaying version info.");
        this.addSystemMessage(`HeliX Version: ${versionString}`);
    }

    /**
     * Displays current session and connection information in the chat window.
     * @param {string} httpsUrl - The current client URL.
     * @param {string} wssUrl - The WebSocket server URL.
     * @param {string} myId - The user's registered identifier.
     * @param {string} peerId - The identifier of the current chat peer.
     */
    addSessionInfo(httpsUrl, wssUrl, myId, peerId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Displaying session info.");
        const now = new Date();
        const dateTimeString = now.toLocaleString(); // Get locale-specific date/time string

        // Build the info string with newlines for display
        const infoText = `--- Session Info ---\n` +
                         `Client URL: ${httpsUrl}\n` +
                         `Server URL: ${wssUrl}\n` +
                         `Your ID: ${myId}\n` +
                         `Peer ID: ${peerId}\n` +
                         `--------------------`;

        // Split the string by newline and add each line as a system message
        // This preserves formatting better than a single message with \n
        infoText.split('\n').forEach(line => {
            this.addSystemMessage(line);
        });
    }

    /**
     * Displays the help information listing available commands in the chat window.
     */
    addHelpInfo() {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Displaying help info.");
        const helpText = `--- Available Commands ---\n` +
                         `/me <action text> : Performs an action (e.g., /me waves).\n` +
                         `/end : Ends the current chat session.\n` +
                         `/version : Displays the current HeliX client version.\n` +
                         `/info : Displays current session and connection information.\n` +
                         `/help : Displays this help message.\n` +
                         `------------------------`;

        // Split the string by newline and add each line as a system message
        helpText.split('\n').forEach(line => {
            this.addSystemMessage(line);
        });
    }


    /** Clears all messages from the message display area. */
    clearMessages() { if (this.messageArea) this.messageArea.innerHTML = ''; }

    // --- NEW: File Transfer Message Display ---

    /**
     * Adds a file transfer status message block to the message area.
     * @param {string} transferId - The unique ID for this transfer.
     * @param {string} peerId - The ID of the peer involved in the transfer.
     * @param {string} fileName - The name of the file.
     * @param {number} fileSize - The size of the file in bytes.
     * @param {boolean} isSender - True if the local user is sending, false if receiving.
     */
    addFileTransferMessage(transferId, peerId, fileName, fileSize, isSender) {
        if (!this.messageArea) return;

        const wasScrolledToBottom = this.messageArea.scrollHeight - this.messageArea.clientHeight <= this.messageArea.scrollTop + 1;

        const messageDiv = document.createElement('div');
        messageDiv.className = 'message-file-transfer';
        messageDiv.dataset.transferId = transferId; // Store transfer ID

        // Format file size nicely
        const formattedSize = this.formatFileSize(fileSize);

        // Create inner structure (using template literals for readability)
        messageDiv.innerHTML = `
            <span class="file-info">
                <span class="file-name" title="${fileName}">${this.truncateFileName(fileName)}</span>
                <span class="file-size">(${formattedSize})</span>
            </span>
            <span class="file-status">${isSender ? 'Waiting for acceptance...' : 'Incoming file request...'}</span>
            <progress class="file-progress" max="100" value="0" style="display: none;"></progress>
            <div class="file-actions">
                ${isSender ?
                    '<button class="file-cancel-btn">Cancel</button>' :
                    '<button class="file-accept-btn">Accept</button><button class="file-reject-btn">Reject</button>'
                }
                <a class="file-download-link" style="display: none;">Download</a>
            </div>
        `;

        this.messageArea.appendChild(messageDiv);

        if (wasScrolledToBottom) {
            this.messageArea.scrollTop = this.messageArea.scrollHeight;
        }
    }

    /**
     * Updates the status text of a specific file transfer message.
     * @param {string} transferId - The ID of the transfer to update.
     * @param {string} statusText - The new status text to display.
     */
    updateFileTransferStatus(transferId, statusText) {
        const messageDiv = this.messageArea?.querySelector(`.message-file-transfer[data-transfer-id="${transferId}"]`);
        const statusSpan = messageDiv?.querySelector('.file-status');
        if (statusSpan) {
            statusSpan.textContent = statusText;
            // Log update only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Updated status for transfer ${transferId} to "${statusText}"`);
        } else {
            // Log failure only if DEBUG is enabled.
            if (config.DEBUG) console.warn(`UI: Could not find status span for transfer ${transferId}`);
        }
    }

    /**
     * Updates the progress bar value for a specific file transfer message.
     * Makes the progress bar visible if it wasn't already.
     * @param {string} transferId - The ID of the transfer to update.
     * @param {number} progressPercent - The progress percentage (0-100).
     */
    updateFileTransferProgress(transferId, progressPercent) {
        const messageDiv = this.messageArea?.querySelector(`.message-file-transfer[data-transfer-id="${transferId}"]`);
        const progressBar = messageDiv?.querySelector('.file-progress');
        if (progressBar) {
            progressBar.value = Math.min(100, Math.max(0, progressPercent)); // Clamp value 0-100
            progressBar.style.display = 'block'; // Ensure progress bar is visible
            // Log update only if DEBUG is enabled.
            // if (config.DEBUG) console.log(`UI: Updated progress for transfer ${transferId} to ${progressPercent.toFixed(1)}%`);
        } else {
             // Log failure only if DEBUG is enabled.
             if (config.DEBUG) console.warn(`UI: Could not find progress bar for transfer ${transferId}`);
        }
    }

    /**
     * Shows the download link for a completed file transfer.
     * Creates an object URL, sets link attributes, hides other actions.
     * @param {string} transferId - The ID of the completed transfer.
     * @param {Blob} blob - The reassembled file Blob.
     * @param {string} fileName - The original filename for the download attribute.
     */
    showFileDownloadLink(transferId, blob, fileName) {
        const messageDiv = this.messageArea?.querySelector(`.message-file-transfer[data-transfer-id="${transferId}"]`);
        const downloadLink = messageDiv?.querySelector('.file-download-link');
        if (downloadLink && blob) {
            try {
                // Create an object URL for the Blob.
                const objectUrl = URL.createObjectURL(blob);
                // Store the URL for later revocation.
                this.objectUrls.set(transferId, objectUrl);
                // Log creation only if DEBUG is enabled.
                if (config.DEBUG) console.log(`UI: Created object URL for transfer ${transferId}: ${objectUrl}`);

                downloadLink.href = objectUrl;
                downloadLink.download = fileName; // Set the filename for download
                downloadLink.style.display = 'inline-block'; // Make the link visible

                // Hide other action buttons (Accept/Reject/Cancel).
                this.hideFileTransferActions(transferId, false); // Hide actions, keep download link

            } catch (error) {
                // Always log errors related to object URL creation.
                console.error(`UI: Error creating object URL for transfer ${transferId}:`, error);
                this.updateFileTransferStatus(transferId, "Error preparing download link.");
            }
        } else {
             // Log failure only if DEBUG is enabled.
             if (config.DEBUG) console.warn(`UI: Could not find download link or blob invalid for transfer ${transferId}`);
        }
    }

    /**
     * Hides the action buttons (Accept, Reject, Cancel) within a file transfer message.
     * Optionally keeps the download link visible if specified.
     * @param {string} transferId - The ID of the transfer whose actions to hide.
     * @param {boolean} [hideDownloadLink=true] - Whether to also hide the download link.
     */
    hideFileTransferActions(transferId, hideDownloadLink = true) {
        const messageDiv = this.messageArea?.querySelector(`.message-file-transfer[data-transfer-id="${transferId}"]`);
        const actionsDiv = messageDiv?.querySelector('.file-actions');
        if (actionsDiv) {
            // Hide individual buttons instead of the whole container if download link needs to stay
            const acceptBtn = actionsDiv.querySelector('.file-accept-btn');
            const rejectBtn = actionsDiv.querySelector('.file-reject-btn');
            const cancelBtn = actionsDiv.querySelector('.file-cancel-btn');
            if (acceptBtn) acceptBtn.style.display = 'none';
            if (rejectBtn) rejectBtn.style.display = 'none';
            if (cancelBtn) cancelBtn.style.display = 'none';

            if (hideDownloadLink) {
                const downloadLink = actionsDiv.querySelector('.file-download-link');
                if (downloadLink) downloadLink.style.display = 'none';
            }
            // Log action only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Hid actions for transfer ${transferId}`);
        } else {
             // Log failure only if DEBUG is enabled.
             if (config.DEBUG) console.warn(`UI: Could not find actions container for transfer ${transferId}`);
        }
    }

    /**
     * Removes an entire file transfer message block from the message area.
     * Also revokes any associated object URL.
     * @param {string} transferId - The ID of the transfer message to remove.
     */
    removeFileTransferMessage(transferId) {
        const messageDiv = this.messageArea?.querySelector(`.message-file-transfer[data-transfer-id="${transferId}"]`);
        if (messageDiv) {
            messageDiv.remove();
            this.revokeObjectURL(transferId); // Revoke URL when message is removed
            // Log removal only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Removed file transfer message for ${transferId}`);
        }
    }

    /**
     * Revokes a previously created object URL to free up memory.
     * @param {string} transferId - The ID of the transfer whose URL should be revoked.
     */
    revokeObjectURL(transferId) {
        if (this.objectUrls.has(transferId)) {
            const url = this.objectUrls.get(transferId);
            URL.revokeObjectURL(url);
            this.objectUrls.delete(transferId);
            // Log revocation only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Revoked object URL for transfer ${transferId}: ${url}`);
        }
    }

    /**
     * Formats a file size in bytes into a human-readable string (KB, MB, GB).
     * @param {number} bytes - The file size in bytes.
     * @returns {string} The formatted file size string.
     */
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    /**
     * Truncates a filename if it's too long, adding ellipsis.
     * @param {string} filename - The original filename.
     * @param {number} [maxLength=30] - The maximum length before truncating.
     * @returns {string} The original or truncated filename.
     */
    truncateFileName(filename, maxLength = 30) {
        if (filename.length <= maxLength) {
            return filename;
        }
        return filename.substring(0, maxLength - 3) + '...';
    }

    // --- End File Transfer Message Display ---

    // --- Typing Indicator Methods ---

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

    // --- Audio Notification Method ---
    /**
     * Attempts to play the preloaded notification sound specified by name.
     * Includes error handling for browser restrictions or loading issues.
     * Checks the isMuted flag before attempting to play.
     * @param {string} soundName - The name of the sound to play (e.g., 'notification', 'begin', 'error').
     */
    playSound(soundName) {
        // Check mute state first
        if (this.isMuted) {
            // Log skip only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Sound '${soundName}' skipped (muted).`);
            return; // Don't play if muted
        }

        // Find the preloaded Audio object.
        const sound = this.sounds[soundName];

        if (sound) {
            // Log play attempt only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Attempting to play sound '${soundName}'.`);
            // Reset playback position to the start in case it was played recently.
            sound.currentTime = 0;
            // The play() method returns a Promise which might be rejected
            // if the browser blocks autoplay before user interaction.
            sound.play()
                .catch(error => {
                    // Always log playback errors.
                    console.error(`UI: Error playing sound '${soundName}':`, error);
                    // Common errors include NotAllowedError (user interaction needed)
                    // or NotSupportedError (file format issue).
                });
        } else {
            // Always log warning if sound object wasn't loaded or name is invalid.
            console.warn(`UI: Cannot play sound, Audio object for '${soundName}' not loaded or invalid name.`);
        }
    }
    // ------------------------------------

    // --- Mute State Management ---
    /**
     * Toggles the internal mute state flag (this.isMuted).
     * Calls updateMuteButtonIcon to reflect the change visually.
     */
    toggleMuteState() {
        this.isMuted = !this.isMuted; // Flip the boolean flag
        // Log state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Mute state toggled to: ${this.isMuted}`);
        this.updateMuteButtonIcon(); // Update the button's appearance
    }

    /**
     * Updates the mute button's icon (🔊/🔇) and CSS class based on the current isMuted state.
     * Directly sets the textContent of the icon span.
     */
    updateMuteButtonIcon() {
        if (!this.muteButton) return; // Exit if button element not found

        const iconSpan = this.muteButton.querySelector('span'); // Get the inner span for the icon
        if (!iconSpan) return; // Exit if span not found

        if (this.isMuted) {
            // Muted state: Set muted icon, add 'muted' class for opacity
            iconSpan.textContent = '🔇'; // Set muted icon directly
            this.muteButton.classList.add('muted');
            this.muteButton.title = "Unmute Notifications"; // Update tooltip
        } else {
            // Unmuted state: Set unmuted icon, remove 'muted' class
            iconSpan.textContent = '🔊'; // Set unmuted icon directly
            this.muteButton.classList.remove('muted');
            this.muteButton.title = "Mute Notifications"; // Update tooltip
        }
    }
    // --------------------------------

    // --- Chat Style Management ---
    /**
     * Applies the initial chat styles based on the default values in the settings controls.
     */
    applyInitialChatStyles() {
        const initialFontFamily = this.fontFamilySelect ? this.fontFamilySelect.value : 'sans-serif'; // Fallback
        const initialFontSize = this.fontSizeInput ? this.fontSizeInput.value : '15'; // Default size
        this.applyChatStyles(initialFontFamily, initialFontSize);
    }

    /**
     * Applies the specified font family and size to the message area.
     * @param {string} fontFamily - The CSS font-family value (e.g., "Arial, sans-serif").
     * @param {string|number} fontSize - The font size value (number or string like "16").
     */
    applyChatStyles(fontFamily, fontSize) {
        if (!this.messageArea) return; // Exit if message area not found

        // Log style application only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Applying chat styles - Family: ${fontFamily}, Size: ${fontSize}px`);

        if (fontFamily) {
            this.messageArea.style.fontFamily = fontFamily;
        }
        if (fontSize) {
            // Ensure 'px' unit is added if it's just a number.
            this.messageArea.style.fontSize = `${fontSize}px`;
        }
    }

    /**
     * Gets the currently applied font family and size from the message area.
     * Returns default values if styles are not set or cannot be retrieved.
     * @returns {{fontFamily: string, fontSize: string}} An object with fontFamily and fontSize (number as string).
     */
    getCurrentChatStyles() {
        let fontFamily = 'sans-serif'; // Default fallback
        let fontSize = '15'; // Default fallback size

        if (this.messageArea) {
            const computedStyle = window.getComputedStyle(this.messageArea);
            fontFamily = computedStyle.fontFamily || fontFamily;
            // Parse font size, removing 'px' and converting to number string
            fontSize = parseInt(computedStyle.fontSize, 10).toString() || fontSize;
        }
        // Log retrieval only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Retrieved current chat styles - Family: ${fontFamily}, Size: ${fontSize}`);
        return { fontFamily, fontSize };
    }
    // --------------------------------

    // --- Info Pane Visibility Checks ---

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
                // Use currentTarget to ensure we get the button the listener was attached to
                const peerId = event.currentTarget.dataset.peerid;
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
                // Use currentTarget to ensure we get the button the listener was attached to
                const peerId = event.currentTarget.dataset.peerid;
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
                 // Use currentTarget to ensure we get the button the listener was attached to
                 const peerId = event.currentTarget.dataset.peerid;
                 if (peerId) {
                     handler(peerId); // Call handler with the ID
                 } else {
                     // Always log this error.
                     console.error("Cancel request button clicked, but no peerId found in dataset.");
                 }
            });
        }
    }

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

    /**
     * Binds a handler function to the mute button's click event.
     * @param {function} handler - The function to call when the mute button is clicked.
     */
    bindMuteButton(handler) {
        if (this.muteButton) {
            this.muteButton.addEventListener('click', handler);
        }
    }

    // --- NEW: File Transfer Bindings ---

    /**
     * Binds a handler function to the attach button's click event.
     * @param {function} handler - The function to call when the attach button is clicked.
     */
    bindAttachButton(handler) {
        if (this.attachButton) {
            this.attachButton.addEventListener('click', handler);
        }
    }

    /**
     * Binds a handler function to the hidden file input's 'change' event.
     * @param {function(Event): void} handler - The function to call when a file is selected.
     */
    bindFileInputChange(handler) {
        if (this.fileInput) {
            this.fileInput.addEventListener('change', handler);
        }
    }

    /**
     * Programmatically clicks the hidden file input element.
     */
    triggerFileInputClick() {
        if (this.fileInput) {
            // Log action only if DEBUG is enabled.
            if (config.DEBUG) console.log("UI: Triggering file input click.");
            this.fileInput.click();
        }
    }

    /**
     * Helper function to bind handlers for dynamically added file transfer buttons.
     * Uses event delegation on the message area.
     * @param {string} buttonClass - The CSS class of the button to target (e.g., '.file-accept-btn').
     * @param {function(string): void} handler - The function to call, passing the transferId.
     */
    _bindDynamicFileButton(buttonClass, handler) {
        if (!this.messageArea) return;
        this.messageArea.addEventListener('click', (event) => {
            const button = event.target.closest(buttonClass);
            if (button) {
                const messageDiv = button.closest('.message-file-transfer');
                const transferId = messageDiv?.dataset?.transferId;
                if (transferId) {
                    // Log dynamic button click only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`UI: Dynamic button ${buttonClass} clicked for transfer ${transferId}`);
                    handler(transferId);
                } else {
                    // Always log this error.
                    console.error(`UI: Clicked ${buttonClass} but could not find transferId on parent.`);
                }
            }
        });
    }

    /** Binds a handler for the dynamic Accept file button. */
    bindFileAccept(handler) { this._bindDynamicFileButton('.file-accept-btn', handler); }
    /** Binds a handler for the dynamic Reject file button. */
    bindFileReject(handler) { this._bindDynamicFileButton('.file-reject-btn', handler); }
    /** Binds a handler for the dynamic Cancel file button. */
    bindFileCancel(handler) { this._bindDynamicFileButton('.file-cancel-btn', handler); }
    /** Binds a handler for the dynamic Download file link/button. */
    bindFileDownload(handler) {
        // Note: We bind to the link itself, but the handler might just log or revoke the URL.
        // The actual download is handled by the browser via the href/download attributes.
        this._bindDynamicFileButton('.file-download-link', handler);
    }
    // ------------------------------------

    // --- Settings Bindings ---
    /**
     * Binds a handler function to the settings button's click event.
     * @param {function} handler - The function to call when the settings button is clicked.
     */
    bindSettingsButton(handler) {
        if (this.settingsButton) {
            this.settingsButton.addEventListener('click', handler);
        }
    }

    /**
     * Binds a handler function to the close settings button's click event.
     * @param {function} handler - The function to call when the close settings button is clicked.
     */
    bindCloseSettingsButton(handler) {
        if (this.closeSettingsButton) {
            this.closeSettingsButton.addEventListener('click', handler);
        }
    }

    /**
     * Binds a handler function to the font family select dropdown's 'change' event.
     * @param {function} handler - The function to call when the selection changes.
     */
    bindFontFamilyChange(handler) {
        if (this.fontFamilySelect) {
            this.fontFamilySelect.addEventListener('change', handler);
        }
    }

    /**
     * Binds a handler function to the font size input's 'input' event.
     * @param {function} handler - The function to call when the input value changes.
     */
    bindFontSizeChange(handler) {
        if (this.fontSizeInput) {
            // Use 'input' for immediate feedback as the user changes the value
            this.fontSizeInput.addEventListener('input', handler);
        }
    }
    // -----------------------------

    // --- Utility ---
    /**
     * Validates that all expected DOM element references were successfully found
     * and that the sound objects were created.
     * Logs warnings for any missing elements or failed sound loads.
     * @returns {boolean} True if all elements were found and sounds loaded, false otherwise.
     */
    validateElements() {
        const domElements = [
            // List all DOM element properties stored in the constructor
            this.statusElement, this.registrationArea, this.identifierInput, this.registerButton,
            this.appContainer, this.sidebar, this.myIdentifierDisplay, this.initiationArea,
            this.peerIdInput, this.startChatButton,
            this.sidebarControls, this.muteButton, this.settingsButton,
            this.sessionListContainer, this.sessionList,
            this.mainContent, this.overlay,
            this.welcomeMessage, this.myIdentifierWelcome,
            this.appVersionDisplay, // Added version display
            this.incomingRequestArea, this.incomingRequestText,
            this.acceptButton, this.denyButton,
            this.infoArea, this.infoMessage, this.closeInfoButton, this.retryRequestButton,
            this.waitingResponseArea, this.waitingResponseText, this.cancelRequestButton,
            this.activeChatArea, this.chatHeader,
            this.peerIdentifierDisplay, this.messageArea,
            this.typingIndicatorArea, this.typingIndicatorText,
            this.messageInputArea,
            this.attachButton, // Added attach button
            this.messageInput,
            this.sendButton, this.disconnectButton,
            // Settings Pane Elements
            this.settingsPane, this.fontFamilySelect, this.fontSizeInput, this.closeSettingsButton,
            // File Input
            this.fileInput // Added file input
        ];
        let allFound = true;
        // Validate DOM elements
        domElements.forEach((el) => {
            const keyName = Object.keys(this).find(key => this[key] === el);
            if (!el) {
                console.warn(`UIController: DOM Element for property '${keyName || 'UNKNOWN'}' not found! Check HTML IDs.`);
                allFound = false;
            }
        });
        // Validate Sound objects
        for (const soundName in this.sounds) {
            if (this.sounds[soundName] === null) {
                console.warn(`UIController: Audio object for sound '${soundName}' failed to load! Check path/file.`);
                allFound = false;
            }
        }
        return allFound;
    }
}
