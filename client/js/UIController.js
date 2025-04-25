// client/js/UIController.js

/**
 * Manages all interactions with the HTML Document Object Model (DOM).
 * This class is responsible for getting references to UI elements,
 * showing/hiding different sections of the application, updating text content,
 * enabling/disabling controls, adding/removing items from lists,
 * displaying messages (including file transfers, actions, and clickable links), playing sounds, managing settings UI,
 * handling the emoji picker, and binding event listeners to UI elements.
 * It acts as the presentation layer, controlled by the SessionManager.
 */
class UIController {
    /**
     * Initializes the UIController by getting references to all necessary DOM elements,
     * preloading notification and UI sounds, setting the initial mute state,
     * applying initial chat styles, populating the emoji picker, and setting the initial UI state.
     * Validates that all expected elements are found.
     */
    constructor() {
        // --- Get References to DOM Elements ---
        // Store references to frequently accessed DOM elements for efficiency and clarity.
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
        this.myIdentifierDisplay = document.getElementById('my-identifier'); // User's ID display in sidebar header.
        this.initiationArea = document.getElementById('initiation-area'); // Container for starting new chats.
        this.peerIdInput = document.getElementById('peer-id-input'); // Input field for peer's ID.
        this.startChatButton = document.getElementById('start-chat-button'); // Button to initiate chat.
        this.sidebarControls = document.getElementById('sidebar-controls'); // Container for sidebar buttons (mute, settings).
        this.muteButton = document.getElementById('mute-button'); // Mute/unmute button.
        this.settingsButton = document.getElementById('settings-button'); // Settings button.
        this.sessionListContainer = document.getElementById('session-list-container'); // Container for the session list.
        this.sessionList = document.getElementById('session-list'); // The <ul> element holding session list items.

        // Main Content Area Panes (different views within the main area)
        this.mainContent = document.getElementById('main-content');
        this.overlay = document.getElementById('overlay'); // Semi-transparent overlay for modal-like panes.
        this.welcomeMessage = document.getElementById('welcome-message'); // Default welcome view pane.
        this.myIdentifierWelcome = document.getElementById('my-identifier-welcome'); // User's ID display within the welcome message.
        this.appVersionDisplay = document.getElementById('app-version-display'); // Element to display app version in welcome message.
        this.incomingRequestArea = document.getElementById('incoming-request-area'); // Pane for incoming chat requests.
        this.incomingRequestText = document.getElementById('incoming-request-text'); // Text element within incoming request pane.
        this.acceptButton = document.getElementById('accept-button'); // Accept button for incoming requests.
        this.denyButton = document.getElementById('deny-button'); // Deny button for incoming requests.
        this.infoArea = document.getElementById('info-area'); // Pane for showing info/errors (denial, timeout, etc.).
        this.infoMessage = document.getElementById('info-message'); // Text element within the info pane.
        this.closeInfoButton = document.getElementById('close-info-button'); // Close button within the info pane.
        this.retryRequestButton = document.getElementById('retry-request-button'); // Retry button within the info pane (shown conditionally).
        this.waitingResponseArea = document.getElementById('waiting-response-area'); // Pane shown while waiting for peer response after initiating.
        this.waitingResponseText = document.getElementById('waiting-response-text'); // Text element within the waiting pane.
        this.cancelRequestButton = document.getElementById('cancel-request-button'); // Cancel button within the waiting pane.
        this.activeChatArea = document.getElementById('active-chat-area'); // Pane for an active chat session.
        this.chatHeader = document.getElementById('chat-header'); // Header within the active chat pane.
        this.peerIdentifierDisplay = document.getElementById('peer-identifier'); // Peer's ID display in the chat header.
        this.messageArea = document.getElementById('message-area'); // Scrollable area where messages are displayed.

        // Typing Indicator Elements
        this.typingIndicatorArea = document.getElementById('typing-indicator-area'); // Container below messages for typing indicator.
        this.typingIndicatorText = document.getElementById('typing-indicator-text'); // The text span showing "Peer is typing...".

        // Message Input Area Elements
        this.messageInputArea = document.getElementById('message-input-area'); // Container for input and associated buttons.
        this.attachButton = document.getElementById('attach-button'); // Attach file button.
        this.emojiPickerButton = document.getElementById('emoji-picker-button'); // Emoji picker button.
        this.messageInput = document.getElementById('message-input'); // The text input field for typing messages.
        this.sendButton = document.getElementById('send-button'); // Send message button.
        this.disconnectButton = document.getElementById('disconnect-button'); // Disconnect/End Session button in chat header.

        // Settings Pane Elements
        this.settingsPane = document.getElementById('settings-pane'); // The settings pane itself.
        this.fontFamilySelect = document.getElementById('font-family-select'); // Font family dropdown.
        this.fontSizeInput = document.getElementById('font-size-input'); // Font size number input.
        this.closeSettingsButton = document.getElementById('close-settings-button'); // Close button for settings pane.

        // File Input Element (Hidden)
        this.fileInput = document.getElementById('file-input'); // Hidden file input triggered by the attach button.

        // Emoji Picker Panel
        this.emojiPickerPanel = document.getElementById('emoji-picker-panel'); // The panel displaying emojis.

        // --- Audio Management ---
        // Object to hold preloaded HTML Audio elements, keyed by sound name.
        this.sounds = {};
        // List of sound names and their corresponding file paths.
        const soundFiles = {
            'notification': 'audio/notification.mp3', // Incoming message/action
            'begin': 'audio/begin.mp3',             // Session successfully established
            'end': 'audio/end.mp3',                 // Session ended/denied/cancelled
            'error': 'audio/error.mp3',             // General error, timeout, failed action
            'registered': 'audio/registered.mp3',   // Successful registration
            'receiverequest': 'audio/receiverequest.mp3', // Incoming session request
            'sendrequest': 'audio/sendrequest.mp3',   // Outgoing session request sent
            'file_request': 'audio/receiverequest.mp3', // Incoming file request (reuse sound)
            'file_complete': 'audio/begin.mp3',        // File transfer successfully completed (reuse sound)
            'file_error': 'audio/error.mp3'            // File transfer error (reuse sound)
        };

        // Preload each sound file by creating an Audio object.
        for (const name in soundFiles) {
            try {
                const audio = new Audio(soundFiles[name]);
                audio.preload = 'auto'; // Suggest the browser preload the audio data.
                this.sounds[name] = audio; // Store the Audio object reference.
                // Log preloading attempt only if DEBUG is enabled.
                if (config.DEBUG) console.log(`UI: Preloading sound '${name}' from '${soundFiles[name]}'.`);
            } catch (error) {
                // Always log errors related to audio object creation.
                console.error(`UI: Failed to create Audio object for sound '${name}':`, error);
                this.sounds[name] = null; // Set to null if creation failed to prevent errors later.
            }
        }

        // --- Mute State ---
        // Tracks whether notification sounds should be played. Controlled by the mute button.
        this.isMuted = false; // Start unmuted by default.
        // -----------------------

        // --- Object URL Tracking ---
        // Map to store generated Blob Object URLs for completed file downloads, keyed by transferId.
        // Needed so they can be revoked later using URL.revokeObjectURL() to free browser memory.
        this.objectUrls = new Map();
        // ---------------------------

        // --- Emoji List ---
        // Defines the list of emojis to display in the picker panel.
        this.emojiList = [
            '😊', '😂', '😍', '🤔', '😎', '😭', '👍', '👎', '❤️', '💔', '🎉', '🔥', '💯', '✅', '❌',
            '👋', '🙏', '👀', '✨', '🚀', '💡', '⚙️', '📎', '🔗', '🔒', '🔓', '🔔', '🔇', '🔊', '💬',
            '😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😇', '😉', '😌', '😋', '😛', '😜', '🤪', '🤨',
            '🧐', '🤓', '🥳', '🥴', '🥺', '😢', '😠', '😡', '🤯', '😳', '😱', '😨', '😰', '😥', '😓',
            '🤗', '🤭', '🤫', '🤥', '😶', '😐', '😑', '😬', '🙄', '😯', '😦', '😧', '😮', '😲', '😴',
            '🤤', '😪', '😵', '🤐', '🤢', '🤮', '🤧', '😷', '🤒', '🤕', '🤑', '🤠', '😈', '👿', '👹',
            '👺', '🤡', '💩', '👻', '💀', '👽', '👾', '🤖', '🎃', '😺', '😸', '😹', '😻', '😼', '😽',
            '🙀', '😿', '😾', '🙈', '🙉', '🙊', '💋', '💌', '💘', '💝', '💖', '💗', '💓', '💞', '💕',
            '💟', '❣️', '💤', '💢', '💣', '💥', '💦', '💨', '💫', '💬', '💭', '👁️‍🗨️', // Add more emojis as desired
        ];
        // ------------------

        // --- Initial UI State ---
        // Set the initial visibility of UI sections (show registration first).
        this.showRegistration();
        // Set the initial mute button icon based on the default state (unmuted).
        this.updateMuteButtonIcon();
        // Apply initial chat message area styles based on default values in the settings controls.
        this.applyInitialChatStyles();
        // Populate the emoji picker panel with clickable emoji spans.
        this._populateEmojiPicker();

        // Log initialization confirmation.
        console.log('UIController initialized.');
        // Validate that all expected DOM elements were found. Log warnings if not.
        if (!this.validateElements()) {
             // Always log validation errors.
             console.error("!!! UIController failed validation - Some elements not found or sounds failed to load! Check HTML IDs and audio paths.");
        }
    }

    /**
     * Updates the text content of the status bar element at the bottom of the page.
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
     * Hides all major panes within the main content area (welcome, chat, info, etc.)
     * AND the overlay element. Used as a reset before showing a specific pane.
     * Also ensures typing indicator and emoji picker are hidden.
     */
    hideAllMainPanes() {
        if (this.welcomeMessage) this.welcomeMessage.style.display = 'none';
        if (this.incomingRequestArea) this.incomingRequestArea.style.display = 'none';
        if (this.activeChatArea) this.activeChatArea.style.display = 'none';
        if (this.infoArea) this.infoArea.style.display = 'none';
        if (this.waitingResponseArea) this.waitingResponseArea.style.display = 'none';
        if (this.settingsPane) this.settingsPane.style.display = 'none'; // Hide settings pane too.
        if (this.overlay) this.overlay.style.display = 'none'; // Hide overlay.
        // Ensure the typing indicator is hidden when switching main panes.
        this.hideTypingIndicator();
        // Hide emoji picker when switching main panes.
        if (this.emojiPickerPanel) this.emojiPickerPanel.style.display = 'none';
    }

    /**
     * Shows the registration area and hides the main application container.
     * Enables registration controls and focuses the identifier input field.
     */
    showRegistration() {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Showing Registration");
        if (this.registrationArea) this.registrationArea.style.display = 'flex'; // Use flex for vertical/horizontal centering.
        if (this.appContainer) this.appContainer.style.display = 'none'; // Hide the main app (sidebar + content).
        this.setRegistrationControlsEnabled(true); // Enable input/button.
        this.setInitiationControlsEnabled(false); // Disable chat initiation controls.
        // Focus input field slightly delayed to ensure visibility and readiness.
        if (this.identifierInput) { setTimeout(() => this.identifierInput.focus(), 0); }
    }

    /**
     * Hides the registration area and shows the main application container (sidebar + main content).
     * Displays the user's registered ID in the sidebar and welcome message.
     * Sets the application version display in the welcome message.
     * Shows the default welcome message pane initially.
     * @param {string} myId - The user's registered identifier.
     */
    showMainApp(myId) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Showing Main App");
        if (this.registrationArea) this.registrationArea.style.display = 'none'; // Hide registration.
        if (this.appContainer) this.appContainer.style.display = 'flex'; // Show the main app layout (sidebar + content).
        if (this.myIdentifierDisplay) this.myIdentifierDisplay.textContent = myId; // Show ID in sidebar header.
        if (this.myIdentifierWelcome) this.myIdentifierWelcome.textContent = myId; // Show ID in welcome message.
        // Set Version Display in the welcome message pane.
        if (this.appVersionDisplay && config && config.APP_VERSION) {
            this.appVersionDisplay.textContent = `Version: ${config.APP_VERSION}`;
        } else if (this.appVersionDisplay) {
            this.appVersionDisplay.textContent = 'Version: Unknown'; // Fallback if config is missing.
        }
        this.showWelcomeMessage(); // Show the default welcome pane within the main content area.
        this.setRegistrationControlsEnabled(false); // Disable registration controls as they are hidden.
    }


    /**
     * Shows the welcome message pane in the main content area.
     * Hides other panes and ensures appropriate controls are enabled/disabled for this state.
     */
    showWelcomeMessage() {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Showing Welcome Message Pane");
        this.hideAllMainPanes(); // Hide other panes (including overlay).
        if (this.welcomeMessage) this.welcomeMessage.style.display = 'block'; // Show welcome pane.
        this.setInitiationControlsEnabled(true); // Allow starting new chats from sidebar.
        this.setChatControlsEnabled(false); // Disable active chat controls.
        this.setIncomingRequestControlsEnabled(false); // Disable accept/deny buttons.
        this.setInfoControlsEnabled(false); // Disable info pane controls.
        this.setWaitingControlsEnabled(false); // Disable waiting pane controls.
        this.focusPeerIdInput(); // Focus the input for starting a new chat.
    }

    /**
     * Shows the incoming chat request pane with the overlay effect.
     * Displays the sender's ID and enables Accept/Deny buttons.
     * @param {string} senderId - The identifier of the peer sending the request.
     */
    showIncomingRequest(senderId) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Showing Incoming Request Pane for ${senderId}`);
        this.hideAllMainPanes(); // Hide other panes first.
        if (this.welcomeMessage) this.welcomeMessage.style.display = 'block'; // Ensure welcome is visible behind overlay.
        if (this.overlay) this.overlay.style.display = 'block'; // Show the overlay.
        if (this.incomingRequestArea) this.incomingRequestArea.style.display = 'block'; // Show the request pane on top.
        if (this.incomingRequestText) this.incomingRequestText.textContent = `Incoming chat request from ${senderId}. Accept or Deny?`;
        this.setIncomingRequestControlsEnabled(true); // Enable accept/deny buttons.
        // Disable other potentially active controls.
        this.setChatControlsEnabled(false);
        this.setInfoControlsEnabled(false);
        this.setWaitingControlsEnabled(false);
        this.setInitiationControlsEnabled(true); // Keep sidebar initiation enabled.
    }

    /**
     * Shows the information pane (for denials, timeouts, errors) with the overlay effect.
     * Displays the provided message and conditionally shows the "Retry" button.
     * @param {string} peerId - The peer ID this information relates to.
     * @param {string} message - The message to display in the pane.
     * @param {boolean} showRetry - Whether to show the "Retry" button (e.g., for request timeouts).
     */
    showInfoMessage(peerId, message, showRetry) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Showing Info Pane for peer ${peerId}. Retry: ${showRetry}`);
        this.hideAllMainPanes(); // Hide other panes first.
        if (this.welcomeMessage) this.welcomeMessage.style.display = 'block'; // Ensure welcome is visible behind overlay.
        if (this.overlay) this.overlay.style.display = 'block'; // Show the overlay.
        if (this.infoArea) this.infoArea.style.display = 'block'; // Show the info pane on top.
        if (this.infoMessage) this.infoMessage.textContent = message || `An issue occurred regarding ${peerId}.`;
        // Store peerId in button datasets for event handlers to retrieve.
        if (this.closeInfoButton) this.closeInfoButton.dataset.peerid = peerId;
        if (this.retryRequestButton) {
            this.retryRequestButton.dataset.peerid = peerId;
            // Show or hide the retry button based on the flag.
            this.retryRequestButton.style.display = showRetry ? 'inline-block' : 'none';
        }
        this.setInfoControlsEnabled(true); // Enable close/retry buttons.
        // Disable other potentially active controls.
        this.setChatControlsEnabled(false);
        this.setIncomingRequestControlsEnabled(false);
        this.setWaitingControlsEnabled(false);
        this.setInitiationControlsEnabled(true); // Keep sidebar initiation enabled.
        // Focus the appropriate button for user convenience.
        const buttonToFocus = showRetry ? this.retryRequestButton : this.closeInfoButton;
        if (buttonToFocus) { setTimeout(() => buttonToFocus.focus(), 0); }
    }

    /**
     * Shows the "waiting for response" pane after initiating a chat, with the overlay effect.
     * Displays the target peer's ID and enables the "Cancel Request" button.
     * @param {string} peerId - The peer ID we are waiting for a response from.
     */
    showWaitingForResponse(peerId) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Showing Waiting for Response Pane for ${peerId}`);
        this.hideAllMainPanes(); // Hide others first.
        if (this.welcomeMessage) this.welcomeMessage.style.display = 'block'; // Ensure welcome is visible behind overlay.
        if (this.overlay) this.overlay.style.display = 'block'; // Show the overlay.
        if (this.waitingResponseArea) this.waitingResponseArea.style.display = 'block'; // Show the waiting pane on top.
        if (this.waitingResponseText) this.waitingResponseText.textContent = `Waiting for ${peerId} to respond...`;
        // Store peerId in button dataset for the event handler.
        if (this.cancelRequestButton) this.cancelRequestButton.dataset.peerid = peerId;
        this.setWaitingControlsEnabled(true); // Enable the cancel button.
        // Disable other potentially active controls.
        this.setChatControlsEnabled(false);
        this.setIncomingRequestControlsEnabled(false);
        this.setInfoControlsEnabled(false);
        this.setInitiationControlsEnabled(true); // Keep sidebar initiation enabled.
        // Focus the cancel button.
        if (this.cancelRequestButton) { setTimeout(() => this.cancelRequestButton.focus(), 0); }
    }

    /**
     * Shows the active chat pane for a specific peer.
     * Clears previous messages from the message area, displays the peer's ID in the header,
     * enables chat controls, and focuses the message input field.
     * (Overlay is not used for the active chat pane).
     * @param {string} peerId - The identifier of the peer for the active chat session.
     */
    showActiveChat(peerId) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Showing Active Chat Pane for ${peerId}`);
        this.hideAllMainPanes(); // Hide others (including overlay).
        if (this.activeChatArea) this.activeChatArea.style.display = 'flex'; // Show chat area (using flex for layout).
        if (this.peerIdentifierDisplay) this.peerIdentifierDisplay.textContent = peerId; // Set peer ID in header.
        this.clearMessageInput(); // Clear any old text in input field.
        this.clearMessages(); // Clear messages from any previously viewed chat.
        this.setActiveSessionInList(peerId); // Highlight this session in the sidebar list.
        this.setChatControlsEnabled(true); // Enable message input, send, disconnect, attach, emoji buttons.
        // Disable other potentially active controls.
        this.setIncomingRequestControlsEnabled(false);
        this.setInfoControlsEnabled(false);
        this.setWaitingControlsEnabled(false);
        this.setInitiationControlsEnabled(true); // Keep sidebar initiation enabled.
        this.focusMessageInput(); // Focus the message input field for immediate typing.
    }

    /**
     * Shows the default view when registered but no specific session is active
     * (i.e., the welcome message pane). Ensures the main app container is visible.
     * Clears any active session highlighting in the sidebar list.
     * @param {string} myId - The user's registered identifier (needed if showing main app for the first time).
     */
    showDefaultRegisteredView(myId) {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Showing Default Registered View (Welcome Pane)");
        // Ensure the main app container is visible if it wasn't already (e.g., after registration).
        if (this.appContainer && this.appContainer.style.display === 'none') {
            this.showMainApp(myId); // This also calls showWelcomeMessage internally.
        } else {
            // If app container is already visible, just show the welcome pane within it.
            this.showWelcomeMessage();
        }
        this.clearActiveSessionInList(); // No session is active in the list in this default view.
        // Disable controls specific to other panes.
        this.setChatControlsEnabled(false);
        this.setIncomingRequestControlsEnabled(false);
        this.setInfoControlsEnabled(false);
        this.setWaitingControlsEnabled(false);
    }

    // --- Settings Pane Management ---
    /**
     * Shows the settings pane with the overlay effect.
     * Populates the settings controls (font family, font size) with current values.
     */
    showSettingsPane() {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Showing Settings Pane");
        this.hideAllMainPanes(); // Hide other panes first.
        if (this.welcomeMessage) this.welcomeMessage.style.display = 'block'; // Ensure welcome is visible behind overlay.
        if (this.overlay) this.overlay.style.display = 'block'; // Show the overlay.
        if (this.settingsPane) this.settingsPane.style.display = 'block'; // Show the settings pane on top.

        // Populate settings controls with current chat style values.
        const currentStyles = this.getCurrentChatStyles();
        if (this.fontFamilySelect) this.fontFamilySelect.value = currentStyles.fontFamily;
        if (this.fontSizeInput) this.fontSizeInput.value = currentStyles.fontSize;

        // Disable other potentially active controls.
        this.setChatControlsEnabled(false);
        this.setIncomingRequestControlsEnabled(false);
        this.setInfoControlsEnabled(false);
        this.setWaitingControlsEnabled(false);
        this.setInitiationControlsEnabled(true); // Keep sidebar initiation enabled.
        // Focus the close button within the settings pane.
        if (this.closeSettingsButton) { setTimeout(() => this.closeSettingsButton.focus(), 0); }
    }

    /**
     * Hides the settings pane and the overlay.
     * Restores the view to the previously active chat session or the default welcome view.
     */
    hideSettingsPane() {
        // Log UI state change only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Hiding Settings Pane");
        if (this.settingsPane) this.settingsPane.style.display = 'none';
        if (this.overlay) this.overlay.style.display = 'none';
        // Decide which view to show after closing settings.
        if (this.displayedPeerId) {
            // If a chat session was active before opening settings, switch back to it.
            this.switchToSessionView(this.displayedPeerId);
        } else {
            // Otherwise, show the default welcome view.
            this.showDefaultRegisteredView(this.identifier); // Assumes identifier is available.
        }
    }
    // -----------------------------------

    // --- Focus Helper Methods ---
    /** Sets focus to the peer ID input field in the sidebar if available and enabled. */
    focusPeerIdInput() {
        if (this.peerIdInput && !this.peerIdInput.disabled) {
            // Use setTimeout to ensure focus occurs after potential layout changes or element visibility updates.
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

    /** Sets focus to the message input field in the active chat area if available and enabled. */
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
     * Internal helper to set the enabled/disabled state and optional loading text of a button.
     * @param {HTMLButtonElement} button - The button element to modify.
     * @param {boolean} enabled - True to enable the button, false to disable it.
     * @param {boolean} [loadingState=false] - True to show loading text and disable, false otherwise.
     * @param {string} [loadingText="Working..."] - Text to display on the button when in loading state.
     * @private
     */
    _setButtonState(button, enabled, loadingState = false, loadingText = "Working...") {
        if (!button) return; // Ignore if button element doesn't exist.
        button.disabled = !enabled || loadingState; // Disable if not enabled OR if loading.
        if (loadingState && enabled === false) { // Show loading text only when explicitly disabled due to loading.
            // Store original text if not already stored (to restore later).
            if (!button.dataset.originalText) { button.dataset.originalText = button.textContent; }
            button.textContent = loadingText; // Set the button text to the loading message.
        } else {
            // Restore original text if it was stored.
            if (button.dataset.originalText) {
                button.textContent = button.dataset.originalText;
                delete button.dataset.originalText; // Remove stored text attribute.
            }
        }
    }

    /** Enables/disables registration input and button, optionally showing loading state on the button. */
    setRegistrationControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Registration Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        if (this.identifierInput) this.identifierInput.disabled = !enabled || loadingState; // Disable input if loading.
        this._setButtonState(this.registerButton, enabled, loadingState, "Registering...");
    }

    /** Enables/disables chat initiation input field and button, optionally showing loading state on the button. */
    setInitiationControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Initiation Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        if (this.peerIdInput) { this.peerIdInput.disabled = !enabled || loadingState; } // Disable input if loading.
        this._setButtonState(this.startChatButton, enabled, loadingState, "Starting...");
    }

    /** Enables/disables incoming request (Accept/Deny) buttons, optionally showing loading state. */
    setIncomingRequestControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Incoming Request Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        this._setButtonState(this.acceptButton, enabled, loadingState, "Accepting...");
        this._setButtonState(this.denyButton, enabled, loadingState, "Denying...");
    }

    /** Enables/disables active chat controls (input, send, disconnect, attach, emoji), optionally showing loading state on buttons. */
    setChatControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Chat Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        if (this.messageInput) this.messageInput.disabled = !enabled || loadingState; // Disable input if loading.
        this._setButtonState(this.sendButton, enabled, loadingState, "Sending...");
        this._setButtonState(this.disconnectButton, enabled, loadingState, "Disconnecting...");
        // Also handle the attach and emoji buttons.
        if (this.attachButton) this.attachButton.disabled = !enabled || loadingState;
        if (this.emojiPickerButton) this.emojiPickerButton.disabled = !enabled || loadingState;
    }


    /** Enables/disables info pane controls (Close, Retry), optionally showing loading state on buttons. */
    setInfoControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Info Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        this._setButtonState(this.closeInfoButton, enabled, loadingState, "Closing...");
        // Handle retry button only if it's currently visible.
        if (this.retryRequestButton && this.retryRequestButton.style.display !== 'none') {
            this._setButtonState(this.retryRequestButton, enabled, loadingState, "Retrying...");
        } else if (this.retryRequestButton) {
            // Ensure retry button is disabled if hidden or parent controls are disabled.
             this.retryRequestButton.disabled = !enabled;
        }
    }

    /** Enables/disables waiting pane controls (Cancel button), optionally showing loading state. */
    setWaitingControlsEnabled(enabled, loadingState = false) {
        // Log control state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting Waiting Controls Enabled: ${enabled}, Loading: ${loadingState}`);
        this._setButtonState(this.cancelRequestButton, enabled, loadingState, "Cancelling...");
    }
    // -----------------------------------------

    // --- Session List Management ---

    /**
     * Adds a new session entry (list item) to the sidebar list if it doesn't already exist.
     * Includes the peer ID text and a hidden notification dot.
     * @param {string} peerId - The identifier of the peer for the new session list item.
     */
    addSessionToList(peerId) {
        // Check if list element exists and if an item for this peer already exists.
        if (!this.sessionList || this.sessionList.querySelector(`li[data-peerid="${peerId}"]`)) {
            return; // Do nothing if list missing or item already present.
        }
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Adding session ${peerId} to list.`);
        const listItem = document.createElement('li');
        listItem.textContent = peerId; // Set text content to the peer ID.
        listItem.dataset.peerid = peerId; // Store peer ID in data attribute for easy retrieval in event handlers.
        // Create and append the notification dot span (initially hidden via CSS).
        const dot = document.createElement('span');
        dot.className = 'notification-dot';
        listItem.appendChild(dot);
        this.sessionList.appendChild(listItem); // Add the new list item to the <ul>.
    }

    /**
     * Removes a session entry (list item) from the sidebar list based on peer ID.
     * @param {string} peerId - The identifier of the peer whose list item should be removed.
     */
    removeSessionFromList(peerId) {
        const listItem = this.sessionList ? this.sessionList.querySelector(`li[data-peerid="${peerId}"]`) : null;
        if (listItem) {
            // Log action only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Removing session ${peerId} from list.`);
            listItem.remove(); // Remove the <li> element from the DOM.
        } else {
            // Log missing item only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Session ${peerId} not found in list for removal.`);
        }
    }

    /**
     * Highlights a specific session in the sidebar list as the currently active one.
     * Removes highlighting from any previously active item and ensures the unread indicator is cleared for the newly active item.
     * @param {string} peerId - The identifier of the peer whose list item should be marked active.
     */
    setActiveSessionInList(peerId) {
        if (!this.sessionList) return;
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Setting active session in list: ${peerId}`);
        this.clearActiveSessionInList(); // Remove 'active-session' class from all other items first.
        const listItem = this.sessionList.querySelector(`li[data-peerid="${peerId}"]`);
        if (listItem) {
            listItem.classList.add('active-session'); // Add the active class for styling.
            listItem.classList.remove('has-unread'); // Ensure unread indicator is off for the active session.
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
     * Will not show the dot if the session is currently the active one (highlighted).
     * @param {string} peerId - The identifier of the peer whose indicator to update.
     * @param {boolean} hasUnread - True to show the dot (add 'has-unread' class), false to hide it (remove class).
     */
    setUnreadIndicator(peerId, hasUnread) {
        if (!this.sessionList) return;
        const listItem = this.sessionList.querySelector(`li[data-peerid="${peerId}"]`);
        if (listItem) {
            if (hasUnread) {
                // Only add 'has-unread' class if the item isn't already the active one.
                if (!listItem.classList.contains('active-session')) {
                    // Log action only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`UI: Setting unread indicator for ${peerId}`);
                    listItem.classList.add('has-unread');
                }
            } else {
                // Always remove 'has-unread' class when requested.
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
     * Includes timestamp and sender information, formatted in an IRC-like style.
     * Automatically scrolls to the bottom if the user was already scrolled down.
     * Calls a helper method to linkify URLs within the message text for 'peer' and 'own' types.
     *
     * @param {string} sender - Identifier of the sender ('System', own ID, or peer ID).
     * @param {string} text - The message content.
     * @param {string} [type='peer'] - Type of message ('peer', 'own', 'system'). Determines styling and sender format.
     */
    addMessage(sender, text, type = 'peer') {
        if (!this.messageArea) return; // Ignore if message area element doesn't exist.

        // Check if user is scrolled near the bottom before adding the new message.
        const wasScrolledToBottom = this.messageArea.scrollHeight - this.messageArea.clientHeight <= this.messageArea.scrollTop + 1;

        // Create the main container div for the message line.
        const messageDiv = document.createElement('div');
        messageDiv.classList.add(`message-${type}`); // Add class based on type for potential styling.

        // Create and format the timestamp span.
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'message-timestamp';
        const now = new Date();
        // Format date and time (e.g., MM/DD/YYYY - HH:MM:SS). Adjust locale/options as needed.
        const dateString = now.toLocaleDateString([], { month: '2-digit', day: '2-digit', year: 'numeric' });
        const timeString = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        timestampSpan.textContent = `[${dateString} - ${timeString}]`;

        // Create and format the sender span.
        const senderSpan = document.createElement('span');
        senderSpan.className = 'message-sender';
        let senderDisplay = sender; // Use the provided sender ID by default.
        // Add specific sender class for styling and adjust display format.
        if (type === 'own') {
            senderSpan.classList.add('sender-own');
            senderDisplay = `<${senderDisplay}>`; // Format as <Sender>
        } else if (type === 'system') {
            senderDisplay = 'System:'; // Display 'System:' instead of ID.
            senderSpan.classList.add('sender-system');
        } else { // 'peer'
            senderSpan.classList.add('sender-peer');
            senderDisplay = `<${senderDisplay}>`; // Format as <Sender>
        }
        senderSpan.textContent = senderDisplay;

        // Create the message text span.
        const textSpan = document.createElement('span');
        textSpan.className = 'message-text';
        // Create a text node with the message content to allow linkification. Add leading space for separation.
        const textNode = document.createTextNode(` ${text}`);
        textSpan.appendChild(textNode);

        // Linkify URLs within the message text for 'peer' and 'own' message types only.
        if (type === 'peer' || type === 'own') {
            this._linkifyTextNode(textNode); // Pass the text node to the helper.
        }

        // Append timestamp, sender, and text spans to the message container div.
        messageDiv.appendChild(timestampSpan);
        messageDiv.appendChild(senderSpan);
        // Only add text span if it's not a system message without text (though usually they have text).
        if (type !== 'system' || text) {
            messageDiv.appendChild(textSpan);
        }

        // Add the complete message div to the message area.
        this.messageArea.appendChild(messageDiv);

        // Auto-scroll to the bottom if the user was already scrolled near the bottom before the message was added.
        if (wasScrolledToBottom) {
            this.messageArea.scrollTop = this.messageArea.scrollHeight;
        }
    }

    /** Convenience method to add a system message using the addMessage structure. */
    addSystemMessage(text) { this.addMessage('System', text, 'system'); }

    /**
     * Adds a '/me' action message to the message display area.
     * Formats as '* Sender actionText' with a timestamp. Scrolls to bottom.
     * Does NOT linkify URLs within action messages.
     *
     * @param {string} sender - Identifier of the user performing the action.
     * @param {string} actionText - The text of the action (what follows /me in the command).
     */
    addMeActionMessage(sender, actionText) {
        if (!this.messageArea) return; // Ignore if message area doesn't exist.

        // Check scroll position before adding.
        const wasScrolledToBottom = this.messageArea.scrollHeight - this.messageArea.clientHeight <= this.messageArea.scrollTop + 1;

        // Create message elements.
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message-me-action'); // Use a specific class for styling action messages.

        // Timestamp.
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'message-timestamp';
        const now = new Date();
        const dateString = now.toLocaleDateString([], { month: '2-digit', day: '2-digit', year: 'numeric' });
        const timeString = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        timestampSpan.textContent = `[${dateString} - ${timeString}]`;

        // Action Text (formatted).
        const actionSpan = document.createElement('span');
        actionSpan.className = 'action-text'; // Use a class for the text part.
        // Use textContent to prevent potential HTML injection from actionText. Format: * Sender actionText
        actionSpan.textContent = ` * ${sender} ${actionText}`;

        // Append elements to message container.
        messageDiv.appendChild(timestampSpan);
        messageDiv.appendChild(actionSpan);

        // Add the complete message div to the message area.
        this.messageArea.appendChild(messageDiv);

        // Auto-scroll if needed.
        if (wasScrolledToBottom) {
            this.messageArea.scrollTop = this.messageArea.scrollHeight;
        }
    }

    /**
     * Adds a command error message to the message display area.
     * Formats similarly to a system message but with an additional error class for distinct styling.
     * @param {string} errorMessage - The error message text to display.
     */
    addCommandError(errorMessage) {
        if (!this.messageArea) return; // Ignore if message area doesn't exist.

        // Check scroll position before adding.
        const wasScrolledToBottom = this.messageArea.scrollHeight - this.messageArea.clientHeight <= this.messageArea.scrollTop + 1;

        // Create message elements.
        const messageDiv = document.createElement('div');
        // Apply both system and error classes for styling.
        messageDiv.classList.add('message-system', 'message-command-error');

        // Timestamp.
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'message-timestamp';
        const now = new Date();
        const dateString = now.toLocaleDateString([], { month: '2-digit', day: '2-digit', year: 'numeric' });
        const timeString = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        timestampSpan.textContent = `[${dateString} - ${timeString}]`;

        // Error Text span.
        const errorSpan = document.createElement('span');
        errorSpan.className = 'error-text'; // Use a class for the text part.
        // Use textContent for safety, add leading space.
        errorSpan.textContent = ` ${errorMessage}`;

        // Append elements to message container.
        messageDiv.appendChild(timestampSpan);
        messageDiv.appendChild(errorSpan);

        // Add the complete message div to the message area.
        this.messageArea.appendChild(messageDiv);

        // Auto-scroll if needed.
        if (wasScrolledToBottom) {
            this.messageArea.scrollTop = this.messageArea.scrollHeight;
        }
    }

    /**
     * Displays the application version information in the chat window as a system message.
     * @param {string} versionString - The application version string (retrieved from config).
     */
    addVersionInfo(versionString) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Displaying version info.");
        this.addSystemMessage(`HeliX Version: ${versionString}`);
    }

    /**
     * Displays current session and connection information in the chat window as multiple system messages.
     * @param {string} httpsUrl - The current client browser URL.
     * @param {string} wssUrl - The WebSocket server URL being used.
     * @param {string} myId - The user's registered identifier.
     * @param {string} peerId - The identifier of the current chat peer.
     */
    addSessionInfo(httpsUrl, wssUrl, myId, peerId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Displaying session info.");
        const now = new Date();
        const dateTimeString = now.toLocaleString(); // Get locale-specific date/time string.

        // Build the info string with newlines for display formatting.
        const infoText = `--- Session Info ---\n` +
                         `Client URL: ${httpsUrl}\n` +
                         `Server URL: ${wssUrl}\n` +
                         `Your ID: ${myId}\n` +
                         `Peer ID: ${peerId}\n` +
                         `Current Time: ${dateTimeString}\n` +
                         `--------------------`;

        // Split the string by newline and add each line as a separate system message
        // to preserve formatting in the chat window.
        infoText.split('\n').forEach(line => {
            this.addSystemMessage(line);
        });
    }

    /**
     * Displays the help information listing available slash commands in the chat window as multiple system messages.
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

        // Split the string by newline and add each line as a separate system message.
        helpText.split('\n').forEach(line => {
            this.addSystemMessage(line);
        });
    }


    /** Clears all content from the message display area. */
    clearMessages() { if (this.messageArea) this.messageArea.innerHTML = ''; }

    // --- File Transfer Message Display ---

    /**
     * Adds a file transfer status message block to the message area.
     * Creates the necessary HTML structure dynamically.
     * @param {string} transferId - The unique ID for this transfer.
     * @param {string} peerId - The ID of the peer involved in the transfer (sender or receiver).
     * @param {string} fileName - The name of the file.
     * @param {number} fileSize - The size of the file in bytes.
     * @param {boolean} isSender - True if the local user is sending, false if receiving (determines initial buttons).
     */
    addFileTransferMessage(transferId, peerId, fileName, fileSize, isSender) {
        if (!this.messageArea) return;

        // Check scroll position before adding.
        const wasScrolledToBottom = this.messageArea.scrollHeight - this.messageArea.clientHeight <= this.messageArea.scrollTop + 1;

        // Create the main container div for the file transfer message.
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message-file-transfer';
        messageDiv.dataset.transferId = transferId; // Store transfer ID for later reference.

        // Format file size into a human-readable string (e.g., KB, MB).
        const formattedSize = this.formatFileSize(fileSize);

        // Create inner HTML structure using template literals for readability.
        // Conditionally renders Cancel button (for sender) or Accept/Reject buttons (for receiver).
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

        // Append the new message block to the message area.
        this.messageArea.appendChild(messageDiv);

        // Auto-scroll if needed.
        if (wasScrolledToBottom) {
            this.messageArea.scrollTop = this.messageArea.scrollHeight;
        }
    }

    /**
     * Updates the status text (e.g., "Uploading...", "Complete.") of a specific file transfer message block.
     * @param {string} transferId - The ID of the transfer message to update.
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
     * Updates the progress bar value for a specific file transfer message block.
     * Makes the progress bar visible if it wasn't already.
     * @param {string} transferId - The ID of the transfer message to update.
     * @param {number} progressPercent - The progress percentage (0-100).
     */
    updateFileTransferProgress(transferId, progressPercent) {
        const messageDiv = this.messageArea?.querySelector(`.message-file-transfer[data-transfer-id="${transferId}"]`);
        const progressBar = messageDiv?.querySelector('.file-progress');
        if (progressBar) {
            progressBar.value = Math.min(100, Math.max(0, progressPercent)); // Clamp value between 0 and 100.
            progressBar.style.display = 'block'; // Ensure progress bar is visible.
            // Avoid logging every progress update unless DEBUG is very verbose.
            // if (config.DEBUG) console.log(`UI: Updated progress for transfer ${transferId} to ${progressPercent.toFixed(1)}%`);
        } else {
             // Log failure only if DEBUG is enabled.
             if (config.DEBUG) console.warn(`UI: Could not find progress bar for transfer ${transferId}`);
        }
    }

    /**
     * Shows the download link for a completed file transfer.
     * Creates a temporary Blob Object URL, sets the link's href and download attributes,
     * makes the link visible, and hides other action buttons.
     * @param {string} transferId - The ID of the completed transfer.
     * @param {Blob | null} blob - The reassembled file Blob. Pass null if only updating UI without a new Blob.
     * @param {string} fileName - The original filename to use for the download attribute.
     */
    showFileDownloadLink(transferId, blob, fileName) {
        const messageDiv = this.messageArea?.querySelector(`.message-file-transfer[data-transfer-id="${transferId}"]`);
        const downloadLink = messageDiv?.querySelector('.file-download-link');
        if (downloadLink) {
            // Only create a new URL if a valid Blob is provided.
            if (blob instanceof Blob) {
                try {
                    // Revoke any existing URL for this transfer first.
                    this.revokeObjectURL(transferId);
                    // Create a new object URL for the Blob.
                    const objectUrl = URL.createObjectURL(blob);
                    // Store the URL for later revocation.
                    this.objectUrls.set(transferId, objectUrl);
                    // Log creation only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`UI: Created object URL for transfer ${transferId}: ${objectUrl}`);
                    downloadLink.href = objectUrl; // Set the link's target.
                } catch (error) {
                    // Always log errors related to object URL creation.
                    console.error(`UI: Error creating object URL for transfer ${transferId}:`, error);
                    this.updateFileTransferStatus(transferId, "Error preparing download link.");
                    return; // Stop if URL creation failed.
                }
            } else if (!downloadLink.href) {
                // If no blob provided and link has no href, cannot show download.
                if (config.DEBUG) console.warn(`UI: Cannot show download link for ${transferId} without a Blob or existing URL.`);
                return;
            }
            // Set filename for download attribute and make link visible.
            downloadLink.download = fileName;
            downloadLink.style.display = 'inline-block';

            // Hide other action buttons (Accept/Reject/Cancel).
            this.hideFileTransferActions(transferId, false); // false = keep download link visible.

        } else {
             // Log failure only if DEBUG is enabled.
             if (config.DEBUG) console.warn(`UI: Could not find download link element for transfer ${transferId}`);
        }
    }

    /**
     * Hides the action buttons (Accept, Reject, Cancel) within a file transfer message block.
     * Optionally keeps the download link visible if specified.
     * @param {string} transferId - The ID of the transfer whose actions to hide.
     * @param {boolean} [hideDownloadLink=true] - Whether to also hide the download link (defaults to true).
     */
    hideFileTransferActions(transferId, hideDownloadLink = true) {
        const messageDiv = this.messageArea?.querySelector(`.message-file-transfer[data-transfer-id="${transferId}"]`);
        const actionsDiv = messageDiv?.querySelector('.file-actions');
        if (actionsDiv) {
            // Hide individual buttons instead of the whole container, in case download link needs to stay.
            const acceptBtn = actionsDiv.querySelector('.file-accept-btn');
            const rejectBtn = actionsDiv.querySelector('.file-reject-btn');
            const cancelBtn = actionsDiv.querySelector('.file-cancel-btn');
            if (acceptBtn) acceptBtn.style.display = 'none';
            if (rejectBtn) rejectBtn.style.display = 'none';
            if (cancelBtn) cancelBtn.style.display = 'none';

            // Hide download link if requested.
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
     * Also revokes any associated Blob Object URL to free memory.
     * @param {string} transferId - The ID of the transfer message block to remove.
     */
    removeFileTransferMessage(transferId) {
        const messageDiv = this.messageArea?.querySelector(`.message-file-transfer[data-transfer-id="${transferId}"]`);
        if (messageDiv) {
            messageDiv.remove(); // Remove the element from the DOM.
            this.revokeObjectURL(transferId); // Revoke associated URL when message is removed.
            // Log removal only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Removed file transfer message for ${transferId}`);
        }
    }

    /**
     * Revokes a previously created Blob Object URL associated with a transfer ID to free up browser memory.
     * Safe to call even if the URL doesn't exist or was already revoked.
     * @param {string} transferId - The ID of the transfer whose URL should be revoked.
     */
    revokeObjectURL(transferId) {
        if (this.objectUrls.has(transferId)) {
            const url = this.objectUrls.get(transferId);
            URL.revokeObjectURL(url); // Tell the browser it no longer needs to keep the Blob reference alive.
            this.objectUrls.delete(transferId); // Remove from our tracking map.
            // Log revocation only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Revoked object URL for transfer ${transferId}: ${url}`);
        }
    }

    /**
     * Formats a file size in bytes into a human-readable string (e.g., "1.2 MB", "500 KB").
     * @param {number} bytes - The file size in bytes.
     * @returns {string} The formatted file size string.
     */
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']; // Add more units if needed.
        // Calculate the appropriate unit index.
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        // Format the number to one decimal place and append the unit.
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    /**
     * Truncates a filename if it exceeds a maximum length, adding ellipsis (...) at the end.
     * @param {string} filename - The original filename.
     * @param {number} [maxLength=30] - The maximum allowed length before truncating.
     * @returns {string} The original or truncated filename.
     */
    truncateFileName(filename, maxLength = 30) {
        if (filename.length <= maxLength) {
            return filename; // Return original if within limit.
        }
        // Return the beginning part plus ellipsis.
        return filename.substring(0, maxLength - 3) + '...';
    }

    // --- End File Transfer Message Display ---

    // --- Typing Indicator Methods ---

    /**
     * Shows the typing indicator text in the dedicated area below messages (e.g., "PeerID is typing...").
     * @param {string} peerId - The ID of the peer who is typing.
     */
    showTypingIndicator(peerId) {
        if (this.typingIndicatorText) {
            this.typingIndicatorText.textContent = `${peerId} is typing...`;
            this.typingIndicatorText.style.display = 'inline'; // Make the text visible.
        }
    }

    /** Hides the typing indicator text element and clears its content. */
    hideTypingIndicator() {
        if (this.typingIndicatorText) {
            this.typingIndicatorText.style.display = 'none'; // Hide the text element.
            this.typingIndicatorText.textContent = ''; // Clear the text content.
        }
    }
    // -----------------------------------

    // --- Audio Notification Method ---
    /**
     * Attempts to play the preloaded notification sound specified by name.
     * Checks the `isMuted` flag before playing. Includes error handling for browser
     * restrictions (e.g., autoplay policies) or sound loading issues.
     * @param {string} soundName - The name of the sound to play (key in `this.sounds` object).
     */
    playSound(soundName) {
        // Check mute state first.
        if (this.isMuted) {
            // Log skip only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Sound '${soundName}' skipped (muted).`);
            return; // Don't play if muted.
        }

        // Find the preloaded Audio object.
        const sound = this.sounds[soundName];

        if (sound) {
            // Log play attempt only if DEBUG is enabled.
            if (config.DEBUG) console.log(`UI: Attempting to play sound '${soundName}'.`);
            // Reset playback position to the start in case it was played recently and hasn't finished.
            sound.currentTime = 0;
            // The play() method returns a Promise which might be rejected by the browser.
            sound.play()
                .catch(error => {
                    // Always log playback errors.
                    console.error(`UI: Error playing sound '${soundName}':`, error);
                    // Common errors include NotAllowedError (user interaction needed for audio)
                    // or NotSupportedError (audio file format issue).
                });
        } else {
            // Always log warning if the sound object wasn't loaded correctly or the name is invalid.
            console.warn(`UI: Cannot play sound, Audio object for '${soundName}' not loaded or invalid name.`);
        }
    }
    // ------------------------------------

    // --- Mute State Management ---
    /**
     * Toggles the internal mute state flag (`this.isMuted`).
     * Calls `updateMuteButtonIcon` to reflect the change visually in the UI.
     */
    toggleMuteState() {
        this.isMuted = !this.isMuted; // Flip the boolean flag.
        // Log state change only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Mute state toggled to: ${this.isMuted}`);
        this.updateMuteButtonIcon(); // Update the button's appearance.
    }

    /**
     * Updates the mute button's icon (🔊/🔇), CSS class ('muted'), and title attribute
     * based on the current `isMuted` state.
     */
    updateMuteButtonIcon() {
        if (!this.muteButton) return; // Exit if button element not found.

        const iconSpan = this.muteButton.querySelector('span'); // Get the inner span holding the icon.
        if (!iconSpan) return; // Exit if span not found.

        if (this.isMuted) {
            // Muted state: Set muted icon, add 'muted' class (for potential CSS styling like opacity), update tooltip.
            iconSpan.textContent = '🔇';
            this.muteButton.classList.add('muted');
            this.muteButton.title = "Unmute Notifications";
        } else {
            // Unmuted state: Set unmuted icon, remove 'muted' class, update tooltip.
            iconSpan.textContent = '🔊';
            this.muteButton.classList.remove('muted');
            this.muteButton.title = "Mute Notifications";
        }
    }
    // --------------------------------

    // --- Chat Style Management ---
    /**
     * Applies the initial chat message area styles based on the default values
     * present in the settings controls (font family select, font size input) when the UI loads.
     */
    applyInitialChatStyles() {
        const initialFontFamily = this.fontFamilySelect ? this.fontFamilySelect.value : 'sans-serif'; // Use select default or fallback.
        const initialFontSize = this.fontSizeInput ? this.fontSizeInput.value : '15'; // Use input default or fallback.
        this.applyChatStyles(initialFontFamily, initialFontSize);
    }

    /**
     * Applies the specified font family and font size (in pixels) to the message area element's inline style.
     * @param {string} fontFamily - The CSS font-family value (e.g., "Arial, sans-serif").
     * @param {string|number} fontSize - The font size value (number or string like "16"). Will be appended with 'px'.
     */
    applyChatStyles(fontFamily, fontSize) {
        if (!this.messageArea) return; // Exit if message area element not found.

        // Log style application only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Applying chat styles - Family: ${fontFamily}, Size: ${fontSize}px`);

        // Apply font family if provided.
        if (fontFamily) {
            this.messageArea.style.fontFamily = fontFamily;
        }
        // Apply font size if provided, ensuring 'px' unit is added.
        if (fontSize) {
            this.messageArea.style.fontSize = `${fontSize}px`;
        }
    }

    /**
     * Gets the currently applied font family and font size from the message area's computed style.
     * Returns default values ('sans-serif', '15') if styles are not set or cannot be retrieved.
     * @returns {{fontFamily: string, fontSize: string}} An object containing the current fontFamily and fontSize (as a string without 'px').
     */
    getCurrentChatStyles() {
        let fontFamily = 'sans-serif'; // Default fallback font family.
        let fontSize = '15'; // Default fallback font size (as string).

        if (this.messageArea) {
            // Get the computed style, which reflects all applied styles (CSS files, inline).
            const computedStyle = window.getComputedStyle(this.messageArea);
            fontFamily = computedStyle.fontFamily || fontFamily; // Use computed value or fallback.
            // Parse font size, removing 'px' and converting to a base-10 integer string.
            fontSize = parseInt(computedStyle.fontSize, 10).toString() || fontSize; // Use parsed value or fallback.
        }
        // Log retrieval only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Retrieved current chat styles - Family: ${fontFamily}, Size: ${fontSize}`);
        return { fontFamily, fontSize };
    }
    // --------------------------------

    // --- Info Pane Visibility Checks ---

    /**
     * Checks if the info pane is currently visible AND associated with the specified peer ID
     * (by checking the `data-peerid` attribute on its buttons).
     * @param {string} peerId - The peer ID to check against the info pane's associated peer.
     * @returns {boolean} True if the info pane is visible and matches the peerId, false otherwise.
     */
    isInfoPaneVisibleFor(peerId) {
        if (!this.infoArea || this.infoArea.style.display === 'none') {
            return false; // Pane is not visible.
        }
        // Check the dataset peerid stored on the close button (or retry button as fallback).
        const storedPeerId = this.closeInfoButton?.dataset?.peerid || this.retryRequestButton?.dataset?.peerid;
        return storedPeerId === peerId; // Return true only if visible and the peerId matches.
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

    /** Binds a handler function to the register button's 'click' event. */
    bindRegisterButton(handler) { if (this.registerButton) this.registerButton.addEventListener('click', handler); }
    /** Binds a handler function to the start chat button's 'click' event. */
    bindStartChatButton(handler) { if (this.startChatButton) this.startChatButton.addEventListener('click', handler); }
    /** Binds a handler function to the accept button's 'click' event. */
    bindAcceptButton(handler) { if (this.acceptButton) this.acceptButton.addEventListener('click', handler); }
    /** Binds a handler function to the deny button's 'click' event. */
    bindDenyButton(handler) { if (this.denyButton) this.denyButton.addEventListener('click', handler); }

    /**
     * Binds a handler function to the send button's 'click' event AND
     * the 'keypress' event (specifically Enter key without Shift) in the message input field.
     * @param {function} handler - The function to call when the message should be sent.
     */
    bindSendButton(handler) {
        if (this.sendButton) this.sendButton.addEventListener('click', handler);
        if (this.messageInput) {
             this.messageInput.addEventListener('keypress', (event) => {
                 // Check for Enter key (key property is 'Enter') and ensure Shift key is not pressed.
                 if (event.key === 'Enter' && !event.shiftKey) {
                     event.preventDefault(); // Prevent default action (e.g., adding a newline).
                     handler(); // Call the provided send message handler function.
                 }
             });
        }
    }

    /** Binds a handler function to the disconnect button's 'click' event in the chat header. */
    bindDisconnectButton(handler) { if (this.disconnectButton) this.disconnectButton.addEventListener('click', handler); }

    /**
     * Binds a handler function to 'click' events on the session list container.
     * Uses event delegation to handle clicks on dynamically added <li> elements within the list.
     * Extracts the peerId from the clicked list item's `data-peerid` attribute.
     * @param {function(string): void} handler - The function to call with the clicked peerId.
     */
    bindSessionListClick(handler) {
         if (this.sessionList) {
             this.sessionList.addEventListener('click', (event) => {
                 // Find the closest ancestor <li> element that has a 'data-peerid' attribute.
                 const listItem = event.target.closest('li[data-peerid]');
                 // If such an element is found and has the attribute, call the handler with the peerId.
                 if (listItem && listItem.dataset.peerid) {
                     handler(listItem.dataset.peerid);
                 }
             });
         }
    }

    /**
     * Binds a handler function to the close button in the info pane's 'click' event.
     * Extracts the peerId associated with the pane from the button's `data-peerid` attribute.
     * @param {function(string): void} handler - The function to call with the associated peerId.
     */
    bindCloseInfoButton(handler) {
        if (this.closeInfoButton) {
            this.closeInfoButton.addEventListener('click', (event) => {
                // Use currentTarget to ensure we get the button the listener was attached to.
                const peerId = event.currentTarget.dataset.peerid;
                if (peerId) {
                    handler(peerId); // Call handler with the retrieved peerId.
                } else {
                    // Always log this error if the dataset attribute is missing.
                    console.error("Close info button clicked, but no peerId found in dataset.");
                }
            });
        }
    }

    /**
     * Binds a handler function to the retry button in the info pane's 'click' event.
     * Extracts the peerId associated with the pane from the button's `data-peerid` attribute.
     * @param {function(string): void} handler - The function to call with the associated peerId.
     */
    bindRetryRequestButton(handler) {
        if (this.retryRequestButton) {
            this.retryRequestButton.addEventListener('click', (event) => {
                // Use currentTarget to ensure we get the button the listener was attached to.
                const peerId = event.currentTarget.dataset.peerid;
                if (peerId) {
                    handler(peerId); // Call handler with the retrieved peerId.
                } else {
                    // Always log this error if the dataset attribute is missing.
                    console.error("Retry button clicked, but no peerId found in dataset.");
                }
            });
        }
    }

    /**
     * Binds a handler function to the cancel request button in the waiting pane's 'click' event.
     * Extracts the peerId associated with the pane from the button's `data-peerid` attribute.
     * @param {function(string): void} handler - The function to call with the associated peerId.
     */
    bindCancelRequestButton(handler) {
        if (this.cancelRequestButton) {
            this.cancelRequestButton.addEventListener('click', (event) => {
                 // Use currentTarget to ensure we get the button the listener was attached to.
                 const peerId = event.currentTarget.dataset.peerid;
                 if (peerId) {
                     handler(peerId); // Call handler with the retrieved peerId.
                 } else {
                     // Always log this error if the dataset attribute is missing.
                     console.error("Cancel request button clicked, but no peerId found in dataset.");
                 }
            });
        }
    }

    /**
     * Attaches an event listener to the message input field for the 'input' event.
     * This event fires immediately whenever the text content changes (typing, pasting, deleting).
     * Used to trigger the local typing indicator logic in SessionManager.
     * @param {function} handler - Function to call when the input value changes.
     */
    bindMessageInput(handler) {
        if (this.messageInput) {
            // 'input' event is generally preferred over 'keydown' or 'keyup' for detecting actual value changes.
            this.messageInput.addEventListener('input', handler);
        }
    }

    /**
     * Binds a handler function to the mute button's 'click' event.
     * @param {function} handler - The function to call when the mute button is clicked (typically `toggleMuteState`).
     */
    bindMuteButton(handler) {
        if (this.muteButton) {
            this.muteButton.addEventListener('click', handler);
        }
    }

    // --- File Transfer Bindings ---

    /**
     * Binds a handler function to the attach button's 'click' event.
     * @param {function} handler - The function to call when the attach button is clicked (typically `triggerFileInputClick`).
     */
    bindAttachButton(handler) {
        if (this.attachButton) {
            this.attachButton.addEventListener('click', handler);
        }
    }

    /**
     * Binds a handler function to the hidden file input's 'change' event.
     * This event fires when the user selects a file (or cancels the dialog).
     * @param {function(Event): void} handler - The function to call with the change event object.
     */
    bindFileInputChange(handler) {
        if (this.fileInput) {
            this.fileInput.addEventListener('change', handler);
        }
    }

    /**
     * Programmatically clicks the hidden file input element to open the browser's file selection dialog.
     */
    triggerFileInputClick() {
        if (this.fileInput) {
            // Log action only if DEBUG is enabled.
            if (config.DEBUG) console.log("UI: Triggering file input click.");
            this.fileInput.click();
        }
    }

    /**
     * Helper function to bind handlers for dynamically added file transfer buttons (Accept, Reject, Cancel, Download).
     * Uses event delegation on the message area container for efficiency.
     * @param {string} buttonClass - The CSS class selector of the button to target (e.g., '.file-accept-btn').
     * @param {function(string): void} handler - The function to call, passing the transferId extracted from the parent message block.
     * @private
     */
    _bindDynamicFileButton(buttonClass, handler) {
        if (!this.messageArea) return;
        // Attach a single listener to the message area.
        this.messageArea.addEventListener('click', (event) => {
            // Check if the clicked element or its ancestor matches the button class selector.
            const button = event.target.closest(buttonClass);
            if (button) {
                // Find the parent file transfer message block to get the transferId.
                const messageDiv = button.closest('.message-file-transfer');
                const transferId = messageDiv?.dataset?.transferId;
                if (transferId) {
                    // Log dynamic button click only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`UI: Dynamic button ${buttonClass} clicked for transfer ${transferId}`);
                    handler(transferId); // Call the provided handler with the transferId.
                } else {
                    // Always log this error if transferId is missing.
                    console.error(`UI: Clicked ${buttonClass} but could not find transferId on parent message block.`);
                }
            }
        });
    }

    /** Binds a handler for the dynamic Accept file button clicks. */
    bindFileAccept(handler) { this._bindDynamicFileButton('.file-accept-btn', handler); }
    /** Binds a handler for the dynamic Reject file button clicks. */
    bindFileReject(handler) { this._bindDynamicFileButton('.file-reject-btn', handler); }
    /** Binds a handler for the dynamic Cancel file button clicks. */
    bindFileCancel(handler) { this._bindDynamicFileButton('.file-cancel-btn', handler); }
    /** Binds a handler for the dynamic Download file link clicks. */
    bindFileDownload(handler) {
        // Note: We bind to the link itself. The handler might just log or revoke the URL,
        // as the actual download is initiated by the browser via the href/download attributes.
        this._bindDynamicFileButton('.file-download-link', handler);
    }
    // ------------------------------------

    // --- Settings Bindings ---
    /**
     * Binds a handler function to the settings button's 'click' event.
     * @param {function} handler - The function to call when the settings button is clicked (typically `showSettingsPane`).
     */
    bindSettingsButton(handler) {
        if (this.settingsButton) {
            this.settingsButton.addEventListener('click', handler);
        }
    }

    /**
     * Binds a handler function to the close settings button's 'click' event.
     * @param {function} handler - The function to call when the close settings button is clicked (typically `hideSettingsPane`).
     */
    bindCloseSettingsButton(handler) {
        if (this.closeSettingsButton) {
            this.closeSettingsButton.addEventListener('click', handler);
        }
    }

    /**
     * Binds a handler function to the font family select dropdown's 'change' event.
     * @param {function(Event): void} handler - The function to call when the selection changes, passing the event object.
     */
    bindFontFamilyChange(handler) {
        if (this.fontFamilySelect) {
            this.fontFamilySelect.addEventListener('change', handler);
        }
    }

    /**
     * Binds a handler function to the font size input's 'input' event (fires as value changes).
     * @param {function(Event): void} handler - The function to call when the input value changes, passing the event object.
     */
    bindFontSizeChange(handler) {
        if (this.fontSizeInput) {
            // Use 'input' event for immediate feedback as the user types or uses arrows.
            this.fontSizeInput.addEventListener('input', handler);
        }
    }
    // -----------------------------

    // --- Emoji Picker Bindings ---
    /**
     * Binds a handler function to the emoji picker button's 'click' event.
     * Stops event propagation to prevent immediate closure by the outside-click listener.
     * @param {function} handler - The function to call when the button is clicked (typically `toggleEmojiPicker`).
     */
    bindEmojiPickerButton(handler) {
        if (this.emojiPickerButton) {
            this.emojiPickerButton.addEventListener('click', (event) => {
                event.stopPropagation(); // Prevent click from bubbling up to the document listener.
                handler();
            });
        }
    }
    // -----------------------------

    // --- Linkify Helper ---
    /**
     * Finds URLs within a given text node and replaces them with clickable anchor (<a>) elements.
     * Modifies the DOM by replacing the original text node with a document fragment
     * containing a mix of text nodes and anchor elements. Opens links in a new tab.
     * @param {Node} textNode - The text node potentially containing URLs to linkify.
     * @private
     */
    _linkifyTextNode(textNode) {
        // Regex to find URLs:
        // - Group 1: Matches http, https, ftp protocols followed by valid URL characters.
        // - Group 2: Matches URLs starting with 'www.' but without a protocol specified.
        const urlRegex = /(\b(?:https?|ftp):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])|(\bwww\.[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
        const textContent = textNode.textContent;
        let match;
        let lastIndex = 0;
        const fragment = document.createDocumentFragment(); // Use fragment for efficient DOM manipulation.
        let foundLink = false; // Flag to track if any links were found in this node.

        // Use regex.exec in a loop to find all URL matches in the text content.
        while ((match = urlRegex.exec(textContent)) !== null) {
            foundLink = true;
            const url = match[0]; // The matched URL string.
            const index = match.index; // Starting index of the URL in the text.

            // Append the text segment before the found URL (if any).
            if (index > lastIndex) {
                fragment.appendChild(document.createTextNode(textContent.substring(lastIndex, index)));
            }

            // Create the anchor (<a>) element for the link.
            const link = document.createElement('a');
            let href = url;
            // Prepend 'https://' if the URL starts with 'www.' but lacks a protocol (captured in group 2).
            if (match[2]) {
                href = `https://${url}`;
            }
            link.href = href;
            link.target = '_blank'; // Open link in a new tab/window.
            link.rel = 'noopener noreferrer'; // Security measure for opening external links.
            link.textContent = url; // Display the original URL text as the link text.
            fragment.appendChild(link); // Add the link to the fragment.

            // Update the index for processing the text segment after this URL.
            lastIndex = urlRegex.lastIndex;
        }

        // If no links were found in this text node, no DOM modification is needed.
        if (!foundLink) {
            return;
        }

        // Append any remaining text after the last found URL.
        if (lastIndex < textContent.length) {
            fragment.appendChild(document.createTextNode(textContent.substring(lastIndex)));
        }

        // Replace the original text node with the new fragment containing text nodes and links.
        textNode.parentNode.replaceChild(fragment, textNode);
        // Log linkification only if DEBUG is enabled.
        if (config.DEBUG) console.log("UI: Linkified URLs in message text.");
    }
    // -----------------------------

    // --- Emoji Picker Methods ---
    /**
     * Populates the emoji picker panel with clickable emoji spans based on `this.emojiList`.
     * Attaches click and keypress listeners to each emoji for insertion.
     * @private
     */
    _populateEmojiPicker() {
        if (!this.emojiPickerPanel) return;
        // Clear any existing emojis first.
        this.emojiPickerPanel.innerHTML = '';
        // Iterate through the defined emoji list.
        this.emojiList.forEach(emoji => {
            const emojiSpan = document.createElement('span');
            emojiSpan.textContent = emoji;
            emojiSpan.title = emoji; // Tooltip for accessibility/clarity.
            emojiSpan.role = 'button'; // Indicate it's clickable via assistive tech.
            emojiSpan.tabIndex = 0; // Make it focusable via keyboard.
            // Add click listener to insert the emoji and close the picker.
            emojiSpan.addEventListener('click', () => {
                this._insertEmoji(emoji);
                this.toggleEmojiPicker(false); // Explicitly hide after selection.
            });
            // Add keypress listener (Enter/Space) for accessibility.
            emojiSpan.addEventListener('keypress', (event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault(); // Prevent default spacebar scroll or enter submit.
                    this._insertEmoji(emoji);
                    this.toggleEmojiPicker(false); // Explicitly hide after selection.
                }
            });
            this.emojiPickerPanel.appendChild(emojiSpan);
        });
        // Log population only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Populated emoji picker with ${this.emojiList.length} emojis.`);
    }

    /**
     * Toggles the visibility of the emoji picker panel.
     * Calculates position relative to the toggle button.
     * Adds/removes a document click listener to handle closing when clicking outside.
     * @param {boolean} [forceShow] - Optional. If true, forces the panel to show. If false, forces hide. If undefined, toggles current state.
     */
    toggleEmojiPicker(forceShow) {
        if (!this.emojiPickerPanel || !this.emojiPickerButton) return;

        // Determine if the panel should be shown based on current state or forceShow parameter.
        const shouldShow = (forceShow === undefined) ? this.emojiPickerPanel.style.display === 'none' : forceShow;

        if (shouldShow) {
            // Calculate position relative to the emoji picker button.
            const buttonRect = this.emojiPickerButton.getBoundingClientRect();
            // Position the panel above the button.
            this.emojiPickerPanel.style.bottom = `${window.innerHeight - buttonRect.top + 5}px`; // 5px gap above button.
            this.emojiPickerPanel.style.left = `${buttonRect.left}px`; // Align left edge initially.
            // Consider potential adjustments if panel goes off-screen left/right.

            this.emojiPickerPanel.style.display = 'block'; // Make the panel visible.
            // Log show only if DEBUG is enabled.
            if (config.DEBUG) console.log("UI: Showing emoji picker.");

            // Add listener to the document to close the picker when clicking outside.
            // Use setTimeout to ensure this listener is added *after* the current click event finishes,
            // preventing immediate closure if the click was on the toggle button itself.
            // Use capture phase and once: true for efficient removal.
            setTimeout(() => {
                document.addEventListener('click', this._handleOutsideEmojiClick, { capture: true, once: true });
            }, 0);

        } else {
            this.emojiPickerPanel.style.display = 'none'; // Hide the panel.
            // Log hide only if DEBUG is enabled.
            if (config.DEBUG) console.log("UI: Hiding emoji picker.");
            // Ensure the outside click listener is removed if it was added.
            document.removeEventListener('click', this._handleOutsideEmojiClick, { capture: true });
        }
    }

    /**
     * Handles clicks on the document when the emoji picker is open.
     * If the click is outside the picker panel and not on the toggle button, it closes the picker.
     * Bound to the document temporarily using `addEventListener` with `once: true`.
     * Needs to be an arrow function or bound function to maintain `this` context if accessing UIController properties.
     * @param {MouseEvent} event - The click event object.
     * @private
     */
    _handleOutsideEmojiClick = (event) => {
        // Check if the click target is outside the panel AND not the toggle button itself.
        if (this.emojiPickerPanel && !this.emojiPickerPanel.contains(event.target) && event.target !== this.emojiPickerButton) {
            // Log outside click only if DEBUG is enabled.
            if (config.DEBUG) console.log("UI: Click detected outside emoji picker. Closing.");
            this.toggleEmojiPicker(false); // Force hide the picker.
        } else {
            // If click was inside or on the button, the listener (with once: true) is automatically removed.
            // If we needed it to persist for subsequent clicks, we'd re-add it here.
        }
    }

    /**
     * Inserts an emoji character into the message input field at the current cursor position or selection.
     * Handles replacing selected text if any. Moves cursor after the inserted emoji.
     * @param {string} emoji - The emoji character to insert.
     * @private
     */
    _insertEmoji(emoji) {
        if (!this.messageInput) return;

        const input = this.messageInput;
        const start = input.selectionStart; // Get current cursor start position.
        const end = input.selectionEnd; // Get current cursor end position (might be same as start).
        const text = input.value;

        // Construct the new value by inserting the emoji at the start position, replacing any selected text.
        input.value = text.substring(0, start) + emoji + text.substring(end);

        // Calculate the new cursor position (after the inserted emoji).
        const newCursorPos = start + emoji.length;
        // Set both start and end selection to the new position (collapses selection).
        input.selectionStart = newCursorPos;
        input.selectionEnd = newCursorPos;

        // Focus the input field again so the user can continue typing.
        input.focus();
        // Log insertion only if DEBUG is enabled.
        if (config.DEBUG) console.log(`UI: Inserted emoji '${emoji}' at position ${start}.`);
    }
    // -----------------------------


    // --- Utility ---
    /**
     * Validates that all expected DOM element references were successfully found during initialization
     * and that the sound objects were created without errors.
     * Logs warnings to the console for any missing elements or failed sound loads.
     * @returns {boolean} True if all critical elements were found and sounds loaded, false otherwise.
     */
    validateElements() {
        // List of all DOM element properties expected to be non-null after constructor runs.
        const domElements = [
            this.statusElement, this.registrationArea, this.identifierInput, this.registerButton,
            this.appContainer, this.sidebar, this.myIdentifierDisplay, this.initiationArea,
            this.peerIdInput, this.startChatButton,
            this.sidebarControls, this.muteButton, this.settingsButton,
            this.sessionListContainer, this.sessionList,
            this.mainContent, this.overlay,
            this.welcomeMessage, this.myIdentifierWelcome,
            this.appVersionDisplay,
            this.incomingRequestArea, this.incomingRequestText,
            this.acceptButton, this.denyButton,
            this.infoArea, this.infoMessage, this.closeInfoButton, this.retryRequestButton,
            this.waitingResponseArea, this.waitingResponseText, this.cancelRequestButton,
            this.activeChatArea, this.chatHeader,
            this.peerIdentifierDisplay, this.messageArea,
            this.typingIndicatorArea, this.typingIndicatorText,
            this.messageInputArea,
            this.attachButton,
            this.emojiPickerButton,
            this.messageInput,
            this.sendButton, this.disconnectButton,
            this.settingsPane, this.fontFamilySelect, this.fontSizeInput, this.closeSettingsButton,
            this.fileInput,
            this.emojiPickerPanel
        ];
        let allFound = true;
        // Validate DOM elements.
        domElements.forEach((el) => {
            // Find the property name associated with the element for logging purposes.
            const keyName = Object.keys(this).find(key => this[key] === el);
            if (!el) {
                console.warn(`UIController: DOM Element for property '${keyName || 'UNKNOWN'}' not found! Check HTML IDs.`);
                allFound = false;
            }
        });
        // Validate Sound objects.
        for (const soundName in this.sounds) {
            if (this.sounds[soundName] === null) {
                console.warn(`UIController: Audio object for sound '${soundName}' failed to load! Check path/file.`);
                allFound = false;
            }
        }
        return allFound;
    }
}
