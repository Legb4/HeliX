// client/js/SessionManager.js

/**
 * Manages the overall state of the chat application, user registration,
 * and all active/pending chat sessions. It acts as the central coordinator,
 * interacting with the WebSocketClient for network communication, the UIController
 * for display updates, and creating/managing individual Session instances.
 * Implements End-to-End Encryption with Perfect Forward Secrecy using ECDH and AES-GCM,
 * and facilitates secure file transfers using IndexedDB for temporary chunk storage.
 */
class SessionManager {
    /**
     * Initializes the SessionManager.
     * @param {WebSocketClient} webSocketClient - Instance for sending/receiving WebSocket messages.
     * @param {UIController} uiController - Instance for manipulating the user interface.
     * @param {typeof CryptoModule} cryptoModuleClass - The CryptoModule class constructor, used to create new crypto instances per session.
     */
    constructor(webSocketClient, uiController, cryptoModuleClass) {
        // Store references to injected dependencies.
        this.wsClient = webSocketClient;
        this.uiController = uiController;
        this.CryptoModuleClass = cryptoModuleClass; // Store the class constructor for creating session-specific crypto instances.

        // --- Constants ---
        // Define timeout durations and delays used throughout the manager.
        this.HANDSHAKE_TIMEOUT_DURATION = 30000; // 30 seconds for handshake steps (key exchange, challenge/response).
        this.REQUEST_TIMEOUT_DURATION = 60000; // 60 seconds for the initial session request (Type 1) to be accepted/denied.
        this.REGISTRATION_TIMEOUT_DURATION = 15000; // 15 seconds to wait for registration success/failure reply from the server.
        this.TYPING_STOP_DELAY = 3000; // Send TYPING_STOP message after 3 seconds of local user inactivity in the message input.
        this.TYPING_INDICATOR_TIMEOUT = 5000; // Hide peer's typing indicator after 5 seconds if no further typing messages or actual messages arrive.
        // File Transfer Constants
        this.MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB limit for file transfers (client-side check).
        this.CHUNK_SIZE = 256 * 1024; // 256 KB chunk size for reading and sending file data.
        this.FILE_ACCEPT_TIMEOUT = 60000; // 60 seconds for receiver to accept/reject an incoming file transfer request.

        // --- Application States ---
        // Define possible states for the overall application manager.
        this.STATE_INITIALIZING = 'INITIALIZING'; // Application starting up.
        this.STATE_CONNECTING = 'CONNECTING'; // WebSocket attempting to connect to the server.
        this.STATE_CONNECTED_UNREGISTERED = 'CONNECTED_UNREGISTERED'; // WebSocket connected, waiting for user to register an identifier.
        this.STATE_REGISTERING = 'REGISTERING'; // Registration message sent to server, awaiting success/failure reply.
        this.STATE_REGISTERED = 'REGISTERED'; // User successfully registered with an identifier.
        this.STATE_FAILED_REGISTRATION = 'FAILED_REGISTRATION'; // Server rejected the registration attempt.
        this.STATE_DISCONNECTED = 'DISCONNECTED'; // WebSocket connection lost or closed definitively.

        // --- Session-Specific States (Reflecting ECDH Handshake Flow) ---
        // Define possible states for individual Session instances, managed by this manager.
        // Initiator states (User A starts chat with User B):
        this.STATE_INITIATING_SESSION = 'INITIATING_SESSION'; // A sent Type 1 request, awaiting B's Type 2 (Accept + B's ECDH Key).
        this.STATE_DERIVING_KEY_INITIATOR = 'DERIVING_KEY_INITIATOR'; // A received Type 2, deriving keys before sending Type 4 (A's ECDH Key).
        this.STATE_KEY_DERIVED_INITIATOR = 'KEY_DERIVED_INITIATOR'; // A derived keys, ready to send Type 4.
        this.STATE_AWAITING_CHALLENGE_RESPONSE = 'AWAITING_CHALLENGE_RESPONSE'; // A sent Type 5 (Challenge), awaiting B's Type 6 (Response).
        this.STATE_RECEIVED_CHALLENGE = 'RECEIVED_CHALLENGE'; // A received Type 5 (Challenge), ready to send Type 6 (Response).
        this.STATE_AWAITING_FINAL_CONFIRMATION = 'AWAITING_FINAL_CONFIRMATION'; // A sent Type 6 (Response), awaiting B's Type 7 (Established).
        // Responder states (User B receives request from User A):
        this.STATE_REQUEST_RECEIVED = 'REQUEST_RECEIVED'; // B received Type 1 request, awaiting user Accept/Deny.
        this.STATE_GENERATING_ACCEPT_KEYS = 'GENERATING_ACCEPT_KEYS'; // B clicked Accept, generating ECDH keys before sending Type 2.
        this.STATE_AWAITING_CHALLENGE = 'AWAITING_CHALLENGE'; // B sent Type 2 (Accept + B's ECDH Key), awaiting A's Type 4 (A's ECDH Key).
        this.STATE_DERIVING_KEY_RESPONDER = 'DERIVING_KEY_RESPONDER'; // B received Type 4, deriving keys before sending Type 5 (Challenge).
        this.STATE_RECEIVED_INITIATOR_KEY = 'RECEIVED_INITIATOR_KEY'; // B received Type 4, keys derived, ready to send Type 5 (Challenge).
        this.STATE_HANDSHAKE_COMPLETE = 'HANDSHAKE_COMPLETE'; // B received Type 6 (Response), verified, ready to send Type 7 (Established).
        // Common states:
        this.STATE_ACTIVE_SESSION = 'ACTIVE_SESSION'; // Handshake complete (Type 7 received/sent), ready for messages (Type 8) and file transfers.
        // End/Error states:
        this.STATE_DENIED = 'DENIED'; // Request explicitly denied (Type 3) or target not found (Type -1).
        this.STATE_REQUEST_TIMED_OUT = 'REQUEST_TIMED_OUT'; // Initial request (Type 1) timed out without response.
        this.STATE_HANDSHAKE_TIMED_OUT = 'HANDSHAKE_TIMED_OUT'; // One of the subsequent handshake steps (Types 2-7) timed out.
        this.STATE_CANCELLED = 'CANCELLED'; // User cancelled an outgoing request before it was accepted/denied.

        // --- Manager State ---
        // Holds the current state of the application manager (one of the STATE_* constants above).
        this.managerState = this.STATE_INITIALIZING;
        // Stores the user's registered identifier after successful registration.
        this.identifier = null;
        // Map storing active/pending Session instances, keyed by peerId (string).
        this.sessions = new Map();
        // Stores the peerId of the session currently awaiting user action (Accept/Deny in the incoming request pane).
        this.pendingPeerIdForAction = null;
        // Stores the peerId of the session currently displayed in the main content area (active chat, info pane, etc.).
        this.displayedPeerId = null;
        // Stores the ID of the registration timeout timer (setTimeout).
        this.registrationTimeoutId = null;

        // --- Local Typing State Tracking ---
        // Tracks if the local user is currently considered "typing" to a specific peer.
        this.isTypingToPeer = new Map(); // Map<peerId (string), boolean>
        // Stores timeout IDs for sending TYPING_STOP messages after inactivity for each peer.
        this.typingStopTimeoutId = new Map(); // Map<peerId (string), timeoutId>
        // --------------------------------------

        // --- IndexedDB State ---
        this.db = null; // Will hold the IndexedDB database object once initialized.
        this.DB_NAME = 'HeliXFileTransferDB'; // Name of the IndexedDB database.
        this.DB_VERSION = 1; // Version of the database schema.
        this.CHUNK_STORE_NAME = 'fileChunks'; // Name of the object store for file chunks.
        // ----------------------------

        // Log initialization confirmation.
        console.log('SessionManager initialized (ECDH Mode, IndexedDB for files).');
        this.updateManagerState(this.STATE_INITIALIZING); // Set initial state.
        this.initDB(); // Start the asynchronous initialization of IndexedDB.
    }

    /**
     * Updates the manager's overall state and logs the transition if DEBUG is enabled.
     * Prevents state changes away from DISCONNECTED unless it's back to INITIALIZING (full reset).
     * @param {string} newState - The new manager state identifier (e.g., 'REGISTERED').
     */
    updateManagerState(newState) {
        // Prevent changing state if already fully disconnected, except for a full reset to INITIALIZING.
        if (this.managerState === this.STATE_DISCONNECTED && newState !== this.STATE_INITIALIZING) {
            // Always log this warning.
            console.warn(`Attempted to change state from DISCONNECTED to ${newState}. Ignoring.`);
            return;
        }
        // Log state transitions only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Manager State transition: ${this.managerState} -> ${newState}`);
        }
        this.managerState = newState;
    }

    // --- Timeout Handling ---

    /**
     * Starts a timeout for handshake steps (key exchange, challenge/response) within a specific session.
     * If the timeout expires before being cleared, handleHandshakeTimeout is called.
     * @param {Session} session - The session instance to start the timeout for.
     */
    startHandshakeTimeout(session) {
        this.clearHandshakeTimeout(session); // Clear any existing handshake timeout for this session first.
        // Log timeout start only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Session [${session.peerId}] Starting handshake timeout (${this.HANDSHAKE_TIMEOUT_DURATION}ms)`);
        }
        // Schedule the timeout.
        session.handshakeTimeoutId = setTimeout(() => {
            this.handleHandshakeTimeout(session.peerId);
        }, this.HANDSHAKE_TIMEOUT_DURATION);
    }

    /**
     * Clears the active handshake timeout for a specific session, if one exists.
     * @param {Session} session - The session instance whose handshake timeout should be cleared.
     */
    clearHandshakeTimeout(session) {
        if (session && session.handshakeTimeoutId) {
            // Log timeout clear only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`Session [${session.peerId}] Clearing handshake timeout.`);
            }
            clearTimeout(session.handshakeTimeoutId);
            session.handshakeTimeoutId = null; // Clear the stored ID.
        }
    }

    /**
     * Handles the expiration of a handshake timeout for a specific peer.
     * Updates the session state to HANDSHAKE_TIMED_OUT, plays an error sound,
     * shows an info message, and resets the session.
     * @param {string} peerId - The ID of the peer whose handshake timed out.
     */
    handleHandshakeTimeout(peerId) {
        // Always log timeout errors.
        console.error(`Session [${peerId}] Handshake timed out!`);
        const session = this.sessions.get(peerId);
        // Define the states during which a handshake timeout is relevant.
        const handshakeStates = [
            this.STATE_DERIVING_KEY_INITIATOR, this.STATE_KEY_DERIVED_INITIATOR,
            this.STATE_AWAITING_CHALLENGE_RESPONSE,
            this.STATE_RECEIVED_CHALLENGE, this.STATE_AWAITING_FINAL_CONFIRMATION,
            this.STATE_GENERATING_ACCEPT_KEYS, this.STATE_AWAITING_CHALLENGE,
            this.STATE_DERIVING_KEY_RESPONDER, this.STATE_RECEIVED_INITIATOR_KEY,
            this.STATE_HANDSHAKE_COMPLETE
        ];
        // Check if the session exists and is still in a relevant handshake state when the timeout fires.
        if (session && handshakeStates.includes(session.state)) {
            session.updateState(this.STATE_HANDSHAKE_TIMED_OUT);
            const message = `Handshake with ${peerId} timed out. Please try initiating the session again.`;
            // Show the info message pane to the user.
            this.uiController.showInfoMessage(peerId, message, false); // No retry option for handshake timeout.
            this.uiController.playSound('error'); // Play error sound.
            // Reset the session internally after updating UI/state.
            // resetSession handles switching view if needed and file transfer cleanup.
            this.resetSession(peerId, false, "Handshake timed out."); // notifyUserViaAlert=false as info pane is shown.
        } else if (session) {
             // Log ignored timeout only if DEBUG is enabled (e.g., session ended before timeout fired).
             if (config.DEBUG) {
                 console.log(`Session [${peerId}] Handshake timeout fired but session state (${session.state}) is no longer relevant. Ignoring.`);
             }
             session.handshakeTimeoutId = null; // Ensure ID is cleared if state changed.
        } else {
             // Always log warning for non-existent session timeout.
             console.warn(`Session [${peerId}] Handshake timeout fired but session no longer exists.`);
        }
    }

    /**
     * Starts a timeout for the initial session request (Type 1).
     * If the timeout expires before the peer accepts/denies, handleRequestTimeout is called.
     * @param {Session} session - The session instance (in INITIATING_SESSION state) to start the timeout for.
     */
    startRequestTimeout(session) {
        this.clearRequestTimeout(session); // Clear any existing request timeout for this session.
        // Log timeout start only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Session [${session.peerId}] Starting request timeout (${this.REQUEST_TIMEOUT_DURATION}ms)`);
        }
        // Schedule the timeout.
        session.requestTimeoutId = setTimeout(() => {
            this.handleRequestTimeout(session.peerId);
        }, this.REQUEST_TIMEOUT_DURATION);
    }

    /**
     * Clears the active initial request timeout for a specific session, if one exists.
     * @param {Session} session - The session instance whose request timeout should be cleared.
     */
    clearRequestTimeout(session) {
        if (session && session.requestTimeoutId) {
            // Log timeout clear only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`Session [${session.peerId}] Clearing request timeout.`);
            }
            clearTimeout(session.requestTimeoutId);
            session.requestTimeoutId = null; // Clear the stored ID.
        }
    }

    /**
     * Handles the expiration of the initial request timeout for a specific peer.
     * Updates the session state to REQUEST_TIMED_OUT, plays an error sound,
     * and shows an info message allowing the user to retry the request.
     * @param {string} peerId - The ID of the peer whose request timed out.
     */
    handleRequestTimeout(peerId) {
        // Always log timeout errors.
        console.error(`Session [${peerId}] Initial request timed out!`);
        const session = this.sessions.get(peerId);
        // Check if the session exists and is still in the initial state when the timeout fires.
        if (session && session.state === this.STATE_INITIATING_SESSION) {
            session.updateState(this.STATE_REQUEST_TIMED_OUT);
            const message = `No response from ${peerId}. Request timed out.`;
            // Show info message with a retry option.
            this.uiController.showInfoMessage(peerId, message, true);
            this.uiController.playSound('error'); // Play error sound.
            // Do NOT reset the session here; allow the user to click Retry or Close in the info pane.
        } else if (session) {
            // Log ignored timeout only if DEBUG is enabled (e.g., request was accepted/denied just before timeout).
            if (config.DEBUG) {
                console.log(`Session [${peerId}] Request timeout fired but session state (${session.state}) is no longer relevant. Ignoring.`);
            }
            session.requestTimeoutId = null; // Ensure ID is cleared if state changed.
        } else {
            // Always log warning for non-existent session timeout.
            console.warn(`Session [${peerId}] Request timeout fired but session no longer exists.`);
        }
    }

    /**
     * Starts a timeout for the registration process (awaiting Type 0.1 or 0.2 from server).
     * If the timeout expires, handleRegistrationTimeout is called.
     */
    startRegistrationTimeout() {
        this.clearRegistrationTimeout(); // Clear any existing registration timeout.
        // Log timeout start only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Starting registration timeout (${this.REGISTRATION_TIMEOUT_DURATION}ms)`);
        }
        // Schedule the timeout.
        this.registrationTimeoutId = setTimeout(() => {
            this.handleRegistrationTimeout();
        }, this.REGISTRATION_TIMEOUT_DURATION);
    }

    /**
     * Clears the active registration timeout, if one exists.
     */
    clearRegistrationTimeout() {
        if (this.registrationTimeoutId) {
            // Log timeout clear only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("Clearing registration timeout.");
            }
            clearTimeout(this.registrationTimeoutId);
            this.registrationTimeoutId = null; // Clear the stored ID.
        }
    }

    /**
     * Handles the expiration of the registration timeout.
     * Updates manager state to FAILED_REGISTRATION, plays an error sound, alerts the user,
     * and re-enables the registration UI controls.
     */
    handleRegistrationTimeout() {
        // Always log timeout errors.
        console.error("Registration timed out!");
        // Only act if the manager was actually in the REGISTERING state when the timeout fired.
        if (this.managerState === this.STATE_REGISTERING) {
            this.updateManagerState(this.STATE_FAILED_REGISTRATION);
            const reason = "No response from server.";
            this.uiController.updateStatus(`Registration Failed: ${reason}`);
            this.uiController.playSound('error'); // Play error sound.
            // Use alert for registration timeout as it's a global failure preventing app use.
            alert(`Registration failed: ${reason}`);
            // Show registration UI again and re-enable input/button.
            this.uiController.showRegistration();
            this.uiController.setRegistrationControlsEnabled(true);
        }
    }
    // -----------------------------

    /**
     * Resets a specific session completely.
     * Cleans up its internal state (keys, messages, etc.), associated timeouts, UI elements (list item, message pane),
     * typing status, and any associated file transfer data (including IndexedDB chunks and object URLs).
     * Switches the view back to default if the reset session was displayed.
     *
     * @param {string} peerId - The ID of the peer whose session needs resetting.
     * @param {boolean} [notifyUserViaAlert=false] - Whether to show a fallback alert to the user with the reason (used if info pane isn't shown).
     * @param {string} [reason="Session reset."] - The reason for the reset (used in logs and optional alert).
     */
    async resetSession(peerId, notifyUserViaAlert = false, reason = "Session reset.") {
        const session = this.sessions.get(peerId);
        if (session) {
            // Log reset attempt only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`Resetting session with peer: ${peerId}. Reason: ${reason}`);
            }
            // 1. Clear all associated timeouts for this session.
            this.clearHandshakeTimeout(session);
            this.clearRequestTimeout(session);
            this.clearTypingIndicatorTimeout(session); // Clear peer typing indicator timeout.
            this.clearLocalTypingTimeout(peerId); // Clear local typing stop timeout.

            // 2. File Transfer Cleanup for this session.
            // Iterate through any active/pending transfers and clean them up.
            if (session.transferStates && session.transferStates.size > 0) {
                // Log cleanup only if DEBUG is enabled.
                if (config.DEBUG) console.log(`Cleaning up ${session.transferStates.size} file transfers for session ${peerId}`);
                const transferIds = Array.from(session.transferStates.keys());
                for (const transferId of transferIds) {
                    this.uiController.removeFileTransferMessage(transferId); // Removes UI element and revokes associated Object URL.
                    await this.deleteChunksFromDB(transferId); // Remove any chunks from IndexedDB.
                }
                // The transferStates map itself will be cleared by session.resetState() below.
            }

            // 3. Check if this session was the one being displayed or pending action before resetting.
            const wasDisplayed = (this.displayedPeerId === peerId);
            const wasPendingAction = (this.pendingPeerIdForAction === peerId);

            // 4. Reset the session object's internal state (keys, messages, etc.).
            session.resetState();
            // 5. Remove the session from the manager's active sessions map.
            this.sessions.delete(peerId);
            // 6. Clean up manager's typing state maps for this peer.
            this.isTypingToPeer.delete(peerId);
            this.typingStopTimeoutId.delete(peerId);

            // 7. Remove the session from the UI list in the sidebar.
            this.uiController.removeSessionFromList(peerId);

            // 8. Update UI based on whether the reset session was active.
            if (wasDisplayed) {
                this.displayedPeerId = null; // No session is displayed now.
                this.uiController.hideTypingIndicator(); // Hide indicator if this chat was active.
                // Show default view *unless* an info message was just displayed for this peer
                // (e.g., timeout, denial). The info pane should persist until closed by the user.
                if (!this.uiController.isInfoPaneVisibleFor(peerId)) {
                     this.uiController.showDefaultRegisteredView(this.identifier);
                }
                // Use alert only if requested AND info pane wasn't shown.
                if (notifyUserViaAlert && reason && !this.uiController.isInfoPaneVisibleFor(peerId)) { alert(reason); }
            }
            else if (wasPendingAction) {
                 // If it was pending action (incoming request), clear the flag.
                 this.pendingPeerIdForAction = null;
                 // If no other chat is displayed, show the welcome message.
                 if (!this.displayedPeerId) { this.uiController.showDefaultRegisteredView(this.identifier); }
                 // Use alert only if requested AND info pane wasn't shown.
                 if (notifyUserViaAlert && reason && !this.uiController.isInfoPaneVisibleFor(peerId)) { alert(reason); }
            } else {
                 // Session was reset but wasn't displayed or pending action (e.g., background cleanup on disconnect).
                 // Use alert only if requested by the caller.
                 if (notifyUserViaAlert && reason) { alert(reason); }
            }

        } else {
            // Always log this warning if trying to reset a non-existent session.
            console.warn(`Attempted to reset non-existent session for peer: ${peerId}`);
        }

        // After resetting, if no sessions remain and we are registered, ensure the default view is shown
        // and initiation controls are enabled.
         if (this.sessions.size === 0 && this.managerState === this.STATE_REGISTERED) {
             // Check again if any info pane is visible before showing default view.
             if (!this.displayedPeerId && !this.pendingPeerIdForAction && !this.uiController.isAnyInfoPaneVisible()) {
                 this.uiController.showDefaultRegisteredView(this.identifier);
             }
             this.uiController.updateStatus(`Registered as: ${this.identifier}`);
             this.uiController.setInitiationControlsEnabled(true);
         }
    }

    /**
     * Called when WebSocket connects but user is not registered. Shows the registration UI.
     * This method name is slightly misleading; it doesn't prompt, it just shows the UI.
     */
    promptForRegistration() {
        this.updateManagerState(this.STATE_CONNECTED_UNREGISTERED);
        this.uiController.showRegistration();
    }

    /**
     * Attempts to register the user with the server using the provided identifier.
     * Sends a Type 0 message, updates state, disables UI, and starts a registration timeout.
     * @param {string} id - The identifier chosen by the user.
     */
    attemptRegistration(id) {
        if (!id) { alert("Please enter an identifier."); return; } // Basic validation.
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Attempting registration for ID: ${id}`);
        this.updateManagerState(this.STATE_REGISTERING);
        // Disable registration UI elements and show loading state on the button.
        this.uiController.setRegistrationControlsEnabled(false, true);
        this.uiController.updateStatus(`Registering as ${id}...`);
        // Construct the registration message (Type 0).
        const msg = { type: 0, payload: { identifier: id } };
        // Send the message via WebSocketClient.
        if (this.wsClient.sendMessage(msg)) {
            // If sending was successful, start the registration timeout.
            this.startRegistrationTimeout();
        } else {
            // If sending failed (e.g., connection lost immediately), handle the failure locally.
            this.handleRegistrationFailure({ error: "Connection error. Cannot send registration." });
        }
    }

    /**
     * Initiates a new chat session with a target peer.
     * Creates a new Session instance, generates ECDH keys for it, sends a Type 1 request,
     * updates the UI to show the "Waiting..." state, plays a sound, and starts the request timeout.
     * Prevents initiating if another request is already pending.
     *
     * @param {string} targetId - The identifier of the peer to connect with.
     */
    async initiateSession(targetId) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Attempting to initiate session with: ${targetId}`);

        // Prevent starting a new request if another outgoing request is already pending user response.
        let pendingInitiationPeer = null;
        for (const [peerId, session] of this.sessions.entries()) {
            if (session.state === this.STATE_INITIATING_SESSION) {
                pendingInitiationPeer = peerId;
                break;
            }
        }
        if (pendingInitiationPeer) {
            alert(`Please cancel or wait for the pending request for ${pendingInitiationPeer} before starting a new one.`);
            return;
        }

        // Ensure the user is registered before initiating.
        if (this.managerState !== this.STATE_REGISTERED) {
            alert("Cannot initiate session: Not registered with the server. Current state: " + this.managerState);
            return;
        }
        // Validate targetId format and prevent self-chat.
        if (!targetId || typeof targetId !== 'string' || targetId.trim() === '') {
            alert("Invalid target identifier provided.");
            return;
        }
        if (targetId === this.identifier) {
            alert("Cannot start a chat session with yourself.");
            return;
        }
        // Prevent starting if a session (in any state) already exists for this peer.
        if (this.sessions.has(targetId)) {
            alert(`A session with ${targetId} already exists or is pending.`);
            // Switch to the existing session view for user context.
            this.switchToSessionView(targetId);
            return;
        }

        this.uiController.updateStatus(`Initiating session with ${targetId}...`);
        // Disable initiation controls while attempting to start to prevent duplicates.
        this.uiController.setInitiationControlsEnabled(false, true); // Show loading state on input/button.

        // 1. Create a new CryptoModule instance dedicated to this session.
        const crypto = new this.CryptoModuleClass();
        // 2. Create a new Session object, starting in the INITIATING_SESSION state.
        const newSession = new Session(targetId, this.STATE_INITIATING_SESSION, crypto);
        // 3. Add the session to the manager's map.
        this.sessions.set(targetId, newSession);
        // 4. Add the session to the UI list in the sidebar.
        this.uiController.addSessionToList(targetId);
        // 5. Switch the main view to this new session (will show the "Waiting..." pane).
        this.switchToSessionView(targetId);

        try {
            // 6. Generate ephemeral ECDH keys specifically for this session.
            const keysGenerated = await newSession.cryptoModule.generateECDHKeys();
            if (!keysGenerated) { throw new Error("Failed to generate cryptographic keys for the session."); }
            // Log key generation only if DEBUG is enabled.
            if (config.DEBUG) console.log(`ECDH keys generated for session with ${targetId}.`);

            // 7. Construct and send the SESSION_REQUEST (Type 1) message.
            // Payload includes target and sender IDs.
            const msg = { type: 1, payload: { targetId: targetId, senderId: this.identifier } };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending SESSION_REQUEST (Type 1):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // 8. Play send request sound and start the request timeout if message sent successfully.
                this.uiController.playSound('sendrequest');
                this.startRequestTimeout(newSession); // Start timer waiting for peer's response (Accept/Deny).
                this.uiController.updateStatus(`Waiting for response from ${targetId}...`);
            } else {
                // Throw error if sending the request failed (e.g., connection issue).
                throw new Error("Connection error. Failed to send session request.");
            }
        } catch (error) {
            // Handle errors during key generation or sending the request.
            // Always log errors.
            console.error("Error during initiateSession:", error);
            this.uiController.playSound('error'); // Play error sound.
            // Use showInfoMessage for better user feedback instead of a simple alert.
            this.uiController.showInfoMessage(targetId, `Failed to initiate session: ${error.message}`, false);
            // Clean up the failed session attempt.
            await this.resetSession(targetId, false); // notifyUserViaAlert=false as info pane handles it.
        } finally {
            // Re-enable initiation controls regardless of success/failure.
            this.uiController.setInitiationControlsEnabled(true);
        }
    }

    /**
     * Accepts an incoming session request from a peer.
     * Generates ECDH keys for the session, sends a Type 2 acceptance message containing the public ECDH key,
     * updates state, and starts the handshake timeout.
     *
     * @param {string} peerId - The identifier of the peer whose request is being accepted.
     */
    async acceptRequest(peerId) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Attempting to accept session request from: ${peerId}`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is in the correct state (REQUEST_RECEIVED).
        if (!session || session.state !== this.STATE_REQUEST_RECEIVED) {
            // Always log this warning.
            console.warn(`Cannot accept request for ${peerId}: Session not found or invalid state (${session?.state}).`);
            // If session exists but wrong state, show its current view. Otherwise show default.
            if (session) this.switchToSessionView(peerId);
            else this.uiController.showDefaultRegisteredView(this.identifier);
            return;
        }

        // Disable incoming request buttons (Accept/Deny) and show loading state.
        this.uiController.setIncomingRequestControlsEnabled(false, true);

        // Clear the pending action flag as we are handling it now.
        if (this.pendingPeerIdForAction === peerId) { this.pendingPeerIdForAction = null; }

        // Update session state and UI status.
        session.updateState(this.STATE_GENERATING_ACCEPT_KEYS);
        this.uiController.updateStatus(`Accepting request from ${peerId}, generating keys...`);
        // Switch view to this session (will likely show welcome/loading initially while keys generate).
        this.switchToSessionView(peerId);

        try {
            // 1. Generate ephemeral ECDH keys specifically for this session.
            const keysGenerated = await session.cryptoModule.generateECDHKeys();
            if (!keysGenerated) { throw new Error("Failed to generate cryptographic keys for the session."); }
            // 2. Export the generated public ECDH key to Base64 SPKI format to send to the peer.
            const publicKeyBase64 = await session.cryptoModule.getPublicKeyBase64();
            if (!publicKeyBase64) { throw new Error("Failed to export public key."); }

            // 3. Construct and send the SESSION_ACCEPT (Type 2) message including the public key.
            const msg = { type: 2, payload: { targetId: peerId, senderId: this.identifier, publicKey: publicKeyBase64 } };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending SESSION_ACCEPT (Type 2 with ECDH key):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // 4. Update state: Now waiting for the initiator's public key (Type 4).
                session.updateState(this.STATE_AWAITING_CHALLENGE);
                // Start the handshake timeout, waiting for the next step from the initiator.
                this.startHandshakeTimeout(session);
                this.uiController.updateStatus(`Waiting for ${peerId}'s public key...`);
            } else {
                // Throw error if sending the acceptance failed.
                throw new Error("Connection error. Failed to send session acceptance.");
            }
        } catch (error) {
            // Handle errors during key generation/export or sending the acceptance.
            // Always log errors.
            console.error("Error during acceptRequest:", error);
            this.uiController.playSound('error'); // Play error sound.
            // Use showInfoMessage for better user feedback.
            this.uiController.showInfoMessage(peerId, `Failed to accept session: ${error.message}`, false);
            // Clean up the failed session attempt.
            await this.resetSession(peerId, false); // notifyUserViaAlert=false.
        } finally {
            // Re-enable incoming request controls only if the process failed before sending the message
            // (i.e., if the session is still in the GENERATING_ACCEPT_KEYS state).
            if (session?.state === this.STATE_GENERATING_ACCEPT_KEYS) {
                 this.uiController.setIncomingRequestControlsEnabled(true);
            }
        }
    }

    /**
     * Denies an incoming session request from a peer.
     * Sends a Type 3 denial message (best effort), plays end sound, and resets the session locally.
     *
     * @param {string} peerId - The identifier of the peer whose request is being denied.
     */
    async denyRequest(peerId) {
        // Log denial only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Denying session request from: ${peerId}`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is in the correct state (REQUEST_RECEIVED).
        if (!session || session.state !== this.STATE_REQUEST_RECEIVED) {
            // Always log this warning.
            console.warn(`Cannot deny request for ${peerId}: Session not found or invalid state (${session?.state}).`);
            return;
        }

        // Disable incoming request buttons and show loading state.
        this.uiController.setIncomingRequestControlsEnabled(false, true);

        // Clear the pending action flag.
        if (this.pendingPeerIdForAction === peerId) { this.pendingPeerIdForAction = null; }

        // Construct and send the SESSION_DENY (Type 3) message.
        const msg = { type: 3, payload: { targetId: peerId, senderId: this.identifier } };
        // Log sending only if DEBUG is enabled.
        if (config.DEBUG) console.log("Sending SESSION_DENY (Type 3):", msg);
        this.wsClient.sendMessage(msg); // Send best effort; don't wait for confirmation.

        // Play end sound as the potential session is being terminated.
        this.uiController.playSound('end');

        // Reset the session locally immediately after sending denial.
        await this.resetSession(peerId, false, `Denied request from ${peerId}.`); // notifyUserViaAlert=false.
        // Show the default welcome view as the request pane is now gone.
        this.uiController.showDefaultRegisteredView(this.identifier);
    }

    // --- Send methods called by processMessageResult ---

    /**
     * Sends the PUBLIC_KEY_RESPONSE (Type 4) message containing own public ECDH key.
     * Called by the initiator after receiving Type 2 (Accept) from the responder and deriving keys.
     * @param {Session} session - The session object.
     */
    async sendPublicKeyResponse(session) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${session.peerId}] Attempting to send PUBLIC_KEY_RESPONSE (Type 4 with ECDH key)...`);
        try {
            // Export own public ECDH key to Base64 SPKI format.
            const publicKeyBase64 = await session.cryptoModule.getPublicKeyBase64();
            if (!publicKeyBase64) { throw new Error("Failed to export own public key."); } // Throw on failure.

            // Construct and send the message.
            const msg = { type: 4, payload: { targetId: session.peerId, senderId: this.identifier, publicKey: publicKeyBase64 } };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending PUBLIC_KEY_RESPONSE (Type 4 with ECDH key):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // Update state: Initiator now waits for the challenge (Type 5).
                session.updateState(this.STATE_AWAITING_CHALLENGE_RESPONSE); // State updated after successful send.
                // Start the handshake timeout for the next step.
                this.startHandshakeTimeout(session);
                this.uiController.updateStatus(`Waiting for challenge from ${session.peerId}...`);
            } else {
                // Throw error if sending the message failed.
                throw new Error("Connection error sending key response.");
            }
        } catch (error) {
            // Always log errors.
            console.error(`Session [${session.peerId}] Error sending Type 4:`, error);
            this.uiController.playSound('error'); // Play error sound.
            // Use showInfoMessage for feedback.
            this.uiController.showInfoMessage(session.peerId, `Handshake Error: ${error.message}`, false);
            await this.resetSession(session.peerId, false); // notifyUserViaAlert=false.
        }
    }

    /**
     * Generates a challenge, encrypts it using the derived AES session key,
     * and sends it as the KEY_CONFIRMATION_CHALLENGE (Type 5) message.
     * Called by the responder after receiving Type 4 (Initiator's Key) and deriving the session key.
     * @param {Session} session - The session object.
     */
    async sendKeyConfirmationChallenge(session) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${session.peerId}] Attempting to send KEY_CONFIRMATION_CHALLENGE (Type 5 using derived key)...`);
        try {
            // Ensure the session key has been derived before proceeding.
            if (!session.cryptoModule.derivedSessionKey) {
                throw new Error("Session key not derived before sending challenge.");
            }
            // Generate unique challenge data (e.g., text including IDs and timestamp).
            const challengeText = `Challenge_for_${session.peerId}_from_${this.identifier}_${Date.now()}`;
            const challengeBuffer = session.cryptoModule.encodeText(challengeText);
            // Store the raw challenge buffer locally to verify the response later.
            session.challengeSent = challengeBuffer;
            // Log generation only if DEBUG is enabled.
            if (config.DEBUG) console.log("Generated challenge data.");

            // Encrypt the challenge buffer using the derived AES session key.
            const encryptionResult = await session.cryptoModule.encryptAES(challengeBuffer);
            if (!encryptionResult) { throw new Error("Failed to encrypt challenge."); } // Throw on failure.

            // Encode the unique IV and the encrypted buffer to Base64 for transmission.
            const ivBase64 = session.cryptoModule.arrayBufferToBase64(encryptionResult.iv);
            const encryptedBase64 = session.cryptoModule.arrayBufferToBase64(encryptionResult.encryptedBuffer);

            // Construct and send the message with IV and encrypted challenge data.
            const msg = {
                type: 5,
                payload: {
                    targetId: session.peerId,
                    senderId: this.identifier,
                    iv: ivBase64,
                    encryptedChallenge: encryptedBase64 // Field contains the encrypted challenge.
                }
            };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending KEY_CONFIRMATION_CHALLENGE (Type 5):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // Update state: Responder now waits for the challenge response (Type 6).
                session.updateState(this.STATE_AWAITING_CHALLENGE_RESPONSE); // Update state after successful send.
                // Start the handshake timeout for the next step.
                this.startHandshakeTimeout(session);
                this.uiController.updateStatus(`Challenge sent to ${session.peerId}. Waiting for response...`);
            } else {
                 // Throw error if sending the message failed.
                 throw new Error("Connection error sending challenge.");
            }
        } catch (error) {
            // Always log errors.
            console.error(`Session [${session.peerId}] Error sending Type 5:`, error);
            this.uiController.playSound('error'); // Play error sound.
            // Use showInfoMessage for feedback.
            this.uiController.showInfoMessage(session.peerId, `Handshake Error: ${error.message}`, false);
            await this.resetSession(session.peerId, false); // notifyUserViaAlert=false.
        }
    }

    /**
     * Encrypts the received challenge data (using the derived AES session key) and sends it back
     * as the KEY_CONFIRMATION_RESPONSE (Type 6) message.
     * Called by the initiator after receiving and decrypting Type 5 (Challenge).
     * @param {Session} session - The session object.
     * @param {ArrayBuffer} challengeData - The raw decrypted challenge data received from the peer.
     */
    async sendKeyConfirmationResponse(session, challengeData) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${session.peerId}] Attempting to send KEY_CONFIRMATION_RESPONSE (Type 6 using derived key)...`);
        try {
            // Ensure session key is derived and the challenge data to encrypt is available.
            if (!session.cryptoModule.derivedSessionKey || !challengeData) {
                throw new Error("Missing session key or challenge data for response.");
            }
            // Encrypt the original challenge data using the derived AES session key.
            const encryptionResult = await session.cryptoModule.encryptAES(challengeData);
            if (!encryptionResult) { throw new Error("Failed to encrypt challenge response."); } // Throw on failure.

            // Encode the unique IV and the encrypted buffer to Base64 for transmission.
            const ivBase64 = session.cryptoModule.arrayBufferToBase64(encryptionResult.iv);
            const encryptedBase64 = session.cryptoModule.arrayBufferToBase64(encryptionResult.encryptedBuffer);

            // Construct and send the message with IV and encrypted response data.
            const msg = {
                type: 6,
                payload: {
                    targetId: session.peerId,
                    senderId: this.identifier,
                    iv: ivBase64,
                    encryptedResponse: encryptedBase64 // Field contains the encrypted response.
                }
            };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending KEY_CONFIRMATION_RESPONSE (Type 6):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // Update state: Initiator now waits for the final confirmation (Type 7).
                session.updateState(this.STATE_AWAITING_FINAL_CONFIRMATION); // Update state after successful send.
                // Start the handshake timeout for the final step.
                this.startHandshakeTimeout(session);
                this.uiController.updateStatus(`Challenge response sent to ${session.peerId}. Waiting for final confirmation...`);
            } else {
                 // Throw error if sending the message failed.
                 throw new Error("Connection error sending challenge response.");
            }
        } catch (error) {
            // Always log errors.
            console.error(`Session [${session.peerId}] Error sending Type 6:`, error);
            this.uiController.playSound('error'); // Play error sound.
            // Use showInfoMessage for feedback.
            this.uiController.showInfoMessage(session.peerId, `Handshake Error: ${error.message}`, false);
            await this.resetSession(session.peerId, false); // notifyUserViaAlert=false.
        }
    }

    /**
     * Sends the SESSION_ESTABLISHED (Type 7) message to confirm successful handshake completion.
     * Called by the responder after receiving and verifying Type 6 (Response).
     * Plays the session begin sound and updates the UI to the active chat state.
     * @param {Session} session - The session object.
     */
    async sendSessionEstablished(session) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${session.peerId}] Attempting to send SESSION_ESTABLISHED (Type 7)...`);
        try {
            // Construct the final confirmation message. Payload is simple.
            const msg = { type: 7, payload: { targetId: session.peerId, senderId: this.identifier, message: "Session established successfully!" } };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending SESSION_ESTABLISHED (Type 7):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // Handshake is complete for the responder!
                session.updateState(this.STATE_ACTIVE_SESSION); // Update state to active.
                this.clearHandshakeTimeout(session); // Handshake successful, clear the timeout.
                this.uiController.addSessionToList(session.peerId); // Ensure session is in the UI list.
                this.switchToSessionView(session.peerId); // Switch to the active chat view.
                this.uiController.playSound('begin'); // Play session begin sound.
                // Log session active message (significant event, not wrapped in DEBUG).
                console.log(`%cSession active with ${session.peerId}. Ready to chat!`, "color: green; font-weight: bold;");
            } else {
                 // Throw error if sending the final confirmation fails.
                 throw new Error("Connection error sending final confirmation.");
            }
        } catch (error) {
            // Always log errors.
            console.error(`Session [${session.peerId}] Error sending Type 7:`, error);
            this.uiController.playSound('error'); // Play error sound.
            // Use showInfoMessage for feedback.
            this.uiController.showInfoMessage(session.peerId, `Handshake Error: ${error.message}`, false);
            await this.resetSession(session.peerId, false); // notifyUserViaAlert=false.
        }
    }

    /**
     * Handles sending a chat message or processing a slash command entered by the user.
     * Parses input for commands (/me, /end, /version, /info, /help).
     * If it's a command like /me, it sends a structured JSON payload indicating an action.
     * Otherwise, it sends a regular message payload.
     * Encrypts the JSON payload (as a string) using the session's AES key and sends as Type 8.
     * Updates the local UI immediately with the sent message or command output/error.
     *
     * @param {string} peerId - The identifier of the recipient peer.
     * @param {string} text - The raw text entered by the user in the message input field.
     */
    async sendEncryptedMessage(peerId, text) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Attempting to send message/command to ${peerId}: "${text}"`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is fully active before sending.
        if (!session || session.state !== this.STATE_ACTIVE_SESSION) {
            // Always log this warning.
            console.warn(`Cannot send message: Session with ${peerId} not active.`);
            // Display error in the chat window if this session is active.
            if (this.displayedPeerId === peerId) {
                this.uiController.addCommandError("Error: Cannot send message, session is not active.");
            }
            return;
        }
        // Ensure the derived session key exists for encryption.
        if (!session.cryptoModule.derivedSessionKey) {
            // Always log this critical error.
            console.error(`Session [${peerId}] Encryption key error: Missing derived session key for active session.`);
            this.uiController.playSound('error');
            this.uiController.showInfoMessage(peerId, "Encryption Error: Session key is missing. Please restart the session.", false);
            await this.resetSession(peerId, false);
            return;
        }
        // Ensure message text is valid (not null, is a string, not just whitespace).
        if (!text || typeof text !== 'string' || text.trim().length === 0) {
            // Always log this warning.
            console.warn("Attempted to send empty message."); return;
        }

        // If the user was marked as typing, send a TYPING_STOP message first before sending the actual message.
        this.sendTypingStop(peerId);

        // Disable chat controls and show loading state while processing/encrypting/sending.
        this.uiController.setChatControlsEnabled(false, true);
        this.uiController.updateStatus(`Processing message to ${peerId}...`);
        let messageSent = false; // Flag to track if the network send was successful.

        try {
            let payloadToSend = null; // This will hold the object {isAction, text} to be JSONified and encrypted, or null if handled locally.
            let localDisplayHandled = false; // Flag to track if local UI update is done by command processing.

            // --- Command Parsing Logic ---
            if (text.startsWith('/')) {
                const spaceIndex = text.indexOf(' ');
                // Extract command (lowercase) and arguments.
                const command = (spaceIndex === -1 ? text.substring(1) : text.substring(1, spaceIndex)).toLowerCase();
                const args = (spaceIndex === -1 ? '' : text.substring(spaceIndex + 1)).trim();

                // Log command parsing only if DEBUG is enabled.
                if (config.DEBUG) console.log(`Parsed command: '${command}', args: '${args}'`);

                localDisplayHandled = true; // Assume command handles its own local display unless it results in a message being sent.

                switch (command) {
                    case 'me': // Action message
                        if (args) {
                            // Valid /me command: Prepare payload to send.
                            payloadToSend = { isAction: true, text: args };
                            // Display the action locally immediately.
                            this.uiController.addMeActionMessage(this.identifier, args);
                        } else {
                            // Invalid /me command (no arguments): Display error locally.
                            this.uiController.addCommandError("Error: /me command requires an action text.");
                        }
                        break;
                    case 'end': // End current session
                        // Use getActivePeerId() to ensure we're ending the *currently viewed* chat.
                        const activePeerIdForEnd = this.getActivePeerId();
                        if (activePeerIdForEnd === peerId) { // Check if the command is for the active chat.
                            this.endSession(peerId); // Call endSession (handles UI/reset/sending Type 9).
                        } else if (activePeerIdForEnd) {
                            this.uiController.addCommandError(`Error: /end can only be used in the active chat (${activePeerIdForEnd}).`);
                        } else {
                            this.uiController.addCommandError("Error: No active session to end.");
                        }
                        break;
                    case 'version': // Display client version
                        this.uiController.addVersionInfo(config.APP_VERSION);
                        break;
                    case 'info': // Display session info
                        const activePeerIdForInfo = this.getActivePeerId();
                        if (activePeerIdForInfo === peerId) { // Check if the command is for the active chat.
                            const httpsUrl = window.location.href;
                            const wssUrl = this.wsClient.url;
                            this.uiController.addSessionInfo(httpsUrl, wssUrl, this.identifier, peerId);
                        } else if (activePeerIdForInfo) {
                            this.uiController.addCommandError(`Error: /info can only be used in the active chat (${activePeerIdForInfo}).`);
                        } else {
                            this.uiController.addCommandError("Error: No active session selected for /info command.");
                        }
                        break;
                    case 'help': // Display help message
                        this.uiController.addHelpInfo();
                        break;
                    default: // Unknown command
                        this.uiController.addCommandError(`Error: Unknown command "/${command}". Type /help for a list of commands.`);
                        break;
                }
            } else {
                // Regular message (no slash command).
                payloadToSend = { isAction: false, text: text };
                // Add the message to the session's history.
                session.addMessageToHistory(this.identifier, text, 'own');
                // Display the message locally immediately if this chat is active.
                if (this.displayedPeerId === peerId) {
                    this.uiController.addMessage(this.identifier, text, 'own');
                }
                localDisplayHandled = true; // Local display handled here.
            }
            // --- End Command Parsing Logic ---

            // Only proceed to encrypt and send if payloadToSend was set (i.e., not a purely local command).
            if (payloadToSend) {
                // 1. Encode the payload object to a JSON string, then to UTF-8 ArrayBuffer.
                const payloadJson = JSON.stringify(payloadToSend);
                const payloadBuffer = session.cryptoModule.encodeText(payloadJson);

                // 2. Encrypt the payload buffer using the derived AES session key.
                this.uiController.updateStatus(`Encrypting message to ${peerId}...`);
                const aesResult = await session.cryptoModule.encryptAES(payloadBuffer);
                if (!aesResult) throw new Error("AES encryption failed.");

                // 3. Encode the unique IV and the encrypted data to Base64 for transmission.
                const ivBase64 = session.cryptoModule.arrayBufferToBase64(aesResult.iv);
                const encryptedDataBase64 = session.cryptoModule.arrayBufferToBase64(aesResult.encryptedBuffer);

                // 4. Construct the ENCRYPTED_CHAT_MESSAGE (Type 8) payload.
                const message = {
                    type: 8,
                    payload: {
                        targetId: peerId,
                        senderId: this.identifier,
                        iv: ivBase64,
                        data: encryptedDataBase64 // Contains the encrypted JSON string.
                    }
                };
                this.uiController.updateStatus(`Sending message to ${peerId}...`);
                // Log sending only if DEBUG is enabled.
                if (config.DEBUG) console.log(`Sending ENCRYPTED_CHAT_MESSAGE (Type 8) to ${peerId}`);

                // 5. Send the message via WebSocketClient.
                if (this.wsClient.sendMessage(message)) {
                    messageSent = true; // Mark send as successful.
                    // Local display was already handled above by command parsing or regular message logic.
                } else {
                    // sendMessage returning false usually indicates a connection issue.
                    // Always log this error.
                    console.error("sendMessage returned false, connection likely lost.");
                    // Display error in the chat window if this session is active.
                    if (this.displayedPeerId === peerId) {
                        this.uiController.addSystemMessage("Error: Failed to send message (connection lost?).");
                    }
                }
            } else if (!localDisplayHandled) {
                // This case handles scenarios where a command was parsed but resulted in no action/message and didn't display anything locally.
                // Log this warning only if DEBUG is enabled.
                if (config.DEBUG) console.log("Command processed locally, nothing sent to peer or displayed.");
            }

        } catch (error) {
            // Handle errors during the encryption or sending process.
            // Always log errors.
            console.error("Error during sendEncryptedMessage:", error);
            this.uiController.playSound('error'); // Play error sound.
            // Display error in the chat window if this session is active.
            if (this.displayedPeerId === peerId) {
                this.uiController.addCommandError(`Error sending message: ${error.message}`);
            } else {
                // Fallback alert if the error occurs for a non-displayed session.
                alert(`Error sending message to ${peerId}: ${error.message}`);
            }
        } finally {
             // Re-enable chat controls regardless of success/failure.
             this.uiController.setChatControlsEnabled(true);
             // Update status and focus input if the session is still active after processing.
             if (session?.state === this.STATE_ACTIVE_SESSION) {
                 this.uiController.updateStatus(`Session active with ${peerId}.`);
                 this.uiController.focusMessageInput();
             }
        }
    }


    /**
     * Ends the chat session with the specified peer from the user's side.
     * Sends a Type 9 (SESSION_END_REQUEST) message to the peer (best effort),
     * plays the end sound, shows an info pane locally confirming the action, and resets the session.
     *
     * @param {string} peerId - The identifier of the peer whose session to end.
     */
    async endSession(peerId) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Attempting to end session with ${peerId}...`);
        const session = this.sessions.get(peerId);
        if (!session) {
            // Always log this warning.
            console.warn(`Attempted to end non-existent session with ${peerId}.`);
            return; // Ignore if session doesn't exist.
        }

        // Disable chat controls while ending.
        this.uiController.setChatControlsEnabled(false, true);
        // Construct and send the SESSION_END_REQUEST (Type 9) message.
        const endMessage = { type: 9, payload: { targetId: peerId, senderId: this.identifier } };
        // Log sending only if DEBUG is enabled.
        if (config.DEBUG) console.log("Sending SESSION_END_REQUEST (Type 9):", endMessage);
        this.wsClient.sendMessage(endMessage); // Send best effort; don't wait for confirmation.
        this.uiController.updateStatus(`Ending session with ${peerId}...`);

        // Play end sound locally.
        this.uiController.playSound('end');

        // Show info pane locally *before* resetting the session to confirm the action.
        const reason = `You ended the session with ${peerId}.`;
        this.uiController.showInfoMessage(peerId, reason, false); // Show info, no retry option.
        // Reset the session locally immediately, but without the alert fallback (info pane handles notification).
        await this.resetSession(peerId, false, reason); // notifyUserViaAlert = false.
    }

    /**
     * Handles the user clicking the "Close" button on an info message pane (denial, timeout, error).
     * If the session associated with the pane is in a terminal error/denial state,
     * it resets the session. Otherwise (e.g., user manually ended), it just hides the pane
     * and shows the default view if nothing else is active.
     *
     * @param {string} peerId - The peer ID associated with the info message being closed.
     */
    async closeInfoMessage(peerId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Closing info message regarding ${peerId}`);
        // Disable info pane controls while processing.
        this.uiController.setInfoControlsEnabled(false, true);

        // Check if the session still exists and if it's in a state that requires cleanup upon closing the info pane.
        const session = this.sessions.get(peerId);
        const terminalStates = [
            this.STATE_DENIED,
            this.STATE_REQUEST_TIMED_OUT,
            this.STATE_HANDSHAKE_TIMED_OUT
            // Add other states here if they should trigger a reset when the info pane is closed.
        ];
        if (session && terminalStates.includes(session.state)) {
            // If the session is in a terminal state (timeout, denial), reset it now.
            if (config.DEBUG) console.log(`Session [${peerId}] is in terminal state (${session.state}). Resetting.`);
            await this.resetSession(peerId, false); // notifyUserViaAlert = false.
        } else if (session) {
            // If the session exists but isn't in a terminal state (e.g., user manually ended, info pane shown before reset),
            // it should have already been reset or will be handled differently. Just log for debugging.
            if (config.DEBUG) console.log(`Info pane closed for session [${peerId}] in state ${session.state}. Session should already be reset or handled.`);
        } else {
            // If the session doesn't exist (already reset), log for debugging.
            if (config.DEBUG) console.log(`Info pane closed for already reset session [${peerId}].`);
        }

        // Hide the info pane (implicitly done by showDefaultRegisteredView or switchToSessionView if needed).
        // Check if the closed info pane was the one being displayed.
        if (this.displayedPeerId === peerId) {
            this.displayedPeerId = null; // Clear displayed peer since info pane is closing.
        }
        // Show default view if nothing else is active or pending.
        if (!this.displayedPeerId && !this.pendingPeerIdForAction) {
            this.uiController.showDefaultRegisteredView(this.identifier);
        } else if (this.displayedPeerId) {
            // If another session *is* active, ensure its view is shown correctly.
            this.switchToSessionView(this.displayedPeerId);
        } else {
            // If no session displayed, but maybe an incoming request is pending?
            // This case might need refinement depending on desired UI flow. Default view is safest.
            this.uiController.showDefaultRegisteredView(this.identifier);
        }
    }


    /**
     * Handles the user clicking the "Retry" button after a request timeout.
     * Resets the session state to INITIATING_SESSION, resends the initial SESSION_REQUEST (Type 1) message,
     * plays the send request sound, and starts the request timeout again.
     * Prevents retrying if another request is already pending.
     *
     * @param {string} peerId - The peer ID associated with the timed-out request to retry.
     */
    async retryRequest(peerId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Retrying session request with ${peerId}`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is in a retryable state (REQUEST_TIMED_OUT).
        if (session && session.state === this.STATE_REQUEST_TIMED_OUT) {

            // Prevent retrying if another outgoing request is already pending user response.
            let pendingInitiationPeer = null;
            for (const [pId, s] of this.sessions.entries()) {
                // Check other sessions (pId !== peerId).
                if (pId !== peerId && s.state === this.STATE_INITIATING_SESSION) {
                    pendingInitiationPeer = pId;
                    break;
                }
            }
            if (pendingInitiationPeer) {
                alert(`Please cancel or wait for the pending request for ${pendingInitiationPeer} before retrying the request for ${peerId}.`);
                return;
            }

            // Disable info pane controls (Retry/Close) and show loading state.
            this.uiController.setInfoControlsEnabled(false, true);
            this.uiController.updateStatus(`Retrying session with ${peerId}...`);
            // Reset session state back to initiating.
            session.updateState(this.STATE_INITIATING_SESSION);
            // Clear any lingering timeouts from the previous attempt.
            this.clearRequestTimeout(session);
            this.clearHandshakeTimeout(session); // Should be null, but clear just in case.
            // Switch view back to the "Waiting..." pane for this session.
            this.switchToSessionView(peerId);

            // Construct and resend the SESSION_REQUEST (Type 1) message.
            const msg = { type: 1, payload: { targetId: peerId, senderId: this.identifier } };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Re-sending SESSION_REQUEST (Type 1):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // Play send request sound and start the request timeout again.
                this.uiController.playSound('sendrequest');
                this.startRequestTimeout(session);
                this.uiController.updateStatus(`Waiting for response from ${peerId}...`);
            } else {
                 // Use showInfoMessage for feedback if send fails.
                 this.uiController.showInfoMessage(peerId, "Connection error retrying request.", false);
                 this.uiController.playSound('error'); // Play error sound.
                 await this.resetSession(peerId, false); // Reset session.
            }
        } else {
            // Always log this warning if trying to retry from an invalid state.
            console.warn(`Cannot retry request for ${peerId}, session not found or not in REQUEST_TIMED_OUT state (${session?.state}).`);
            // If session exists but wrong state, close the info message.
            if (session) { await this.closeInfoMessage(peerId); }
            // If session doesn't exist, just show default view.
            else { this.uiController.showDefaultRegisteredView(this.identifier); }
        }
    }

    /**
     * Handles the user clicking the "Cancel Request" button while waiting for a peer response (INITIATING_SESSION state).
     * Sends a Type 9 message (interpreted as cancellation by the server/peer if handshake not complete),
     * plays the end sound, and resets the session locally.
     *
     * @param {string} peerId - The peer ID of the outgoing request to cancel.
     */
    async cancelRequest(peerId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Cancelling session request to ${peerId}`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is in the initiating state.
        if (session && session.state === this.STATE_INITIATING_SESSION) {
            // Disable waiting pane controls (Cancel button).
            this.uiController.setWaitingControlsEnabled(false, true);
            // Clear the request timeout as we are cancelling.
            this.clearRequestTimeout(session);
            // Construct and send a SESSION_END_REQUEST (Type 9). Server handles this as cancellation if handshake incomplete.
            const cancelMsg = { type: 9, payload: { targetId: peerId, senderId: this.identifier } };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending SESSION_END_REQUEST (Type 9) for cancellation:", cancelMsg);
            this.wsClient.sendMessage(cancelMsg); // Send best effort.
            // Play end sound locally.
            this.uiController.playSound('end');
            // Reset the session locally.
            await this.resetSession(peerId, false, `Request to ${peerId} cancelled.`); // notifyUserViaAlert=false.
        } else {
            // Always log this warning if trying to cancel from an invalid state.
            console.warn(`Cannot cancel request for ${peerId}, session not found or not in initiating state (${session?.state})`);
        }
    }

    // --- Local Typing Handlers ---

    /**
     * Called by main.js when the local user types in the message input for an active chat.
     * Sends a TYPING_START (Type 10) message to the peer if not already sent recently,
     * and resets the timeout for sending the TYPING_STOP message.
     *
     * @param {string} peerId - The peer ID of the active chat session where typing occurred.
     */
    handleLocalTyping(peerId) {
        const session = this.sessions.get(peerId);
        // Only handle typing for fully active sessions.
        if (!session || session.state !== this.STATE_ACTIVE_SESSION) {
            return;
        }

        // If the user wasn't previously marked as typing to this specific peer...
        if (!this.isTypingToPeer.get(peerId)) {
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Sending TYPING_START to ${peerId}`);
            // Construct and send the TYPING_START (Type 10) message.
            const msg = { type: 10, payload: { targetId: peerId, senderId: this.identifier } };
            if (this.wsClient.sendMessage(msg)) {
                // Mark the user as typing *after* successful send.
                this.isTypingToPeer.set(peerId, true);
            } else {
                // If send failed (e.g., connection dropped), don't proceed with timeout logic.
                return;
            }
        }

        // Clear any existing timeout scheduled to send TYPING_STOP for this peer.
        this.clearLocalTypingTimeout(peerId);

        // Set a new timeout. If the user doesn't type again within TYPING_STOP_DELAY milliseconds,
        // the sendTypingStop function will be called automatically.
        const timeoutId = setTimeout(() => {
            this.sendTypingStop(peerId);
        }, this.TYPING_STOP_DELAY);
        // Store the new timeout ID, associated with the peer.
        this.typingStopTimeoutId.set(peerId, timeoutId);
    }

    /**
     * Sends a TYPING_STOP (Type 11) message to the peer if the user was marked as typing to them.
     * Called either by the timeout in handleLocalTyping or explicitly (e.g., before sending a message).
     * Clears the local typing state and the associated timeout.
     *
     * @param {string} peerId - The peer ID to send the TYPING_STOP message to.
     */
    sendTypingStop(peerId) {
        // Only send if the user was actually marked as typing to this peer.
        if (this.isTypingToPeer.get(peerId)) {
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Sending TYPING_STOP to ${peerId}`);
            // Construct and send the TYPING_STOP (Type 11) message.
            const msg = { type: 11, payload: { targetId: peerId, senderId: this.identifier } };
            this.wsClient.sendMessage(msg); // Send best effort.
            // Mark the user as no longer typing to this peer.
            this.isTypingToPeer.set(peerId, false);
        }
        // Always clear the timeout associated with this peer, even if we didn't send the message (e.g., state changed).
        this.clearLocalTypingTimeout(peerId);
    }

    /**
     * Clears the timeout associated with sending a TYPING_STOP message for a specific peer.
     * @param {string} peerId - The peer ID whose typing stop timeout should be cleared.
     */
    clearLocalTypingTimeout(peerId) {
        if (this.typingStopTimeoutId.has(peerId)) {
            clearTimeout(this.typingStopTimeoutId.get(peerId));
            this.typingStopTimeoutId.delete(peerId);
        }
    }
    // ---------------------------------

    // --- Peer Typing Indicator Timeout ---

    /**
     * Starts a timeout to automatically hide the "peer is typing" indicator for a session
     * if no further typing messages (Type 10) or actual chat messages (Type 8) are received from that peer.
     * @param {Session} session - The session instance for which to start the timeout.
     */
    startTypingIndicatorTimeout(session) {
        this.clearTypingIndicatorTimeout(session); // Clear existing timeout first.
        // Log timeout start only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${session.peerId}] Starting typing indicator timeout (${this.TYPING_INDICATOR_TIMEOUT}ms)`);
        // Schedule the timeout.
        session.typingIndicatorTimeoutId = setTimeout(() => {
            // Log timeout event only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Session [${session.peerId}] Typing indicator timed out.`);
            session.peerIsTyping = false; // Mark peer as not typing in session state.
            // If this session is currently displayed, hide the indicator in the UI.
            if (this.displayedPeerId === session.peerId) {
                this.uiController.hideTypingIndicator();
            }
        }, this.TYPING_INDICATOR_TIMEOUT);
    }

    /**
     * Clears the timeout responsible for hiding the peer's typing indicator for a specific session.
     * Called when a TYPING_STOP message arrives, an actual message arrives, or the session is reset/switched.
     * @param {Session} session - The session instance whose typing indicator timeout should be cleared.
     */
    clearTypingIndicatorTimeout(session) {
        if (session && session.typingIndicatorTimeoutId) {
            // Log timeout clear only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Session [${session.peerId}] Clearing typing indicator timeout.`);
            clearTimeout(session.typingIndicatorTimeoutId);
            session.typingIndicatorTimeoutId = null; // Clear the stored ID.
        }
    }
    // ---------------------------------------

    // --- Notify peers on disconnect ---

    /**
     * Attempts to send a SESSION_END (Type 9) message to all connected or handshaking peers
     * when the client is disconnecting (e.g., page unload). This is a best-effort notification
     * as the connection might close before messages are sent.
     */
    notifyPeersOfDisconnect() {
        // Only proceed if registered and there are active/pending sessions.
        if (!this.identifier || this.sessions.size === 0) { return; }
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log("Attempting to notify active/pending peers of disconnect...");
        this.sessions.forEach((session, peerId) => {
            // Define states where notifying the peer makes sense (active or during handshake).
            const relevantStates = [
                this.STATE_ACTIVE_SESSION,
                this.STATE_DERIVING_KEY_INITIATOR, this.STATE_KEY_DERIVED_INITIATOR,
                this.STATE_AWAITING_CHALLENGE_RESPONSE,
                this.STATE_RECEIVED_CHALLENGE, this.STATE_AWAITING_FINAL_CONFIRMATION,
                this.STATE_GENERATING_ACCEPT_KEYS, this.STATE_AWAITING_CHALLENGE,
                this.STATE_DERIVING_KEY_RESPONDER, this.STATE_RECEIVED_INITIATOR_KEY,
                this.STATE_HANDSHAKE_COMPLETE,
                this.STATE_INITIATING_SESSION, // Notify even if just initiated.
                this.STATE_REQUEST_RECEIVED // Notify even if just received request.
            ];
            // If the session is in a relevant state...
            if (relevantStates.includes(session.state)) {
                // Log sending only if DEBUG is enabled.
                if (config.DEBUG) console.log(`Sending Type 9 disconnect notification to ${peerId}`);
                const endMessage = { type: 9, payload: { targetId: peerId, senderId: this.identifier } };
                try {
                     // Try to send directly using the WebSocket object if it's still open.
                     // Bypasses the usual sendMessage checks as this happens during unload.
                     if (this.wsClient.websocket && this.wsClient.websocket.readyState === WebSocket.OPEN) {
                         this.wsClient.websocket.send(JSON.stringify(endMessage));
                     }
                } catch (e) {
                    // Always log this warning if sending fails during unload.
                    console.warn(`Error sending disconnect notification to ${peerId} during unload: ${e.message}`);
                }
            }
        });
    }
    // -----------------------------------------------------

    // --- Central Message Handling and Routing ---

    /**
     * Handles raw incoming message data string from the WebSocketClient.
     * Parses the JSON, determines the message type and sender/target, performs basic validation,
     * and routes the message to the appropriate handler (registration, specific session, file transfer, etc.).
     * @param {string} messageData - The raw message string received from the WebSocket server.
     */
    async handleIncomingMessage(messageData) {
        // Log raw message only if DEBUG is enabled.
        if (config.DEBUG) console.log('SessionManager received raw message data:', messageData);
        let message;
        try {
            // 1. Parse the incoming JSON string.
            message = JSON.parse(messageData);
            const type = message.type;
            const payload = message.payload;
            // Sender ID is usually in the payload, except for server-generated messages (e.g., registration replies, errors).
            const senderId = payload?.senderId;

            // Log parsed message details only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Parsed message: Type=${type}, From=${senderId || 'Server/N/A'}, Payload=`, payload);

            // 2. Handle Manager-Level Messages (Registration Replies, Server Errors) first.
            if (type === 0.1) { // Registration Success
                this.handleRegistrationSuccess(payload);
                return; // Processing complete for this message.
            }
            if (type === 0.2) { // Registration Failure
                this.handleRegistrationFailure(payload);
                return; // Processing complete for this message.
            }
            if (type === -2) { // Rate Limit Exceeded / Server Error Disconnect
                const errorMessage = payload?.error || "Server initiated disconnect (reason unspecified).";
                // Always log server errors.
                console.error(`Received server error (Type -2): ${errorMessage}`);
                this.uiController.playSound('error'); // Play error sound.
                // Alert the user immediately about the server-initiated disconnect.
                alert(`Disconnected by Server: ${errorMessage}`);
                // Immediately trigger the disconnection cleanup and UI reset logic.
                await this.handleDisconnection(errorMessage); // Pass the reason.
                return; // Stop processing this message further.
            }

            // 3. Validate Sender ID for Session-Related Messages
            // Most messages should have a senderId. Type -1 (Error) might have targetId instead.
            if (!senderId && type !== -1) {
                // Always log this warning.
                console.warn(`Message type ${type} missing senderId in payload. Ignoring.`);
                return;
            }

            // 4. Determine Relevant Peer and Session for Routing
            let session;
            let relevantPeerId;

            if (type === -1) { // User Not Found / Server Error related to a target
                // Error messages use targetId to indicate who the error relates to.
                relevantPeerId = payload.targetId;
                session = this.sessions.get(relevantPeerId); // Find session if it exists.
                this.handleUserNotFound(relevantPeerId, payload); // Handle the error message display.
                return; // Processing complete for Type -1.
            } else {
                // For all other session-related messages, the sender is the relevant peer.
                relevantPeerId = senderId;
                session = this.sessions.get(relevantPeerId); // Find session associated with the sender.
            }

            // 5. Handle New Session Request (Type 1) specifically.
            if (type === 1) {
                this.handleSessionRequest(senderId, payload); // Creates a new session if valid.
                return; // Processing complete for Type 1.
            }

            // 6. Route Message to Existing Session or Ignore
            // If the message is not Type 1 and doesn't correspond to an existing session, ignore it.
            if (!session) {
                // Always log this warning.
                console.warn(`No session found for relevant peer ${relevantPeerId} to handle message type ${type}. Ignoring.`);
                return;
            }

            // 7. Route File Transfer Messages (Types 12-17) to dedicated handler.
            if (type >= 12 && type <= 17) {
                // Log routing only if DEBUG is enabled.
                if (config.DEBUG) console.log(`Routing file transfer message type ${type} to session [${relevantPeerId}]`);
                // Process the file transfer message and get an action result.
                const fileActionResult = await this.processFileTransferMessage(session, type, payload);
                // Process the result (e.g., update UI, play sound).
                await this.processMessageResult(session, fileActionResult);
                return; // Processing complete for file transfer messages.
            }

            // 8. Process Regular Chat/Handshake Message within the Session instance.
            // Log routing only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Routing message type ${type} to session [${relevantPeerId}]`);
            // Call the session's processMessage method, which returns an action object.
            const result = await session.processMessage(type, payload, this);
            // Process the action requested by the session (e.g., send reply, update UI).
            await this.processMessageResult(session, result);

        } catch (error) {
            // Catch errors during JSON parsing, routing, or message processing.
            // Always log these errors.
            console.error('Failed to parse/route/handle incoming message:', error, messageData);
            this.uiController.playSound('error'); // Play error sound for general processing errors.
            this.uiController.updateStatus("Error processing incoming message");
            // Consider showing a generic error to the user if appropriate.
        }
    }

    /**
     * Processes the action object returned by a Session's processMessage method
     * OR by the processFileTransferMessage method.
     * Executes the requested action, such as sending a specific message type, updating the UI,
     * resetting the session, or handling typing indicators. Plays sounds as appropriate for the action.
     *
     * @param {Session} session - The session instance that processed the message and generated the result.
     * @param {object} result - The action object returned (e.g., { action: 'SEND_TYPE_4' }, { action: 'DISPLAY_MESSAGE', ... }).
     */
    async processMessageResult(session, result) {
        // Ignore if session or result/action is invalid.
        if (!session || !result || !result.action) {
            // Log invalid result only if DEBUG is enabled.
            if (config.DEBUG) console.warn(`Invalid session or result action received:`, session, result);
            return;
        }

        const peerId = session.peerId; // Get peerId for convenience in logging and UI updates.
        // Log action request only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${peerId}] Action requested: ${result.action}`);

        // --- Timeout Clearing Logic ---
        // Clear handshake timeout if we are moving out of a handshake state towards active/reset/info.
        const handshakeStates = [
            this.STATE_DERIVING_KEY_INITIATOR, this.STATE_KEY_DERIVED_INITIATOR,
            this.STATE_AWAITING_CHALLENGE_RESPONSE,
            this.STATE_RECEIVED_CHALLENGE, this.STATE_AWAITING_FINAL_CONFIRMATION,
            this.STATE_GENERATING_ACCEPT_KEYS, this.STATE_AWAITING_CHALLENGE,
            this.STATE_DERIVING_KEY_RESPONDER, this.STATE_RECEIVED_INITIATOR_KEY,
            this.STATE_HANDSHAKE_COMPLETE
        ];
        const wasInHandshake = handshakeStates.includes(session.state);
        // Clear if action indicates handshake ended (SESSION_ACTIVE, RESET, SHOW_INFO).
        if (wasInHandshake && ['SESSION_ACTIVE', 'RESET', 'SHOW_INFO'].includes(result.action)) {
             this.clearHandshakeTimeout(session);
        }
        // Clear initial request timeout if we received accept (leading to SEND_TYPE_4) or deny/error (SHOW_INFO).
        if (result.action === 'SEND_TYPE_4' || result.action === 'SHOW_INFO') {
             this.clearRequestTimeout(session);
        }
        // --- End Timeout Clearing ---

        // Execute action based on the result object's 'action' property.
        switch (result.action) {
            // Actions requesting specific message sends:
            case 'SEND_TYPE_4': // Send own public key (Initiator)
                this.uiController.updateStatus(`Received acceptance from ${peerId}. Preparing response...`);
                await this.sendPublicKeyResponse(session);
                break;
            case 'SEND_TYPE_5': // Send challenge (Responder)
                this.uiController.updateStatus(`Received ${peerId}'s public key. Preparing challenge...`);
                await this.sendKeyConfirmationChallenge(session);
                break;
            case 'SEND_TYPE_6': // Send challenge response (Initiator)
                this.uiController.updateStatus(`Challenge received from ${peerId}. Preparing response...`);
                await this.sendKeyConfirmationResponse(session, result.challengeData);
                break;
            case 'SEND_TYPE_7': // Send session established confirmation (Responder)
                this.uiController.updateStatus(`Challenge verified with ${peerId}. Establishing session...`);
                await this.sendSessionEstablished(session); // Plays 'begin' sound internally on success.
                break;

            // Action indicating session is now active (received by Initiator after getting Type 7):
            case 'SESSION_ACTIVE':
                this.clearHandshakeTimeout(session); // Ensure handshake timeout is cleared for initiator too.
                this.switchToSessionView(peerId); // Ensure view is updated to active chat.
                this.uiController.playSound('begin'); // Play session begin sound.
                // Log session active message (significant event, not wrapped in DEBUG).
                console.log(`%cSession active with ${peerId}. Ready to chat!`, "color: green; font-weight: bold;");
                break;

            // Actions requesting UI updates:
            case 'DISPLAY_MESSAGE': // Display regular chat message
                // When a message arrives, clear any "peer is typing" indicator timeout and hide the indicator.
                this.clearTypingIndicatorTimeout(session);
                if (this.displayedPeerId === peerId) {
                    this.uiController.hideTypingIndicator(); // Hide indicator in active chat.
                    this.uiController.addMessage(result.sender, result.text, result.msgType); // Add message to UI.
                } else {
                    // If chat not displayed, mark session as having unread messages in the sidebar list.
                    this.uiController.setUnreadIndicator(peerId, true);
                }
                // Play notification sound ONLY for peer messages (not own or system messages).
                if (result.msgType === 'peer') {
                    this.uiController.playSound('notification');
                }
                break;
            case 'DISPLAY_ME_ACTION': // Display /me action message
                // Clear typing indicator when action message arrives.
                this.clearTypingIndicatorTimeout(session);
                if (this.displayedPeerId === peerId) {
                    this.uiController.hideTypingIndicator(); // Hide indicator in active chat.
                    // Call the UIController method specifically for /me actions.
                    this.uiController.addMeActionMessage(result.sender, result.text);
                } else {
                    // Mark as unread if chat not displayed.
                    this.uiController.setUnreadIndicator(peerId, true);
                }
                // Play notification sound for /me actions as well.
                this.uiController.playSound('notification');
                break;
            case 'DISPLAY_SYSTEM_MESSAGE': // Display system message (e.g., error during decryption)
                 // Display system messages only if the relevant chat is currently active.
                 if (this.displayedPeerId === peerId) {
                    this.uiController.addSystemMessage(result.text);
                } else {
                    // Always log system message warnings for non-active chats.
                    console.warn(`System message for non-active session ${peerId}: ${result.text}`);
                    // Add to history even if not displayed immediately.
                    session.addMessageToHistory('System', result.text, 'system');
                    this.uiController.setUnreadIndicator(peerId, true); // Mark unread.
                }
                break;
            case 'SHOW_INFO': // Show info pane (denial, timeout, specific error)
                // Use the reason provided in the result object for the message.
                const messageToShow = result.message || result.reason || `An issue occurred with ${peerId}.`;
                // Determine if retry button should be shown (only for request timeout currently).
                const showRetry = result.showRetry || false;
                // Update the UI to show the info pane.
                this.uiController.showInfoMessage(peerId, messageToShow, showRetry);
                // Play error sound if it's a denial or timeout state.
                if (session.state === this.STATE_DENIED || session.state === this.STATE_REQUEST_TIMED_OUT || session.state === this.STATE_HANDSHAKE_TIMED_OUT) {
                    this.uiController.playSound('error');
                }
                // Re-enable initiation controls if this was the only session attempt and it failed definitively (denial/handshake timeout).
                const definitiveFailureStates = [this.STATE_DENIED, this.STATE_HANDSHAKE_TIMED_OUT];
                if (definitiveFailureStates.includes(session.state)) {
                     if (this.sessions.size <= 1) { this.uiController.setInitiationControlsEnabled(true); }
                }
                break;

            // Action requesting session reset:
            case 'RESET':
                const reason = result.reason || `Session with ${peerId} ended.`;
                const notifyViaAlert = result.notifyUser || false; // Check if alert fallback is requested (e.g., for Type 9).

                // Play appropriate sound based on context (error or clean end).
                // Check if the reason indicates an error or if the session state implies an error.
                const isErrorReset = reason.toLowerCase().includes('error') ||
                                     reason.toLowerCase().includes('failed') ||
                                     session.state === this.STATE_HANDSHAKE_TIMED_OUT;
                if (isErrorReset) {
                    this.uiController.playSound('error');
                } else if (reason.includes('ended by') || reason.includes('You ended') || reason.includes('denied request') || reason.includes('cancelled')) {
                    // Play end sound for clean disconnects (Type 9, local end, denial, cancellation).
                    this.uiController.playSound('end');
                }

                // Always try to show the info pane if there's a reason, providing better context than an alert.
                if (result.reason) {
                    // Log display attempt only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`Displaying reset reason for ${peerId}: ${result.reason}`);
                    // Show info message, typically no retry for disconnect/error resets.
                    this.uiController.showInfoMessage(peerId, result.reason, false);
                    // Reset the session *after* showing the message.
                    // Pass notifyUserViaAlert=false because the info pane handles the notification.
                    await this.resetSession(peerId, false, result.reason);
                } else {
                    // If no specific reason provided (should be rare for RESET action), just reset.
                    // Use alert notification only if requested by the result (e.g., Type 9 disconnect).
                    await this.resetSession(peerId, notifyViaAlert, reason);
                }
                break;

            // Handle Typing Indicator Actions requested by the session:
            case 'SHOW_TYPING': // Peer started typing
                if (this.displayedPeerId === peerId) { // Only show if chat is active.
                    this.uiController.showTypingIndicator(peerId);
                }
                // Start the timeout to hide the indicator automatically if no further activity.
                this.startTypingIndicatorTimeout(session);
                break;
            case 'HIDE_TYPING': // Peer stopped typing
                this.clearTypingIndicatorTimeout(session); // Clear the auto-hide timeout.
                if (this.displayedPeerId === peerId) { // Only hide if chat is active.
                    this.uiController.hideTypingIndicator();
                }
                break;

            // Default case for unknown or 'NONE' actions:
            case 'NONE':
            default:
                // No specific action needed from SessionManager.
                // Ensure handshake timeout is cleared if applicable (e.g., buffered challenge processed).
                if (wasInHandshake) this.clearHandshakeTimeout(session);
                break;
        }
    }


    // --- Manager-Level Handlers ---

    /**
     * Handles the registration success message (Type 0.1) from the server.
     * Stores the confirmed identifier, updates manager state, plays sound, and shows the main app UI.
     * @param {object} payload - Expected: { identifier: string, message: string }
     */
    handleRegistrationSuccess(payload) {
        this.clearRegistrationTimeout(); // Stop the registration timeout.
        this.identifier = payload.identifier; // Store the confirmed identifier.
        this.updateManagerState(this.STATE_REGISTERED); // Update manager state.
        // Log success (significant event, not wrapped in DEBUG).
        console.log(`Successfully registered as: ${this.identifier}`);
        this.uiController.playSound('registered'); // Play registration success sound.
        // Show the main application UI (sidebar, content area) and hide registration.
        this.uiController.showMainApp(this.identifier);
        this.uiController.updateStatus(`Registered as: ${this.identifier}`);
        // Re-enable registration controls (though the area is now hidden).
        this.uiController.setRegistrationControlsEnabled(true);
    }

    /**
     * Handles the registration failure message (Type 0.2) from the server.
     * Updates manager state, plays error sound, alerts the user with the reason,
     * and keeps the registration UI visible and enabled for another attempt.
     * @param {object} payload - Expected: { identifier?: string, error: string }
     */
    handleRegistrationFailure(payload) {
        this.clearRegistrationTimeout(); // Stop the registration timeout.
        this.updateManagerState(this.STATE_FAILED_REGISTRATION); // Update manager state.
        const reason = payload?.error || "Unknown registration error.";
        const requestedId = payload?.identifier || "the requested ID";
        // Always log registration errors.
        console.error(`Registration failed for '${requestedId}': ${reason}`);
        this.uiController.updateStatus(`Registration Failed: ${reason}`);
        this.uiController.playSound('error'); // Play error sound.
        // Use alert for registration failure as it's a global issue preventing app use.
        alert(`Registration failed: ${reason}\nPlease try a different identifier.`);
        // Keep registration UI visible and re-enable input/button.
        this.uiController.showRegistration();
        this.uiController.setRegistrationControlsEnabled(true);
    }

    /**
     * Handles the user not found error message (Type -1) from the server.
     * Typically received when trying to initiate a session with an unknown/offline user.
     * Updates the relevant session state to DENIED, plays error sound, and shows an info message.
     * @param {string} targetIdFailed - The identifier that was not found by the server.
     * @param {object} payload - Expected: { targetId: string, message: string }
     */
    handleUserNotFound(targetIdFailed, payload) {
        const session = this.sessions.get(targetIdFailed);
        const errorMessage = payload.message || `User '${targetIdFailed}' not found or disconnected.`;
        // Always log server errors.
        console.error(`Server Error: ${errorMessage}`);
        this.uiController.playSound('error'); // Play error sound.
        // Check if we have a session for this peer and it was in the initiating state.
        if (session && session.state === this.STATE_INITIATING_SESSION) {
            // Log action only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Showing denial info for ${targetIdFailed} after user not found error.`);
            // Clear timeouts associated with the failed request.
            this.clearRequestTimeout(session);
            this.clearHandshakeTimeout(session); // Should be null, but clear just in case.
            // Update state to DENIED.
            session.updateState(this.STATE_DENIED);
            // Show info message using the UI controller. No retry for user not found.
            this.uiController.showInfoMessage(targetIdFailed, errorMessage, false);
            // Do NOT reset the session here; let the user close the info pane, which triggers reset.
        } else {
             // Always log this warning if error received for unexpected session/state.
             console.warn(`Received user not found for ${targetIdFailed}, but no matching session in INITIATING_SESSION state.`);
             // Show a general status update/alert for unexpected errors.
             this.uiController.updateStatus(`Error: ${errorMessage}`);
             alert(`Server Error: ${errorMessage}`); // Use alert for unexpected errors.
        }
        // Re-enable initiation controls if this was the only session attempt.
        if (this.sessions.size <= 1) { this.uiController.setInitiationControlsEnabled(true); }
    }

    /**
     * Handles an incoming session request (Type 1) from a peer.
     * Creates a new Session instance in the REQUEST_RECEIVED state if valid.
     * Plays request sound and updates the UI to show the incoming request pane
     * or marks the session as unread in the list if another session/pane is active.
     * Prevents handling if not registered, another request is pending action, or session already exists.
     *
     * @param {string} senderId - The identifier of the peer initiating the request.
     * @param {object} payload - Expected: { targetId: string (own ID), senderId: string }
     */
    handleSessionRequest(senderId, payload) {
        // Log request received (significant event, not wrapped in DEBUG).
        console.log(`Incoming session request received from: ${senderId}`);
        // Ignore if manager is not in the REGISTERED state.
        if (this.managerState !== this.STATE_REGISTERED) {
            // Always log this warning.
            console.warn(`Ignoring incoming request from ${senderId}: Manager not in REGISTERED state.`);
            return;
        }
        // Ignore if another request is already pending user action (Accept/Deny).
        if (this.pendingPeerIdForAction) {
            // Always log this warning.
            console.warn(`Ignoring incoming request from ${senderId}: Another request from ${this.pendingPeerIdForAction} is pending user action.`);
            // Potential enhancement: Queue requests or send a "busy" response back to senderId.
            return;
        }
        // Ignore if a session with this peer already exists (in any state).
        if (this.sessions.has(senderId)) {
            // Always log this warning.
            console.warn(`Ignoring duplicate session request from ${senderId}. Session already exists.`);
            return;
        }

        // 1. Create a new CryptoModule instance specifically for this incoming session.
        const crypto = new this.CryptoModuleClass();
        // 2. Create a new Session object, starting in the REQUEST_RECEIVED state.
        const newSession = new Session(senderId, this.STATE_REQUEST_RECEIVED, crypto);
        // 3. Add the session to the manager's map.
        this.sessions.set(senderId, newSession);
        // 4. Add the session to the UI list in the sidebar.
        this.uiController.addSessionToList(senderId);

        // 5. Play incoming request sound.
        this.uiController.playSound('receiverequest');

        // 6. Update the main UI view.
        if (!this.displayedPeerId) {
            // If no other chat/pane is active, show the incoming request pane immediately.
            this.pendingPeerIdForAction = senderId; // Mark this peer as needing user action.
            this.uiController.showIncomingRequest(senderId);
            this.uiController.updateStatus(`Incoming request from ${senderId}`);
        } else {
            // If another chat/pane is active, just mark the new session as unread in the list.
            // Log this action only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Another session active. Marking ${senderId} as pending request.`);
            this.uiController.setUnreadIndicator(senderId, true);
            this.uiController.updateStatus(`Incoming request from ${senderId} (see session list)`);
            // User will need to click the session in the list to see the Accept/Deny options.
        }
    }

    /**
     * Handles the WebSocket disconnection event OR a forced disconnect trigger (e.g., server error).
     * Clears all session timeouts, resets all sessions (including file transfer cleanup),
     * updates manager state to DISCONNECTED, plays error sound, alerts the user,
     * and shows the registration screen. Prevents running twice if already disconnected.
     *
     * @param {string} [reason=null] - Optional reason for the disconnection, used for status updates and alert.
     */
    async handleDisconnection(reason = null) {
         // Prevent running the cleanup logic multiple times if already disconnected.
         if (this.managerState === this.STATE_DISCONNECTED) {
             // Log skipped call only if DEBUG is enabled.
             if (config.DEBUG) console.log("handleDisconnection called but already disconnected. Skipping.");
             return;
         }
         // Use the provided reason or a default message.
         const disconnectReason = reason || "Connection lost.";
         // Log disconnection (significant event, not wrapped in DEBUG).
         console.log(`SessionManager: Handling disconnection. Reason: ${disconnectReason}`);

         // 1. Clear any pending registration timeout.
         this.clearRegistrationTimeout();

         // 2. Perform cleanup for any active file transfers across all sessions.
         await this.handleDisconnectionCleanup();

         // 3. Reset all active/pending sessions.
         if (this.sessions.size > 0) {
             const peerIds = Array.from(this.sessions.keys()); // Get all peer IDs currently tracked.
             // Reset each session without individual user notification (global disconnect).
             // resetSession now handles file transfer cleanup internally as well.
             for (const peerId of peerIds) {
                 await this.resetSession(peerId, false); // notifyUserViaAlert = false.
             }
             // The sessions map should now be empty after resetSession calls.
         }

         // 4. Update manager state and clear session tracking variables.
         this.updateManagerState(this.STATE_DISCONNECTED); // Set state *before* UI updates.
         this.displayedPeerId = null;
         this.pendingPeerIdForAction = null;
         this.identifier = null; // Clear registered identifier.

         // 5. Play error sound for disconnection.
         this.uiController.playSound('error');

         // 6. Update UI status and show the registration screen.
         // Use alert for the main disconnection event as it affects the whole app.
         alert(`Disconnected: ${disconnectReason}`);
         this.uiController.updateStatus(disconnectReason);
         this.uiController.showRegistration(); // Show registration UI for potential reconnect/re-register.
    }

    /**
     * Switches the main content view to display the specified session.
     * Updates the UI based on the session's current state (active chat, incoming request, info, waiting, etc.).
     * Clears the unread indicator and hides the typing indicator for the switched-to session.
     * Populates the message area with history for active chats.
     *
     * @param {string} peerId - The identifier of the peer whose session view to display.
     */
    switchToSessionView(peerId) {
        const session = this.sessions.get(peerId);
        // If session doesn't exist (e.g., reset just happened), show default view.
        if (!session) {
            // Always log this warning.
            console.warn(`Attempted to switch to non-existent session: ${peerId}`);
            this.uiController.showDefaultRegisteredView(this.identifier);
            return;
        }

        // Log view switch only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Switching view to session with ${peerId}`);
        this.displayedPeerId = peerId; // Set this *before* updating UI panes.

        // Hide typing indicator when switching views (it will be reshown if peer is still typing).
        this.uiController.hideTypingIndicator();

        // Clear the unread indicator for the session being viewed.
        this.uiController.setUnreadIndicator(peerId, false);
        // Set this session as the active one in the sidebar list (visual highlight).
        this.uiController.setActiveSessionInList(peerId);

        // Show the appropriate main content pane based on the session's state.
        if (session.state === this.STATE_ACTIVE_SESSION) {
            // Show the active chat interface.
            this.uiController.showActiveChat(peerId);
            // Populate message area with stored history for this session.
            session.messages.forEach(msg => {
                // Display regular messages and /me actions from history.
                if (msg.type === 'me-action') {
                    this.uiController.addMeActionMessage(msg.sender, msg.text);
                } else if (msg.type !== 'file') { // Assuming file messages aren't stored in history this way yet.
                     this.uiController.addMessage(msg.sender, msg.text, msg.type);
                }
                // Note: Re-rendering file transfer messages from history might require more complex state saving/restoration.
            });
            // Re-render any active file transfers for this session from its transferStates map.
            if (session.transferStates) {
                session.transferStates.forEach((state, transferId) => {
                    // Add the message block back to the UI.
                    this.uiController.addFileTransferMessage(transferId, peerId, state.fileName, state.fileSize, state.isSender);
                    // Update its status and progress.
                    this.uiController.updateFileTransferStatus(transferId, state.status);
                    if (state.progress > 0) {
                        this.uiController.updateFileTransferProgress(transferId, state.progress);
                    }
                    // Show appropriate buttons based on current state.
                    if (state.status === 'complete' && !state.isSender && state.blobUrl) {
                         // If complete and receiver, show download link (assuming blobUrl is still valid or recreated).
                         // This part needs careful implementation regarding Blob persistence/recreation.
                         // For simplicity, we might only show download link upon initial completion, not on view switch.
                         this.uiController.showFileDownloadLink(transferId, null, state.fileName); // Pass null blob for now, UI needs to handle this
                    } else if (state.status === 'pending_acceptance' && !state.isSender) {
                        // Show accept/reject if waiting for receiver's action.
                        // (Handled by default in addFileTransferMessage)
                    } else if ((state.status === 'initiating' || state.status === 'uploading') && state.isSender) {
                        // Show cancel if sender and initiating/uploading.
                        // (Handled by default in addFileTransferMessage)
                    } else {
                        // Hide all actions for other states (e.g., rejected, error, completed sender).
                        this.uiController.hideFileTransferActions(transferId);
                    }
                });
            }
            this.uiController.updateStatus(`Session active with ${peerId}.`);
        } else if (session.state === this.STATE_REQUEST_RECEIVED) {
            // If switching to a session that has an incoming request needing action.
            this.pendingPeerIdForAction = peerId; // Mark as needing user action.
            this.uiController.showIncomingRequest(peerId); // Show the Accept/Deny pane.
            this.uiController.updateStatus(`Incoming request from ${peerId}`);
        } else if (session.state === this.STATE_DENIED || session.state === this.STATE_HANDSHAKE_TIMED_OUT) {
             // Show info pane for denied or handshake timeout states.
             const message = session.state === this.STATE_DENIED ? `Session request denied by ${peerId}.` : `Handshake with ${peerId} timed out. Please try initiating the session again.`;
             this.uiController.showInfoMessage(peerId, message, false); // No retry option.
             this.uiController.updateStatus(message);
        } else if (session.state === this.STATE_REQUEST_TIMED_OUT) {
             // Show info pane for initial request timeout state.
             const message = `No response from ${peerId}. Request timed out.`;
             this.uiController.showInfoMessage(peerId, message, true); // Allow retry.
             this.uiController.updateStatus(message);
        } else if (session.state === this.STATE_INITIATING_SESSION) {
             // Show waiting pane if we initiated and are waiting for accept/deny.
             this.uiController.showWaitingForResponse(peerId);
             this.uiController.updateStatus(`Waiting for response from ${peerId}...`);
        }
        else { // Other intermediate handshake states
            // For other states (key exchange, challenge/response), show the default welcome message pane.
            // The status bar provides context about the ongoing handshake.
            // Log this only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Session with ${peerId} is handshaking (state: ${session.state}). Showing welcome message.`);
            this.uiController.showWelcomeMessage(); // Show default welcome/instructions pane.
            // Provide more descriptive status for handshake states.
            let statusText = `Session with ${peerId}: ${session.state}`; // Default status
            if (session.state === this.STATE_DERIVING_KEY_INITIATOR || session.state === this.STATE_DERIVING_KEY_RESPONDER) {
                statusText = `Session with ${peerId}: Deriving keys...`;
            } else if (session.state === this.STATE_AWAITING_CHALLENGE) {
                statusText = `Session with ${peerId}: Waiting for peer's key...`;
            } else if (session.state === this.STATE_AWAITING_CHALLENGE_RESPONSE) {
                statusText = `Session with ${peerId}: Waiting for challenge response...`;
            } else if (session.state === this.STATE_RECEIVED_CHALLENGE) {
                statusText = `Session with ${peerId}: Received challenge, preparing response...`;
            } else if (session.state === this.STATE_AWAITING_FINAL_CONFIRMATION) {
                statusText = `Session with ${peerId}: Waiting for final confirmation...`;
            } else if (session.state === this.STATE_HANDSHAKE_COMPLETE) {
                 statusText = `Session with ${peerId}: Handshake complete, establishing...`;
            }
            this.uiController.updateStatus(statusText);
        }
    }

    /**
     * Gets the peer ID of the currently displayed chat session or info pane.
     * @returns {string|null} The peer ID string, or null if no session is actively displayed.
     */
    getActivePeerId() {
        return this.displayedPeerId;
    }

    // --- File Transfer Logic ---

    /**
     * Handles the file selection event from the hidden file input.
     * Validates the file, creates a unique transfer ID, stores initial state,
     * updates the UI, and sends the file transfer request (Type 12) to the peer.
     *
     * @param {Event} event - The file input 'change' event object.
     */
    async handleFileSelection(event) {
        const fileInput = event.target;
        if (!fileInput.files || fileInput.files.length === 0) {
            // Log cancellation only if DEBUG is enabled.
            if (config.DEBUG) console.log("File selection cancelled or no file chosen.");
            return; // No file selected or dialog cancelled.
        }
        const file = fileInput.files[0];
        // Reset the file input value immediately to allow selecting the same file again later if needed.
        fileInput.value = '';

        const targetId = this.getActivePeerId(); // Get the currently active chat peer.
        if (!targetId) {
            alert("No active chat session selected to send the file to.");
            return;
        }
        const session = this.sessions.get(targetId);
        // Ensure the session is active before allowing file transfer.
        if (!session || session.state !== this.STATE_ACTIVE_SESSION) {
            alert(`Session with ${targetId} is not active. Cannot send file.`);
            return;
        }

        // Log file details only if DEBUG is enabled.
        if (config.DEBUG) console.log(`File selected: Name=${file.name}, Size=${file.size}, Type=${file.type}`);

        // Validate file size against the configured limit.
        if (file.size > this.MAX_FILE_SIZE) {
            alert(`File is too large (${this.uiController.formatFileSize(file.size)}). Maximum size is ${this.uiController.formatFileSize(this.MAX_FILE_SIZE)}.`);
            return;
        }
        if (file.size === 0) {
            alert("Cannot send empty files.");
            return;
        }

        // Generate a unique ID for this specific file transfer using browser's crypto API.
        const transferId = crypto.randomUUID();
        // Log transfer initiation only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Initiating file transfer ${transferId} to ${targetId}`);

        // Store initial transfer state in the session's transfer map.
        session.addTransferState(transferId, {
            file: file, // Store the File object itself for later reading.
            status: 'initiating', // Initial status: waiting for peer acceptance.
            progress: 0,
            fileName: file.name, // Store metadata needed by the receiver.
            fileSize: file.size,
            fileType: file.type,
            isSender: true // Mark this client as the sender for this transfer.
        });

        // Display the initial file transfer message block in the UI.
        this.uiController.addFileTransferMessage(transferId, targetId, file.name, file.size, true); // true for isSender.

        // Send the FILE_TRANSFER_REQUEST (Type 12) message to the peer.
        const requestPayload = {
            targetId: targetId,
            senderId: this.identifier,
            transferId: transferId,
            fileName: file.name,
            fileSize: file.size,
            fileType: file.type || 'application/octet-stream' // Provide a default MIME type if unknown.
        };
        if (this.wsClient.sendMessage({ type: 12, payload: requestPayload })) {
            this.uiController.updateStatus(`Requesting file transfer to ${targetId}...`);
            // Consider adding a timeout for the peer to accept/reject the transfer.
            // this.startFileAcceptTimeout(transferId); // Example placeholder
        } else {
            // Handle failure to send the request message.
            this.uiController.updateFileTransferStatus(transferId, "Error: Failed to send transfer request.");
            this.uiController.playSound('file_error');
            session.removeTransferState(transferId); // Clean up state if request failed to send.
            // Optionally remove the UI message or leave it with the error status.
        }
    }

    /**
     * Starts the process of reading the selected file in chunks, encrypting each chunk,
     * and sending it to the peer via WebSocket messages (Type 15).
     * Updates the UI with progress information. Sends a completion message (Type 16) when done.
     * Handles cancellation and errors during the upload.
     *
     * @param {Session} session - The session object associated with the transfer.
     * @param {string} transferId - The ID of the file transfer to start uploading.
     */
    async startFileUpload(session, transferId) {
        const transferState = session.getTransferState(transferId);
        // Ensure the transfer state is valid and ready for upload.
        if (!transferState || !transferState.file || transferState.status !== 'uploading') {
            // Always log this warning.
            console.warn(`Cannot start upload for transfer ${transferId}: Invalid state (${transferState?.status}) or missing file.`);
            return;
        }

        const file = transferState.file;
        const peerId = session.peerId;
        let chunkIndex = 0;
        let offset = 0;
        // Log start only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Starting file upload for ${transferId} (${file.name})`);
        // Update UI to show initial progress.
        this.uiController.updateFileTransferStatus(transferId, "Uploading 0%...");
        this.uiController.updateFileTransferProgress(transferId, 0); // Show progress bar.

        try {
            // Loop through the file, reading it chunk by chunk.
            while (offset < file.size) {
                // Check if transfer was cancelled externally (e.g., user clicked cancel, disconnect) before processing next chunk.
                const currentState = session.getTransferState(transferId);
                if (!currentState || currentState.status !== 'uploading') {
                    // Always log cancellation/error during upload.
                    console.log(`Upload for transfer ${transferId} aborted. Status changed to: ${currentState?.status}`);
                    return; // Stop the upload loop.
                }

                // Read the next chunk from the file.
                const end = Math.min(offset + this.CHUNK_SIZE, file.size);
                const chunkBlob = file.slice(offset, end);
                const chunkBuffer = await chunkBlob.arrayBuffer(); // Get chunk data as ArrayBuffer.

                // Encrypt the chunk using the session's derived AES key.
                const encryptedResult = await session.cryptoModule.encryptAES(chunkBuffer);
                if (!encryptedResult) {
                    throw new Error(`Encryption failed for chunk ${chunkIndex}`);
                }

                // Prepare the payload for the FILE_CHUNK message (Type 15).
                const chunkPayload = {
                    targetId: peerId,
                    senderId: this.identifier,
                    transferId: transferId,
                    chunkIndex: chunkIndex,
                    iv: session.cryptoModule.arrayBufferToBase64(encryptedResult.iv), // Base64 encoded IV.
                    data: session.cryptoModule.arrayBufferToBase64(encryptedResult.encryptedBuffer) // Base64 encoded ciphertext.
                };

                // Send the chunk message.
                if (!this.wsClient.sendMessage({ type: 15, payload: chunkPayload })) {
                    throw new Error(`Connection error sending chunk ${chunkIndex}`);
                }

                // Update progress based on the amount of data sent.
                offset += chunkBuffer.byteLength;
                const progressPercent = (offset / file.size) * 100;
                transferState.progress = progressPercent; // Update progress in the state object.
                // Update the UI progress bar and status text.
                this.uiController.updateFileTransferProgress(transferId, progressPercent);
                this.uiController.updateFileTransferStatus(transferId, `Uploading ${progressPercent.toFixed(1)}%...`);

                chunkIndex++;

                // Optional: Add a small delay to prevent flooding the event loop/network, especially for large files.
                // await new Promise(resolve => setTimeout(resolve, 5)); // e.g., 5ms delay
            }

            // All chunks sent successfully. Send the FILE_TRANSFER_COMPLETE message (Type 16).
            // Log completion only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Finished sending chunks for transfer ${transferId}. Sending completion message.`);
            const completePayload = { targetId: peerId, senderId: this.identifier, transferId: transferId };
            if (this.wsClient.sendMessage({ type: 16, payload: completePayload })) {
                // Update local state and UI to reflect completion from sender's side.
                transferState.status = 'complete';
                this.uiController.updateFileTransferStatus(transferId, "Upload complete. Waiting for peer confirmation.");
                this.uiController.hideFileTransferActions(transferId); // Hide the cancel button.
            } else {
                throw new Error("Connection error sending completion message.");
            }

        } catch (error) {
            // Handle errors during the upload loop (reading, encrypting, sending).
            // Always log upload errors.
            console.error(`Error during file upload for ${transferId}:`, error);
            this.uiController.playSound('file_error');
            this.uiController.updateFileTransferStatus(transferId, `Error: ${error.message}`);
            this.uiController.hideFileTransferActions(transferId); // Hide cancel button on error.
            // Send an error notification (Type 17) to the peer.
            const errorPayload = { targetId: peerId, senderId: this.identifier, transferId: transferId, error: `Upload failed: ${error.message}` };
            this.wsClient.sendMessage({ type: 17, payload: errorPayload }); // Send best effort.
            // Clean up local state for the failed transfer.
            session.removeTransferState(transferId);
        }
    }

    /**
     * Handles the user clicking the Accept button for an incoming file transfer request.
     * Updates the transfer state, hides UI actions, and sends the acceptance message (Type 13) to the sender.
     * @param {string} transferId - The ID of the transfer being accepted.
     */
    async handleAcceptFile(transferId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Handling accept for file transfer ${transferId}`);
        // Find the session and transfer state associated with this transferId.
        let session = null;
        let transferState = null;
        for (const s of this.sessions.values()) { // Iterate through all active sessions.
            transferState = s.getTransferState(transferId);
            if (transferState) {
                session = s; // Found the session containing this transfer.
                break;
            }
        }

        // Ensure the transfer exists and is in the correct state (pending acceptance).
        if (!session || !transferState || transferState.status !== 'pending_acceptance') {
            // Always log this warning.
            console.warn(`Cannot accept file transfer ${transferId}: Session or transfer state not found or invalid status (${transferState?.status}).`);
            return;
        }

        const peerId = transferState.senderId; // Get the sender's ID from the state.

        // Update UI immediately to show acceptance and hide buttons.
        this.uiController.updateFileTransferStatus(transferId, "Accepted. Waiting for data...");
        this.uiController.hideFileTransferActions(transferId); // Hide accept/reject buttons.

        // Update internal transfer state.
        transferState.status = 'accepted'; // Ready to receive chunks.

        // Send acceptance message (Type 13) back to the sender.
        const acceptPayload = { targetId: peerId, senderId: this.identifier, transferId: transferId };
        if (!this.wsClient.sendMessage({ type: 13, payload: acceptPayload })) {
            // Handle failure to send the acceptance message.
            this.uiController.updateFileTransferStatus(transferId, "Error: Failed to send acceptance.");
            this.uiController.playSound('file_error');
            transferState.status = 'error'; // Revert status to error.
            // Consider cleaning up DB if needed, though no chunks should exist yet.
        } else {
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Sent acceptance for transfer ${transferId} to ${peerId}`);
            // Optionally play a sound to confirm acceptance locally.
        }
    }

    /**
     * Handles the user clicking the Reject button for an incoming file transfer request.
     * Updates the UI, sends the rejection message (Type 14) to the sender, plays a sound,
     * and cleans up the local transfer state.
     * @param {string} transferId - The ID of the transfer being rejected.
     */
    async handleRejectFile(transferId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Handling reject for file transfer ${transferId}`);
        // Find the session and transfer state.
        let session = null;
        let transferState = null;
        for (const s of this.sessions.values()) {
            transferState = s.getTransferState(transferId);
            if (transferState) {
                session = s;
                break;
            }
        }

        // Ensure the transfer exists and is in the correct state.
        if (!session || !transferState || transferState.status !== 'pending_acceptance') {
            // Always log this warning.
            console.warn(`Cannot reject file transfer ${transferId}: Session or transfer state not found or invalid status (${transferState?.status}).`);
            return;
        }

        const peerId = transferState.senderId; // Get the sender's ID.

        // Update UI to show rejection and hide buttons.
        this.uiController.updateFileTransferStatus(transferId, "Rejected.");
        this.uiController.hideFileTransferActions(transferId);
        this.uiController.playSound('end'); // Use end sound for rejection/cancellation.

        // Send rejection message (Type 14) to the sender.
        const rejectPayload = { targetId: peerId, senderId: this.identifier, transferId: transferId };
        this.wsClient.sendMessage({ type: 14, payload: rejectPayload }); // Send best effort.

        // Clean up local state for this transfer.
        session.removeTransferState(transferId);
        await this.deleteChunksFromDB(transferId); // Clean up any potential DB entries (though unlikely).
    }

    /**
     * Handles the user clicking the Cancel button for an ongoing file transfer (sender side).
     * Updates the UI, sends an error/cancel message (Type 17) to the peer, plays a sound,
     * and cleans up the local transfer state.
     * @param {string} transferId - The ID of the transfer being cancelled.
     */
    async handleCancelTransfer(transferId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Handling cancel for file transfer ${transferId}`);
        // Find the session and transfer state, ensuring it's an outgoing transfer.
        let session = null;
        let transferState = null;
        for (const s of this.sessions.values()) {
            transferState = s.getTransferState(transferId);
            if (transferState && transferState.isSender) { // Check if we are the sender.
                session = s;
                break;
            }
        }

        // Only allow cancellation if initiating or uploading.
        const cancellableStates = ['initiating', 'uploading'];
        if (!session || !transferState || !cancellableStates.includes(transferState.status)) {
            // Always log this warning.
            console.warn(`Cannot cancel file transfer ${transferId}: Session/transfer not found or invalid status (${transferState?.status}).`);
            return;
        }

        const peerId = session.peerId; // Get the recipient's ID.

        // Update UI to show cancellation and hide buttons.
        this.uiController.updateFileTransferStatus(transferId, "Cancelled.");
        this.uiController.hideFileTransferActions(transferId);
        this.uiController.playSound('end'); // Use end sound for cancellation.

        // Update internal state immediately to stop the upload loop if it's running.
        transferState.status = 'cancelled';

        // Send error/cancel message (Type 17) to the peer.
        const errorPayload = { targetId: peerId, senderId: this.identifier, transferId: transferId, error: "Transfer cancelled by sender." };
        this.wsClient.sendMessage({ type: 17, payload: errorPayload }); // Send best effort.

        // Clean up local state for this transfer.
        session.removeTransferState(transferId);
        // No DB cleanup needed for the sender.
    }

    /**
     * Processes incoming file transfer related messages (Types 12-17) received from a peer.
     * Routes the message to the specific internal handler (_handleFile...) based on the type.
     *
     * @param {Session} session - The session object associated with the sender of the message.
     * @param {number} type - The file transfer message type identifier (12-17).
     * @param {object} payload - The message payload containing transfer details.
     * @returns {Promise<object>} An action object for processMessageResult (usually { action: 'NONE' } as handlers update UI directly).
     */
    async processFileTransferMessage(session, type, payload) {
        // Log processing attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Session [${session.peerId}] Processing file transfer message type ${type}`);
        }
        try {
            // Route based on file transfer message type.
            switch (type) {
                case 12: return await this._handleFileTransferRequest(session, payload); // Received request
                case 13: return await this._handleFileTransferAccept(session, payload); // Peer accepted our request
                case 14: return await this._handleFileTransferReject(session, payload); // Peer rejected our request
                case 15: return await this._handleFileChunk(session, payload); // Received a file chunk
                case 16: return await this._handleFileTransferComplete(session, payload); // Peer finished sending chunks
                case 17: return await this._handleFileTransferError(session, payload); // Peer reported an error / cancelled
                default:
                    // Always log unhandled types as warnings.
                    console.warn(`Session [${session.peerId}] Received unhandled file transfer message type: ${type}`);
                    return { action: 'NONE' }; // No action for unknown types.
            }
        } catch (error) {
            // Always log unexpected errors during file transfer message processing.
            console.error(`Session [${session.peerId}] Unexpected error processing file transfer message type ${type}:`, error);
            // Return a generic system message action for SessionManager to display.
            return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Internal error processing file transfer: ${error.message}` };
        }
    }

    // --- Internal File Transfer Message Handlers ---

    /**
     * Handles an incoming FILE_TRANSFER_REQUEST (Type 12).
     * Stores initial transfer state and displays the request in the UI for the user to accept/reject.
     * @param {Session} session - The session associated with the sender.
     * @param {object} payload - Contains transferId, fileName, fileSize, fileType, senderId.
     * @returns {Promise<object>} Action object { action: 'NONE' }.
     * @private
     */
    async _handleFileTransferRequest(session, payload) {
        const { transferId, fileName, fileSize, fileType, senderId } = payload;
        // Log request only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Received file transfer request ${transferId} from ${senderId}: ${fileName} (${fileSize} bytes)`);

        // Basic validation of required payload fields.
        if (!transferId || !fileName || fileSize === undefined || !senderId) {
            // Always log validation warnings.
            console.warn(`Invalid file transfer request payload from ${senderId}:`, payload);
            return { action: 'NONE' }; // Ignore invalid request.
        }

        // Check if a transfer with this ID already exists (shouldn't happen normally).
        if (session.getTransferState(transferId)) {
             // Always log this warning.
             console.warn(`Duplicate file transfer request received for ID ${transferId}. Ignoring.`);
             return { action: 'NONE' };
        }

        // Store initial state for the incoming transfer.
        session.addTransferState(transferId, {
            status: 'pending_acceptance', // Waiting for local user action.
            progress: 0,
            fileName: fileName,
            fileSize: fileSize,
            fileType: fileType,
            senderId: senderId, // Store who sent the request.
            isSender: false // Mark this client as the receiver.
        });

        // Display the request message block in the UI, showing Accept/Reject buttons.
        this.uiController.addFileTransferMessage(transferId, senderId, fileName, fileSize, false); // false for isSender.
        this.uiController.playSound('file_request'); // Play notification sound for incoming request.

        // If the chat isn't currently active, mark the session as having unread activity.
        if (this.displayedPeerId !== session.peerId) {
            this.uiController.setUnreadIndicator(session.peerId, true);
        }

        // Consider adding a timeout for the user to accept/reject the request.

        return { action: 'NONE' }; // No further action needed until user interacts with the UI buttons.
    }

    /**
     * Handles an incoming FILE_TRANSFER_ACCEPT (Type 13) message from the peer.
     * Updates the transfer state and initiates the file upload process.
     * @param {Session} session - The session associated with the peer who accepted.
     * @param {object} payload - Contains transferId.
     * @returns {Promise<object>} Action object { action: 'NONE' }.
     * @private
     */
    async _handleFileTransferAccept(session, payload) {
        const { transferId } = payload;
        // Log acceptance only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Received acceptance for file transfer ${transferId} from ${session.peerId}`);

        const transferState = session.getTransferState(transferId);
        // Ensure the transfer exists, we are the sender, and were waiting for acceptance.
        if (!transferState || !transferState.isSender || transferState.status !== 'initiating') {
            // Always log this warning.
            console.warn(`Received unexpected acceptance for transfer ${transferId} or invalid state (${transferState?.status}).`);
            return { action: 'NONE' };
        }

        // Update state and UI status.
        transferState.status = 'uploading'; // Change state to uploading.
        this.uiController.updateFileTransferStatus(transferId, "Peer accepted. Starting upload...");
        // Optionally hide the cancel button during upload, or leave it visible.
        // this.uiController.hideFileTransferActions(transferId);

        // Start the asynchronous file upload process (reading chunks, encrypting, sending).
        this.startFileUpload(session, transferId); // Intentionally not awaited, runs in background.

        return { action: 'NONE' };
    }

    /**
     * Handles an incoming FILE_TRANSFER_REJECT (Type 14) message from the peer.
     * Updates the UI, plays a sound, and cleans up the local transfer state.
     * @param {Session} session - The session associated with the peer who rejected.
     * @param {object} payload - Contains transferId.
     * @returns {Promise<object>} Action object { action: 'NONE' }.
     * @private
     */
    async _handleFileTransferReject(session, payload) {
        const { transferId } = payload;
        // Log rejection only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Received rejection for file transfer ${transferId} from ${session.peerId}`);

        const transferState = session.getTransferState(transferId);
        // Ensure the transfer exists, we are the sender, and were waiting for acceptance.
        if (!transferState || !transferState.isSender || transferState.status !== 'initiating') {
            // Always log this warning.
            console.warn(`Received unexpected rejection for transfer ${transferId} or invalid state (${transferState?.status}).`);
            return { action: 'NONE' };
        }

        // Update state and UI status.
        transferState.status = 'rejected';
        this.uiController.updateFileTransferStatus(transferId, "Peer rejected the file transfer.");
        this.uiController.hideFileTransferActions(transferId); // Hide the cancel button.
        this.uiController.playSound('end'); // Play end/reject sound.

        // Clean up local state for this transfer.
        session.removeTransferState(transferId);
        // No DB cleanup needed for the sender.

        return { action: 'NONE' };
    }

    /**
     * Handles an incoming FILE_CHUNK (Type 15) message.
     * Decrypts the chunk data, stores it in IndexedDB, and updates UI progress.
     * Handles potential decryption or DB errors.
     * @param {Session} session - The session associated with the sender of the chunk.
     * @param {object} payload - Contains transferId, chunkIndex, iv, data (Base64 encrypted chunk).
     * @returns {Promise<object>} Action object { action: 'NONE' }.
     * @private
     */
    async _handleFileChunk(session, payload) {
        const { transferId, chunkIndex, iv, data } = payload;
        // Log chunk receipt only if DEBUG is enabled (can be very verbose).
        // if (config.DEBUG) console.log(`Received chunk ${chunkIndex} for transfer ${transferId}`);

        const transferState = session.getTransferState(transferId);
        // Ensure the transfer exists, we are the receiver, and are expecting data.
        if (!transferState || transferState.isSender || (transferState.status !== 'accepted' && transferState.status !== 'receiving')) {
            // Always log this warning.
            console.warn(`Received unexpected chunk for transfer ${transferId} or invalid state (${transferState?.status}).`);
            // Consider sending an error back to the sender.
            return { action: 'NONE' };
        }

        // Update status to 'receiving' if this is the first chunk.
        if (transferState.status === 'accepted') {
            transferState.status = 'receiving';
        }

        try {
            // Decode Base64 IV and encrypted data.
            const ivBuffer = session.cryptoModule.base64ToArrayBuffer(iv);
            const encryptedBuffer = session.cryptoModule.base64ToArrayBuffer(data);

            // Decrypt the chunk using the session's AES key.
            const decryptedChunk = await session.cryptoModule.decryptAES(encryptedBuffer, new Uint8Array(ivBuffer));
            if (!decryptedChunk) {
                throw new Error(`Decryption failed for chunk ${chunkIndex}`);
            }

            // Store the decrypted chunk data in IndexedDB, associated with the transferId and chunkIndex.
            await this.addChunkToDB(transferId, chunkIndex, decryptedChunk);

            // Update progress display. Calculate percentage based on chunk index and total file size.
            // Note: This assumes chunks arrive mostly in order for accurate progress display.
            const progressPercent = Math.min(100, ((chunkIndex + 1) * this.CHUNK_SIZE / transferState.fileSize) * 100);
            transferState.progress = progressPercent; // Update progress in the state object.
            this.uiController.updateFileTransferProgress(transferId, progressPercent);
            this.uiController.updateFileTransferStatus(transferId, `Receiving ${progressPercent.toFixed(1)}%...`);

        } catch (error) {
            // Handle errors during chunk processing (decoding, decryption, DB storage).
            // Always log errors.
            console.error(`Error processing chunk ${chunkIndex} for transfer ${transferId}:`, error);
            this.uiController.playSound('file_error');
            this.uiController.updateFileTransferStatus(transferId, `Error: ${error.message}`);
            this.uiController.hideFileTransferActions(transferId); // Hide accept/reject if still visible.
            // Send an error notification (Type 17) back to the sender.
            const errorPayload = { targetId: transferState.senderId, senderId: this.identifier, transferId: transferId, error: `Failed to process chunk ${chunkIndex}: ${error.message}` };
            this.wsClient.sendMessage({ type: 17, payload: errorPayload }); // Send best effort.
            // Clean up local state and any chunks stored in DB for this failed transfer.
            await this.deleteChunksFromDB(transferId);
            session.removeTransferState(transferId);
        }

        return { action: 'NONE' };
    }

    /**
     * Handles an incoming FILE_TRANSFER_COMPLETE (Type 16) message from the sender.
     * Retrieves all stored chunks from IndexedDB, assembles them into a Blob,
     * verifies the size, creates an Object URL, and displays the download link in the UI.
     * Cleans up IndexedDB chunks on success. Handles assembly errors.
     * @param {Session} session - The session associated with the sender.
     * @param {object} payload - Contains transferId.
     * @returns {Promise<object>} Action object { action: 'NONE' }.
     * @private
     */
    async _handleFileTransferComplete(session, payload) {
        const { transferId } = payload;
        // Log completion signal only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Received transfer complete signal for ${transferId}`);

        const transferState = session.getTransferState(transferId);
        // Ensure the transfer exists, we are the receiver, and were receiving chunks.
        if (!transferState || transferState.isSender || transferState.status !== 'receiving') {
            // Always log this warning.
            console.warn(`Received unexpected completion for transfer ${transferId} or invalid state (${transferState?.status}).`);
            return { action: 'NONE' };
        }

        // Update UI to indicate assembly process.
        this.uiController.updateFileTransferStatus(transferId, "Transfer complete. Assembling file...");
        this.uiController.updateFileTransferProgress(transferId, 100); // Ensure progress shows 100%.

        try {
            // Retrieve all stored chunks for this transferId from IndexedDB.
            const chunks = await this.getChunksFromDB(transferId);
            if (!chunks || chunks.length === 0) {
                throw new Error("File assembly failed: No chunks found in database.");
            }

            // Verify completeness (simple count check against expected number).
            const expectedChunks = Math.ceil(transferState.fileSize / this.CHUNK_SIZE);
            if (chunks.length !== expectedChunks) {
                // More robust check: ensure all indices from 0 to expectedChunks-1 are present.
                const receivedIndices = new Set(chunks.map(c => c.chunkIndex));
                const missing = [];
                for (let i = 0; i < expectedChunks; i++) {
                    if (!receivedIndices.has(i)) {
                        missing.push(i);
                    }
                }
                if (missing.length > 0) {
                    // Throw error if specific chunks are missing.
                    throw new Error(`File assembly failed: Missing chunks (${missing.join(', ')}). Expected ${expectedChunks}, got ${chunks.length}.`);
                }
                 // Log warning if count mismatch but all indices seem present (unlikely but possible).
                 console.warn(`Chunk count mismatch for ${transferId}. Expected ${expectedChunks}, got ${chunks.length}. Proceeding with assembly.`);
            }

            // Sort chunks by index - CRITICAL for correct file assembly!
            chunks.sort((a, b) => a.chunkIndex - b.chunkIndex);

            // Assemble the final file Blob from the ordered chunk data.
            const blob = new Blob(chunks.map(c => c.data), { type: transferState.fileType });

            // Verify the final assembled blob size matches the expected size from metadata.
            if (blob.size !== transferState.fileSize) {
                throw new Error(`Assembled file size mismatch. Expected ${transferState.fileSize}, got ${blob.size}.`);
            }

            // Show the download link in the UI, creating an Object URL for the Blob.
            this.uiController.showFileDownloadLink(transferId, blob, transferState.fileName);
            this.uiController.updateFileTransferStatus(transferId, "Download ready.");
            this.uiController.playSound('file_complete'); // Play completion sound.

            // Clean up stored chunks from IndexedDB *after* successful assembly and link creation.
            await this.deleteChunksFromDB(transferId);
            // Update the status in the session state.
            transferState.status = 'complete';
            // Store the blob URL in the state temporarily for potential revocation later.
            transferState.blobUrl = this.uiController.objectUrls.get(transferId);

        } catch (error) {
            // Handle errors during chunk retrieval, assembly, or verification.
            // Always log assembly errors.
            console.error(`Error assembling file for transfer ${transferId}:`, error);
            this.uiController.playSound('file_error');
            this.uiController.updateFileTransferStatus(transferId, `Error: ${error.message}`);
            this.uiController.hideFileTransferActions(transferId); // Hide download link placeholder on error.
            // Send an error notification (Type 17) back to the sender.
            const errorPayload = { targetId: transferState.senderId, senderId: this.identifier, transferId: transferId, error: `File assembly failed: ${error.message}` };
            this.wsClient.sendMessage({ type: 17, payload: errorPayload }); // Send best effort.
            // Clean up local state and any potentially stored chunks in DB.
            await this.deleteChunksFromDB(transferId);
            session.removeTransferState(transferId);
        }

        return { action: 'NONE' };
    }

    /**
     * Handles an incoming FILE_TRANSFER_ERROR (Type 17) message from the peer.
     * Updates the UI to show the error and cleans up the local transfer state.
     * @param {Session} session - The session associated with the peer reporting the error.
     * @param {object} payload - Contains transferId and an optional error message string.
     * @returns {Promise<object>} Action object { action: 'NONE' }.
     * @private
     */
    async _handleFileTransferError(session, payload) {
        const { transferId, error } = payload;
        const errorMessage = error || "Peer reported an unspecified error.";
        // Log error only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Received error for file transfer ${transferId} from ${session.peerId}: ${errorMessage}`);

        const transferState = session.getTransferState(transferId);
        if (!transferState) {
            // Always log this warning if error received for an unknown transfer.
            console.warn(`Received error for unknown transfer ${transferId}.`);
            return { action: 'NONE' };
        }

        // Update UI to show the error status and hide actions.
        this.uiController.updateFileTransferStatus(transferId, `Error: ${errorMessage}`);
        this.uiController.hideFileTransferActions(transferId);
        this.uiController.playSound('file_error'); // Play error sound.

        // Clean up local state and potentially DB chunks (attempt cleanup regardless of sender/receiver).
        await this.deleteChunksFromDB(transferId);
        session.removeTransferState(transferId);

        return { action: 'NONE' };
    }

    // --- IndexedDB Helper Methods ---

    /**
     * Initializes the IndexedDB database connection and creates the object store if needed.
     * Stores the database connection instance in `this.db`.
     */
    async initDB() {
        return new Promise((resolve, reject) => {
            // Log DB init only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Initializing IndexedDB: ${this.DB_NAME} v${this.DB_VERSION}`);

            // Check for IndexedDB browser support.
            if (!window.indexedDB) {
                console.error("IndexedDB not supported by this browser.");
                alert("File transfer requires IndexedDB support, which is not available in your browser.");
                reject("IndexedDB not supported.");
                return;
            }

            // Request opening the database.
            const request = indexedDB.open(this.DB_NAME, this.DB_VERSION);

            // Handle errors during DB opening.
            request.onerror = (event) => {
                // Always log DB errors.
                console.error("IndexedDB error:", event.target.error);
                reject(`IndexedDB error: ${event.target.error}`);
            };

            // Handle successful DB opening.
            request.onsuccess = (event) => {
                this.db = event.target.result; // Store the DB connection instance.
                // Log success only if DEBUG is enabled.
                if (config.DEBUG) console.log("IndexedDB initialized successfully.");
                resolve(this.db);
            };

            // Handle database upgrades (schema changes, initial creation).
            request.onupgradeneeded = (event) => {
                // Log upgrade only if DEBUG is enabled.
                if (config.DEBUG) console.log("IndexedDB upgrade needed.");
                const db = event.target.result;
                // Check if the object store for chunks already exists.
                if (!db.objectStoreNames.contains(this.CHUNK_STORE_NAME)) {
                    // Create the object store if it doesn't exist.
                    // Schema: { transferId, chunkIndex, data }
                    // Use a composite key [transferId, chunkIndex] for uniqueness and efficient lookup/sorting.
                    const store = db.createObjectStore(this.CHUNK_STORE_NAME, { keyPath: ['transferId', 'chunkIndex'] });
                    // Create an index on transferId alone for easily finding/deleting all chunks for a specific transfer.
                    store.createIndex('transferIdIndex', 'transferId', { unique: false });
                    // Log store creation only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`Object store '${this.CHUNK_STORE_NAME}' created.`);
                }
            };
        });
    }

    /**
     * Gets a transaction and object store reference for database operations.
     * @param {'readonly' | 'readwrite'} mode - The transaction mode ('readonly' or 'readwrite').
     * @returns {IDBObjectStore} The object store instance ready for use.
     * @throws {Error} If IndexedDB is not initialized (`this.db` is null).
     * @private
     */
    _getStore(mode) {
        if (!this.db) {
            throw new Error("IndexedDB is not initialized.");
        }
        // Start a transaction on the chunk store with the specified mode.
        const transaction = this.db.transaction(this.CHUNK_STORE_NAME, mode);
        // Return the object store interface from the transaction.
        return transaction.objectStore(this.CHUNK_STORE_NAME);
    }

    /**
     * Adds a decrypted file chunk to the IndexedDB store.
     * Uses a Promise to ensure the operation completes successfully.
     * @param {string} transferId - The transfer ID the chunk belongs to.
     * @param {number} chunkIndex - The index of this chunk within the transfer.
     * @param {ArrayBuffer} data - The decrypted chunk data (ArrayBuffer).
     * @returns {Promise<void>} Resolves on successful addition, rejects on error.
     */
    async addChunkToDB(transferId, chunkIndex, data) {
        return new Promise((resolve, reject) => {
            if (!this.db) {
                // Always log this error.
                console.error("Attempted to add chunk to DB, but DB is not initialized.");
                return reject(new Error("IndexedDB not initialized."));
            }
            try {
                // Start a readwrite transaction.
                const transaction = this.db.transaction(this.CHUNK_STORE_NAME, 'readwrite');
                const store = transaction.objectStore(this.CHUNK_STORE_NAME);

                // Log transaction start only if DEBUG is enabled.
                if (config.DEBUG) console.log(`DB: Starting transaction to add chunk ${chunkIndex} for ${transferId}`);

                // Handle transaction errors globally for this operation.
                transaction.onerror = (event) => {
                    // Always log DB errors.
                    console.error(`DB: Transaction error adding chunk ${chunkIndex} for ${transferId}:`, event.target.error);
                    reject(event.target.error || new Error("IndexedDB transaction failed"));
                };

                // Handle successful transaction completion.
                transaction.oncomplete = () => {
                    // Log completion only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`DB: Transaction complete for adding chunk ${chunkIndex} for ${transferId}.`);
                    resolve(); // Resolve the promise when the transaction commits.
                };

                // Queue the put request (add/update) within the transaction.
                // The object includes the composite key fields (transferId, chunkIndex) and the data.
                const request = store.put({ transferId, chunkIndex, data });

                // Handle request-specific errors (less common if transaction handles it, but good practice).
                request.onerror = (event) => {
                    // Always log DB errors.
                    console.error(`DB: Request error adding chunk ${chunkIndex} for ${transferId}:`, event.target.error);
                    // Don't reject here; let the transaction error handler manage the rejection.
                };
                 request.onsuccess = () => {
                     // Log put success only if DEBUG is enabled (indicates request queued successfully).
                     if (config.DEBUG) console.log(`DB: Put request successful for chunk ${chunkIndex} for ${transferId}. Waiting for transaction commit...`);
                 };

            } catch (error) {
                 // Always log errors getting store or starting transaction.
                 console.error("Error accessing IndexedDB store for adding chunk:", error);
                 reject(error);
            }
        });
    }

    /**
     * Retrieves all stored chunks for a given transfer ID from IndexedDB.
     * @param {string} transferId - The transfer ID whose chunks to retrieve.
     * @returns {Promise<Array<{transferId: string, chunkIndex: number, data: ArrayBuffer}>>} A promise resolving to an array of chunk objects.
     */
    async getChunksFromDB(transferId) {
        return new Promise((resolve, reject) => {
             if (!this.db) {
                // Always log this error.
                console.error("Attempted to get chunks from DB, but DB is not initialized.");
                return reject(new Error("IndexedDB not initialized."));
            }
            try {
                // Start a readonly transaction.
                const store = this._getStore('readonly');
                // Use the index on 'transferId' to efficiently get all matching records.
                const index = store.index('transferIdIndex');
                const request = index.getAll(transferId); // Get all records where transferId matches.

                // Handle successful retrieval.
                request.onsuccess = (event) => {
                    // Log retrieval only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`DB: Retrieved ${event.target.result.length} chunks for transfer ${transferId} from DB.`);
                    resolve(event.target.result); // result is an array of chunk objects {transferId, chunkIndex, data}.
                };
                // Handle errors during retrieval.
                request.onerror = (event) => {
                    // Always log DB errors.
                    console.error(`DB: Error retrieving chunks for ${transferId} from DB:`, event.target.error);
                    reject(event.target.error);
                };
            } catch (error) {
                 // Always log errors getting store.
                 console.error("Error accessing IndexedDB store for getting chunks:", error);
                 reject(error);
            }
        });
    }

    /**
     * Deletes all chunks associated with a given transfer ID from IndexedDB.
     * Uses an index and cursor for efficient deletion.
     * @param {string} transferId - The transfer ID whose chunks should be deleted.
     * @returns {Promise<void>} Resolves when the deletion transaction completes, rejects on error.
     */
    async deleteChunksFromDB(transferId) {
        return new Promise((resolve, reject) => {
             if (!this.db) {
                // Always log this warning if DB isn't ready.
                console.warn("Attempted to delete chunks from DB, but DB is not initialized.");
                // Resolve successfully as there's nothing to delete if DB isn't there.
                return resolve();
            }
            try {
                // Start a readwrite transaction.
                const transaction = this.db.transaction(this.CHUNK_STORE_NAME, 'readwrite');
                const store = transaction.objectStore(this.CHUNK_STORE_NAME);
                // Use the index on 'transferId' to efficiently find records to delete.
                const index = store.index('transferIdIndex');
                // Open a cursor over the keys matching the transferId.
                const request = index.openKeyCursor(IDBKeyRange.only(transferId));
                let deleteCount = 0; // Track how many records were deleted.

                // Log transaction start only if DEBUG is enabled.
                if (config.DEBUG) console.log(`DB: Starting transaction to delete chunks for ${transferId}`);

                // Handle transaction errors globally.
                transaction.onerror = (event) => {
                    // Always log DB errors.
                    console.error(`DB: Transaction error deleting chunks for ${transferId}:`, event.target.error);
                    reject(event.target.error || new Error("IndexedDB transaction failed"));
                };

                // Handle successful transaction completion.
                transaction.oncomplete = () => {
                    // Log completion only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`DB: Transaction complete for deleting ${deleteCount} chunks for ${transferId}.`);
                    resolve(); // Resolve the promise when the transaction commits.
                };

                // Process results from the cursor request.
                request.onsuccess = (event) => {
                    const cursor = event.target.result;
                    if (cursor) {
                        // Found a key matching the transferId. Delete the corresponding record using its primary key.
                        // The primary key for our store is the composite key [transferId, chunkIndex].
                        store.delete(cursor.primaryKey);
                        deleteCount++;
                        cursor.continue(); // Move to the next matching key.
                    }
                    // When cursor is null, all matching keys have been processed.
                    // The transaction's oncomplete handler will resolve the promise.
                };
                // Handle errors specifically from the cursor request.
                request.onerror = (event) => {
                    // Always log DB errors.
                    console.error(`DB: Cursor error deleting chunks for ${transferId}:`, event.target.error);
                    // Don't reject here; let the transaction error handler manage rejection.
                };

            } catch (error) {
                 // Always log errors getting store or starting transaction.
                 console.error("Error accessing IndexedDB store for deleting chunks:", error);
                 reject(error);
            }
        });
    }

    // --- End IndexedDB ---

    // --- Disconnect Cleanup ---
    /**
     * Performs cleanup tasks specifically related to file transfers when the WebSocket disconnects
     * or the page unloads. Iterates through all sessions and their transfers, updating UI,
     * deleting DB chunks, and revoking object URLs.
     */
    async handleDisconnectionCleanup() {
        // Log cleanup attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log("Performing disconnection cleanup for file transfers...");
        if (this.sessions.size > 0) {
            // Iterate through all managed sessions.
            for (const [peerId, session] of this.sessions.entries()) {
                // Check if the session has any active file transfers.
                if (session.transferStates && session.transferStates.size > 0) {
                    const transferIds = Array.from(session.transferStates.keys());
                    // Iterate through each transfer associated with this session.
                    for (const transferId of transferIds) {
                        const state = session.getTransferState(transferId);
                        if (state) {
                            // Log specific transfer cleanup only if DEBUG is enabled.
                            if (config.DEBUG) console.log(`Cleaning up transfer ${transferId} (status: ${state.status}) during disconnect.`);
                            // Update UI to show cancellation/error due to disconnect.
                            this.uiController.updateFileTransferStatus(transferId, "Cancelled (Disconnected)");
                            this.uiController.hideFileTransferActions(transferId); // Hide buttons.
                            // Clean up any stored chunks in IndexedDB.
                            await this.deleteChunksFromDB(transferId);
                            // Remove the transfer state from the session object (will also be cleared by resetSession).
                            session.removeTransferState(transferId);
                            // Revoke any associated object URLs to free memory.
                            this.uiController.revokeObjectURL(transferId);
                        }
                    }
                }
            }
        }
    }
    // --- End Disconnect Cleanup ---

} // End SessionManager Class
