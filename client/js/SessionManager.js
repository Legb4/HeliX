// client/js/SessionManager.js

/**
 * Manages the overall state of the chat application, user registration,
 * and all active/pending chat sessions. It acts as the central coordinator,
 * interacting with the WebSocketClient for network communication, the UIController
 * for display updates, and creating/managing individual Session instances.
 * This version uses ECDH for Perfect Forward Secrecy, IndexedDB for file transfers,
 * and implements Short Authentication String (SAS) verification.
 */
class SessionManager {
    /**
     * Initializes the SessionManager.
     * @param {WebSocketClient} webSocketClient - Instance for sending/receiving WebSocket messages.
     * @param {UIController} uiController - Instance for manipulating the user interface.
     * @param {typeof CryptoModule} cryptoModuleClass - The CryptoModule class itself (not an instance), used to create new crypto instances per session.
     */
    constructor(webSocketClient, uiController, cryptoModuleClass) {
        // Store references to injected dependencies.
        this.wsClient = webSocketClient;
        this.uiController = uiController;
        this.CryptoModuleClass = cryptoModuleClass; // Store the class constructor

        // --- Constants ---
        // Define timeout durations and delays used throughout the manager.
        this.HANDSHAKE_TIMEOUT_DURATION = 30000; // 30 seconds for handshake steps (key exchange, challenge, SAS). Increased slightly
        this.REQUEST_TIMEOUT_DURATION = 60000; // 60 seconds for the initial session request to be accepted/denied.
        this.REGISTRATION_TIMEOUT_DURATION = 15000; // 15 seconds to wait for registration success/failure reply.
        this.TYPING_STOP_DELAY = 3000; // Send TYPING_STOP message after 3 seconds of local user inactivity.
        this.TYPING_INDICATOR_TIMEOUT = 5000; // Hide peer's typing indicator after 5 seconds if no further typing messages or actual messages arrive.
        // File Transfer Constants
        this.MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB limit (adjust as needed)
        this.CHUNK_SIZE = 256 * 1024; // 256 KB chunk size (adjust as needed)
        this.FILE_ACCEPT_TIMEOUT = 60000; // 60 seconds for receiver to accept/reject file

        // --- Application States ---
        // Define possible states for the overall application manager.
        this.STATE_INITIALIZING = 'INITIALIZING'; // App just started.
        this.STATE_CONNECTING = 'CONNECTING'; // WebSocket attempting to connect.
        this.STATE_CONNECTED_UNREGISTERED = 'CONNECTED_UNREGISTERED'; // WebSocket connected, waiting for user registration.
        this.STATE_REGISTERING = 'REGISTERING'; // Registration message sent, awaiting reply.
        this.STATE_REGISTERED = 'REGISTERED'; // User successfully registered with an identifier.
        this.STATE_FAILED_REGISTRATION = 'FAILED_REGISTRATION'; // Registration attempt failed.
        this.STATE_DISCONNECTED = 'DISCONNECTED'; // WebSocket connection lost or closed.

        // --- Session-Specific States (Reflecting ECDH + SAS Flow) ---
        // Define possible states for individual Session instances.
        // Initiator states:
        this.STATE_INITIATING_SESSION = 'INITIATING_SESSION'; // Sent Type 1 request, awaiting Type 2 (Accept + Peer ECDH Key).
        this.STATE_DERIVING_KEY_INITIATOR = 'DERIVING_KEY_INITIATOR'; // Received Type 2, deriving keys before sending Type 4.
        this.STATE_KEY_DERIVED_INITIATOR = 'KEY_DERIVED_INITIATOR'; // Keys derived, ready to send Type 4.
        this.STATE_AWAITING_CHALLENGE_RESPONSE = 'AWAITING_CHALLENGE_RESPONSE'; // Sent Type 5, awaiting Type 6 (Response).
        this.STATE_RECEIVED_CHALLENGE = 'RECEIVED_CHALLENGE'; // Received Type 5 (Challenge), ready to send Type 6 (Response).
        this.STATE_AWAITING_FINAL_CONFIRMATION = 'AWAITING_FINAL_CONFIRMATION'; // Sent Type 6, awaiting Type 7 (Established).
        // Responder states:
        this.STATE_REQUEST_RECEIVED = 'REQUEST_RECEIVED'; // Received Type 1 request, awaiting user Accept/Deny.
        this.STATE_GENERATING_ACCEPT_KEYS = 'GENERATING_ACCEPT_KEYS'; // User clicked Accept, generating ECDH keys before sending Type 2.
        this.STATE_AWAITING_CHALLENGE = 'AWAITING_CHALLENGE'; // Sent Type 2 (Accept + Own ECDH Key), awaiting Type 4 (Initiator ECDH Key).
        this.STATE_DERIVING_KEY_RESPONDER = 'DERIVING_KEY_RESPONDER'; // Received Type 4, deriving keys before sending Type 5.
        this.STATE_RECEIVED_INITIATOR_KEY = 'RECEIVED_INITIATOR_KEY'; // Received Type 4, keys derived, ready to send Type 5 (Challenge).
        this.STATE_HANDSHAKE_COMPLETE_RESPONDER = 'HANDSHAKE_COMPLETE_RESPONDER'; // Received Type 6, verified, ready to send Type 7. (Intermediate state)
        // SAS Verification states:
        this.STATE_AWAITING_SAS_VERIFICATION = 'AWAITING_SAS_VERIFICATION'; // Handshake complete (Type 7 received/sent), SAS calculated, waiting for user/peer confirmation.
        this.STATE_SAS_CONFIRMED_LOCAL = 'SAS_CONFIRMED_LOCAL'; // Local user confirmed SAS match, waiting for peer confirmation (Type 7.1).
        this.STATE_SAS_CONFIRMED_PEER = 'SAS_CONFIRMED_PEER'; // Peer sent SAS confirmation (Type 7.1), waiting for local user confirmation.
        // Common states:
        this.STATE_ACTIVE_SESSION = 'ACTIVE_SESSION'; // Handshake & SAS verification complete, ready for messages (Type 8).
        // End/Error states:
        this.STATE_DENIED = 'DENIED'; // Request explicitly denied (Type 3) or target not found (Type -1).
        this.STATE_REQUEST_TIMED_OUT = 'REQUEST_TIMED_OUT'; // Initial request (Type 1) timed out.
        this.STATE_HANDSHAKE_TIMED_OUT = 'HANDSHAKE_TIMED_OUT'; // One of the handshake steps timed out.
        this.STATE_CANCELLED = 'CANCELLED'; // User cancelled an outgoing request.
        this.STATE_SAS_DENIED = 'SAS_DENIED'; // User clicked "Deny / Abort" or "Cancel" during SAS verification.

        // --- Manager State ---
        // Holds the current state of the application manager.
        this.managerState = this.STATE_INITIALIZING;
        // Stores the user's registered identifier.
        this.identifier = null;
        // Map storing active/pending Session instances, keyed by peerId.
        this.sessions = new Map();
        // Stores the peerId of the session currently awaiting user action (Accept/Deny).
        this.pendingPeerIdForAction = null;
        // Stores the peerId of the session currently displayed in the main content area.
        this.displayedPeerId = null;
        // Stores the ID of the registration timeout timer.
        this.registrationTimeoutId = null;

        // --- Local Typing State Tracking ---
        // Tracks if the local user is currently considered "typing" to a specific peer.
        this.isTypingToPeer = new Map(); // Map<peerId, boolean>
        // Stores timeout IDs for sending TYPING_STOP messages after inactivity.
        this.typingStopTimeoutId = new Map(); // Map<peerId, timeoutId>
        // --------------------------------------

        // --- IndexedDB State ---
        this.db = null; // Will hold the IndexedDB database object.
        this.DB_NAME = 'HeliXFileTransferDB';
        this.DB_VERSION = 1;
        this.CHUNK_STORE_NAME = 'fileChunks';
        // ----------------------------

        // --- Message Type Constants ---
        this.TYPE_SAS_CONFIRM = 7.1;
        // ------------------------------------

        // Log initialization (not wrapped in DEBUG as it's fundamental)
        console.log('SessionManager initialized (ECDH Mode, IndexedDB for files, SAS Verification).');
        this.updateManagerState(this.STATE_INITIALIZING); // Set initial state.
        this.initDB(); // Initialize IndexedDB connection.
    }

    /**
     * Updates the manager's overall state and logs the transition.
     * Prevents state changes away from DISCONNECTED unless it's back to INITIALIZING.
     * @param {string} newState - The new manager state identifier.
     */
    updateManagerState(newState) {
        // Prevent changing state if already fully disconnected, except for a full reset.
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
     * Starts a timeout for handshake steps within a specific session.
     * If the timeout expires, handleHandshakeTimeout is called.
     * @param {Session} session - The session to start the timeout for.
     */
    startHandshakeTimeout(session) {
        this.clearHandshakeTimeout(session); // Clear any existing timeout first.
        // Log timeout start only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Session [${session.peerId}] Starting handshake timeout (${this.HANDSHAKE_TIMEOUT_DURATION}ms)`);
        }
        session.handshakeTimeoutId = setTimeout(() => {
            this.handleHandshakeTimeout(session.peerId);
        }, this.HANDSHAKE_TIMEOUT_DURATION);
    }

    /**
     * Clears the handshake timeout for a specific session.
     * @param {Session} session - The session whose timeout should be cleared.
     */
    clearHandshakeTimeout(session) {
        if (session && session.handshakeTimeoutId) {
            // Log timeout clear only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`Session [${session.peerId}] Clearing handshake timeout.`);
            }
            clearTimeout(session.handshakeTimeoutId);
            session.handshakeTimeoutId = null;
        }
    }

    /**
     * Handles the expiration of a handshake timeout for a specific peer.
     * Updates the session state, plays an error sound, and potentially shows an info message.
     * @param {string} peerId - The ID of the peer whose handshake timed out.
     */
    handleHandshakeTimeout(peerId) {
        // Always log timeout errors.
        console.error(`Session [${peerId}] Handshake timed out!`);
        const session = this.sessions.get(peerId);
        // Define the states during which a handshake timeout is relevant (adjust for ECDH + SAS flow)
        const handshakeStates = [
            this.STATE_DERIVING_KEY_INITIATOR, this.STATE_KEY_DERIVED_INITIATOR,
            this.STATE_AWAITING_CHALLENGE_RESPONSE,
            this.STATE_RECEIVED_CHALLENGE, this.STATE_AWAITING_FINAL_CONFIRMATION,
            this.STATE_GENERATING_ACCEPT_KEYS, this.STATE_AWAITING_CHALLENGE,
            this.STATE_DERIVING_KEY_RESPONDER, this.STATE_RECEIVED_INITIATOR_KEY,
            this.STATE_HANDSHAKE_COMPLETE_RESPONDER, // Added intermediate state
            // SAS states are also part of the extended handshake/verification
            this.STATE_AWAITING_SAS_VERIFICATION,
            this.STATE_SAS_CONFIRMED_LOCAL,
            this.STATE_SAS_CONFIRMED_PEER
        ];
        // Check if the session exists and is still in a relevant handshake state.
        if (session && handshakeStates.includes(session.state)) {
            session.updateState(this.STATE_HANDSHAKE_TIMED_OUT);
            const message = `Handshake or verification with ${peerId} timed out. Please try initiating the session again.`;
            // Always try to show the info message pane for handshake timeouts.
            this.uiController.showInfoMessage(peerId, message, false); // No retry for handshake timeout.
            this.uiController.playSound('error'); // Play error sound
            // Reset the session internally after updating UI/state
            // Note: resetSession will handle switching view if needed.
            this.resetSession(peerId, false, "Handshake timed out."); // notifyUserViaAlert=false as info pane is shown
        } else if (session) {
             // Log ignored timeout only if DEBUG is enabled.
             if (config.DEBUG) {
                 console.log(`Session [${peerId}] Handshake timeout fired but session state (${session.state}) is no longer relevant. Ignoring.`);
             }
             session.handshakeTimeoutId = null; // Ensure ID is cleared.
        } else {
             // Always log warning for non-existent session timeout.
             console.warn(`Session [${peerId}] Handshake timeout fired but session no longer exists.`);
        }
    }

    /**
     * Starts a timeout for the initial session request (Type 1).
     * If the timeout expires, handleRequestTimeout is called.
     * @param {Session} session - The session to start the timeout for.
     */
    startRequestTimeout(session) {
        this.clearRequestTimeout(session); // Clear existing timeout.
        // Log timeout start only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Session [${session.peerId}] Starting request timeout (${this.REQUEST_TIMEOUT_DURATION}ms)`);
        }
        session.requestTimeoutId = setTimeout(() => {
            this.handleRequestTimeout(session.peerId);
        }, this.REQUEST_TIMEOUT_DURATION);
    }

    /**
     * Clears the initial request timeout for a specific session.
     * @param {Session} session - The session whose timeout should be cleared.
     */
    clearRequestTimeout(session) {
        if (session && session.requestTimeoutId) {
            // Log timeout clear only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`Session [${session.peerId}] Clearing request timeout.`);
            }
            clearTimeout(session.requestTimeoutId);
            session.requestTimeoutId = null;
        }
    }

    /**
     * Handles the expiration of the initial request timeout for a specific peer.
     * Updates the session state, plays an error sound, and potentially shows an info message allowing retry.
     * @param {string} peerId - The ID of the peer whose request timed out.
     */
    handleRequestTimeout(peerId) {
        // Always log timeout errors.
        console.error(`Session [${peerId}] Initial request timed out!`);
        const session = this.sessions.get(peerId);
        // Check if the session exists and is still in the initial state.
        if (session && session.state === this.STATE_INITIATING_SESSION) {
            session.updateState(this.STATE_REQUEST_TIMED_OUT);
            const message = `No response from ${peerId}. Request timed out.`;
            // Always show info message with retry option for request timeout.
            this.uiController.showInfoMessage(peerId, message, true); // Show retry button.
            this.uiController.playSound('error'); // Play error sound
            // Do NOT reset the session here, allow user to retry or close via UI.
        } else if (session) {
            // Log ignored timeout only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`Session [${peerId}] Request timeout fired but session state (${session.state}) is no longer relevant. Ignoring.`);
            }
            session.requestTimeoutId = null; // Ensure ID is cleared.
        } else {
            // Always log warning for non-existent session timeout.
            console.warn(`Session [${peerId}] Request timeout fired but session no longer exists.`);
        }
    }

    /**
     * Starts a timeout for the registration process (awaiting Type 0.1 or 0.2).
     * If the timeout expires, handleRegistrationTimeout is called.
     */
    startRegistrationTimeout() {
        this.clearRegistrationTimeout(); // Clear existing timeout.
        // Log timeout start only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Starting registration timeout (${this.REGISTRATION_TIMEOUT_DURATION}ms)`);
        }
        this.registrationTimeoutId = setTimeout(() => {
            this.handleRegistrationTimeout();
        }, this.REGISTRATION_TIMEOUT_DURATION);
    }

    /**
     * Clears the registration timeout.
     */
    clearRegistrationTimeout() {
        if (this.registrationTimeoutId) {
            // Log timeout clear only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("Clearing registration timeout.");
            }
            clearTimeout(this.registrationTimeoutId);
            this.registrationTimeoutId = null;
        }
    }

    /**
     * Handles the expiration of the registration timeout.
     * Updates manager state, plays an error sound, alerts the user, and re-enables registration UI.
     */
    handleRegistrationTimeout() {
        // Always log timeout errors.
        console.error("Registration timed out!");
        // Only act if we were actually waiting for registration.
        if (this.managerState === this.STATE_REGISTERING) {
            this.updateManagerState(this.STATE_FAILED_REGISTRATION);
            const reason = "No response from server.";
            this.uiController.updateStatus(`Registration Failed: ${reason}`);
            this.uiController.playSound('error'); // Play error sound
            // Use alert for registration timeout as it's a global failure.
            alert(`Registration failed: ${reason}`);
            // Show registration UI again and re-enable controls.
            this.uiController.showRegistration();
            this.uiController.setRegistrationControlsEnabled(true);
        }
    }
    // -----------------------------

    /**
     * Resets a specific session, cleaning up its state, timeouts, UI elements, typing status,
     * SAS status, and any associated file transfer data (including IndexedDB chunks and object URLs).
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
            // Clear all associated timeouts for this session.
            this.clearHandshakeTimeout(session);
            this.clearRequestTimeout(session);
            this.clearTypingIndicatorTimeout(session); // Clear peer typing indicator timeout
            this.clearLocalTypingTimeout(peerId); // Clear local typing stop timeout

            // File Transfer Cleanup
            // Iterate through any active/pending transfers for this session and clean them up.
            if (session.transferStates && session.transferStates.size > 0) {
                // Log cleanup only if DEBUG is enabled.
                if (config.DEBUG) console.log(`Cleaning up ${session.transferStates.size} file transfers for session ${peerId}`);
                const transferIds = Array.from(session.transferStates.keys());
                for (const transferId of transferIds) {
                    this.uiController.removeFileTransferMessage(transferId); // Removes UI and revokes URL
                    await this.deleteChunksFromDB(transferId); // Remove from IndexedDB
                }
                session.transferStates.clear(); // Clear the map in the session object
            }

            // Check if this session was the one being displayed or pending action.
            const wasDisplayed = (this.displayedPeerId === peerId);
            const wasPendingAction = (this.pendingPeerIdForAction === peerId);

            // Reset the session object's internal state (includes keys, SAS state, etc.).
            session.resetState();
            // Remove the session from the manager's active sessions map.
            this.sessions.delete(peerId);
            // Clean up typing state maps for this peer.
            this.isTypingToPeer.delete(peerId);
            this.typingStopTimeoutId.delete(peerId);

            // Remove the session from the UI list.
            this.uiController.removeSessionFromList(peerId);

            // Update UI based on whether the reset session was active.
            if (wasDisplayed) {
                this.displayedPeerId = null; // No session is displayed now.
                this.uiController.hideTypingIndicator(); // Hide indicator if this chat was active.
                // Show default view *unless* an info message or SAS pane was just displayed for this peer.
                // These panes should persist until closed/handled by the user.
                if (!this.uiController.isInfoPaneVisibleFor(peerId) && !this.uiController.isSasPaneVisibleFor(peerId)) { // Check SAS pane too
                     this.uiController.showDefaultRegisteredView(this.identifier);
                }
                // Use alert only if requested AND info/SAS pane wasn't shown.
                if (notifyUserViaAlert && reason && !this.uiController.isInfoPaneVisibleFor(peerId) && !this.uiController.isSasPaneVisibleFor(peerId)) { alert(reason); }
            }
            else if (wasPendingAction) {
                 // If it was pending action (incoming request), clear the flag.
                 this.pendingPeerIdForAction = null;
                 // If no other chat is displayed, show the welcome message.
                 if (!this.displayedPeerId) { this.uiController.showDefaultRegisteredView(this.identifier); }
                 // Use alert only if requested AND info/SAS pane wasn't shown.
                 if (notifyUserViaAlert && reason && !this.uiController.isInfoPaneVisibleFor(peerId) && !this.uiController.isSasPaneVisibleFor(peerId)) { alert(reason); }
            } else {
                 // Session was reset but wasn't displayed or pending action.
                 // Use alert if requested.
                 if (notifyUserViaAlert && reason) { alert(reason); }
            }

        } else {
            // Always log this warning.
            console.warn(`Attempted to reset non-existent session for peer: ${peerId}`);
        }

        // After resetting, if no sessions remain and we are registered, ensure the default view is shown
        // and initiation controls are enabled.
         if (this.sessions.size === 0 && this.managerState === this.STATE_REGISTERED) {
             if (!this.displayedPeerId && !this.pendingPeerIdForAction && !this.uiController.isAnyInfoPaneVisible() && !this.uiController.isAnySasPaneVisible()) { // Check SAS pane too
                 this.uiController.showDefaultRegisteredView(this.identifier);
             }
             this.uiController.updateStatus(`Registered as: ${this.identifier}`);
             this.uiController.setInitiationControlsEnabled(true);
         }
    }

    /**
     * Called when WebSocket connects but user is not registered. Shows the registration UI.
     */
    promptForRegistration() {
        this.updateManagerState(this.STATE_CONNECTED_UNREGISTERED);
        this.uiController.showRegistration();
    }

    /**
     * Attempts to register the user with the server using the provided identifier.
     * Sends a Type 0 message.
     * @param {string} id - The identifier chosen by the user.
     */
    attemptRegistration(id) {
        if (!id) { alert("Please enter an identifier."); return; } // Basic validation.
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Attempting registration for ID: ${id}`);
        this.updateManagerState(this.STATE_REGISTERING);
        // Disable registration UI elements and show loading state.
        this.uiController.setRegistrationControlsEnabled(false, true);
        this.uiController.updateStatus(`Registering as ${id}...`);
        // Construct the registration message.
        const msg = { type: 0, payload: { identifier: id } };
        // Send the message via WebSocketClient.
        if (this.wsClient.sendMessage(msg)) {
            // If sending was successful, start the registration timeout.
            this.startRegistrationTimeout();
        } else {
            // If sending failed (e.g., connection lost immediately), handle failure.
            this.handleRegistrationFailure({ error: "Connection error. Cannot send registration." });
        }
    }

    /**
     * Initiates a new chat session with a target peer.
     * Creates a new Session instance, generates ECDH keys, sends a Type 1 request,
     * and plays the send request sound.
     * @param {string} targetId - The identifier of the peer to connect with.
     */
    async initiateSession(targetId) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Attempting to initiate session with: ${targetId}`);

        // Prevent starting a new request if another outgoing request is already pending.
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
            alert("Not registered. Current state: " + this.managerState);
            return;
        }
        // Validate targetId.
        if (!targetId || typeof targetId !== 'string' || targetId.trim() === '') {
            alert("Invalid targetId.");
            return;
        }
        // Prevent chatting with self.
        if (targetId === this.identifier) {
            alert("Cannot chat with self.");
            return;
        }
        // Prevent starting if a session (in any state) already exists for this peer.
        if (this.sessions.has(targetId)) {
            alert(`Session with ${targetId} already exists.`);
            // Optionally, could switch to the existing session view here.
            this.switchToSessionView(targetId); // Switch to existing session
            return;
        }

        this.uiController.updateStatus(`Initiating session with ${targetId}...`);
        // Disable initiation controls while attempting to start
        this.uiController.setInitiationControlsEnabled(false, true); // Show loading on input

        // 1. Create a new CryptoModule instance dedicated to this session.
        const crypto = new this.CryptoModuleClass();
        // 2. Create a new Session object.
        const newSession = new Session(targetId, this.STATE_INITIATING_SESSION, crypto);
        // 3. Add the session to the manager's map.
        this.sessions.set(targetId, newSession);
        // 4. Add the session to the UI list.
        this.uiController.addSessionToList(targetId);
        // 5. Switch the main view to this new session (will show "Waiting..." pane).
        this.switchToSessionView(targetId);

        try {
            // 6. Generate ECDH keys for this session.
            const keysGenerated = await newSession.cryptoModule.generateECDHKeys(); // Use ECDH
            if (!keysGenerated) { throw new Error("Key generation failed"); }
            // Log key generation only if DEBUG is enabled.
            if (config.DEBUG) console.log(`ECDH keys generated for session with ${targetId}.`);

            // 7. Construct and send the SESSION_REQUEST (Type 1) message.
            // Payload remains the same for Type 1.
            const msg = { type: 1, payload: { targetId: targetId, senderId: this.identifier } };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending SESSION_REQUEST (Type 1):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // 8. Play send request sound and start timeout if message sent successfully.
                this.uiController.playSound('sendrequest'); // Play sound on successful send
                this.startRequestTimeout(newSession);
                this.uiController.updateStatus(`Waiting for response from ${targetId}...`);
            } else {
                // Throw error if sending failed.
                throw new Error("Connection error. Failed to send session request.");
            }
        } catch (error) {
            // Handle errors during key generation or sending.
            // Always log errors.
            console.error("Error during initiateSession:", error);
            this.uiController.playSound('error'); // Play error sound
            // Use showInfoMessage for better feedback instead of alert
            this.uiController.showInfoMessage(targetId, `Failed to initiate session: ${error.message}`, false);
            // Clean up the failed session attempt.
            await this.resetSession(targetId, false); // notifyUserViaAlert=false
        } finally {
            // Re-enable initiation controls regardless of success/failure
            this.uiController.setInitiationControlsEnabled(true);
        }
    }

    /**
     * Accepts an incoming session request from a peer.
     * Generates ECDH keys, sends a Type 2 acceptance message with the public ECDH key.
     * @param {string} peerId - The identifier of the peer whose request is being accepted.
     */
    async acceptRequest(peerId) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Attempting to accept session request from: ${peerId}`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is in the correct state.
        if (!session || session.state !== this.STATE_REQUEST_RECEIVED) {
            // Always log this warning.
            console.warn(`Cannot accept request for ${peerId}: Session not found or invalid state (${session?.state}).`);
            // If session exists but wrong state, maybe show default view?
            if (session) this.switchToSessionView(peerId); // Show current state
            else this.uiController.showDefaultRegisteredView(this.identifier);
            return;
        }

        // Disable incoming request buttons and show loading state.
        this.uiController.setIncomingRequestControlsEnabled(false, true);

        // Clear the pending action flag as we are handling it now.
        if (this.pendingPeerIdForAction === peerId) { this.pendingPeerIdForAction = null; }

        // Update session state and UI status.
        session.updateState(this.STATE_GENERATING_ACCEPT_KEYS);
        this.uiController.updateStatus(`Accepting request from ${peerId}, generating keys...`);
        // Switch view to this session (will likely show welcome/loading initially).
        this.switchToSessionView(peerId);

        try {
            // 1. Generate ECDH keys for this session.
            const keysGenerated = await session.cryptoModule.generateECDHKeys(); // Use ECDH
            if (!keysGenerated) { throw new Error("Key generation failed"); }
            // 2. Export the generated public ECDH key to Base64 SPKI format.
            const publicKeyBase64 = await session.cryptoModule.getPublicKeyBase64();
            if (!publicKeyBase64) { throw new Error("Key export failed"); }

            // 3. Construct and send the SESSION_ACCEPT (Type 2) message with the ECDH public key.
            const msg = { type: 2, payload: { targetId: peerId, senderId: this.identifier, publicKey: publicKeyBase64 } };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending SESSION_ACCEPT (Type 2 with ECDH key):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // 4. Update state and start handshake timeout if message sent successfully.
                session.updateState(this.STATE_AWAITING_CHALLENGE); // We now wait for their key (Type 4)
                this.startHandshakeTimeout(session);
                this.uiController.updateStatus(`Waiting for ${peerId}'s public key...`);
            } else {
                // Throw error if sending failed.
                throw new Error("Connection error. Failed to send session acceptance.");
            }
        } catch (error) {
            // Handle errors during key generation/export or sending.
            // Always log errors.
            console.error("Error during acceptRequest:", error);
            this.uiController.playSound('error'); // Play error sound
            // Use showInfoMessage for better feedback instead of alert
            this.uiController.showInfoMessage(peerId, `Failed to accept session: ${error.message}`, false);
            // Clean up the failed session attempt.
            await this.resetSession(peerId, false); // notifyUserViaAlert=false
        } finally {
            // Re-enable incoming request controls if the pane is still visible (e.g., if error occurred before send)
            if (session?.state === this.STATE_GENERATING_ACCEPT_KEYS) {
                 this.uiController.setIncomingRequestControlsEnabled(true);
            }
        }
    }

    /**
     * Denies an incoming session request from a peer.
     * Sends a Type 3 denial message, plays end sound, and resets the session.
     * @param {string} peerId - The identifier of the peer whose request is being denied.
     */
    async denyRequest(peerId) {
        // Log denial only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Denying session request from: ${peerId}`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is in the correct state.
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
        this.wsClient.sendMessage(msg); // Send best effort.

        // Play end sound as the potential session is being terminated.
        this.uiController.playSound('end');

        // Reset the session locally immediately after sending denial.
        await this.resetSession(peerId, false, `Denied request from ${peerId}.`); // notifyUserViaAlert=false
        // Show the default welcome view as the request pane is now gone.
        this.uiController.showDefaultRegisteredView(this.identifier);
    }

    // --- Send methods called by processMessageResult ---

    /**
     * Sends the PUBLIC_KEY_RESPONSE (Type 4) message containing own public ECDH key.
     * Called by initiator after receiving Type 2 (Accept) from responder.
     * @param {Session} session - The session object.
     */
    async sendPublicKeyResponse(session) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${session.peerId}] Attempting to send PUBLIC_KEY_RESPONSE (Type 4 with ECDH key)...`);
        try {
            // Export own public ECDH key.
            const publicKeyBase64 = await session.cryptoModule.getPublicKeyBase64();
            if (!publicKeyBase64) { throw new Error("Key export failed."); } // Throw on failure

            // Construct and send message.
            const msg = { type: 4, payload: { targetId: session.peerId, senderId: this.identifier, publicKey: publicKeyBase64 } };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending PUBLIC_KEY_RESPONSE (Type 4 with ECDH key):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // Start handshake timeout, waiting for Type 5 (Challenge).
                session.updateState(this.STATE_AWAITING_CHALLENGE_RESPONSE); // Update state after successful send - Initiator waits for challenge
                this.startHandshakeTimeout(session);
                this.uiController.updateStatus(`Waiting for challenge from ${session.peerId}...`);
            } else {
                // Throw error if send fails.
                throw new Error("Connection error sending key response.");
            }
        } catch (error) {
            // Always log errors.
            console.error(`Session [${session.peerId}] Error sending Type 4:`, error);
            this.uiController.playSound('error'); // Play error sound
            // Use showInfoMessage for feedback
            this.uiController.showInfoMessage(session.peerId, `Handshake Error: ${error.message}`, false);
            await this.resetSession(session.peerId, false); // notifyUserViaAlert=false
        }
    }

    /**
     * Generates, encrypts (using derived AES key), and sends the KEY_CONFIRMATION_CHALLENGE (Type 5) message.
     * Called by responder after receiving Type 4 (Initiator's Key) and deriving the session key.
     * @param {Session} session - The session object.
     */
    async sendKeyConfirmationChallenge(session) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${session.peerId}] Attempting to send KEY_CONFIRMATION_CHALLENGE (Type 5 using derived key)...`);
        try {
            // Ensure the session key has been derived.
            if (!session.cryptoModule.derivedSessionKey) {
                throw new Error("Session key not derived before sending challenge.");
            }
            // Generate challenge data (e.g., unique text).
            const challengeText = `Challenge_for_${session.peerId}_from_${this.identifier}_${Date.now()}`;
            const challengeBuffer = session.cryptoModule.encodeText(challengeText);
            // Store the raw challenge buffer to verify the response later.
            session.challengeSent = challengeBuffer;
            // Log generation only if DEBUG is enabled.
            if (config.DEBUG) console.log("Generated challenge data.");

            // Encrypt the challenge buffer using the derived AES session key.
            const encryptionResult = await session.cryptoModule.encryptAES(challengeBuffer);
            if (!encryptionResult) { throw new Error("Failed to encrypt challenge."); } // Throw on failure

            // Encode IV and encrypted buffer to Base64.
            const ivBase64 = session.cryptoModule.arrayBufferToBase64(encryptionResult.iv);
            const encryptedBase64 = session.cryptoModule.arrayBufferToBase64(encryptionResult.encryptedBuffer);

            // Construct and send message with IV and encrypted data.
            const msg = {
                type: 5,
                payload: {
                    targetId: session.peerId,
                    senderId: this.identifier,
                    iv: ivBase64,
                    encryptedChallenge: encryptedBase64 // Renamed field for clarity
                }
            };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending KEY_CONFIRMATION_CHALLENGE (Type 5):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // Start handshake timeout, waiting for Type 6 (Response).
                session.updateState(this.STATE_AWAITING_CHALLENGE_RESPONSE); // Update state after successful send
                this.startHandshakeTimeout(session);
                this.uiController.updateStatus(`Challenge sent to ${session.peerId}. Waiting for response...`);
            } else {
                 // Throw error if send fails.
                 throw new Error("Connection error sending challenge.");
            }
        } catch (error) {
            // Always log errors.
            console.error(`Session [${session.peerId}] Error sending Type 5:`, error);
            this.uiController.playSound('error'); // Play error sound
            // Use showInfoMessage for feedback
            this.uiController.showInfoMessage(session.peerId, `Handshake Error: ${error.message}`, false);
            await this.resetSession(session.peerId, false); // notifyUserViaAlert=false
        }
    }

    /**
     * Encrypts the received challenge data (using derived AES key) and sends it back as KEY_CONFIRMATION_RESPONSE (Type 6).
     * Called by initiator after receiving and decrypting Type 5 (Challenge) and deriving the session key.
     * @param {Session} session - The session object.
     * @param {ArrayBuffer} challengeData - The raw decrypted challenge data received from the peer.
     */
    async sendKeyConfirmationResponse(session, challengeData) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${session.peerId}] Attempting to send KEY_CONFIRMATION_RESPONSE (Type 6 using derived key)...`);
        try {
            // Ensure session key is derived and challenge data is available.
            if (!session.cryptoModule.derivedSessionKey || !challengeData) {
                throw new Error("Missing session key or challenge data for response.");
            }
            // Encrypt the original challenge data using the derived AES session key.
            const encryptionResult = await session.cryptoModule.encryptAES(challengeData);
            if (!encryptionResult) { throw new Error("Failed to encrypt challenge response."); } // Throw on failure

            // Encode IV and encrypted buffer to Base64.
            const ivBase64 = session.cryptoModule.arrayBufferToBase64(encryptionResult.iv);
            const encryptedBase64 = session.cryptoModule.arrayBufferToBase64(encryptionResult.encryptedBuffer);

            // Construct and send message with IV and encrypted data.
            const msg = {
                type: 6,
                payload: {
                    targetId: session.peerId,
                    senderId: this.identifier,
                    iv: ivBase64,
                    encryptedResponse: encryptedBase64 // Renamed field for clarity
                }
            };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending KEY_CONFIRMATION_RESPONSE (Type 6):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // Start handshake timeout, waiting for Type 7 (Established).
                session.updateState(this.STATE_AWAITING_FINAL_CONFIRMATION); // Update state after successful send
                this.startHandshakeTimeout(session);
                this.uiController.updateStatus(`Challenge response sent to ${session.peerId}. Waiting for final confirmation...`);
            } else {
                 // Throw error if send fails.
                 throw new Error("Connection error sending challenge response.");
            }
        } catch (error) {
            // Always log errors.
            console.error(`Session [${session.peerId}] Error sending Type 6:`, error);
            this.uiController.playSound('error'); // Play error sound
            // Use showInfoMessage for feedback
            this.uiController.showInfoMessage(session.peerId, `Handshake Error: ${error.message}`, false);
            await this.resetSession(session.peerId, false); // notifyUserViaAlert=false
        }
    }

    /**
     * Sends the SESSION_ESTABLISHED (Type 7) message to confirm successful handshake.
     * Called by responder after receiving and verifying Type 6 (Response).
     * After sending, triggers SAS calculation locally for the responder.
     * @param {Session} session - The session object.
     */
    async sendSessionEstablished(session) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${session.peerId}] Attempting to send SESSION_ESTABLISHED (Type 7)...`);
        try {
            // Construct the final confirmation message. Payload remains simple.
            const msg = { type: 7, payload: { targetId: session.peerId, senderId: this.identifier, message: "Session established successfully!" } };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending SESSION_ESTABLISHED (Type 7):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // Trigger SAS calculation AFTER sending Type 7
                // The Responder has now completed the crypto handshake and notified the Initiator.
                // Now, the Responder calculates and shows their own SAS pane.
                session.updateState(this.STATE_HANDSHAKE_COMPLETE_RESPONDER); // Intermediate state
                this.uiController.updateStatus(`Handshake complete with ${session.peerId}. Verifying connection...`);
                // Use processMessageResult to handle the SAS calculation and UI update
                // This keeps the logic centralized.
                await this.processMessageResult(session, { action: 'CALCULATE_AND_SHOW_SAS' });
            } else {
                 // Throw error if final confirmation send fails.
                 throw new Error("Connection error sending final confirmation.");
            }
        } catch (error) {
            // Always log errors.
            console.error(`Session [${session.peerId}] Error sending Type 7:`, error);
            this.uiController.playSound('error'); // Play error sound
            // Use showInfoMessage for feedback
            this.uiController.showInfoMessage(session.peerId, `Handshake Error: ${error.message}`, false);
            await this.resetSession(session.peerId, false); // notifyUserViaAlert=false
        }
    }

    /**
     * Handles sending a chat message or processing a slash command.
     * If it's a command like /me, it sends a structured payload.
     * Otherwise, it sends a regular message payload.
     * Encrypts the payload (as JSON string) and sends as Type 8.
     * Updates local UI immediately.
     * @param {string} peerId - The identifier of the recipient peer.
     * @param {string} text - The raw text entered by the user.
     */
    async sendEncryptedMessage(peerId, text) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Attempting to send message/command to ${peerId}: "${text}"`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is active.
        if (!session || session.state !== this.STATE_ACTIVE_SESSION) {
            // Always log this warning.
            console.warn(`Cannot send message: Session with ${peerId} not active.`);
            // Use addCommandError for feedback
            if (this.displayedPeerId === peerId) {
                this.uiController.addCommandError("Error: Cannot send message, session is not active.");
            }
            return;
        }
        // Ensure the derived session key exists.
        if (!session.cryptoModule.derivedSessionKey) {
            // Always log this critical error.
            console.error(`Session [${peerId}] Encryption key error: Missing derived session key.`);
            this.uiController.playSound('error');
            this.uiController.showInfoMessage(peerId, "Encryption Error: Session key is missing. Please restart the session.", false);
            await this.resetSession(peerId, false);
            return;
        }
        // Ensure message text is valid.
        if (!text || typeof text !== 'string' || text.trim().length === 0) {
            // Always log this warning.
            console.warn("Attempted to send empty message."); return;
        }

        // If we were typing, send TYPING_STOP first
        this.sendTypingStop(peerId);

        // Disable chat controls and show loading state while processing/encrypting/sending.
        this.uiController.setChatControlsEnabled(false, true);
        this.uiController.updateStatus(`Processing message to ${peerId}...`);
        let messageSent = false; // Flag to track if send was successful.

        try {
            let payloadToSend = null; // This will hold the object {isAction, text} or null if handled locally
            let localDisplayHandled = false; // Flag to track if local UI update is done

            // --- Command Parsing Logic ---
            if (text.startsWith('/')) {
                const spaceIndex = text.indexOf(' ');
                const command = (spaceIndex === -1 ? text.substring(1) : text.substring(1, spaceIndex)).toLowerCase();
                const args = (spaceIndex === -1 ? '' : text.substring(spaceIndex + 1)).trim();

                // Log command parsing only if DEBUG is enabled.
                if (config.DEBUG) console.log(`Parsed command: '${command}', args: '${args}'`);

                localDisplayHandled = true; // Assume handled locally unless sending a message

                switch (command) {
                    case 'me':
                        if (args) {
                            // Valid /me command
                            payloadToSend = { isAction: true, text: args };
                            this.uiController.addMeActionMessage(this.identifier, args);
                        } else {
                            // Invalid /me command (no arguments)
                            this.uiController.addCommandError("Error: /me command requires an action.");
                        }
                        break;
                    case 'end':
                        // Use getActivePeerId() to ensure we're ending the *current* chat
                        const activePeerIdForEnd = this.getActivePeerId();
                        if (activePeerIdForEnd === peerId) { // Check if the command is for the active chat
                            this.endSession(peerId); // Call endSession (which handles UI/reset)
                        } else if (activePeerIdForEnd) {
                            this.uiController.addCommandError(`Error: /end can only be used in the active chat (${activePeerIdForEnd}).`);
                        } else {
                            this.uiController.addCommandError("Error: No active session to end.");
                        }
                        break;
                    case 'version':
                        this.uiController.addVersionInfo(config.APP_VERSION);
                        break;
                    case 'info':
                        const activePeerIdForInfo = this.getActivePeerId();
                        if (activePeerIdForInfo === peerId) { // Check if the command is for the active chat
                            const httpsUrl = window.location.href;
                            const wssUrl = this.wsClient.url;
                            this.uiController.addSessionInfo(httpsUrl, wssUrl, this.identifier, peerId);
                        } else if (activePeerIdForInfo) {
                            this.uiController.addCommandError(`Error: /info can only be used in the active chat (${activePeerIdForInfo}).`);
                        } else {
                            this.uiController.addCommandError("Error: No active session selected for /info command.");
                        }
                        break;
                    case 'help':
                        this.uiController.addHelpInfo();
                        break;
                    default:
                        // Unknown command
                        this.uiController.addCommandError(`Error: Unknown command "/${command}". Type /help for a list of commands.`);
                        break;
                }
            } else {
                // Regular message (no slash command)
                payloadToSend = { isAction: false, text: text };
                session.addMessageToHistory(this.identifier, text, 'own');
                if (this.displayedPeerId === peerId) {
                    this.uiController.addMessage(this.identifier, text, 'own');
                }
                localDisplayHandled = true;
            }
            // --- End Command Parsing Logic ---

            // Only proceed to encrypt and send if payloadToSend is valid
            if (payloadToSend) {
                // 1. Encode the payload object to a JSON string, then to UTF-8 ArrayBuffer.
                const payloadJson = JSON.stringify(payloadToSend);
                const payloadBuffer = session.cryptoModule.encodeText(payloadJson);

                // 2. Encrypt the payload buffer using the derived AES session key.
                this.uiController.updateStatus(`Encrypting message to ${peerId}...`);
                const aesResult = await session.cryptoModule.encryptAES(payloadBuffer);
                if (!aesResult) throw new Error("AES encryption failed.");

                // 3. Encode the IV and the encrypted data to Base64.
                const ivBase64 = session.cryptoModule.arrayBufferToBase64(aesResult.iv);
                const encryptedDataBase64 = session.cryptoModule.arrayBufferToBase64(aesResult.encryptedBuffer);

                // 4. Construct the ENCRYPTED_CHAT_MESSAGE (Type 8) payload.
                const message = {
                    type: 8,
                    payload: {
                        targetId: peerId,
                        senderId: this.identifier,
                        iv: ivBase64,
                        data: encryptedDataBase64
                    }
                };
                this.uiController.updateStatus(`Sending message to ${peerId}...`);
                // Log sending only if DEBUG is enabled.
                if (config.DEBUG) console.log(`Sending ENCRYPTED_CHAT_MESSAGE (Type 8) to ${peerId}`);

                // 5. Send the message via WebSocketClient.
                if (this.wsClient.sendMessage(message)) {
                    messageSent = true;
                    // Local display was already handled above
                } else {
                    // sendMessage returning false usually indicates connection issue.
                    // Always log this error.
                    console.error("sendMessage returned false, connection likely lost.");
                    if (this.displayedPeerId === peerId) {
                        this.uiController.addSystemMessage("Error: Failed to send message (connection lost?).");
                    }
                }
            } else if (!localDisplayHandled) {
                // This case should ideally not be reached if logic is correct,
                // but handles scenarios where a command was parsed but resulted in no action/message.
                // Log this warning only if DEBUG is enabled.
                if (config.DEBUG) console.log("Command processed locally, nothing sent to peer.");
            }

        } catch (error) {
            // Handle errors during the encryption/sending process.
            // Always log errors.
            console.error("Error during sendEncryptedMessage:", error);
            this.uiController.playSound('error'); // Play error sound
            if (this.displayedPeerId === peerId) {
                // Use addCommandError for send errors
                this.uiController.addCommandError(`Error sending message: ${error.message}`);
            } else {
                alert(`Error sending message to ${peerId}: ${error.message}`);
            }
        } finally {
             // Re-enable chat controls regardless of success/failure.
             this.uiController.setChatControlsEnabled(true);
             // Update status and focus input if session is still active.
             if (session?.state === this.STATE_ACTIVE_SESSION) {
                 this.uiController.updateStatus(`Session active with ${peerId}.`);
                 this.uiController.focusMessageInput();
             }
        }
    }


    /**
     * Ends the chat session with the specified peer from the user's side.
     * Sends a Type 9 message, plays end sound, shows an info pane locally, and resets the session.
     * @param {string} peerId - The identifier of the peer whose session to end.
     */
    async endSession(peerId) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Attempting to end session with ${peerId}...`);
        const session = this.sessions.get(peerId);
        if (!session) { return; } // Ignore if session doesn't exist.

        // Disable chat controls while ending.
        this.uiController.setChatControlsEnabled(false, true);
        // Construct and send the SESSION_END_REQUEST (Type 9) message.
        const endMessage = { type: 9, payload: { targetId: peerId, senderId: this.identifier } };
        // Log sending only if DEBUG is enabled.
        if (config.DEBUG) console.log("Sending SESSION_END_REQUEST (Type 9):", endMessage);
        this.wsClient.sendMessage(endMessage); // Send best effort.
        this.uiController.updateStatus(`Ending session with ${peerId}...`);

        // Play end sound locally.
        this.uiController.playSound('end');

        // Show info pane locally *before* resetting the session.
        // Use a reason appropriate to the state (e.g., if SAS was denied vs. normal end)
        let reason = `You ended the session with ${peerId}.`;
        if (session.state === this.STATE_SAS_DENIED) {
            reason = `Session aborted due to verification mismatch or cancellation with ${peerId}.`;
        }
        this.uiController.showInfoMessage(peerId, reason, false); // Show info, no retry
        // Reset the session locally immediately, but without the alert fallback.
        await this.resetSession(peerId, false, reason); // notifyUserViaAlert = false
    }

    /**
     * Handles the user clicking the "Close" button on an info message pane.
     * If the session associated with the pane is in a terminal error/denial state,
     * it resets the session. Otherwise, it just hides the pane and shows the default view.
     * @param {string} peerId - The peer ID associated with the info message.
     */
    async closeInfoMessage(peerId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Closing info message regarding ${peerId}`);
        // Disable info pane controls.
        this.uiController.setInfoControlsEnabled(false, true);

        // Check if the session still exists and if it's in a state that requires cleanup upon closing the info pane.
        const session = this.sessions.get(peerId);
        const terminalStates = [
            this.STATE_DENIED,
            this.STATE_REQUEST_TIMED_OUT,
            this.STATE_HANDSHAKE_TIMED_OUT,
            this.STATE_SAS_DENIED // Add SAS denial state
        ];
        if (session && terminalStates.includes(session.state)) {
            // If the session is in a terminal state, reset it now.
            if (config.DEBUG) console.log(`Session [${peerId}] is in terminal state (${session.state}). Resetting.`);
            await this.resetSession(peerId, false); // notifyUserViaAlert = false
        } else if (session) {
            // If the session exists but isn't in a terminal state (e.g., user manually ended),
            // it should have already been reset. Just log for debugging.
            if (config.DEBUG) console.log(`Info pane closed for session [${peerId}] in state ${session.state}. Session should already be reset.`);
        } else {
            // If the session doesn't exist (already reset), log for debugging.
            if (config.DEBUG) console.log(`Info pane closed for already reset session [${peerId}].`);
        }

        // Hide the info pane (implicitly done by showDefaultRegisteredView if needed)
        // If no other chat is displayed, show the default welcome view.
        // Check if the closed info pane was the one being displayed.
        if (this.displayedPeerId === peerId) {
            this.displayedPeerId = null; // Clear displayed peer since info pane is closing
        }
        // Show default view if nothing else is active
        if (!this.displayedPeerId && !this.pendingPeerIdForAction) {
            this.uiController.showDefaultRegisteredView(this.identifier);
        } else if (this.displayedPeerId) {
            // If another session *is* active, ensure its view is shown correctly
            this.switchToSessionView(this.displayedPeerId);
        } else {
            // If no session displayed, but maybe an incoming request is pending?
            // This case might need refinement depending on desired UI flow.
            // For now, default view is safest.
            this.uiController.showDefaultRegisteredView(this.identifier);
        }
    }


    /**
     * Handles the user clicking the "Retry" button after a request timeout.
     * Resends the initial SESSION_REQUEST (Type 1) message and plays send request sound.
     * @param {string} peerId - The peer ID associated with the timed-out request.
     */
    async retryRequest(peerId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Retrying session request with ${peerId}`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is in a retryable state (timed out or denied - though deny retry might be less common).
        if (session && (session.state === this.STATE_REQUEST_TIMED_OUT || session.state === this.STATE_DENIED)) {

            // Prevent retrying if another outgoing request is already pending.
            let pendingInitiationPeer = null;
            for (const [pId, s] of this.sessions.entries()) {
                // Check other sessions (pId !== peerId)
                if (pId !== peerId && s.state === this.STATE_INITIATING_SESSION) {
                    pendingInitiationPeer = pId;
                    break;
                }
            }
            if (pendingInitiationPeer) {
                alert(`Please cancel or wait for the pending request for ${pendingInitiationPeer} before retrying the request for ${peerId}.`);
                return;
            }

            // Disable info pane controls and show loading state.
            this.uiController.setInfoControlsEnabled(false, true);
            this.uiController.updateStatus(`Retrying session with ${peerId}...`);
            // Reset session state back to initiating.
            session.updateState(this.STATE_INITIATING_SESSION);
            // Clear any lingering timeouts from the previous attempt.
            this.clearRequestTimeout(session);
            this.clearHandshakeTimeout(session);
            // Switch view back to the "Waiting..." pane for this session.
            this.switchToSessionView(peerId);

            // Construct and resend the SESSION_REQUEST (Type 1) message.
            const msg = { type: 1, payload: { targetId: peerId, senderId: this.identifier } };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Re-sending SESSION_REQUEST (Type 1):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // Play send request sound and start timeout again.
                this.uiController.playSound('sendrequest');
                this.startRequestTimeout(session);
                this.uiController.updateStatus(`Waiting for response from ${peerId}...`);
            } else {
                 // Use showInfoMessage for feedback if send fails
                 this.uiController.showInfoMessage(peerId, "Connection error retrying request.", false);
                 this.uiController.playSound('error'); // Play error sound
                 await this.resetSession(peerId, false); // Reset session
            }
        } else {
            // Always log this warning.
            console.warn(`Cannot retry request for ${peerId}, session not found or not in a retryable state (${session?.state}).`);
            // If session exists but wrong state, close the info message.
            if (session) { await this.closeInfoMessage(peerId); }
            // If session doesn't exist, just show default view.
            else { this.uiController.showDefaultRegisteredView(this.identifier); }
        }
    }

    /**
     * Handles the user clicking the "Cancel Request" button while waiting for a peer response.
     * Sends a Type 9 message (interpreted as cancellation by the server/peer if handshake not complete),
     * plays end sound, and resets the session locally.
     * @param {string} peerId - The peer ID of the outgoing request to cancel.
     */
    async cancelRequest(peerId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Cancelling session request to ${peerId}`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is in the initiating state.
        if (session && session.state === this.STATE_INITIATING_SESSION) {
            // Disable waiting pane controls.
            this.uiController.setWaitingControlsEnabled(false, true);
            // Clear the request timeout as we are cancelling.
            this.clearRequestTimeout(session);
            // Construct and send a SESSION_END_REQUEST (Type 9).
            const cancelMsg = { type: 9, payload: { targetId: peerId, senderId: this.identifier } };
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log("Sending SESSION_END_REQUEST (Type 9) for cancellation:", cancelMsg);
            this.wsClient.sendMessage(cancelMsg); // Send best effort.
            // Play end sound locally.
            this.uiController.playSound('end');
            // Reset the session locally.
            await this.resetSession(peerId, false, `Request to ${peerId} cancelled.`);
        } else {
            // Always log this warning.
            console.warn(`Cannot cancel request for ${peerId}, session not found or not in initiating state (${session?.state})`);
        }
    }

    // --- Local Typing Handlers ---

    /**
     * Called by main.js when the local user types in the message input for an active chat.
     * Sends a TYPING_START (Type 10) message if not already sent, and resets the TYPING_STOP timeout.
     * @param {string} peerId - The peer ID of the active chat session.
     */
    handleLocalTyping(peerId) {
        const session = this.sessions.get(peerId);
        // Only handle typing for active sessions.
        if (!session || session.state !== this.STATE_ACTIVE_SESSION) {
            return;
        }

        // If the user wasn't previously marked as typing to this peer...
        if (!this.isTypingToPeer.get(peerId)) {
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Sending TYPING_START to ${peerId}`);
            // Construct and send the TYPING_START (Type 10) message.
            const msg = { type: 10, payload: { targetId: peerId, senderId: this.identifier } };
            if (this.wsClient.sendMessage(msg)) {
                // Mark the user as typing *after* successful send.
                this.isTypingToPeer.set(peerId, true);
            } else {
                // If send failed (e.g., connection dropped), don't proceed.
                return;
            }
        }

        // Clear any existing timeout scheduled to send TYPING_STOP for this peer.
        this.clearLocalTypingTimeout(peerId);

        // Set a new timeout. If the user doesn't type again within TYPING_STOP_DELAY,
        // the sendTypingStop function will be called.
        const timeoutId = setTimeout(() => {
            this.sendTypingStop(peerId);
        }, this.TYPING_STOP_DELAY);
        // Store the new timeout ID.
        this.typingStopTimeoutId.set(peerId, timeoutId);
    }

    /**
     * Sends a TYPING_STOP (Type 11) message to the peer if the user was marked as typing.
     * Called either by the timeout in handleLocalTyping or explicitly (e.g., before sending a message).
     * @param {string} peerId - The peer ID to send the stop message to.
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
        // Always clear the timeout, even if we didn't send the message (e.g., state changed).
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
     * if no further typing messages or actual messages are received.
     * @param {Session} session - The session for which to start the timeout.
     */
    startTypingIndicatorTimeout(session) {
        this.clearTypingIndicatorTimeout(session); // Clear existing timeout first.
        // Log timeout start only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${session.peerId}] Starting typing indicator timeout (${this.TYPING_INDICATOR_TIMEOUT}ms)`);
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
     * Clears the timeout responsible for hiding the peer's typing indicator.
     * Called when a TYPING_STOP message arrives, an actual message arrives, or the session is reset/switched.
     * @param {Session} session - The session whose typing indicator timeout should be cleared.
     */
    clearTypingIndicatorTimeout(session) {
        if (session && session.typingIndicatorTimeoutId) {
            // Log timeout clear only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Session [${session.peerId}] Clearing typing indicator timeout.`);
            clearTimeout(session.typingIndicatorTimeoutId);
            session.typingIndicatorTimeoutId = null;
        }
    }
    // ---------------------------------------

    // --- Notify peers on disconnect ---

    /**
     * Attempts to send a SESSION_END (Type 9) message to all connected/handshaking peers
     * when the client is disconnecting (e.g., page unload). This is a best-effort notification.
     */
    notifyPeersOfDisconnect() {
        // Only proceed if registered and there are sessions.
        if (!this.identifier || this.sessions.size === 0) { return; }
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log("Attempting to notify active peers of disconnect...");
        this.sessions.forEach((session, peerId) => {
            // Define states where notifying the peer makes sense. Include SAS states.
            const relevantStates = [
                this.STATE_ACTIVE_SESSION,
                this.STATE_DERIVING_KEY_INITIATOR, this.STATE_KEY_DERIVED_INITIATOR,
                this.STATE_AWAITING_CHALLENGE_RESPONSE,
                this.STATE_RECEIVED_CHALLENGE, this.STATE_AWAITING_FINAL_CONFIRMATION,
                this.STATE_GENERATING_ACCEPT_KEYS, this.STATE_AWAITING_CHALLENGE,
                this.STATE_DERIVING_KEY_RESPONDER, this.STATE_RECEIVED_INITIATOR_KEY,
                this.STATE_HANDSHAKE_COMPLETE_RESPONDER, // Added intermediate state
                this.STATE_AWAITING_SAS_VERIFICATION,
                this.STATE_SAS_CONFIRMED_LOCAL,
                this.STATE_SAS_CONFIRMED_PEER,
                this.STATE_INITIATING_SESSION, this.STATE_REQUEST_RECEIVED // Notify even if pending/handshaking
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
                    // Always log this warning.
                    console.warn(`Error sending disconnect notification to ${peerId} during unload: ${e.message}`);
                }
            }
        });
    }
    // -----------------------------------------------------

    // --- Central Message Handling and Routing ---

    /**
     * Handles raw incoming message data from the WebSocketClient.
     * Parses the JSON, determines the message type and sender, and routes
     * the message to the appropriate handler (registration, specific session, etc.).
     * @param {string} messageData - The raw message string received from the WebSocket.
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
            // Sender ID is usually in the payload, except for server-generated messages like registration replies.
            const senderId = payload?.senderId;

            // Log parsed message only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Parsed message: Type=${type}, From=${senderId || 'N/A'}, Payload=`, payload);

            // 2. Handle Manager-Level Messages (Registration Replies, Server Errors)
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
                this.uiController.playSound('error'); // Play error sound
                // Alert the user immediately.
                alert(`Disconnected by Server: ${errorMessage}`);
                // Immediately trigger the disconnection cleanup and UI reset logic.
                await this.handleDisconnection(errorMessage); // Pass the reason
                return; // Stop processing this message further.
            }

            // 3. Validate Sender ID for Session Messages
            // Most messages should have a senderId. Type -1 (Error) might have targetId instead.
            if (!senderId && type !== -1) {
                // Always log this warning.
                console.warn(`Msg type ${type} missing senderId. Ignoring.`);
                return;
            }

            // 4. Determine Relevant Peer and Session
            let session;
            let relevantPeerId;

            if (type === -1) { // User Not Found / Server Error
                // Error messages use targetId to indicate who the error relates to.
                relevantPeerId = payload.targetId;
                session = this.sessions.get(relevantPeerId);
                this.handleUserNotFound(relevantPeerId, payload); // Plays error sound internally
                return; // Processing complete.
            } else {
                // For all other messages, the sender is the relevant peer.
                relevantPeerId = senderId;
                session = this.sessions.get(relevantPeerId);
            }

            // 5. Handle New Session Request (Type 1)
            if (type === 1) {
                this.handleSessionRequest(senderId, payload); // Plays request sound internally
                return; // Processing complete.
            }

            // 6. Route Message to Existing Session
            // If the message is not Type 1 and doesn't correspond to an existing session, ignore it.
            if (!session) {
                // Always log this warning.
                console.warn(`No session found for relevant peer ${relevantPeerId}, msg type ${type}. Ignoring.`);
                return;
            }

            // Route File Transfer Messages
            if (type >= 12 && type <= 17) {
                // Log routing only if DEBUG is enabled.
                if (config.DEBUG) console.log(`Routing file transfer message type ${type} to session [${relevantPeerId}]`);
                const fileActionResult = await this.processFileTransferMessage(session, type, payload);
                await this.processMessageResult(session, fileActionResult); // Use existing result processor
                return; // Processing complete for file transfer messages.
            }

            // 7. Process Regular Chat/Handshake/SAS Message within the Session
            // Log routing only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Routing message type ${type} to session [${relevantPeerId}]`);
            // Call the session's processMessage method, which returns an action object.
            const result = await session.processMessage(type, payload, this);
            // Process the action requested by the session.
            await this.processMessageResult(session, result); // Plays sounds internally based on action

        } catch (error) {
            // Catch errors during parsing, routing, or processing.
            // Always log these errors.
            console.error('Failed to parse/route/handle message:', error, messageData);
            this.uiController.playSound('error'); // Play error sound for general processing errors
            this.uiController.updateStatus("Error processing message");
            // Potentially show a generic error to the user if appropriate
            // alert("An error occurred while processing a message from the server.");
        }
    }

    /**
     * Processes the action object returned by a Session's processMessage method
     * OR by the processFileTransferMessage method.
     * Executes the requested action, such as sending a message, updating the UI,
     * resetting the session, or handling typing indicators. Plays sounds as appropriate.
     * @param {Session} session - The session instance that processed the message.
     * @param {object} result - The action object returned (e.g., { action: 'SEND_TYPE_4' }).
     */
    async processMessageResult(session, result) {
        // Ignore if session or result/action is invalid.
        if (!session || !result || !result.action) return;

        const peerId = session.peerId; // Get peerId for convenience
        // Log action request only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${peerId}] Action requested: ${result.action}`);

        // --- Timeout Clearing Logic ---
        // Clear handshake timeout if we are moving out of a handshake state towards active/reset/SAS
        const handshakeStates = [
            this.STATE_DERIVING_KEY_INITIATOR, this.STATE_KEY_DERIVED_INITIATOR,
            this.STATE_AWAITING_CHALLENGE_RESPONSE,
            this.STATE_RECEIVED_CHALLENGE, this.STATE_AWAITING_FINAL_CONFIRMATION,
            this.STATE_GENERATING_ACCEPT_KEYS, this.STATE_AWAITING_CHALLENGE,
            this.STATE_DERIVING_KEY_RESPONDER, this.STATE_RECEIVED_INITIATOR_KEY,
            this.STATE_HANDSHAKE_COMPLETE_RESPONDER, // Added intermediate state
            // SAS states are part of the extended handshake
            this.STATE_AWAITING_SAS_VERIFICATION,
            this.STATE_SAS_CONFIRMED_LOCAL,
            this.STATE_SAS_CONFIRMED_PEER
        ];
        const wasInHandshake = handshakeStates.includes(session.state);
        // Clear if action is SESSION_ACTIVE, RESET, SHOW_INFO, or CALCULATE_AND_SHOW_SAS
        if (wasInHandshake && ['SESSION_ACTIVE', 'RESET', 'SHOW_INFO', 'CALCULATE_AND_SHOW_SAS'].includes(result.action)) {
             this.clearHandshakeTimeout(session);
        }
        // Clear request timeout if we received accept (SEND_TYPE_4) or deny/error (SHOW_INFO)
        if (result.action === 'SEND_TYPE_4' || result.action === 'SHOW_INFO') {
             this.clearRequestTimeout(session);
        }
        // --- End Timeout Clearing ---

        // Execute action based on the result object.
        switch (result.action) {
            // Actions requesting specific message sends:
            case 'SEND_TYPE_4':
                this.uiController.updateStatus(`Received acceptance from ${peerId}. Preparing response...`);
                await this.sendPublicKeyResponse(session); // Sends ECDH key now
                break;
            case 'SEND_TYPE_5':
                this.uiController.updateStatus(`Received ${peerId}'s public key. Preparing challenge...`);
                await this.sendKeyConfirmationChallenge(session); // Sends AES encrypted challenge
                break;
            case 'SEND_TYPE_6':
                this.uiController.updateStatus(`Challenge received from ${peerId}. Preparing response...`);
                await this.sendKeyConfirmationResponse(session, result.challengeData); // Sends AES encrypted response
                break;
            case 'SEND_TYPE_7':
                this.uiController.updateStatus(`Challenge verified with ${peerId}. Establishing session...`);
                await this.sendSessionEstablished(session); // Now triggers SAS flow locally
                break;

            // SAS Verification Flow
            case 'CALCULATE_AND_SHOW_SAS':
                this.uiController.updateStatus(`Handshake complete with ${peerId}. Verifying connection...`);
                try {
                    const sasString = await session.cryptoModule.deriveSas(session.peerPublicKey);
                    if (sasString) {
                        session.sas = sasString; // Store the derived SAS
                        session.updateState(this.STATE_AWAITING_SAS_VERIFICATION); // Update state
                        this.uiController.showSasVerificationPane(peerId, sasString); // Show the pane
                        this.startHandshakeTimeout(session); // Restart timeout for SAS verification step
                    } else {
                        throw new Error("Failed to derive SAS.");
                    }
                } catch (error) {
                    console.error(`Session [${peerId}] Error calculating/showing SAS:`, error);
                    this.uiController.playSound('error');
                    await this.resetSession(peerId, true, `Security verification failed: ${error.message}`);
                }
                break;
            case 'PEER_SAS_CONFIRMED':
                // Peer confirmed. Check if we have also confirmed locally.
                if (session.localSasConfirmed) {
                    // Both confirmed! Session is now active.
                    session.updateState(this.STATE_ACTIVE_SESSION);
                    this.clearHandshakeTimeout(session); // Verification complete
                    this.uiController.showActiveChat(peerId); // Show chat UI
                    this.uiController.enableActiveChatControls(); // Enable input etc.
                    this.uiController.playSound('begin'); // Play session begin sound
                    console.log(`%cSession active with ${peerId}. SAS Verified. Ready to chat!`, "color: green; font-weight: bold;");
                    this.uiController.updateStatus(`Session active with ${peerId}.`);
                } else {
                    // Peer confirmed, but we haven't yet. Update state and status.
                    session.updateState(this.STATE_SAS_CONFIRMED_PEER); // Update state
                    this.uiController.updateStatus(`Peer ${peerId} confirmed match. Waiting for your confirmation.`);
                    // Keep SAS pane visible, keep timeout running.
                }
                break;

            // Actions requesting UI updates:
            case 'DISPLAY_MESSAGE':
                // When a message arrives, clear any "peer is typing" indicator timeout and hide the indicator.
                this.clearTypingIndicatorTimeout(session);
                if (this.displayedPeerId === peerId) {
                    this.uiController.hideTypingIndicator();
                    this.uiController.addMessage(result.sender, result.text, result.msgType);
                } else {
                    // If chat not displayed, mark session as having unread messages.
                    this.uiController.setUnreadIndicator(peerId, true);
                }
                // Play notification sound ONLY for peer messages (not own or system)
                if (result.msgType === 'peer') {
                    this.uiController.playSound('notification');
                }
                break;
            case 'DISPLAY_ME_ACTION':
                // Clear typing indicator when action message arrives.
                this.clearTypingIndicatorTimeout(session);
                if (this.displayedPeerId === peerId) {
                    this.uiController.hideTypingIndicator();
                    // Call the new UIController method for /me actions
                    this.uiController.addMeActionMessage(result.sender, result.text);
                } else {
                    // Mark as unread if chat not displayed.
                    this.uiController.setUnreadIndicator(peerId, true);
                }
                // Play notification sound for /me actions
                this.uiController.playSound('notification');
                break;
            case 'DISPLAY_SYSTEM_MESSAGE':
                 // Display system messages only if the relevant chat is active.
                 if (this.displayedPeerId === peerId) {
                    this.uiController.addSystemMessage(result.text);
                } else {
                    // Always log system message warnings for inactive chats.
                    console.warn(`System message for non-active session ${peerId}: ${result.text}`);
                    session.addMessageToHistory('System', result.text, 'system'); // Add to history
                    this.uiController.setUnreadIndicator(peerId, true); // Mark unread
                }
                break;
            case 'SHOW_INFO':
                // Show the info pane (denial, timeout, or specific error reason from RESET).
                // Use the reason provided in the result object.
                const messageToShow = result.message || result.reason || `An issue occurred with ${peerId}.`;
                // Determine if retry should be shown (only for request timeout currently).
                const showRetry = result.showRetry || false;
                // Update the UI pane.
                this.uiController.showInfoMessage(peerId, messageToShow, showRetry);
                // Play error sound if it's a denial or timeout
                if (session.state === this.STATE_DENIED || session.state === this.STATE_REQUEST_TIMED_OUT || session.state === this.STATE_HANDSHAKE_TIMED_OUT) {
                    this.uiController.playSound('error');
                }
                // Re-enable initiation controls if this was the only session attempt and it failed definitively.
                const definitiveFailureStates = [this.STATE_DENIED, this.STATE_HANDSHAKE_TIMED_OUT];
                if (definitiveFailureStates.includes(session.state)) {
                     if (this.sessions.size <= 1) { this.uiController.setInitiationControlsEnabled(true); }
                }
                break;

            // Action requesting session reset:
            case 'RESET':
                const reason = result.reason || `Session with ${peerId} ended.`;
                const notifyViaAlert = result.notifyUser || false; // Check if alert fallback is requested

                // Play appropriate sound based on context (error or clean end)
                // Check if the reason indicates a handshake error or if the session state implies an error
                const isErrorReset = reason.toLowerCase().includes('error') ||
                                     reason.toLowerCase().includes('failed') ||
                                     session.state === this.STATE_HANDSHAKE_TIMED_OUT ||
                                     session.state === this.STATE_SAS_DENIED; // Include SAS denial
                if (isErrorReset) {
                    this.uiController.playSound('error');
                } else if (reason.includes('ended by') || reason.includes('You ended') || reason.includes('denied request') || reason.includes('cancelled')) {
                    // Play end sound for clean disconnects (Type 9, local end, denial, cancellation)
                    this.uiController.playSound('end');
                }

                // Always try to show the info pane if there's a reason, regardless of current view.
                // This provides better context than an alert.
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

            // Handle Typing Indicator Actions
            case 'SHOW_TYPING':
                if (this.displayedPeerId === peerId) {
                    this.uiController.showTypingIndicator(peerId);
                }
                this.startTypingIndicatorTimeout(session);
                break;
            case 'HIDE_TYPING':
                this.clearTypingIndicatorTimeout(session);
                if (this.displayedPeerId === peerId) {
                    this.uiController.hideTypingIndicator();
                }
                break;

            // Default case for unknown or 'NONE' actions:
            case 'NONE':
            default:
                // No specific action needed, but ensure handshake timeout is cleared if applicable.
                if (wasInHandshake) this.clearHandshakeTimeout(session);
                break;
        }
    }


    // --- Manager-Level Handlers ---

    /**
     * Handles the registration success message (Type 0.1) from the server.
     * Stores the identifier, updates manager state, plays sound, and shows the main app UI.
     * @param {object} payload - Expected: { identifier: string, message: string }
     */
    handleRegistrationSuccess(payload) {
        this.clearRegistrationTimeout(); // Stop the timeout.
        this.identifier = payload.identifier; // Store the confirmed identifier.
        this.updateManagerState(this.STATE_REGISTERED); // Update state.
        // Log success (not wrapped in DEBUG as it's significant).
        console.log(`Successfully registered as: ${this.identifier}`);
        this.uiController.playSound('registered'); // Play registration success sound
        // Show the main application UI (sidebar, content area).
        this.uiController.showMainApp(this.identifier);
        this.uiController.updateStatus(`Registered as: ${this.identifier}`);
        // Re-enable registration controls (though the area is now hidden).
        this.uiController.setRegistrationControlsEnabled(true);
    }

    /**
     * Handles the registration failure message (Type 0.2) from the server.
     * Updates manager state, plays error sound, alerts the user, and keeps the registration UI visible.
     * @param {object} payload - Expected: { identifier?: string, error: string }
     */
    handleRegistrationFailure(payload) {
        this.clearRegistrationTimeout(); // Stop the timeout.
        this.updateManagerState(this.STATE_FAILED_REGISTRATION); // Update state.
        const reason = payload?.error || "Unknown registration error.";
        const requestedId = payload?.identifier || "the requested ID";
        // Always log registration errors.
        console.error(`Registration failed for '${requestedId}': ${reason}`);
        this.uiController.updateStatus(`Registration Failed: ${reason}`);
        this.uiController.playSound('error'); // Play error sound
        // Use alert for registration failure as it's a global issue preventing app use.
        alert(`Registration failed: ${reason}\nPlease try a different identifier.`);
        // Keep registration UI visible and re-enable controls.
        this.uiController.showRegistration();
        this.uiController.setRegistrationControlsEnabled(true);
    }

    /**
     * Handles the user not found error message (Type -1) from the server.
     * Typically received when trying to initiate a session with an unknown/offline user.
     * Updates the relevant session state to DENIED, plays error sound, and shows an info message.
     * @param {string} targetIdFailed - The identifier that was not found.
     * @param {object} payload - Expected: { targetId: string, message: string }
     */
    handleUserNotFound(targetIdFailed, payload) {
        const session = this.sessions.get(targetIdFailed);
        const errorMessage = payload.message || `User '${targetIdFailed}' not found or disconnected.`;
        // Always log server errors.
        console.error(`Server Error: ${errorMessage}`);
        this.uiController.playSound('error'); // Play error sound
        // Check if we have a session for this peer and it was in the initiating state.
        if (session && session.state === this.STATE_INITIATING_SESSION) {
            // Log action only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Showing denial info for ${targetIdFailed} after user not found error.`);
            // Clear timeouts associated with the failed request.
            this.clearRequestTimeout(session);
            this.clearHandshakeTimeout(session); // Should be null, but clear just in case.
            // Update state to DENIED.
            session.updateState(this.STATE_DENIED);
            // Show info message using the UI controller.
            this.uiController.showInfoMessage(targetIdFailed, errorMessage, false); // No retry for user not found.
            // Do NOT reset the session here, let user close the info pane.
        } else {
             // Always log this warning.
             console.warn(`Received user not found for ${targetIdFailed}, but no matching session in INITIATING_SESSION state.`);
             // Show a general status update/alert.
             this.uiController.updateStatus(`Error: ${errorMessage}`);
             alert(`Server Error: ${errorMessage}`); // Use alert for unexpected errors.
        }
        // Re-enable initiation controls if this was the only session attempt.
        if (this.sessions.size <= 1) { this.uiController.setInitiationControlsEnabled(true); }
    }

    /**
     * Handles an incoming session request (Type 1) from a peer.
     * Creates a new Session instance in the REQUEST_RECEIVED state.
     * Plays request sound and updates the UI to show the incoming request or marks the session as unread if busy.
     * @param {string} senderId - The identifier of the peer initiating the request.
     * @param {object} payload - Expected: { targetId: string (own ID), senderId: string }
     */
    handleSessionRequest(senderId, payload) {
        // Log request received (not wrapped in DEBUG as it's significant).
        console.log(`Incoming session request received from: ${senderId}`);
        // Ignore if not registered or if another request is already pending user action.
        if (this.managerState !== this.STATE_REGISTERED) {
            // Always log this warning.
            console.warn(`Ignoring incoming request from ${senderId}: Manager not in REGISTERED state.`);
            return;
        }
        if (this.pendingPeerIdForAction) {
            // Always log this warning.
            console.warn(`Ignoring incoming request from ${senderId}: Another request from ${this.pendingPeerIdForAction} is pending user action.`);
            // Potential enhancement: Queue requests or send a "busy" response.
            return;
        }
        // Ignore if a session with this peer already exists (in any state).
        if (this.sessions.has(senderId)) {
            // Always log this warning.
            console.warn(`Ignoring duplicate session request from ${senderId}.`);
            return;
        }

        // 1. Create a new CryptoModule for this session.
        const crypto = new this.CryptoModuleClass();
        // 2. Create a new Session object in the REQUEST_RECEIVED state.
        const newSession = new Session(senderId, this.STATE_REQUEST_RECEIVED, crypto);
        // 3. Add the session to the manager's map.
        this.sessions.set(senderId, newSession);
        // 4. Add the session to the UI list.
        this.uiController.addSessionToList(senderId);

        // 5. Play request sound.
        this.uiController.playSound('receiverequest'); // Use the renamed sound

        // 6. Update the main UI view.
        if (!this.displayedPeerId) {
            // If no other chat/pane is active, show the incoming request pane immediately.
            this.pendingPeerIdForAction = senderId; // Mark this peer as needing action.
            this.uiController.showIncomingRequest(senderId);
            this.uiController.updateStatus(`Incoming request from ${senderId}`);
        } else {
            // If another chat/pane is active, just mark the new session as unread in the list.
            // Log this action only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Another session active. Marking ${senderId} as pending request.`);
            this.uiController.setUnreadIndicator(senderId, true);
            this.uiController.updateStatus(`Incoming request from ${senderId} (see session list)`);
            // User will need to click the session in the list to accept/deny.
        }
    }

    /**
     * Handles the WebSocket disconnection event OR a forced disconnect trigger.
     * Clears all session timeouts, resets all sessions, updates manager state,
     * plays error sound, and shows the registration screen. Prevents running twice if already disconnected.
     * @param {string} [reason=null] - Optional reason for the disconnection, used for status updates.
     */
    async handleDisconnection(reason = null) {
         // Prevent running the cleanup logic multiple times
         if (this.managerState === this.STATE_DISCONNECTED) {
             // Log skipped call only if DEBUG is enabled.
             if (config.DEBUG) console.log("handleDisconnection called but already disconnected. Skipping.");
             return;
         }
         // Use the provided reason or a default message
         const disconnectReason = reason || "Connection lost.";
         // Log disconnection (not wrapped in DEBUG as it's significant).
         console.log(`SessionManager: Handling disconnection. Reason: ${disconnectReason}`);

         this.clearRegistrationTimeout(); // Clear registration timeout if it was running.
         const currentActivePeer = this.displayedPeerId; // Store potentially active peer.

         // Cleanup active file transfers before resetting sessions
         await this.handleDisconnectionCleanup();

         // If there were active sessions, reset them all.
         if (this.sessions.size > 0) {
             const peerIds = Array.from(this.sessions.keys()); // Get all peer IDs.
             // Reset each session without individual user notification.
             // resetSession now handles file transfer cleanup internally as well.
             for (const peerId of peerIds) {
                 await this.resetSession(peerId, false);
             }
         }

         // Update manager state and clear session tracking variables.
         this.updateManagerState(this.STATE_DISCONNECTED); // Set state *before* UI updates
         this.displayedPeerId = null;
         this.pendingPeerIdForAction = null;
         this.identifier = null; // Clear registered identifier.

         // Play error sound for disconnection.
         this.uiController.playSound('error');

         // Update UI status and show the registration screen.
         // Use alert for the main disconnection event as it affects the whole app.
         alert(`Disconnected: ${disconnectReason}`);
         this.uiController.updateStatus(disconnectReason);
         this.uiController.showRegistration();
    }

    /**
     * Switches the main content view to display the specified session.
     * Updates the UI based on the session's current state (active chat, incoming request, info, SAS, etc.).
     * Clears unread indicators and hides typing indicators for the switched-to session.
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

        // Hide typing indicator when switching views
        this.uiController.hideTypingIndicator();

        // Clear the unread indicator for the session being viewed.
        this.uiController.setUnreadIndicator(peerId, false);
        // Set this session as the active one in the sidebar list.
        this.uiController.setActiveSessionInList(peerId);

        // Show the appropriate main content pane based on the session's state.
        if (session.state === this.STATE_ACTIVE_SESSION) {
            this.uiController.showActiveChat(peerId);
            // Populate message area with history for this session.
            session.messages.forEach(msg => {
                if (msg.type === 'me-action') {
                    this.uiController.addMeActionMessage(msg.sender, msg.text);
                } else if (msg.type !== 'file') { // Assuming a 'file' type isn't used for history yet
                     this.uiController.addMessage(msg.sender, msg.text, msg.type);
                } else {
                    // TODO: Need logic to re-render file transfer messages from history if needed
                }
            });
            // Re-render any active file transfers for this session
            if (session.transferStates) {
                session.transferStates.forEach((state, transferId) => {
                    this.uiController.addFileTransferMessage(transferId, peerId, state.fileName, state.fileSize, state.isSender);
                    this.uiController.updateFileTransferStatus(transferId, state.status);
                    if (state.progress > 0) {
                        this.uiController.updateFileTransferProgress(transferId, state.progress);
                    }
                    if (state.status === 'complete' && !state.isSender && state.blobUrl) {
                         // Assume blobUrl is available if state is complete (might need adjustment)
                    } else if (state.status === 'pending_acceptance' && !state.isSender) {
                        // Show accept/reject (handled by addFileTransferMessage)
                    } else if ((state.status === 'initiating' || state.status === 'uploading') && state.isSender) {
                        // Show cancel (handled by addFileTransferMessage)
                    } else {
                        this.uiController.hideFileTransferActions(transferId);
                    }
                });
            }
            // Enable chat controls since session is active
            this.uiController.enableActiveChatControls();
            this.uiController.updateStatus(`Session active with ${peerId}.`);
        } else if (session.state === this.STATE_REQUEST_RECEIVED) {
            // If switching to a session that has an incoming request needing action.
            this.pendingPeerIdForAction = peerId; // Mark as needing action.
            this.uiController.showIncomingRequest(peerId);
            this.uiController.updateStatus(`Incoming request from ${peerId}`);
        } else if (session.state === this.STATE_DENIED || session.state === this.STATE_HANDSHAKE_TIMED_OUT || session.state === this.STATE_SAS_DENIED) {
             // Show info pane for denied, handshake timeout, or SAS denied states.
             let message = `An issue occurred with ${peerId}.`;
             if (session.state === this.STATE_DENIED) message = `Session request denied by ${peerId}.`;
             if (session.state === this.STATE_HANDSHAKE_TIMED_OUT) message = `Handshake or verification with ${peerId} timed out.`;
             if (session.state === this.STATE_SAS_DENIED) message = `Session aborted due to verification mismatch or cancellation with ${peerId}.`; // Updated message
             this.uiController.showInfoMessage(peerId, message, false); // No retry.
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
        // Handle SAS Verification State
        else if (session.state === this.STATE_AWAITING_SAS_VERIFICATION ||
                 session.state === this.STATE_SAS_CONFIRMED_LOCAL ||
                 session.state === this.STATE_SAS_CONFIRMED_PEER) {
            if (session.sas) {
                this.uiController.showSasVerificationPane(peerId, session.sas);
                let statusText = `Verify connection with ${peerId}...`;
                if (session.state === this.STATE_SAS_CONFIRMED_LOCAL) statusText = `Waiting for ${peerId} to confirm... Click Cancel to abort.`; // Updated status
                if (session.state === this.STATE_SAS_CONFIRMED_PEER) statusText = `Peer ${peerId} confirmed. Waiting for your confirmation...`;
                this.uiController.updateStatus(statusText);
                // Ensure correct buttons are shown based on state
                this.uiController.setSasControlsEnabled(true, false, session.state === this.STATE_SAS_CONFIRMED_LOCAL); // Show Cancel only if local confirmed
            } else {
                // Should not happen if state is correct, but handle gracefully
                console.error(`Session [${peerId}] in SAS state but SAS string is missing!`);
                this.uiController.showInfoMessage(peerId, "Error during security verification.", false);
            }
        }
        else { // Other intermediate handshake states
            // For other states (key exchange, challenge/response), just show the welcome message pane
            // as there's no specific UI for these intermediate steps currently.
            // The status bar provides context.
            // Log this only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Session with ${peerId} is handshaking (state: ${session.state}). Showing welcome message.`);
            this.uiController.showWelcomeMessage(); // Show default welcome/instructions pane.
            // Provide more descriptive status for handshake states
            let statusText = `Session with ${peerId}: ${session.state}`;
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
            } else if (session.state === this.STATE_HANDSHAKE_COMPLETE_RESPONDER) {
                 statusText = `Session with ${peerId}: Handshake complete, verifying...`;
            }
            this.uiController.updateStatus(statusText);
        }
    }

    /**
     * Gets the peer ID of the currently displayed chat session.
     * @returns {string|null} The peer ID or null if no session is displayed.
     */
    getActivePeerId() {
        return this.displayedPeerId;
    }

    // --- SAS Verification Handlers ---

    /**
     * Handles the user clicking the "Confirm Match" button in the SAS pane.
     * Sends a confirmation message (Type 7.1) to the peer and updates state.
     * If both sides have confirmed, transitions to the active chat state.
     * @param {string} peerId - The peer ID for the session being confirmed.
     */
    async handleSasConfirm(peerId) {
        const session = this.sessions.get(peerId);
        if (!session || (session.state !== this.STATE_AWAITING_SAS_VERIFICATION && session.state !== this.STATE_SAS_CONFIRMED_PEER)) {
            console.warn(`Cannot confirm SAS for ${peerId}: Session not found or invalid state (${session?.state}).`);
            return;
        }
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${peerId}] Local user confirmed SAS match.`);

        // --- MODIFICATION: Show Cancel button while waiting ---
        // Hide Confirm/Deny, show Cancel button (enabled)
        // Pass enabled=true, loadingState=false, showCancel=true
        this.uiController.setSasControlsEnabled(true, false, true);
        // --- END MODIFICATION ---

        session.localSasConfirmed = true; // Mark local confirmation

        // Send confirmation message to peer
        const msg = { type: this.TYPE_SAS_CONFIRM, payload: { targetId: peerId, senderId: this.identifier } };
        if (this.wsClient.sendMessage(msg)) {
            // Check if peer has already confirmed
            if (session.peerSasConfirmed) {
                // Both confirmed! Activate session.
                session.updateState(this.STATE_ACTIVE_SESSION);
                this.clearHandshakeTimeout(session); // Verification complete
                this.uiController.showActiveChat(peerId); // Show chat UI
                this.uiController.enableActiveChatControls(); // Enable input etc.
                this.uiController.playSound('begin'); // Play session begin sound
                console.log(`%cSession active with ${peerId}. SAS Verified. Ready to chat!`, "color: green; font-weight: bold;");
                this.uiController.updateStatus(`Session active with ${peerId}.`);
            } else {
                // We confirmed, but waiting for peer. Update state and status.
                session.updateState(this.STATE_SAS_CONFIRMED_LOCAL);
                this.uiController.updateStatus(`Confirmation sent. Waiting for ${peerId} to confirm... Click Cancel to abort.`); // Updated status
                // Keep SAS pane visible (with Cancel button shown), keep timeout running.
                // Buttons already updated by setSasControlsEnabled above.
            }
        } else {
            // Failed to send confirmation
            console.error(`Session [${peerId}] Failed to send SAS confirmation.`);
            this.uiController.playSound('error');
            // Re-enable Confirm/Deny buttons on send failure
            this.uiController.setSasControlsEnabled(true, false, false);
            // Show error in status or info pane? For now, just status.
            this.uiController.updateStatus(`Error sending confirmation to ${peerId}.`);
            // Reset local confirmation flag
            session.localSasConfirmed = false;
        }
    }

    /**
     * Handles the user clicking the "Deny / Abort" button in the SAS pane.
     * Ends the session locally and notifies the peer.
     * @param {string} peerId - The peer ID for the session being denied/aborted.
     */
    async handleSasDeny(peerId) {
        const session = this.sessions.get(peerId);
        // Allow denial only if awaiting verification (before local confirm)
        if (!session || session.state !== this.STATE_AWAITING_SAS_VERIFICATION) {
            console.warn(`Cannot deny SAS for ${peerId}: Session not found or invalid state (${session?.state}).`);
            return;
        }
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${peerId}] Local user denied SAS match / aborted session.`);

        // Disable SAS controls immediately
        this.uiController.setSasControlsEnabled(false, true, false); // Show loading on Deny button

        // Update state to reflect denial
        session.updateState(this.STATE_SAS_DENIED);

        // End the session (sends Type 9, resets locally, shows info pane)
        const reason = `Session aborted due to verification mismatch or cancellation with ${peerId}.`;
        await this.endSession(peerId); // endSession will call resetSession
        // Ensure the specific info message is shown after resetSession might have cleared the view
        this.uiController.showInfoMessage(peerId, reason, false);
    }

    /**
     * Handles the user clicking the "Cancel" button after confirming SAS locally.
     * Ends the session locally and notifies the peer.
     * @param {string} peerId - The peer ID for the session being cancelled.
     */
    async handleSasCancelPending(peerId) {
        const session = this.sessions.get(peerId);
        // Only allow cancellation if we have confirmed locally but are waiting for peer
        if (!session || session.state !== this.STATE_SAS_CONFIRMED_LOCAL) {
            console.warn(`Cannot cancel SAS for ${peerId}: Session not found or invalid state (${session?.state}).`);
            return;
        }
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${peerId}] Local user cancelled SAS while waiting for peer.`);

        // Disable SAS controls immediately
        this.uiController.setSasControlsEnabled(false, true, true); // Show loading on Cancel button

        // Update state to reflect cancellation/denial
        session.updateState(this.STATE_SAS_DENIED); // Reuse SAS_DENIED state

        // End the session (sends Type 9, resets locally, shows info pane)
        const reason = `Session cancelled while waiting for ${peerId} to confirm verification.`;
        await this.endSession(peerId); // endSession will call resetSession
        // Ensure the specific info message is shown after resetSession might have cleared the view
        this.uiController.showInfoMessage(peerId, reason, false);
    }
    // --- END SAS Verification Handlers ---


    // --- File Transfer Logic ---

    /**
     * Handles the file selection event from the hidden file input.
     * Initiates the file transfer request process.
     * @param {Event} event - The file input change event.
     */
    async handleFileSelection(event) {
        const fileInput = event.target;
        if (!fileInput.files || fileInput.files.length === 0) {
            // Log only if DEBUG is enabled.
            if (config.DEBUG) console.log("File selection cancelled or no file chosen.");
            return; // No file selected
        }
        const file = fileInput.files[0];
        // Reset the file input value to allow selecting the same file again later.
        fileInput.value = '';

        const targetId = this.getActivePeerId();
        if (!targetId) {
            alert("No active chat session selected to send the file to.");
            return;
        }
        const session = this.sessions.get(targetId);
        if (!session || session.state !== this.STATE_ACTIVE_SESSION) {
            alert(`Session with ${targetId} is not active. Cannot send file.`);
            return;
        }

        // Log file details only if DEBUG is enabled.
        if (config.DEBUG) console.log(`File selected: Name=${file.name}, Size=${file.size}, Type=${file.type}`);

        // Check file size
        if (file.size > this.MAX_FILE_SIZE) {
            alert(`File is too large (${this.uiController.formatFileSize(file.size)}). Maximum size is ${this.uiController.formatFileSize(this.MAX_FILE_SIZE)}.`);
            return;
        }
        if (file.size === 0) {
            alert("Cannot send empty files.");
            return;
        }

        // Generate unique ID for this transfer
        const transferId = crypto.randomUUID();
        // Log transfer initiation only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Initiating file transfer ${transferId} to ${targetId}`);

        // Store initial transfer state in the session
        session.addTransferState(transferId, {
            file: file,
            status: 'initiating', // Initial status
            progress: 0,
            fileName: file.name, // Store metadata for receiver UI
            fileSize: file.size,
            fileType: file.type,
            isSender: true // Mark this client as the sender for this transfer
        });

        // Display initial status in UI
        this.uiController.addFileTransferMessage(transferId, targetId, file.name, file.size, true); // true for isSender

        // Send the request message to the peer
        const requestPayload = {
            targetId: targetId,
            senderId: this.identifier,
            transferId: transferId,
            fileName: file.name,
            fileSize: file.size,
            fileType: file.type || 'application/octet-stream' // Provide a default type
        };
        if (this.wsClient.sendMessage({ type: 12, payload: requestPayload })) {
            this.uiController.updateStatus(`Requesting file transfer to ${targetId}...`);
            // TODO: Add timeout for acceptance? (e.g., this.startFileAcceptTimeout(transferId))
        } else {
            this.uiController.updateFileTransferStatus(transferId, "Error: Failed to send transfer request.");
            this.uiController.playSound('file_error');
            session.removeTransferState(transferId); // Clean up state
            // Optionally remove the UI message or leave it with the error
        }
    }

    /**
     * Starts the process of reading, encrypting, and sending file chunks.
     * @param {Session} session - The session object.
     * @param {string} transferId - The ID of the file transfer to start uploading.
     */
    async startFileUpload(session, transferId) {
        const transferState = session.getTransferState(transferId);
        if (!transferState || !transferState.file || transferState.status !== 'uploading') {
            // Always log this warning.
            console.warn(`Cannot start upload for transfer ${transferId}: Invalid state or missing file.`);
            return;
        }

        const file = transferState.file;
        const peerId = session.peerId;
        let chunkIndex = 0;
        let offset = 0;
        // Log start only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Starting file upload for ${transferId} (${file.name})`);
        this.uiController.updateFileTransferStatus(transferId, "Uploading 0%...");
        this.uiController.updateFileTransferProgress(transferId, 0); // Show progress bar

        try {
            while (offset < file.size) {
                // Check if transfer was cancelled externally (e.g., disconnect)
                const currentState = session.getTransferState(transferId);
                if (!currentState || currentState.status !== 'uploading') {
                    // Always log cancellation/error during upload.
                    console.log(`Upload for transfer ${transferId} aborted. Status: ${currentState?.status}`);
                    return; // Stop uploading
                }

                const end = Math.min(offset + this.CHUNK_SIZE, file.size);
                const chunkBlob = file.slice(offset, end);
                const chunkBuffer = await chunkBlob.arrayBuffer();

                // Encrypt the chunk
                const encryptedResult = await session.cryptoModule.encryptAES(chunkBuffer);
                if (!encryptedResult) {
                    throw new Error(`Encryption failed for chunk ${chunkIndex}`);
                }

                // Prepare payload
                const chunkPayload = {
                    targetId: peerId,
                    senderId: this.identifier,
                    transferId: transferId,
                    chunkIndex: chunkIndex,
                    iv: session.cryptoModule.arrayBufferToBase64(encryptedResult.iv),
                    data: session.cryptoModule.arrayBufferToBase64(encryptedResult.encryptedBuffer)
                };

                // Send the chunk
                if (!this.wsClient.sendMessage({ type: 15, payload: chunkPayload })) {
                    throw new Error(`Connection error sending chunk ${chunkIndex}`);
                }

                // Update progress
                offset += chunkBuffer.byteLength;
                const progressPercent = (offset / file.size) * 100;
                transferState.progress = progressPercent; // Update state object
                this.uiController.updateFileTransferProgress(transferId, progressPercent);
                this.uiController.updateFileTransferStatus(transferId, `Uploading ${progressPercent.toFixed(1)}%...`);

                chunkIndex++;

                // Optional: Add a small delay to prevent flooding the event loop/network
                // await new Promise(resolve => setTimeout(resolve, 5));
            }

            // All chunks sent, send completion message
            // Log completion only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Finished sending chunks for transfer ${transferId}. Sending completion message.`);
            const completePayload = { targetId: peerId, senderId: this.identifier, transferId: transferId };
            if (this.wsClient.sendMessage({ type: 16, payload: completePayload })) {
                transferState.status = 'complete';
                this.uiController.updateFileTransferStatus(transferId, "Upload complete."); // Updated message
                this.uiController.hideFileTransferActions(transferId); // Hide cancel button
            } else {
                throw new Error("Connection error sending completion message.");
            }

        } catch (error) {
            // Always log upload errors.
            console.error(`Error during file upload for ${transferId}:`, error);
            this.uiController.playSound('file_error');
            this.uiController.updateFileTransferStatus(transferId, `Error: ${error.message}`);
            this.uiController.hideFileTransferActions(transferId);
            // Send error notification to peer
            const errorPayload = { targetId: peerId, senderId: this.identifier, transferId: transferId, error: `Upload failed: ${error.message}` };
            this.wsClient.sendMessage({ type: 17, payload: errorPayload });
            // Clean up local state
            session.removeTransferState(transferId);
        }
    }

    /**
     * Handles the user clicking the Accept button for an incoming file transfer.
     * @param {string} transferId - The ID of the transfer being accepted.
     */
    async handleAcceptFile(transferId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Handling accept for file transfer ${transferId}`);
        // Find the session associated with this transfer (need senderId from transfer state)
        let session = null;
        let transferState = null;
        for (const s of this.sessions.values()) {
            transferState = s.getTransferState(transferId);
            if (transferState) {
                session = s;
                break;
            }
        }

        if (!session || !transferState || transferState.status !== 'pending_acceptance') {
            // Always log this warning.
            console.warn(`Cannot accept file transfer ${transferId}: Session or transfer state not found or invalid status.`);
            return;
        }

        const peerId = transferState.senderId; // Get the sender's ID

        // Update UI immediately
        this.uiController.updateFileTransferStatus(transferId, "Accepted. Waiting for data...");
        this.uiController.hideFileTransferActions(transferId); // Hide accept/reject

        // Update internal state
        transferState.status = 'accepted'; // Or 'receiving'

        // Send acceptance message back to the sender
        const acceptPayload = { targetId: peerId, senderId: this.identifier, transferId: transferId };
        if (!this.wsClient.sendMessage({ type: 13, payload: acceptPayload })) {
            this.uiController.updateFileTransferStatus(transferId, "Error: Failed to send acceptance.");
            this.uiController.playSound('file_error');
            transferState.status = 'error'; // Revert status
            // Clean up DB? Probably not needed yet.
        } else {
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Sent acceptance for transfer ${transferId} to ${peerId}`);
            // Optionally play a sound
            // this.uiController.playSound('notification');
        }
    }

    /**
     * Handles the user clicking the Reject button for an incoming file transfer.
     * @param {string} transferId - The ID of the transfer being rejected.
     */
    async handleRejectFile(transferId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Handling reject for file transfer ${transferId}`);
        // Find the session and transfer state
        let session = null;
        let transferState = null;
        for (const s of this.sessions.values()) {
            transferState = s.getTransferState(transferId);
            if (transferState) {
                session = s;
                break;
            }
        }

        if (!session || !transferState || transferState.status !== 'pending_acceptance') {
            // Always log this warning.
            console.warn(`Cannot reject file transfer ${transferId}: Session or transfer state not found or invalid status.`);
            return;
        }

        const peerId = transferState.senderId;

        // Update UI
        this.uiController.updateFileTransferStatus(transferId, "Rejected.");
        this.uiController.hideFileTransferActions(transferId);
        this.uiController.playSound('end'); // Use end sound for rejection

        // Send rejection message
        const rejectPayload = { targetId: peerId, senderId: this.identifier, transferId: transferId };
        this.wsClient.sendMessage({ type: 14, payload: rejectPayload }); // Send best effort

        // Clean up local state
        session.removeTransferState(transferId);
        await this.deleteChunksFromDB(transferId); // Clean up any potential DB entries
    }

    /**
     * Handles the user clicking the Cancel button for an ongoing file transfer (sender side).
     * @param {string} transferId - The ID of the transfer being cancelled.
     */
    async handleCancelTransfer(transferId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Handling cancel for file transfer ${transferId}`);
        // Find the session and transfer state
        let session = null;
        let transferState = null;
        for (const s of this.sessions.values()) {
            transferState = s.getTransferState(transferId);
            if (transferState && transferState.isSender) { // Ensure it's an outgoing transfer
                session = s;
                break;
            }
        }

        // Only allow cancellation if initiating or uploading
        const cancellableStates = ['initiating', 'uploading'];
        if (!session || !transferState || !cancellableStates.includes(transferState.status)) {
            // Always log this warning.
            console.warn(`Cannot cancel file transfer ${transferId}: Session/transfer not found or invalid status (${transferState?.status}).`);
            return;
        }

        const peerId = session.peerId;

        // Update UI
        this.uiController.updateFileTransferStatus(transferId, "Cancelled.");
        this.uiController.hideFileTransferActions(transferId);
        this.uiController.playSound('end'); // Use end sound for cancel

        // Update internal state immediately to stop upload loop if running
        transferState.status = 'cancelled';

        // Send error/cancel message to peer
        const errorPayload = { targetId: peerId, senderId: this.identifier, transferId: transferId, error: "Transfer cancelled by sender." };
        this.wsClient.sendMessage({ type: 17, payload: errorPayload }); // Send best effort

        // Clean up local state
        session.removeTransferState(transferId);
        // No DB cleanup needed for sender
    }

    /**
     * Processes incoming file transfer related messages (Types 12-17).
     * Routes to specific internal handlers.
     * @param {Session} session - The session object associated with the sender.
     * @param {number} type - The message type (12-17).
     * @param {object} payload - The message payload.
     * @returns {Promise<object>} An action object for processMessageResult.
     */
    async processFileTransferMessage(session, type, payload) {
        // Log processing attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Session [${session.peerId}] Processing file transfer message type ${type}`);
        }
        try {
            switch (type) {
                case 12: return await this._handleFileTransferRequest(session, payload);
                case 13: return await this._handleFileTransferAccept(session, payload);
                case 14: return await this._handleFileTransferReject(session, payload);
                case 15: return await this._handleFileChunk(session, payload);
                case 16: return await this._handleFileTransferComplete(session, payload);
                case 17: return await this._handleFileTransferError(session, payload);
                default:
                    // Always log unhandled types as warnings.
                    console.warn(`Session [${session.peerId}] Received unhandled file transfer message type: ${type}`);
                    return { action: 'NONE' };
            }
        } catch (error) {
            // Always log unexpected errors.
            console.error(`Session [${session.peerId}] Unexpected error processing file transfer message type ${type}:`, error);
            // Return a generic RESET or error display action if appropriate
            return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Internal error processing file transfer: ${error.message}` };
        }
    }

    // --- Internal File Transfer Message Handlers ---

    /**
     * Handles an incoming file transfer request (Type 12).
     * Stores initial state including expected chunk count.
     * @param {Session} session - The session object (receiver's session).
     * @param {object} payload - The request payload.
     * @returns {Promise<object>} Action object (always 'NONE' for now).
     */
    async _handleFileTransferRequest(session, payload) {
        const { transferId, fileName, fileSize, fileType, senderId } = payload;
        // Log request only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Received file transfer request ${transferId} from ${senderId}: ${fileName} (${fileSize} bytes)`);

        // Basic validation
        if (!transferId || !fileName || fileSize === undefined || !senderId) {
            // Always log validation warnings.
            console.warn(`Invalid file transfer request payload from ${senderId}:`, payload);
            return { action: 'NONE' }; // Ignore invalid request
        }

        // Check if a transfer with this ID already exists (shouldn't happen normally)
        if (session.getTransferState(transferId)) {
             // Always log this warning.
             console.warn(`Duplicate file transfer request received for ID ${transferId}. Ignoring.`);
             return { action: 'NONE' };
        }

        // NEW: Calculate expected chunks
        const expectedChunks = Math.ceil(fileSize / this.CHUNK_SIZE);

        // Store initial state for the incoming transfer
        session.addTransferState(transferId, {
            status: 'pending_acceptance',
            progress: 0,
            fileName: fileName,
            fileSize: fileSize,
            fileType: fileType,
            senderId: senderId, // Store who sent it
            isSender: false, // Mark this client as the receiver
            expectedChunks: expectedChunks, // NEW: Store expected chunk count
            receivedChunkCount: 0, // NEW: Initialize received count
            completionSignalReceived: false // NEW: Flag for Type 16
        });

        // Display the request in the UI
        this.uiController.addFileTransferMessage(transferId, senderId, fileName, fileSize, false); // false for isSender
        this.uiController.playSound('file_request'); // Play notification sound

        // If the chat isn't active, mark as unread
        if (this.displayedPeerId !== session.peerId) {
            this.uiController.setUnreadIndicator(session.peerId, true);
        }

        // TODO: Add timeout for user to accept/reject?

        return { action: 'NONE' }; // No further action needed until user interacts
    }

    /**
     * Handles the peer accepting the file transfer (Type 13).
     * Updates state and starts the upload process.
     * @param {Session} session - The session object (sender's session).
     * @param {object} payload - The acceptance payload.
     * @returns {Promise<object>} Action object (always 'NONE').
     */
    async _handleFileTransferAccept(session, payload) {
        const { transferId } = payload;
        // Log acceptance only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Received acceptance for file transfer ${transferId} from ${session.peerId}`);

        const transferState = session.getTransferState(transferId);
        if (!transferState || !transferState.isSender || transferState.status !== 'initiating') {
            // Always log this warning.
            console.warn(`Received unexpected acceptance for transfer ${transferId} or invalid state.`);
            return { action: 'NONE' };
        }

        // Update state and UI
        transferState.status = 'uploading';
        this.uiController.updateFileTransferStatus(transferId, "Peer accepted. Starting upload...");
        this.uiController.hideFileTransferActions(transferId); // Hide cancel button temporarily? Or leave it?

        // Start the upload process
        this.startFileUpload(session, transferId); // Intentionally not awaited

        return { action: 'NONE' };
    }

    /**
     * Handles the peer rejecting the file transfer (Type 14).
     * Updates UI and cleans up the transfer state.
     * @param {Session} session - The session object (sender's session).
     * @param {object} payload - The rejection payload.
     * @returns {Promise<object>} Action object (always 'NONE').
     */
    async _handleFileTransferReject(session, payload) {
        const { transferId } = payload;
        // Log rejection only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Received rejection for file transfer ${transferId} from ${session.peerId}`);

        const transferState = session.getTransferState(transferId);
        if (!transferState || !transferState.isSender || transferState.status !== 'initiating') {
            // Always log this warning.
            console.warn(`Received unexpected rejection for transfer ${transferId} or invalid state.`);
            return { action: 'NONE' };
        }

        // Update state and UI
        transferState.status = 'rejected';
        this.uiController.updateFileTransferStatus(transferId, "Peer rejected the file transfer.");
        this.uiController.hideFileTransferActions(transferId); // Hide cancel button
        this.uiController.playSound('end'); // Play end/reject sound

        // Clean up local state
        session.removeTransferState(transferId);
        // No DB cleanup needed for sender

        return { action: 'NONE' };
    }

    /**
     * Handles receiving a file chunk (Type 15).
     * Decrypts, stores in DB, updates progress, and attempts assembly.
     * @param {Session} session - The session object (receiver's session).
     * @param {object} payload - The chunk payload.
     * @returns {Promise<object>} Action object (always 'NONE').
     */
    async _handleFileChunk(session, payload) {
        const { transferId, chunkIndex, iv, data } = payload;
        // Log chunk receipt only if DEBUG is enabled (can be very verbose)
        // if (config.DEBUG) console.log(`Received chunk ${chunkIndex} for transfer ${transferId}`);

        const transferState = session.getTransferState(transferId);
        // Only process if we are the receiver and expecting data
        if (!transferState || transferState.isSender || (transferState.status !== 'accepted' && transferState.status !== 'receiving')) {
            // Always log this warning.
            console.warn(`Received unexpected chunk for transfer ${transferId} or invalid state (${transferState?.status}).`);
            // Maybe send an error back?
            return { action: 'NONE' };
        }

        // Update status if this is the first chunk
        if (transferState.status === 'accepted') {
            transferState.status = 'receiving';
        }

        try {
            // Decode Base64
            const ivBuffer = session.cryptoModule.base64ToArrayBuffer(iv);
            const encryptedBuffer = session.cryptoModule.base64ToArrayBuffer(data);

            // Decrypt chunk
            const decryptedChunk = await session.cryptoModule.decryptAES(encryptedBuffer, new Uint8Array(ivBuffer));
            if (!decryptedChunk) {
                throw new Error(`Decryption failed for chunk ${chunkIndex}`);
            }

            // Store chunk in IndexedDB
            await this.addChunkToDB(transferId, chunkIndex, decryptedChunk);

            // NEW: Increment received chunk count
            transferState.receivedChunkCount++;

            // Update progress (calculate based on index and total size)
            // Note: We don't know the total number of chunks easily, so use size.
            // Use receivedChunkCount for more accurate progress representation
            const progressPercent = Math.min(100, (transferState.receivedChunkCount / transferState.expectedChunks) * 100);
            transferState.progress = progressPercent; // Update state
            this.uiController.updateFileTransferProgress(transferId, progressPercent);
            this.uiController.updateFileTransferStatus(transferId, `Receiving ${progressPercent.toFixed(1)}%...`);

            // NEW: Attempt assembly after storing chunk
            await this._attemptFileAssembly(session, transferId);

        } catch (error) {
            // Always log errors during chunk processing.
            console.error(`Error processing chunk ${chunkIndex} for transfer ${transferId}:`, error);
            this.uiController.playSound('file_error');
            this.uiController.updateFileTransferStatus(transferId, `Error: ${error.message}`);
            this.uiController.hideFileTransferActions(transferId);
            // Send error notification to peer
            const errorPayload = { targetId: transferState.senderId, senderId: this.identifier, transferId: transferId, error: `Failed to process chunk ${chunkIndex}: ${error.message}` };
            this.wsClient.sendMessage({ type: 17, payload: errorPayload });
            // Clean up local state and DB
            await this.deleteChunksFromDB(transferId);
            session.removeTransferState(transferId);
        }

        return { action: 'NONE' };
    }

    /**
     * Handles the file transfer completion signal (Type 16).
     * Sets a flag and attempts assembly.
     * @param {Session} session - The session object (receiver's session).
     * @param {object} payload - The completion payload.
     * @returns {Promise<object>} Action object (always 'NONE').
     */
    async _handleFileTransferComplete(session, payload) {
        const { transferId } = payload;
        // Log completion signal only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Received transfer complete signal for ${transferId}`);

        const transferState = session.getTransferState(transferId);
        // Only process if we are the receiver and were receiving/accepted
        if (!transferState || transferState.isSender || (transferState.status !== 'receiving' && transferState.status !== 'accepted')) {
            // Always log this warning.
            console.warn(`Received unexpected completion for transfer ${transferId} or invalid state (${transferState?.status}).`);
            return { action: 'NONE' };
        }

        // NEW: Set completion flag
        transferState.completionSignalReceived = true;

        // Update UI slightly differently - we know sender finished, but maybe not all chunks processed yet
        if (transferState.receivedChunkCount < transferState.expectedChunks) {
            this.uiController.updateFileTransferStatus(transferId, `Sender finished. Waiting for remaining chunks (${transferState.receivedChunkCount}/${transferState.expectedChunks})...`);
        } else {
            // If we already have all chunks, update status to assembling
            this.uiController.updateFileTransferStatus(transferId, "Transfer complete. Assembling file...");
        }
        this.uiController.updateFileTransferProgress(transferId, 100); // Show 100% as sender is done

        // NEW: Attempt assembly
        await this._attemptFileAssembly(session, transferId);

        return { action: 'NONE' };
    }

    /**
     * Handles a file transfer error message (Type 17) from the peer.
     * Updates UI and cleans up the transfer state.
     * @param {Session} session - The session object.
     * @param {object} payload - The error payload.
     * @returns {Promise<object>} Action object (always 'NONE').
     */
    async _handleFileTransferError(session, payload) {
        const { transferId, error } = payload;
        const errorMessage = error || "Peer reported an error.";
        // Log error only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Received error for file transfer ${transferId} from ${session.peerId}: ${errorMessage}`);

        const transferState = session.getTransferState(transferId);
        if (!transferState) {
            // Always log this warning.
            console.warn(`Received error for unknown transfer ${transferId}.`);
            return { action: 'NONE' };
        }

        // Update UI
        this.uiController.updateFileTransferStatus(transferId, `Error: ${errorMessage}`);
        this.uiController.hideFileTransferActions(transferId);
        this.uiController.playSound('file_error');

        // Clean up local state and potentially DB
        await this.deleteChunksFromDB(transferId); // Attempt DB cleanup regardless of sender/receiver
        session.removeTransferState(transferId);

        return { action: 'NONE' };
    }

    /**
     * NEW: Attempts to assemble the file if all chunks and the completion signal have been received.
     * @param {Session} session - The session object (receiver's session).
     * @param {string} transferId - The ID of the transfer to potentially assemble.
     * @private
     */
    async _attemptFileAssembly(session, transferId) {
        const transferState = session.getTransferState(transferId);

        // Check if assembly conditions are met
        if (transferState &&
            transferState.completionSignalReceived === true &&
            transferState.receivedChunkCount === transferState.expectedChunks)
        {
            // Log assembly attempt only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Attempting final assembly for transfer ${transferId}`);
            this.uiController.updateFileTransferStatus(transferId, "Transfer complete. Assembling file...");

            try {
                // Retrieve all chunks from IndexedDB
                const chunks = await this.getChunksFromDB(transferId);
                if (!chunks || chunks.length === 0) {
                    throw new Error("No chunks found in database for assembly.");
                }

                // Verify completeness (check count again just in case)
                if (chunks.length !== transferState.expectedChunks) {
                    // More robust check: ensure all indices from 0 to expectedChunks-1 are present.
                    const receivedIndices = new Set(chunks.map(c => c.chunkIndex));
                    const missing = [];
                    for (let i = 0; i < transferState.expectedChunks; i++) {
                        if (!receivedIndices.has(i)) {
                            missing.push(i);
                        }
                    }
                    if (missing.length > 0) {
                        throw new Error(`File assembly failed: Missing chunks (${missing.join(', ')}). Expected ${transferState.expectedChunks}, got ${chunks.length}.`);
                    }
                     // Always log this warning.
                     console.warn(`Chunk count mismatch for ${transferId}. Expected ${transferState.expectedChunks}, got ${chunks.length}. Proceeding anyway.`);
                }

                // Sort chunks by index - IMPORTANT!
                chunks.sort((a, b) => a.chunkIndex - b.chunkIndex);

                // Assemble Blob
                const blob = new Blob(chunks.map(c => c.data), { type: transferState.fileType });

                // Verify final blob size matches expected size
                if (blob.size !== transferState.fileSize) {
                    throw new Error(`Assembled file size mismatch. Expected ${transferState.fileSize}, got ${blob.size}.`);
                }

                // Show download link
                this.uiController.showFileDownloadLink(transferId, blob, transferState.fileName);
                this.uiController.updateFileTransferStatus(transferId, "Download ready.");
                this.uiController.playSound('file_complete');

                // Clean up DB and mark state as complete
                await this.deleteChunksFromDB(transferId);
                transferState.status = 'complete'; // Mark as complete in session state

            } catch (error) {
                // Always log assembly errors.
                console.error(`Error assembling file for transfer ${transferId}:`, error);
                this.uiController.playSound('file_error');
                this.uiController.updateFileTransferStatus(transferId, `Error: ${error.message}`);
                this.uiController.hideFileTransferActions(transferId);
                // Send error notification to peer
                const errorPayload = { targetId: transferState.senderId, senderId: this.identifier, transferId: transferId, error: `File assembly failed: ${error.message}` };
                this.wsClient.sendMessage({ type: 17, payload: errorPayload });
                // Clean up local state and DB
                await this.deleteChunksFromDB(transferId);
                session.removeTransferState(transferId);
            }
        } else if (transferState) {
            // Log conditions not met only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`Assembly conditions not met for ${transferId}: Signal Received=${transferState.completionSignalReceived}, Chunks Received=${transferState.receivedChunkCount}/${transferState.expectedChunks}`);
            }
        }
    }

    // --- IndexedDB Helper Methods ---

    /**
     * Initializes the IndexedDB database connection.
     */
    async initDB() {
        return new Promise((resolve, reject) => {
            // Log DB init only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Initializing IndexedDB: ${this.DB_NAME} v${this.DB_VERSION}`);

            // Check for IndexedDB support
            if (!window.indexedDB) {
                console.error("IndexedDB not supported by this browser.");
                alert("File transfer requires IndexedDB support, which is not available in your browser.");
                reject("IndexedDB not supported.");
                return;
            }

            const request = indexedDB.open(this.DB_NAME, this.DB_VERSION);

            request.onerror = (event) => {
                // Always log DB errors.
                console.error("IndexedDB error:", event.target.error);
                reject(`IndexedDB error: ${event.target.error}`);
            };

            request.onsuccess = (event) => {
                this.db = event.target.result;
                // Log success only if DEBUG is enabled.
                if (config.DEBUG) console.log("IndexedDB initialized successfully.");
                resolve(this.db);
            };

            request.onupgradeneeded = (event) => {
                // Log upgrade only if DEBUG is enabled.
                if (config.DEBUG) console.log("IndexedDB upgrade needed.");
                const db = event.target.result;
                if (!db.objectStoreNames.contains(this.CHUNK_STORE_NAME)) {
                    // Create object store for chunks: { transferId, chunkIndex, data }
                    // Use a composite key [transferId, chunkIndex] for uniqueness and efficient lookup/sorting.
                    const store = db.createObjectStore(this.CHUNK_STORE_NAME, { keyPath: ['transferId', 'chunkIndex'] });
                    // Optional: Create an index on transferId alone for easy deletion of all chunks for a transfer.
                    store.createIndex('transferIdIndex', 'transferId', { unique: false });
                    // Log store creation only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`Object store '${this.CHUNK_STORE_NAME}' created.`);
                }
            };
        });
    }

    /**
     * Gets a transaction and object store reference.
     * @param {'readonly' | 'readwrite'} mode - The transaction mode.
     * @returns {IDBObjectStore} The object store instance.
     * @throws {Error} If DB is not initialized.
     */
    _getStore(mode) {
        if (!this.db) {
            throw new Error("IndexedDB is not initialized.");
        }
        const transaction = this.db.transaction(this.CHUNK_STORE_NAME, mode);
        return transaction.objectStore(this.CHUNK_STORE_NAME);
    }

    /**
     * Adds a file chunk to the IndexedDB store.
     * Ensures the promise resolves only after the transaction completes.
     * @param {string} transferId - The transfer ID.
     * @param {number} chunkIndex - The index of the chunk.
     * @param {ArrayBuffer} data - The decrypted chunk data.
     * @returns {Promise<void>}
     */
    async addChunkToDB(transferId, chunkIndex, data) {
        return new Promise((resolve, reject) => {
            if (!this.db) {
                // Always log this error.
                console.error("Attempted to add chunk to DB, but DB is not initialized.");
                return reject(new Error("IndexedDB not initialized."));
            }
            try {
                // Start transaction
                const transaction = this.db.transaction(this.CHUNK_STORE_NAME, 'readwrite');
                const store = transaction.objectStore(this.CHUNK_STORE_NAME);

                // Log transaction start only if DEBUG is enabled.
                // if (config.DEBUG) console.log(`DB: Starting transaction to add chunk ${chunkIndex} for ${transferId}`);

                // Handle transaction errors
                transaction.onerror = (event) => {
                    // Always log DB errors.
                    console.error(`DB: Transaction error adding chunk ${chunkIndex} for ${transferId}:`, event.target.error);
                    reject(event.target.error || new Error("IndexedDB transaction failed"));
                };

                // Handle transaction completion
                transaction.oncomplete = () => {
                    // Log completion only if DEBUG is enabled.
                    // if (config.DEBUG) console.log(`DB: Transaction complete for adding chunk ${chunkIndex} for ${transferId}.`);
                    resolve();
                };

                // Queue the put request within the transaction
                const request = store.put({ transferId, chunkIndex, data });

                // Handle request-specific errors (less common if transaction handles it)
                request.onerror = (event) => {
                    // Always log DB errors.
                    console.error(`DB: Request error adding chunk ${chunkIndex} for ${transferId}:`, event.target.error);
                    // Don't reject here, let the transaction error handler do it.
                    // reject(event.target.error);
                };
                 request.onsuccess = () => {
                     // Log put success only if DEBUG is enabled.
                     // if (config.DEBUG) console.log(`DB: Put request successful for chunk ${chunkIndex} for ${transferId}. Waiting for transaction commit...`);
                 };

            } catch (error) {
                 // Always log errors getting store/starting transaction.
                 console.error("Error accessing IndexedDB store for adding chunk:", error);
                 reject(error);
            }
        });
    }

    /**
     * Retrieves all chunks for a given transfer ID from IndexedDB.
     * @param {string} transferId - The transfer ID.
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
                const store = this._getStore('readonly');
                // Use the index on transferId to get all matching records
                const index = store.index('transferIdIndex');
                const request = index.getAll(transferId); // Get all records matching the transferId

                request.onsuccess = (event) => {
                    // Log retrieval only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`DB: Retrieved ${event.target.result.length} chunks for transfer ${transferId} from DB.`);
                    resolve(event.target.result); // result is an array of chunk objects
                };
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
     * @param {string} transferId - The transfer ID.
     * @returns {Promise<void>}
     */
    async deleteChunksFromDB(transferId) {
        return new Promise((resolve, reject) => {
             if (!this.db) {
                // Always log this warning.
                console.warn("Attempted to delete chunks from DB, but DB is not initialized.");
                // Resolve successfully as there's nothing to delete if DB isn't there.
                return resolve();
            }
            try {
                const transaction = this.db.transaction(this.CHUNK_STORE_NAME, 'readwrite');
                const store = transaction.objectStore(this.CHUNK_STORE_NAME);
                // Use the index to efficiently delete all chunks for the transferId
                const index = store.index('transferIdIndex');
                const request = index.openKeyCursor(IDBKeyRange.only(transferId)); // Cursor to find keys matching transferId
                let deleteCount = 0;

                // Log transaction start only if DEBUG is enabled.
                // if (config.DEBUG) console.log(`DB: Starting transaction to delete chunks for ${transferId}`);

                transaction.onerror = (event) => {
                    // Always log DB errors.
                    console.error(`DB: Transaction error deleting chunks for ${transferId}:`, event.target.error);
                    reject(event.target.error || new Error("IndexedDB transaction failed"));
                };

                transaction.oncomplete = () => {
                    // Log completion only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`DB: Transaction complete for deleting ${deleteCount} chunks for ${transferId}.`);
                    resolve();
                };

                request.onsuccess = (event) => {
                    const cursor = event.target.result;
                    if (cursor) {
                        // Found a key matching the transferId, delete the corresponding record using its primary key
                        store.delete(cursor.primaryKey);
                        deleteCount++;
                        cursor.continue(); // Move to the next matching key
                    }
                    // No 'else' needed here, transaction oncomplete handles the final resolve.
                };
                // Request specific error (less likely for cursor)
                request.onerror = (event) => {
                    // Always log DB errors.
                    console.error(`DB: Cursor error deleting chunks for ${transferId}:`, event.target.error);
                    // Don't reject here, let the transaction error handler do it.
                };

            } catch (error) {
                 // Always log errors getting store/starting transaction.
                 console.error("Error accessing IndexedDB store for deleting chunks:", error);
                 reject(error);
            }
        });
    }

    // --- End IndexedDB ---

    // --- Disconnect Cleanup ---
    /**
     * Cleans up any pending or active file transfers when the WebSocket disconnects
     * or the page unloads.
     */
    async handleDisconnectionCleanup() {
        // Log cleanup attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log("Performing disconnection cleanup for file transfers...");
        if (this.sessions.size > 0) {
            for (const [peerId, session] of this.sessions.entries()) {
                if (session.transferStates && session.transferStates.size > 0) {
                    const transferIds = Array.from(session.transferStates.keys());
                    for (const transferId of transferIds) {
                        const state = session.getTransferState(transferId);
                        if (state) {
                            // Log specific transfer cleanup only if DEBUG is enabled.
                            if (config.DEBUG) console.log(`Cleaning up transfer ${transferId} (status: ${state.status}) during disconnect.`);
                            // Update UI to show cancellation/error
                            this.uiController.updateFileTransferStatus(transferId, "Cancelled (Disconnected)");
                            this.uiController.hideFileTransferActions(transferId);
                            // Clean up DB and session state
                            await this.deleteChunksFromDB(transferId);
                            session.removeTransferState(transferId);
                            // Revoke any object URLs
                            this.uiController.revokeObjectURL(transferId);
                        }
                    }
                }
            }
        }
    }
    // --- End Disconnect Cleanup ---

} // End SessionManager Class