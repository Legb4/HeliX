// client/js/SessionManager.js

/**
 * Manages the overall state of the chat application, user registration,
 * and all active/pending chat sessions. It acts as the central coordinator,
 * interacting with the WebSocketClient for network communication, the UIController
 * for display updates, and creating/managing individual Session instances.
 * This version uses ECDH for Perfect Forward Secrecy.
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
        this.HANDSHAKE_TIMEOUT_DURATION = 30000; // 30 seconds for handshake steps (key exchange, challenge).
        this.REQUEST_TIMEOUT_DURATION = 60000; // 60 seconds for the initial session request to be accepted/denied.
        this.REGISTRATION_TIMEOUT_DURATION = 15000; // 15 seconds to wait for registration success/failure reply.
        this.TYPING_STOP_DELAY = 3000; // Send TYPING_STOP message after 3 seconds of local user inactivity.
        this.TYPING_INDICATOR_TIMEOUT = 5000; // Hide peer's typing indicator after 5 seconds if no further typing messages or actual messages arrive.

        // --- Application States ---
        // Define possible states for the overall application manager.
        this.STATE_INITIALIZING = 'INITIALIZING'; // App just started.
        this.STATE_CONNECTING = 'CONNECTING'; // WebSocket attempting to connect.
        this.STATE_CONNECTED_UNREGISTERED = 'CONNECTED_UNREGISTERED'; // WebSocket connected, waiting for user registration.
        this.STATE_REGISTERING = 'REGISTERING'; // Registration message sent, awaiting reply.
        this.STATE_REGISTERED = 'REGISTERED'; // User successfully registered with an identifier.
        this.STATE_FAILED_REGISTRATION = 'FAILED_REGISTRATION'; // Registration attempt failed.
        this.STATE_DISCONNECTED = 'DISCONNECTED'; // WebSocket connection lost or closed.

        // --- Session-Specific States (Reflecting ECDH Flow) ---
        // Define possible states for individual Session instances.
        // Initiator states:
        this.STATE_INITIATING_SESSION = 'INITIATING_SESSION'; // Sent Type 1 request, awaiting Type 2 (Accept + Peer ECDH Key).
        this.STATE_DERIVING_KEY_INITIATOR = 'DERIVING_KEY_INITIATOR'; // Received Type 2, deriving keys before sending Type 4.
        this.STATE_KEY_DERIVED_INITIATOR = 'KEY_DERIVED_INITIATOR'; // Keys derived, ready to send Type 4.
        this.STATE_AWAITING_PEER_KEY = 'AWAITING_PEER_KEY'; // (Obsolete with ECDH flow, covered by DERIVING/RECEIVED_CHALLENGE)
        this.STATE_RECEIVED_CHALLENGE = 'RECEIVED_CHALLENGE'; // Received Type 5 (Challenge), ready to send Type 6 (Response).
        this.STATE_AWAITING_FINAL_CONFIRMATION = 'AWAITING_FINAL_CONFIRMATION'; // Sent Type 6, awaiting Type 7 (Established).
        // Responder states:
        this.STATE_REQUEST_RECEIVED = 'REQUEST_RECEIVED'; // Received Type 1 request, awaiting user Accept/Deny.
        this.STATE_GENERATING_ACCEPT_KEYS = 'GENERATING_ACCEPT_KEYS'; // User clicked Accept, generating ECDH keys before sending Type 2.
        this.STATE_AWAITING_CHALLENGE = 'AWAITING_CHALLENGE'; // Sent Type 2 (Accept + Own ECDH Key), awaiting Type 4 (Initiator ECDH Key).
        this.STATE_DERIVING_KEY_RESPONDER = 'DERIVING_KEY_RESPONDER'; // Received Type 4, deriving keys before sending Type 5.
        this.STATE_RECEIVED_INITIATOR_KEY = 'RECEIVED_INITIATOR_KEY'; // Received Type 4, keys derived, ready to send Type 5 (Challenge).
        this.STATE_HANDSHAKE_COMPLETE = 'HANDSHAKE_COMPLETE'; // Received Type 6 (Response), verified, ready to send Type 7.
        // Common states:
        this.STATE_ACTIVE_SESSION = 'ACTIVE_SESSION'; // Handshake complete (Type 7 received/sent), ready for messages (Type 8).
        // End/Error states:
        this.STATE_DENIED = 'DENIED'; // Request explicitly denied (Type 3) or target not found (Type -1).
        this.STATE_REQUEST_TIMED_OUT = 'REQUEST_TIMED_OUT'; // Initial request (Type 1) timed out.
        this.STATE_HANDSHAKE_TIMED_OUT = 'HANDSHAKE_TIMED_OUT'; // One of the handshake steps timed out.
        this.STATE_CANCELLED = 'CANCELLED'; // User cancelled an outgoing request.
        // Note: STATE_DISCONNECTED is a manager state, sessions are reset on disconnect.

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

        // Log initialization (not wrapped in DEBUG as it's fundamental)
        console.log('SessionManager initialized (ECDH Mode).');
        this.updateManagerState(this.STATE_INITIALIZING); // Set initial state.
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

    // --- Timeout Handling (No changes needed for PFS) ---

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
     * Updates the session state and potentially shows an info message.
     * @param {string} peerId - The ID of the peer whose handshake timed out.
     */
    handleHandshakeTimeout(peerId) {
        // Always log timeout errors.
        console.error(`Session [${peerId}] Handshake timed out!`);
        const session = this.sessions.get(peerId);
        // Define the states during which a handshake timeout is relevant (adjust for ECDH flow)
        const handshakeStates = [
            this.STATE_DERIVING_KEY_INITIATOR, this.STATE_KEY_DERIVED_INITIATOR,
            this.STATE_RECEIVED_CHALLENGE, this.STATE_AWAITING_FINAL_CONFIRMATION,
            this.STATE_GENERATING_ACCEPT_KEYS, this.STATE_AWAITING_CHALLENGE,
            this.STATE_DERIVING_KEY_RESPONDER, this.STATE_RECEIVED_INITIATOR_KEY,
            this.STATE_HANDSHAKE_COMPLETE
        ];
        // Check if the session exists and is still in a relevant handshake state.
        if (session && handshakeStates.includes(session.state)) {
            session.updateState(this.STATE_HANDSHAKE_TIMED_OUT);
            const message = `Handshake with ${peerId} timed out. Please try initiating the session again.`;
            // Always try to show the info message pane for handshake timeouts.
            this.uiController.showInfoMessage(peerId, message, false); // No retry for handshake timeout.
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
     * Updates the session state and potentially shows an info message allowing retry.
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
     * Updates manager state, alerts the user, and re-enables registration UI.
     */
    handleRegistrationTimeout() {
        // Always log timeout errors.
        console.error("Registration timed out!");
        // Only act if we were actually waiting for registration.
        if (this.managerState === this.STATE_REGISTERING) {
            this.updateManagerState(this.STATE_FAILED_REGISTRATION);
            const reason = "No response from server.";
            this.uiController.updateStatus(`Registration Failed: ${reason}`);
            // Use alert for registration timeout as it's a global failure.
            alert(`Registration failed: ${reason}`);
            // Show registration UI again and re-enable controls.
            this.uiController.showRegistration();
            this.uiController.setRegistrationControlsEnabled(true);
        }
    }
    // -----------------------------

    /**
     * Resets a specific session, cleaning up its state, timeouts, UI elements, and typing status.
     * @param {string} peerId - The ID of the peer whose session needs resetting.
     * @param {boolean} [notifyUserViaAlert=false] - Whether to show a fallback alert to the user with the reason (used if info pane isn't shown).
     * @param {string} [reason="Session reset."] - The reason for the reset (used in logs and optional alert).
     */
    resetSession(peerId, notifyUserViaAlert = false, reason = "Session reset.") {
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

            // Check if this session was the one being displayed or pending action.
            const wasDisplayed = (this.displayedPeerId === peerId);
            const wasPendingAction = (this.pendingPeerIdForAction === peerId);

            // Reset the session object's internal state and keys.
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
                // Show default view *unless* an info message was just displayed for this peer.
                // The info message pane should persist until closed by the user.
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
             if (!this.displayedPeerId && !this.pendingPeerIdForAction && !this.uiController.isAnyInfoPaneVisible()) {
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
     * Creates a new Session instance, generates ECDH keys, and sends a Type 1 request.
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
                // 8. Start the request timeout if message sent successfully.
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
            // Use showInfoMessage for better feedback instead of alert
            this.uiController.showInfoMessage(targetId, `Failed to initiate session: ${error.message}`, false);
            // Clean up the failed session attempt.
            this.resetSession(targetId, false); // notifyUserViaAlert=false as info pane shown
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
            // Use showInfoMessage for better feedback instead of alert
            this.uiController.showInfoMessage(peerId, `Failed to accept session: ${error.message}`, false);
            // Clean up the failed session attempt.
            this.resetSession(peerId, false); // notifyUserViaAlert=false as info pane shown
        } finally {
            // Re-enable incoming request controls if the pane is still visible (e.g., if error occurred before send)
            if (session?.state === this.STATE_GENERATING_ACCEPT_KEYS) {
                 this.uiController.setIncomingRequestControlsEnabled(true);
            }
        }
    }

    /**
     * Denies an incoming session request from a peer.
     * Sends a Type 3 denial message and resets the session.
     * @param {string} peerId - The identifier of the peer whose request is being denied.
     */
    denyRequest(peerId) {
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

        // Reset the session locally immediately after sending denial.
        this.resetSession(peerId, false, `Denied request from ${peerId}.`); // notifyUserViaAlert=false
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
                session.updateState(this.STATE_AWAITING_CHALLENGE); // Update state after successful send
                this.startHandshakeTimeout(session);
                this.uiController.updateStatus(`Waiting for challenge from ${session.peerId}...`);
            } else {
                // Throw error if send fails.
                throw new Error("Connection error sending key response.");
            }
        } catch (error) {
            // Always log errors.
            console.error(`Session [${session.peerId}] Error sending Type 4:`, error);
            // Use showInfoMessage for feedback
            this.uiController.showInfoMessage(session.peerId, `Handshake Error: ${error.message}`, false);
            this.resetSession(session.peerId, false); // notifyUserViaAlert=false
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
            // Use showInfoMessage for feedback
            this.uiController.showInfoMessage(session.peerId, `Handshake Error: ${error.message}`, false);
            this.resetSession(session.peerId, false); // notifyUserViaAlert=false
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
            // Use showInfoMessage for feedback
            this.uiController.showInfoMessage(session.peerId, `Handshake Error: ${error.message}`, false);
            this.resetSession(session.peerId, false); // notifyUserViaAlert=false
        }
    }

    /**
     * Sends the SESSION_ESTABLISHED (Type 7) message to confirm successful handshake.
     * Called by responder after receiving and verifying Type 6 (Response).
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
                // Handshake is complete! Update state, clear timeout, update UI.
                session.updateState(this.STATE_ACTIVE_SESSION);
                this.clearHandshakeTimeout(session); // Handshake successful, no more timeout needed.
                this.uiController.addSessionToList(session.peerId); // Ensure it's in the list.
                this.switchToSessionView(session.peerId); // Switch to the active chat view.
                // Log session active message (not wrapped in DEBUG as it's significant)
                console.log(`%cSession active with ${session.peerId}. Ready to chat!`, "color: green; font-weight: bold;");
            } else {
                 // Throw error if final confirmation send fails.
                 throw new Error("Connection error sending final confirmation.");
            }
        } catch (error) {
            // Always log errors.
            console.error(`Session [${session.peerId}] Error sending Type 7:`, error);
            // Use showInfoMessage for feedback
            this.uiController.showInfoMessage(session.peerId, `Handshake Error: ${error.message}`, false);
            this.resetSession(session.peerId, false); // notifyUserViaAlert=false
        }
    }

    /**
     * Encrypts and sends a chat message (Type 8) to the specified peer using the derived session key.
     * @param {string} peerId - The identifier of the recipient peer.
     * @param {string} text - The plaintext message to send.
     */
    async sendEncryptedMessage(peerId, text) {
        // Log attempt only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Attempting to send encrypted message to ${peerId}: "${text}"`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is active.
        if (!session || session.state !== this.STATE_ACTIVE_SESSION) {
            // Always log this warning.
            console.warn(`Cannot send message: Session with ${peerId} not active.`);
            // Provide feedback if trying to send in wrong state
            if (this.displayedPeerId === peerId) {
                this.uiController.addSystemMessage("Cannot send message: Session is not active.");
            }
            return;
        }
        // Ensure the derived session key exists within the session's crypto module.
        if (!session.cryptoModule.derivedSessionKey) {
            // Always log this critical error.
            console.error(`Session [${peerId}] Encryption key error: Missing derived session key.`);
            // Use showInfoMessage for critical key error
            this.uiController.showInfoMessage(peerId, "Encryption Error: Session key is missing. Please restart the session.", false);
            this.resetSession(peerId, false); // Reset session
            return;
        }
        // Ensure message text is valid.
        if (!text || typeof text !== 'string' || text.trim().length === 0) {
            // Always log this warning.
            console.warn("Attempted to send empty message."); return;
        }

        // --- If we were typing, send TYPING_STOP first ---
        this.sendTypingStop(peerId);
        // ------------------------------------------------

        // Disable chat controls and show loading state while encrypting/sending.
        this.uiController.setChatControlsEnabled(false, true);
        this.uiController.updateStatus(`Encrypting message to ${peerId}...`);
        let messageSent = false; // Flag to track if send was successful.

        try {
            // 1. Encode the plaintext message to a UTF-8 ArrayBuffer.
            const messageBuffer = session.cryptoModule.encodeText(text);
            // 2. Encrypt the message buffer using the derived AES session key.
            const aesResult = await session.cryptoModule.encryptAES(messageBuffer);
            if (!aesResult) throw new Error("AES encryption failed.");
            // 3. Encode the IV and the encrypted message data to Base64.
            const ivBase64 = session.cryptoModule.arrayBufferToBase64(aesResult.iv);
            const encryptedDataBase64 = session.cryptoModule.arrayBufferToBase64(aesResult.encryptedBuffer);

            // 4. Construct the ENCRYPTED_CHAT_MESSAGE (Type 8) payload.
            const message = {
                type: 8,
                payload: {
                    targetId: peerId,
                    senderId: this.identifier,
                    iv: ivBase64,                     // AES IV
                    data: encryptedDataBase64         // AES encrypted message
                }
            };
            this.uiController.updateStatus(`Sending message to ${peerId}...`);
            // Log sending only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Sending ENCRYPTED_CHAT_MESSAGE (Type 8) to ${peerId}`);
            // 5. Send the message via WebSocketClient.
            if (this.wsClient.sendMessage(message)) {
                messageSent = true;
                // Add the message to local history immediately.
                session.addMessageToHistory(this.identifier, text, 'own');
                // If this chat is currently displayed, add the message to the UI.
                if (this.displayedPeerId === peerId) {
                    this.uiController.addMessage(this.identifier, text, 'own');
                }
            } else {
                 // sendMessage returning false usually indicates connection issue.
                 // Always log this error.
                 console.error("sendMessage returned false, connection likely lost.");
                 // Status might be updated by the WebSocketClient's close handler.
                 // Provide feedback in the chat window if possible.
                 if (this.displayedPeerId === peerId) {
                     this.uiController.addSystemMessage("Error: Failed to send message (connection lost?).");
                 }
            }
        } catch (error) {
            // Handle errors during the encryption/sending process.
            // Always log errors.
            console.error("Error during sendEncryptedMessage:", error);
            // Use addSystemMessage for feedback in the chat window instead of alert
            if (this.displayedPeerId === peerId) {
                this.uiController.addSystemMessage(`Error sending message: ${error.message}`);
            } else {
                // If chat not active, maybe alert is okay, or log differently
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
     * Sends a Type 9 message, shows an info pane locally, and resets the session.
     * @param {string} peerId - The identifier of the peer whose session to end.
     */
    endSession(peerId) {
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

        // --- MODIFICATION START ---
        // Show info pane locally *before* resetting the session.
        const reason = `You ended the session with ${peerId}.`;
        this.uiController.showInfoMessage(peerId, reason, false); // Show info, no retry
        // Reset the session locally immediately, but without the alert fallback.
        this.resetSession(peerId, false, reason); // notifyUserViaAlert = false
        // --- MODIFICATION END ---
    }

    /**
     * Handles the user clicking the "Close" button on an info message pane.
     * If the session associated with the pane is in a terminal error/denial state,
     * it resets the session. Otherwise, it just hides the pane and shows the default view.
     * @param {string} peerId - The peer ID associated with the info message.
     */
    closeInfoMessage(peerId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Closing info message regarding ${peerId}`);
        // Disable info pane controls.
        this.uiController.setInfoControlsEnabled(false, true);

        // --- MODIFICATION START ---
        // Check if the session still exists and if it's in a state that requires cleanup upon closing the info pane.
        const session = this.sessions.get(peerId);
        const terminalStates = [
            this.STATE_DENIED,
            this.STATE_REQUEST_TIMED_OUT,
            this.STATE_HANDSHAKE_TIMED_OUT
        ];
        if (session && terminalStates.includes(session.state)) {
            // If the session is in a terminal state, reset it now.
            if (config.DEBUG) console.log(`Session [${peerId}] is in terminal state (${session.state}). Resetting.`);
            this.resetSession(peerId, false); // notifyUserViaAlert = false
        } else if (session) {
            // If the session exists but isn't in a terminal state (e.g., user manually ended),
            // it should have already been reset. Just log for debugging.
            if (config.DEBUG) console.log(`Info pane closed for session [${peerId}] in state ${session.state}. Session should already be reset.`);
        } else {
            // If the session doesn't exist (already reset), log for debugging.
            if (config.DEBUG) console.log(`Info pane closed for already reset session [${peerId}].`);
        }
        // --- MODIFICATION END ---

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
     * Resends the initial SESSION_REQUEST (Type 1) message.
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
                // Start the request timeout again.
                this.startRequestTimeout(session);
                this.uiController.updateStatus(`Waiting for response from ${peerId}...`);
            } else {
                 // Use showInfoMessage for feedback if send fails
                 this.uiController.showInfoMessage(peerId, "Connection error retrying request.", false);
                 this.resetSession(peerId, false); // Reset session
            }
        } else {
            // Always log this warning.
            console.warn(`Cannot retry request for ${peerId}, session not found or not in a retryable state (${session?.state}).`);
            // If session exists but wrong state, close the info message.
            if (session) { this.closeInfoMessage(peerId); }
            // If session doesn't exist, just show default view.
            else { this.uiController.showDefaultRegisteredView(this.identifier); }
        }
    }

    /**
     * Handles the user clicking the "Cancel Request" button while waiting for a peer response.
     * Sends a Type 9 message (interpreted as cancellation by the server/peer if handshake not complete)
     * and resets the session locally.
     * @param {string} peerId - The peer ID of the outgoing request to cancel.
     */
    cancelRequest(peerId) {
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
            // Reset the session locally.
            this.resetSession(peerId, false, `Request to ${peerId} cancelled.`);
        } else {
            // Always log this warning.
            console.warn(`Cannot cancel request for ${peerId}, session not found or not in initiating state (${session?.state})`);
        }
    }

    // --- Local Typing Handlers (No changes needed for PFS) ---

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

    // --- Peer Typing Indicator Timeout (No changes needed for PFS) ---

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

    // --- Notify peers on disconnect (No changes needed for PFS) ---

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
            // Define states where notifying the peer makes sense.
            const relevantStates = [
                this.STATE_ACTIVE_SESSION,
                this.STATE_DERIVING_KEY_INITIATOR, this.STATE_KEY_DERIVED_INITIATOR,
                this.STATE_RECEIVED_CHALLENGE, this.STATE_AWAITING_FINAL_CONFIRMATION,
                this.STATE_GENERATING_ACCEPT_KEYS, this.STATE_AWAITING_CHALLENGE,
                this.STATE_DERIVING_KEY_RESPONDER, this.STATE_RECEIVED_INITIATOR_KEY,
                this.STATE_HANDSHAKE_COMPLETE,
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

    // --- Central Message Handling and Routing (No changes needed for PFS) ---

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
                // Alert the user immediately.
                alert(`Disconnected by Server: ${errorMessage}`);
                // Immediately trigger the disconnection cleanup and UI reset logic.
                this.handleDisconnection(errorMessage); // Pass the reason
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
                this.handleUserNotFound(relevantPeerId, payload);
                return; // Processing complete.
            } else {
                // For all other messages, the sender is the relevant peer.
                relevantPeerId = senderId;
                session = this.sessions.get(relevantPeerId);
            }

            // 5. Handle New Session Request (Type 1)
            if (type === 1) {
                this.handleSessionRequest(senderId, payload);
                return; // Processing complete.
            }

            // 6. Route Message to Existing Session
            // If the message is not Type 1 and doesn't correspond to an existing session, ignore it.
            if (!session) {
                // Always log this warning.
                console.warn(`No session found for relevant peer ${relevantPeerId}, msg type ${type}. Ignoring.`);
                return;
            }

            // 7. Process Message within the Session
            // Log routing only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Routing message type ${type} to session [${relevantPeerId}]`);
            // Call the session's processMessage method, which returns an action object.
            const result = await session.processMessage(type, payload, this);
            // Process the action requested by the session.
            await this.processMessageResult(session, result);

        } catch (error) {
            // Catch errors during parsing, routing, or processing.
            // Always log these errors.
            console.error('Failed to parse/route/handle message:', error, messageData);
            this.uiController.updateStatus("Error processing message");
            // Potentially show a generic error to the user if appropriate
            // alert("An error occurred while processing a message from the server.");
        }
    }

    /**
     * Processes the action object returned by a Session's processMessage method.
     * Executes the requested action, such as sending a message, updating the UI,
     * resetting the session, or handling typing indicators.
     * @param {Session} session - The session instance that processed the message.
     * @param {object} result - The action object returned by session.processMessage (e.g., { action: 'SEND_TYPE_4' }).
     */
    async processMessageResult(session, result) {
        // Ignore if session or result/action is invalid.
        if (!session || !result || !result.action) return;

        const peerId = session.peerId; // Get peerId for convenience
        // Log action request only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${peerId}] Action requested: ${result.action}`);

        // --- Timeout Clearing Logic (No changes needed for PFS) ---
        // Clear handshake timeout if we are moving out of a handshake state towards active/reset
        const handshakeStates = [
            this.STATE_DERIVING_KEY_INITIATOR, this.STATE_KEY_DERIVED_INITIATOR,
            this.STATE_RECEIVED_CHALLENGE, this.STATE_AWAITING_FINAL_CONFIRMATION,
            this.STATE_GENERATING_ACCEPT_KEYS, this.STATE_AWAITING_CHALLENGE,
            this.STATE_DERIVING_KEY_RESPONDER, this.STATE_RECEIVED_INITIATOR_KEY,
            this.STATE_HANDSHAKE_COMPLETE
        ];
        const wasInHandshake = handshakeStates.includes(session.state);
        // Clear if action is SESSION_ACTIVE, RESET, or SHOW_INFO (indicating handshake ended)
        if (wasInHandshake && ['SESSION_ACTIVE', 'RESET', 'SHOW_INFO'].includes(result.action)) {
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
                await this.sendSessionEstablished(session);
                break;

            // Action indicating session is now active (from initiator's perspective after receiving Type 7):
            case 'SESSION_ACTIVE':
                this.switchToSessionView(peerId); // Ensure view is updated.
                // Log session active message (not wrapped in DEBUG as it's significant)
                console.log(`%cSession active with ${peerId}. Ready to chat!`, "color: green; font-weight: bold;");
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

                // Always try to show the info pane if there's a reason, regardless of current view.
                // This provides better context than an alert.
                if (result.reason) {
                    // Log display attempt only if DEBUG is enabled.
                    if (config.DEBUG) console.log(`Displaying reset reason for ${peerId}: ${result.reason}`);
                    // Show info message, typically no retry for disconnect/error resets.
                    this.uiController.showInfoMessage(peerId, result.reason, false);
                    // Reset the session *after* showing the message.
                    // Pass notifyUserViaAlert=false because the info pane handles the notification.
                    this.resetSession(peerId, false, result.reason);
                } else {
                    // If no specific reason provided (should be rare for RESET action), just reset.
                    // Use alert notification only if requested by the result (e.g., Type 9 disconnect).
                    this.resetSession(peerId, notifyViaAlert, reason);
                }
                break;

            // Handle Typing Indicator Actions (No changes needed for PFS)
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


    // --- Manager-Level Handlers (No changes needed for PFS) ---

    /**
     * Handles the registration success message (Type 0.1) from the server.
     * Stores the identifier, updates manager state, and shows the main app UI.
     * @param {object} payload - Expected: { identifier: string, message: string }
     */
    handleRegistrationSuccess(payload) {
        this.clearRegistrationTimeout(); // Stop the timeout.
        this.identifier = payload.identifier; // Store the confirmed identifier.
        this.updateManagerState(this.STATE_REGISTERED); // Update state.
        // Log success (not wrapped in DEBUG as it's significant).
        console.log(`Successfully registered as: ${this.identifier}`);
        // Show the main application UI (sidebar, content area).
        this.uiController.showMainApp(this.identifier);
        this.uiController.updateStatus(`Registered as: ${this.identifier}`);
        // Re-enable registration controls (though the area is now hidden).
        this.uiController.setRegistrationControlsEnabled(true);
    }

    /**
     * Handles the registration failure message (Type 0.2) from the server.
     * Updates manager state, alerts the user, and keeps the registration UI visible.
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
        // Use alert for registration failure as it's a global issue preventing app use.
        alert(`Registration failed: ${reason}\nPlease try a different identifier.`);
        // Keep registration UI visible and re-enable controls.
        this.uiController.showRegistration();
        this.uiController.setRegistrationControlsEnabled(true);
    }

    /**
     * Handles the user not found error message (Type -1) from the server.
     * Typically received when trying to initiate a session with an unknown/offline user.
     * Updates the relevant session state to DENIED and shows an info message.
     * @param {string} targetIdFailed - The identifier that was not found.
     * @param {object} payload - Expected: { targetId: string, message: string }
     */
    handleUserNotFound(targetIdFailed, payload) {
        const session = this.sessions.get(targetIdFailed);
        const errorMessage = payload.message || `User '${targetIdFailed}' not found or disconnected.`;
        // Always log server errors.
        console.error(`Server Error: ${errorMessage}`);
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
     * Updates the UI to show the incoming request or marks the session as unread if busy.
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

        // 5. Update the main UI view.
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
     * and shows the registration screen. Prevents running twice if already disconnected.
     * @param {string} [reason=null] - Optional reason for the disconnection, used for status updates.
     */
    handleDisconnection(reason = null) {
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

         // If there were active sessions, reset them all.
         if (this.sessions.size > 0) {
             const peerIds = Array.from(this.sessions.keys()); // Get all peer IDs.
             // Reset each session without individual user notification.
             peerIds.forEach(peerId => this.resetSession(peerId, false));
         }

         // Update manager state and clear session tracking variables.
         this.updateManagerState(this.STATE_DISCONNECTED); // Set state *before* UI updates
         this.displayedPeerId = null;
         this.pendingPeerIdForAction = null;
         this.identifier = null; // Clear registered identifier.

         // Update UI status and show the registration screen.
         // Use alert for the main disconnection event as it affects the whole app.
         alert(`Disconnected: ${disconnectReason}`);
         this.uiController.updateStatus(disconnectReason);
         this.uiController.showRegistration();
    }

    /**
     * Switches the main content view to display the specified session.
     * Updates the UI based on the session's current state (active chat, incoming request, info, etc.).
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

        // --- Hide typing indicator when switching views ---
        this.uiController.hideTypingIndicator();
        // -------------------------------------------------

        // Clear the unread indicator for the session being viewed.
        this.uiController.setUnreadIndicator(peerId, false);
        // Set this session as the active one in the sidebar list.
        this.uiController.setActiveSessionInList(peerId);

        // Show the appropriate main content pane based on the session's state.
        if (session.state === this.STATE_ACTIVE_SESSION) {
            this.uiController.showActiveChat(peerId);
            // Populate message area with history for this session.
            session.messages.forEach(msg => {
                this.uiController.addMessage(msg.sender, msg.text, msg.type);
            });
            this.uiController.updateStatus(`Session active with ${peerId}.`);
        } else if (session.state === this.STATE_REQUEST_RECEIVED) {
            // If switching to a session that has an incoming request needing action.
            this.pendingPeerIdForAction = peerId; // Mark as needing action.
            this.uiController.showIncomingRequest(peerId);
            this.uiController.updateStatus(`Incoming request from ${peerId}`);
        } else if (session.state === this.STATE_DENIED || session.state === this.STATE_HANDSHAKE_TIMED_OUT) {
             // Show info pane for denied or handshake timeout states.
             const message = session.state === this.STATE_DENIED ? `Session request denied by ${peerId}.` : `Handshake with ${peerId} timed out. Please try initiating the session again.`;
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
     * Gets the peer ID of the currently displayed chat session.
     * @returns {string|null} The peer ID or null if no session is displayed.
     */
    getActivePeerId() {
        return this.displayedPeerId;
    }
}
