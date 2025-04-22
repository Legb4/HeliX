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
        this.STATE_AWAITING_PEER_KEY = 'AWAITING_PEER_KEY'; // Received Type 2, sent Type 4 (Own ECDH Key), awaiting Type 5 (Challenge).
        this.STATE_AWAITING_CHALLENGE_RESPONSE = 'AWAITING_CHALLENGE_RESPONSE'; // Received Type 5 (Challenge), sent Type 6 (Response), awaiting Type 7 (Established).
        // Responder states:
        this.STATE_REQUEST_RECEIVED = 'REQUEST_RECEIVED'; // Received Type 1 request, awaiting user Accept/Deny.
        this.STATE_GENERATING_ACCEPT_KEYS = 'GENERATING_ACCEPT_KEYS'; // User clicked Accept, generating ECDH keys before sending Type 2.
        this.STATE_AWAITING_CHALLENGE = 'AWAITING_CHALLENGE'; // Sent Type 2 (Accept + Own ECDH Key), awaiting Type 4 (Initiator ECDH Key).
        this.STATE_RECEIVED_INITIATOR_KEY = 'RECEIVED_INITIATOR_KEY'; // Received Type 4, derived key, awaiting Type 5 (Challenge).
        this.STATE_RECEIVED_CHALLENGE = 'RECEIVED_CHALLENGE'; // Received Type 5, sent Type 6 (Response), awaiting Type 7 (Established).
        // Common states:
        // Note: Some previous states like RECEIVED_PEER_KEY are implicitly covered by the ECDH flow states.
        this.STATE_HANDSHAKE_COMPLETE = 'HANDSHAKE_COMPLETE'; // Challenge verified (Type 6 received/sent). Ready for final confirmation.
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
            console.warn(`Attempted to change state from DISCONNECTED to ${newState}. Ignoring.`);
            return;
        }
        console.log(`Manager State transition: ${this.managerState} -> ${newState}`);
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
        console.log(`Session [${session.peerId}] Starting handshake timeout (${this.HANDSHAKE_TIMEOUT_DURATION}ms)`);
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
            console.log(`Session [${session.peerId}] Clearing handshake timeout.`);
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
        console.error(`Session [${peerId}] Handshake timed out!`);
        const session = this.sessions.get(peerId);
        // Define the states during which a handshake timeout is relevant (adjust for ECDH flow)
        const handshakeStates = [
            this.STATE_AWAITING_PEER_KEY, // Initiator waiting for Type 5
            this.STATE_AWAITING_CHALLENGE, // Responder waiting for Type 4
            this.STATE_RECEIVED_INITIATOR_KEY, // Responder waiting for Type 5
            this.STATE_AWAITING_CHALLENGE_RESPONSE, // Initiator waiting for Type 7
            this.STATE_RECEIVED_CHALLENGE, // Responder waiting for Type 7
            this.STATE_HANDSHAKE_COMPLETE // Technically handshake done, but waiting for final confirmation
        ];
        // Check if the session exists and is still in a relevant handshake state.
        if (session && handshakeStates.includes(session.state)) {
            session.updateState(this.STATE_HANDSHAKE_TIMED_OUT);
            const message = `Handshake with ${peerId} timed out.`;
            // If this session was being displayed, show the info message directly.
            if (this.displayedPeerId === peerId) {
                this.uiController.showInfoMessage(peerId, message, false); // No retry for handshake timeout.
            } else {
                // Otherwise, add a system message to history and mark as unread.
                session.addMessageToHistory('System', message, 'system');
                this.uiController.setUnreadIndicator(peerId, true);
            }
        } else if (session) {
             // Timeout fired, but state changed in the meantime (e.g., session ended). Ignore.
             console.log(`Session [${peerId}] Handshake timeout fired but session state (${session.state}) is no longer relevant. Ignoring.`);
             session.handshakeTimeoutId = null; // Ensure ID is cleared.
        } else {
             // Timeout fired, but session was already removed. Ignore.
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
        console.log(`Session [${session.peerId}] Starting request timeout (${this.REQUEST_TIMEOUT_DURATION}ms)`);
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
            console.log(`Session [${session.peerId}] Clearing request timeout.`);
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
        console.error(`Session [${peerId}] Initial request timed out!`);
        const session = this.sessions.get(peerId);
        // Check if the session exists and is still in the initial state.
        if (session && session.state === this.STATE_INITIATING_SESSION) {
            session.updateState(this.STATE_REQUEST_TIMED_OUT);
            const message = `No response from ${peerId}. Request timed out.`;
            // If this session was displayed, show info message with retry option.
            if (this.displayedPeerId === peerId) {
                this.uiController.showInfoMessage(peerId, message, true); // Show retry button.
            } else {
                // Otherwise, add system message and mark unread.
                session.addMessageToHistory('System', message, 'system');
                this.uiController.setUnreadIndicator(peerId, true);
            }
        } else if (session) {
            // Timeout fired, but state changed (e.g., request cancelled). Ignore.
            console.log(`Session [${peerId}] Request timeout fired but session state (${session.state}) is no longer relevant. Ignoring.`);
            session.requestTimeoutId = null; // Ensure ID is cleared.
        } else {
            // Timeout fired, but session removed. Ignore.
            console.warn(`Session [${peerId}] Request timeout fired but session no longer exists.`);
        }
    }

    /**
     * Starts a timeout for the registration process (awaiting Type 0.1 or 0.2).
     * If the timeout expires, handleRegistrationTimeout is called.
     */
    startRegistrationTimeout() {
        this.clearRegistrationTimeout(); // Clear existing timeout.
        console.log(`Starting registration timeout (${this.REGISTRATION_TIMEOUT_DURATION}ms)`);
        this.registrationTimeoutId = setTimeout(() => {
            this.handleRegistrationTimeout();
        }, this.REGISTRATION_TIMEOUT_DURATION);
    }

    /**
     * Clears the registration timeout.
     */
    clearRegistrationTimeout() {
        if (this.registrationTimeoutId) {
            console.log("Clearing registration timeout.");
            clearTimeout(this.registrationTimeoutId);
            this.registrationTimeoutId = null;
        }
    }

    /**
     * Handles the expiration of the registration timeout.
     * Updates manager state, alerts the user, and re-enables registration UI.
     */
    handleRegistrationTimeout() {
        console.error("Registration timed out!");
        // Only act if we were actually waiting for registration.
        if (this.managerState === this.STATE_REGISTERING) {
            this.updateManagerState(this.STATE_FAILED_REGISTRATION);
            const reason = "No response from server.";
            this.uiController.updateStatus(`Registration Failed: ${reason}`);
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
     * @param {boolean} [notifyUser=false] - Whether to show an alert to the user with the reason.
     * @param {string} [reason="Session reset."] - The reason for the reset (used in logs and optional alert).
     */
    resetSession(peerId, notifyUser = false, reason = "Session reset.") {
        const session = this.sessions.get(peerId);
        if (session) {
            console.log(`Resetting session with peer: ${peerId}. Reason: ${reason}`);
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
                this.uiController.showDefaultRegisteredView(this.identifier); // Show welcome message.
                if (notifyUser && reason) { alert(reason); } // Show alert if requested.
            }
            else if (wasPendingAction) {
                 // If it was pending action (incoming request), clear the flag.
                 this.pendingPeerIdForAction = null;
                 // If no other chat is displayed, show the welcome message.
                 if (!this.displayedPeerId) { this.uiController.showDefaultRegisteredView(this.identifier); }
                 if (notifyUser && reason) { alert(reason); } // Show alert if requested.
            }

        } else {
            // Log if trying to reset a session that doesn't exist.
            console.warn(`Attempted to reset non-existent session for peer: ${peerId}`);
        }

        // After resetting, if no sessions remain and we are registered, ensure the default view is shown
        // and initiation controls are enabled.
         if (this.sessions.size === 0 && this.managerState === this.STATE_REGISTERED) {
             if (!this.displayedPeerId && !this.pendingPeerIdForAction) {
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
        console.log(`Attempting registration for ID: ${id}`);
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
        console.log(`Attempting to initiate session with: ${targetId}`);

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
            return;
        }

        this.uiController.updateStatus(`Initiating session with ${targetId}...`);

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
            console.log(`ECDH keys generated for session with ${targetId}.`);

            // 7. Construct and send the SESSION_REQUEST (Type 1) message.
            // Payload remains the same for Type 1.
            const msg = { type: 1, payload: { targetId: targetId, senderId: this.identifier } };
            console.log("Sending SESSION_REQUEST (Type 1):", msg);
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
            console.error("Error during initiateSession:", error);
            alert(`Failed to initiate session: ${error.message}`);
            // Clean up the failed session attempt.
            this.resetSession(targetId);
        }
    }

    /**
     * Accepts an incoming session request from a peer.
     * Generates ECDH keys, sends a Type 2 acceptance message with the public ECDH key.
     * @param {string} peerId - The identifier of the peer whose request is being accepted.
     */
    async acceptRequest(peerId) {
        console.log(`Attempting to accept session request from: ${peerId}`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is in the correct state.
        if (!session || session.state !== this.STATE_REQUEST_RECEIVED) {
            console.warn(`Cannot accept request for ${peerId}: Session not found or invalid state (${session?.state}).`);
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
            console.log("Sending SESSION_ACCEPT (Type 2 with ECDH key):", msg);
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
            console.error("Error during acceptRequest:", error);
            alert(`Failed to accept session: ${error.message}`);
            // Clean up the failed session attempt.
            this.resetSession(peerId);
        }
    }

    /**
     * Denies an incoming session request from a peer.
     * Sends a Type 3 denial message and resets the session.
     * @param {string} peerId - The identifier of the peer whose request is being denied.
     */
    denyRequest(peerId) {
        console.log(`Denying session request from: ${peerId}`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is in the correct state.
        if (!session || session.state !== this.STATE_REQUEST_RECEIVED) {
            console.warn(`Cannot deny request for ${peerId}: Session not found or invalid state (${session?.state}).`);
            return;
        }

        // Disable incoming request buttons and show loading state.
        this.uiController.setIncomingRequestControlsEnabled(false, true);

        // Clear the pending action flag.
        if (this.pendingPeerIdForAction === peerId) { this.pendingPeerIdForAction = null; }

        // Construct and send the SESSION_DENY (Type 3) message.
        const msg = { type: 3, payload: { targetId: peerId, senderId: this.identifier } };
        console.log("Sending SESSION_DENY (Type 3):", msg);
        this.wsClient.sendMessage(msg); // Send best effort.

        // Reset the session locally immediately after sending denial.
        this.resetSession(peerId);
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
        console.log(`Session [${session.peerId}] Attempting to send PUBLIC_KEY_RESPONSE (Type 4 with ECDH key)...`);
        // Export own public ECDH key.
        const publicKeyBase64 = await session.cryptoModule.getPublicKeyBase64();
        if (!publicKeyBase64) {
            alert("Key export failed.");
            this.resetSession(session.peerId, true, "Key export failed during handshake.");
            return;
        }
        // Construct and send message.
        const msg = { type: 4, payload: { targetId: session.peerId, senderId: this.identifier, publicKey: publicKeyBase64 } };
        console.log("Sending PUBLIC_KEY_RESPONSE (Type 4 with ECDH key):", msg);
        if (this.wsClient.sendMessage(msg)) {
            // Start handshake timeout, waiting for Type 5 (Challenge).
            this.startHandshakeTimeout(session);
            this.uiController.updateStatus(`Waiting for challenge from ${session.peerId}...`);
        } else {
            // Reset session if send fails.
            this.resetSession(session.peerId, true, "Connection error sending key response.");
        }
    }

    /**
     * Generates, encrypts (using derived AES key), and sends the KEY_CONFIRMATION_CHALLENGE (Type 5) message.
     * Called by responder after receiving Type 4 (Initiator's Key) and deriving the session key.
     * @param {Session} session - The session object.
     */
    async sendKeyConfirmationChallenge(session) {
        console.log(`Session [${session.peerId}] Attempting to send KEY_CONFIRMATION_CHALLENGE (Type 5 using derived key)...`);
        // Ensure the session key has been derived.
        if (!session.cryptoModule.derivedSessionKey) {
            this.resetSession(session.peerId, true, "Session key not derived before sending challenge.");
            return;
        }
        // Generate challenge data (e.g., unique text).
        const challengeText = `Challenge_for_${session.peerId}_from_${this.identifier}_${Date.now()}`;
        const challengeBuffer = session.cryptoModule.encodeText(challengeText);
        // Store the raw challenge buffer to verify the response later.
        session.challengeSent = challengeBuffer;
        console.log("Generated challenge data.");

        // Encrypt the challenge buffer using the derived AES session key.
        const encryptionResult = await session.cryptoModule.encryptAES(challengeBuffer);
        if (!encryptionResult) {
            alert("Encrypt challenge failed.");
            this.resetSession(session.peerId, true, "Failed to encrypt challenge.");
            return;
        }
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
        console.log("Sending KEY_CONFIRMATION_CHALLENGE (Type 5):", msg);
        if (this.wsClient.sendMessage(msg)) {
            // Start handshake timeout, waiting for Type 6 (Response).
            this.startHandshakeTimeout(session);
            this.uiController.updateStatus(`Challenge sent to ${session.peerId}. Waiting for response...`);
        } else {
             // Reset session if send fails.
             this.resetSession(session.peerId, true, "Connection error sending challenge.");
        }
    }

    /**
     * Encrypts the received challenge data (using derived AES key) and sends it back as KEY_CONFIRMATION_RESPONSE (Type 6).
     * Called by initiator after receiving and decrypting Type 5 (Challenge) and deriving the session key.
     * @param {Session} session - The session object.
     * @param {ArrayBuffer} challengeData - The raw decrypted challenge data received from the peer.
     */
    async sendKeyConfirmationResponse(session, challengeData) {
        console.log(`Session [${session.peerId}] Attempting to send KEY_CONFIRMATION_RESPONSE (Type 6 using derived key)...`);
        // Ensure session key is derived and challenge data is available.
        if (!session.cryptoModule.derivedSessionKey || !challengeData) {
            this.resetSession(session.peerId, true, "Missing session key or challenge data for response.");
            return;
        }
        // Encrypt the original challenge data using the derived AES session key.
        const encryptionResult = await session.cryptoModule.encryptAES(challengeData);
        if (!encryptionResult) {
            alert("Encrypt response failed.");
            this.resetSession(session.peerId, true, "Failed to encrypt challenge response.");
            return;
        }
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
        console.log("Sending KEY_CONFIRMATION_RESPONSE (Type 6):", msg);
        if (this.wsClient.sendMessage(msg)) {
            // Start handshake timeout, waiting for Type 7 (Established).
            this.startHandshakeTimeout(session);
            this.uiController.updateStatus(`Challenge response sent to ${session.peerId}. Waiting for final confirmation...`);
        } else {
             // Reset session if send fails.
             this.resetSession(session.peerId, true, "Connection error sending challenge response.");
        }
    }

    /**
     * Sends the SESSION_ESTABLISHED (Type 7) message to confirm successful handshake.
     * Called by responder after receiving and verifying Type 6 (Response).
     * @param {Session} session - The session object.
     */
    async sendSessionEstablished(session) {
        console.log(`Session [${session.peerId}] Attempting to send SESSION_ESTABLISHED (Type 7)...`);
        // Construct the final confirmation message. Payload remains simple.
        const msg = { type: 7, payload: { targetId: session.peerId, senderId: this.identifier, message: "Session established successfully!" } };
        console.log("Sending SESSION_ESTABLISHED (Type 7):", msg);
        if (this.wsClient.sendMessage(msg)) {
            // Handshake is complete! Update state, clear timeout, update UI.
            session.updateState(this.STATE_ACTIVE_SESSION);
            this.clearHandshakeTimeout(session); // Handshake successful, no more timeout needed.
            this.uiController.addSessionToList(session.peerId); // Ensure it's in the list.
            this.switchToSessionView(session.peerId); // Switch to the active chat view.
            console.log(`%cSession active with ${session.peerId}. Ready to chat!`, "color: green; font-weight: bold;");
        } else {
             // Reset session if final confirmation send fails.
             this.resetSession(session.peerId, true, "Connection error sending final confirmation.");
        }
    }

    /**
     * Encrypts and sends a chat message (Type 8) to the specified peer using the derived session key.
     * @param {string} peerId - The identifier of the recipient peer.
     * @param {string} text - The plaintext message to send.
     */
    async sendEncryptedMessage(peerId, text) {
        console.log(`Attempting to send encrypted message to ${peerId}: "${text}"`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is active.
        if (!session || session.state !== this.STATE_ACTIVE_SESSION) {
            console.warn(`Cannot send message: Session with ${peerId} not active.`); return;
        }
        // Ensure the derived session key exists within the session's crypto module.
        if (!session.cryptoModule.derivedSessionKey) {
            this.resetSession(peerId, true, "Encryption key error: Missing derived session key."); return;
        }
        // Ensure message text is valid.
        if (!text || typeof text !== 'string' || text.trim().length === 0) {
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
            //    Note: No encryptedKey field needed anymore.
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
            console.log(`Sending ENCRYPTED_CHAT_MESSAGE (Type 8) to ${peerId}`);
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
                 console.error("sendMessage returned false, connection likely lost.");
                 // Status might be updated by the WebSocketClient's close handler.
            }
        } catch (error) {
            // Handle errors during the encryption/sending process.
            console.error("Error during sendEncryptedMessage:", error);
            alert(`Error sending message: ${error.message}`);
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
     * Sends a Type 9 message and resets the session locally.
     * @param {string} peerId - The identifier of the peer whose session to end.
     */
    endSession(peerId) {
        console.log(`Attempting to end session with ${peerId}...`);
        const session = this.sessions.get(peerId);
        if (!session) { return; } // Ignore if session doesn't exist.

        // Disable chat controls while ending.
        this.uiController.setChatControlsEnabled(false, true);
        // Construct and send the SESSION_END_REQUEST (Type 9) message.
        const endMessage = { type: 9, payload: { targetId: peerId, senderId: this.identifier } };
        console.log("Sending SESSION_END_REQUEST (Type 9):", endMessage);
        this.wsClient.sendMessage(endMessage); // Send best effort.
        this.uiController.updateStatus(`Ending session with ${peerId}...`);
        // Reset the session locally immediately, notifying the user.
        this.resetSession(peerId, true, `You ended the session with ${peerId}.`);
    }

    /**
     * Handles the user clicking the "Close" button on an info message pane (denial, timeout).
     * Resets the associated session without notifying the user again via alert.
     * @param {string} peerId - The peer ID associated with the info message.
     */
    closeInfoMessage(peerId) {
        console.log(`Closing info message regarding ${peerId}`);
        // Disable info pane controls.
        this.uiController.setInfoControlsEnabled(false, true);
        // Reset the session state.
        this.resetSession(peerId, false); // notifyUser = false
        // If no other chat is displayed, show the default welcome view.
        if (!this.displayedPeerId) {
            this.uiController.showDefaultRegisteredView(this.identifier);
        }
    }

    /**
     * Handles the user clicking the "Retry" button after a request timeout.
     * Resends the initial SESSION_REQUEST (Type 1) message.
     * @param {string} peerId - The peer ID associated with the timed-out request.
     */
    async retryRequest(peerId) {
        console.log(`Retrying session request with ${peerId}`);
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
            console.log("Re-sending SESSION_REQUEST (Type 1):", msg);
            if (this.wsClient.sendMessage(msg)) {
                // Start the request timeout again.
                this.startRequestTimeout(session);
                this.uiController.updateStatus(`Waiting for response from ${peerId}...`);
            } else {
                 // Reset session if send fails.
                 this.resetSession(peerId, true, "Connection error retrying request.");
            }
        } else {
            // Log if retry attempted in an invalid state or for non-existent session.
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
        console.log(`Cancelling session request to ${peerId}`);
        const session = this.sessions.get(peerId);
        // Ensure session exists and is in the initiating state.
        if (session && session.state === this.STATE_INITIATING_SESSION) {
            // Disable waiting pane controls.
            this.uiController.setWaitingControlsEnabled(false, true);
            // Clear the request timeout as we are cancelling.
            this.clearRequestTimeout(session);
            // Construct and send a SESSION_END_REQUEST (Type 9).
            // If the peer hasn't processed the Type 1 yet, this might be ignored,
            // but it signals intent if they have. The main effect is local reset.
            const cancelMsg = { type: 9, payload: { targetId: peerId, senderId: this.identifier } };
            console.log("Sending SESSION_END_REQUEST (Type 9) for cancellation:", cancelMsg);
            this.wsClient.sendMessage(cancelMsg); // Send best effort.
            // Reset the session locally.
            this.resetSession(peerId, false, `Request to ${peerId} cancelled.`);
        } else {
            // Log if cancel attempted in wrong state or for non-existent session.
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
            console.log(`Sending TYPING_START to ${peerId}`);
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
            console.log(`Sending TYPING_STOP to ${peerId}`);
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
        console.log(`Session [${session.peerId}] Starting typing indicator timeout (${this.TYPING_INDICATOR_TIMEOUT}ms)`);
        session.typingIndicatorTimeoutId = setTimeout(() => {
            console.log(`Session [${session.peerId}] Typing indicator timed out.`);
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
            console.log(`Session [${session.peerId}] Clearing typing indicator timeout.`);
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
        console.log("Attempting to notify active peers of disconnect...");
        this.sessions.forEach((session, peerId) => {
            // Define states where notifying the peer makes sense.
            const relevantStates = [
                this.STATE_ACTIVE_SESSION, this.STATE_AWAITING_PEER_KEY,
                this.STATE_AWAITING_CHALLENGE, this.STATE_RECEIVED_INITIATOR_KEY,
                this.STATE_AWAITING_CHALLENGE_RESPONSE, this.STATE_RECEIVED_CHALLENGE,
                this.STATE_HANDSHAKE_COMPLETE,
                this.STATE_INITIATING_SESSION, this.STATE_REQUEST_RECEIVED // Notify even if pending/handshaking
            ];
            // If the session is in a relevant state...
            if (relevantStates.includes(session.state)) {
                console.log(`Sending Type 9 disconnect notification to ${peerId}`);
                const endMessage = { type: 9, payload: { targetId: peerId, senderId: this.identifier } };
                try {
                     // Try to send directly using the WebSocket object if it's still open.
                     // Bypasses the usual sendMessage checks as this happens during unload.
                     if (this.wsClient.websocket && this.wsClient.websocket.readyState === WebSocket.OPEN) {
                         this.wsClient.websocket.send(JSON.stringify(endMessage));
                     }
                } catch (e) {
                    // Log errors, but don't stop notifying other peers.
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
        console.log('SessionManager received raw message data:', messageData);
        let message;
        try {
            // 1. Parse the incoming JSON string.
            message = JSON.parse(messageData);
            const type = message.type;
            const payload = message.payload;
            // Sender ID is usually in the payload, except for server-generated messages like registration replies.
            const senderId = payload?.senderId;

            console.log(`Parsed message: Type=${type}, From=${senderId || 'N/A'}, Payload=`, payload);

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
                console.warn(`No session found for relevant peer ${relevantPeerId}, msg type ${type}. Ignoring.`);
                return;
            }

            // 7. Process Message within the Session
            console.log(`Routing message type ${type} to session [${relevantPeerId}]`);
            // Call the session's processMessage method, which returns an action object.
            const result = await session.processMessage(type, payload, this);
            // Process the action requested by the session.
            await this.processMessageResult(session, result);

        } catch (error) {
            // Catch errors during parsing, routing, or processing.
            console.error('Failed to parse/route/handle message:', error, messageData);
            this.uiController.updateStatus("Error processing message");
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

        console.log(`Session [${session.peerId}] Action requested: ${result.action}`);

        // --- Timeout Clearing Logic (No changes needed for PFS) ---
        const handshakeStates = [
            this.STATE_AWAITING_PEER_KEY,
            this.STATE_AWAITING_CHALLENGE, this.STATE_RECEIVED_INITIATOR_KEY,
            this.STATE_AWAITING_CHALLENGE_RESPONSE, this.STATE_RECEIVED_CHALLENGE,
            this.STATE_HANDSHAKE_COMPLETE
        ];
        const wasInHandshake = handshakeStates.includes(session.state);
        if (wasInHandshake && result.action !== 'SESSION_ACTIVE') {
             this.clearHandshakeTimeout(session);
        }
        if (result.action === 'SEND_TYPE_4' || result.action === 'SHOW_INFO') {
             this.clearRequestTimeout(session);
        }
        // --- End Timeout Clearing ---

        // Execute action based on the result object.
        switch (result.action) {
            // Actions requesting specific message sends:
            case 'SEND_TYPE_4':
                this.uiController.updateStatus(`Received acceptance from ${session.peerId}. Preparing response...`);
                await this.sendPublicKeyResponse(session); // Sends ECDH key now
                break;
            case 'SEND_TYPE_5':
                this.uiController.updateStatus(`Received ${session.peerId}'s public key. Preparing challenge...`);
                await this.sendKeyConfirmationChallenge(session); // Sends AES encrypted challenge
                break;
            case 'SEND_TYPE_6':
                this.uiController.updateStatus(`Challenge received from ${session.peerId}. Preparing response...`);
                await this.sendKeyConfirmationResponse(session, result.challengeData); // Sends AES encrypted response
                break;
            case 'SEND_TYPE_7':
                this.uiController.updateStatus(`Challenge verified with ${session.peerId}. Establishing session...`);
                await this.sendSessionEstablished(session);
                break;

            // Action indicating session is now active (from initiator's perspective after receiving Type 7):
            case 'SESSION_ACTIVE':
                this.switchToSessionView(session.peerId); // Ensure view is updated.
                console.log(`%cSession active with ${session.peerId}. Ready to chat!`, "color: green; font-weight: bold;");
                break;

            // Actions requesting UI updates:
            case 'DISPLAY_MESSAGE':
                // When a message arrives, clear any "peer is typing" indicator timeout and hide the indicator.
                this.clearTypingIndicatorTimeout(session);
                if (this.displayedPeerId === session.peerId) {
                    this.uiController.hideTypingIndicator();
                    this.uiController.addMessage(result.sender, result.text, result.msgType);
                } else {
                    // If chat not displayed, mark session as having unread messages.
                    this.uiController.setUnreadIndicator(session.peerId, true);
                }
                break;
            case 'DISPLAY_SYSTEM_MESSAGE':
                 // Display system messages only if the relevant chat is active.
                 if (this.displayedPeerId === session.peerId) {
                    this.uiController.addSystemMessage(result.text);
                } else {
                    // Log system messages for inactive chats, maybe mark unread?
                    console.warn(`System message for non-active session ${session.peerId}: ${result.text}`);
                    session.addMessageToHistory('System', result.text, 'system'); // Add to history
                    this.uiController.setUnreadIndicator(session.peerId, true); // Mark unread
                }
                break;
            case 'SHOW_INFO':
                // Show the info pane (denial, timeout).
                this.uiController.showInfoMessage(session.peerId, result.message, result.showRetry);
                // Re-enable initiation controls if this was the only session attempt.
                if (session.state === this.STATE_DENIED || session.state === this.STATE_REQUEST_TIMED_OUT || session.state === this.STATE_HANDSHAKE_TIMED_OUT) {
                     if (this.sessions.size <= 1) { this.uiController.setInitiationControlsEnabled(true); }
                }
                break;

            // Action requesting session reset:
            case 'RESET':
                this.resetSession(session.peerId, result.notifyUser, result.reason);
                break;

            // Handle Typing Indicator Actions (No changes needed for PFS)
            case 'SHOW_TYPING':
                if (this.displayedPeerId === session.peerId) {
                    this.uiController.showTypingIndicator(session.peerId);
                }
                this.startTypingIndicatorTimeout(session);
                break;
            case 'HIDE_TYPING':
                this.clearTypingIndicatorTimeout(session);
                if (this.displayedPeerId === session.peerId) {
                    this.uiController.hideTypingIndicator();
                }
                break;

            // Default case for unknown or 'NONE' actions:
            case 'NONE':
            default:
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
        console.error(`Registration failed for '${requestedId}': ${reason}`);
        this.uiController.updateStatus(`Registration Failed: ${reason}`);
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
        console.error(`Server Error: ${errorMessage}`);
        // Check if we have a session for this peer and it was in the initiating state.
        if (session && session.state === this.STATE_INITIATING_SESSION) {
            console.log(`Showing denial info for ${targetIdFailed} after user not found error.`);
            // Clear timeouts associated with the failed request.
            this.clearRequestTimeout(session);
            this.clearHandshakeTimeout(session); // Should be null, but clear just in case.
            // Update state to DENIED.
            session.updateState(this.STATE_DENIED);
            // Show info message (no retry option for user not found).
            this.uiController.showInfoMessage(targetIdFailed, errorMessage, false);
        } else {
             // Received error for a peer we weren't actively trying to connect to, or state mismatch.
             console.warn(`Received user not found for ${targetIdFailed}, but no matching session in INITIATING_SESSION state.`);
             // Show a general status update/alert.
             this.uiController.updateStatus(`Error: ${errorMessage}`);
             alert(`Server Error: ${errorMessage}`);
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
        console.log(`Incoming session request received from: ${senderId}`);
        // Ignore if not registered or if another request is already pending user action.
        if (this.managerState !== this.STATE_REGISTERED) {
            console.warn(`Ignoring incoming request from ${senderId}: Manager not in REGISTERED state.`);
            return;
        }
        if (this.pendingPeerIdForAction) {
            console.warn(`Ignoring incoming request from ${senderId}: Another request from ${this.pendingPeerIdForAction} is pending user action.`);
            // Potential enhancement: Queue requests or send a "busy" response.
            return;
        }
        // Ignore if a session with this peer already exists (in any state).
        if (this.sessions.has(senderId)) {
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
            console.log(`Another session active. Marking ${senderId} as pending request.`);
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
             console.log("handleDisconnection called but already disconnected. Skipping.");
             return;
         }
         // Use the provided reason or a default message
         const disconnectReason = reason || "Connection lost.";
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
            console.warn(`Attempted to switch to non-existent session: ${peerId}`);
            this.uiController.showDefaultRegisteredView(this.identifier);
            return;
        }

        console.log(`Switching view to session with ${peerId}`);
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
             const message = session.state === this.STATE_DENIED ? `Session request denied by ${peerId}.` : `Handshake with ${peerId} timed out.`;
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
            console.log(`Session with ${peerId} is handshaking (state: ${session.state}). Showing welcome message.`);
            this.uiController.showWelcomeMessage(); // Show default welcome/instructions pane.
            this.uiController.updateStatus(`Session with ${peerId} is currently ${session.state}.`);
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
