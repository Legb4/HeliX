// client/js/Session.js

/**
 * Represents a single chat session with a specific peer.
 * Manages the state of the session (e.g., initiating, active, denied),
 * holds cryptographic keys relevant to this session (via its own CryptoModule instance),
 * stores message history, handles timeouts, and processes incoming messages for this peer.
 */
class Session {
    /**
     * Creates a new Session instance.
     * @param {string} peerId - The unique identifier of the peer for this session.
     * @param {string} initialState - The initial state of the session (e.g., 'INITIATING_SESSION', 'REQUEST_RECEIVED').
     * @param {CryptoModule} cryptoModuleInstance - A dedicated instance of CryptoModule for this session's keys.
     */
    constructor(peerId, initialState, cryptoModuleInstance) {
        // Validate required constructor arguments.
        if (!peerId || !initialState || !cryptoModuleInstance) {
            throw new Error("Session requires peerId, initialState, and cryptoModuleInstance");
        }

        // --- Session Properties ---
        this.peerId = peerId; // Identifier of the remote peer.
        this.state = initialState; // Current state of the session handshake/chat.
        this.cryptoModule = cryptoModuleInstance; // Dedicated crypto handler for this session's keys.
        this.peerPublicKey = null; // Stores the imported CryptoKey object of the peer's public RSA key.
        this.challengeSent = null; // Stores the ArrayBuffer of the challenge sent to the peer during handshake.
        this.challengeReceived = null; // Stores the ArrayBuffer of the challenge received from the peer.
        this.messages = []; // Array to store message history objects { sender, text, type }.
        this.handshakeTimeoutId = null; // Stores the ID of the handshake timeout timer.
        this.requestTimeoutId = null; // Stores the ID of the initial request timeout timer.

        // --- NEW: Typing Indicator State ---
        // Tracks whether the peer is currently marked as typing.
        this.peerIsTyping = false;
        // Stores the ID of the timeout used to automatically hide the peer's typing indicator.
        this.typingIndicatorTimeoutId = null;
        // ---------------------------------

        console.log(`New session created for peer: ${this.peerId}, initial state: ${this.state}`);
    }

    /**
     * Updates the state of the session.
     * @param {string} newState - The new state identifier.
     */
    updateState(newState) {
        console.log(`Session [${this.peerId}] State transition: ${this.state} -> ${newState}`);
        this.state = newState;
    }

    /**
     * Resets the session state, clearing keys, challenges, messages, and timeouts.
     * Called when a session ends, is denied, times out, or encounters a critical error.
     */
    resetState() {
         console.log(`Resetting state for session [${this.peerId}]`);
         // Clear any pending timeouts to prevent them from firing after reset.
         if (this.handshakeTimeoutId) { clearTimeout(this.handshakeTimeoutId); this.handshakeTimeoutId = null; }
         if (this.requestTimeoutId) { clearTimeout(this.requestTimeoutId); this.requestTimeoutId = null; }
         // Clear the timeout associated with hiding the peer's typing indicator.
         if (this.typingIndicatorTimeoutId) {
             clearTimeout(this.typingIndicatorTimeoutId);
             this.typingIndicatorTimeoutId = null;
         }

         // Clear session-specific cryptographic materials and state.
         this.challengeSent = null;
         this.challengeReceived = null;
         this.peerPublicKey = null;
         this.cryptoModule.wipeKeys(); // Tell the dedicated crypto module to wipe its RSA keys.
         this.messages = []; // Clear message history.
         this.peerIsTyping = false; // Reset peer typing status.
    }

    /**
     * Stores the imported peer's public RSA key (CryptoKey object).
     * @param {CryptoKey} keyObject - The peer's public CryptoKey.
     * @returns {boolean} True if the key was stored successfully, false otherwise.
     */
    setPeerPublicKey(keyObject) {
        // Basic validation: ensure it's a non-null object (CryptoKey).
        if (keyObject && typeof keyObject === 'object') {
            this.peerPublicKey = keyObject;
            console.log(`Session [${this.peerId}] Stored peer public key.`);
            return true;
        } else {
            console.error(`Session [${this.peerId}] Invalid object provided for peer public key:`, keyObject);
            return false;
        }
    }

    /**
     * Adds a message object to the session's history.
     * @param {string} sender - The identifier of the sender ('System', own ID, or peer ID).
     * @param {string} text - The message content.
     * @param {string} type - The message type ('system', 'own', 'peer').
     */
    addMessageToHistory(sender, text, type) {
        this.messages.push({ sender, text, type });
    }

    // --- Central Message Processor for this Session ---

    /**
     * Processes an incoming message payload relevant to this specific session.
     * Routes the message to the appropriate internal handler based on its type.
     * @param {number} type - The message type identifier (e.g., 2 for ACCEPT, 8 for MESSAGE).
     * @param {object} payload - The message payload object.
     * @param {SessionManager} manager - The SessionManager instance (provides access to states, etc.).
     * @returns {Promise<object>} An action object for the SessionManager (e.g., { action: 'SEND_TYPE_4' }).
     */
    async processMessage(type, payload, manager) {
        console.log(`Session [${this.peerId}] Processing message type ${type} in state ${this.state}`);

        // Route based on message type.
        switch (type) {
            // Handshake & Session Management Messages
            case 2: return await this._handleAccept(payload, manager); // Peer accepted our request
            case 3: return this._handleDeny(payload, manager);         // Peer denied our request
            case 4: return await this._handlePublicKeyResponse(payload, manager); // Peer sent their public key (response to our accept)
            case 5: return await this._handleKeyConfirmationChallenge(payload, manager); // Peer sent encrypted challenge
            case 6: return await this._handleKeyConfirmationResponse(payload, manager); // Peer sent response to our challenge
            case 7: return this._handleSessionEstablished(payload, manager); // Peer confirmed session establishment
            case 9: return this._handleSessionEnd(payload, manager); // Peer initiated session end

            // Data Message
            case 8: return await this._handleEncryptedMessage(payload, manager); // Encrypted chat message

            // --- NEW: Handle Typing Indicators ---
            case 10: return this._handleTypingStart(payload, manager); // Peer started typing
            case 11: return this._handleTypingStop(payload, manager);  // Peer stopped typing
            // -----------------------------------

            default:
                // Log unhandled message types for debugging.
                console.warn(`Session [${this.peerId}] Received unhandled message type in processMessage: ${type}`);
                return { action: 'NONE' }; // No action needed for unknown types.
        }
    }

    // --- Internal Handlers (return action objects for SessionManager) ---
    // These methods handle the logic for specific incoming message types.
    // They perform cryptographic operations, update session state, and return
    // an object describing the next action the SessionManager should take.

    /**
     * Handles SESSION_ACCEPT (Type 2) message from the peer.
     * Imports the peer's public key.
     * @param {object} payload - Expected: { publicKey: string (Base64) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'SEND_TYPE_4' } on success, { action: 'RESET', reason: string } on failure.
     */
    async _handleAccept(payload, manager) {
        const publicKeyBase64 = payload.publicKey;
        // Validate payload and import the key.
        if (!publicKeyBase64) { return { action: 'RESET', reason: 'Invalid Type 2 received (missing key).' }; }
        const importedKey = await this.cryptoModule.importPublicKeyBase64(publicKeyBase64);
        if (!importedKey) { return { action: 'RESET', reason: 'Failed to import peer key.' }; }
        // Store the imported key.
        if (!this.setPeerPublicKey(importedKey)) { return { action: 'RESET', reason: 'Failed to store peer key.' }; }
        // Update state and request SessionManager to send our public key back.
        this.updateState(manager.STATE_RECEIVED_PEER_KEY);
        return { action: 'SEND_TYPE_4' };
    }

    /**
     * Handles SESSION_DENY (Type 3) message from the peer.
     * @param {object} payload - Expected: {} (no specific data needed)
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {object} Action object: { action: 'SHOW_INFO', message: string, showRetry: boolean }
     */
    _handleDeny(payload, manager) {
        const message = `Session request denied by ${this.peerId}.`;
        console.log(message);
        // Update state and request SessionManager to show an info message to the user.
        this.updateState(manager.STATE_DENIED);
        return { action: 'SHOW_INFO', message: message, showRetry: false }; // No retry option for explicit denial.
    }

    /**
     * Handles PUBLIC_KEY_RESPONSE (Type 4) message from the peer (their response to our Type 2 Accept).
     * Imports the initiator's (peer's) public key.
     * @param {object} payload - Expected: { publicKey: string (Base64) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'SEND_TYPE_5' } on success, { action: 'RESET', reason: string } on failure.
     */
    async _handlePublicKeyResponse(payload, manager) {
        const publicKeyBase64 = payload.publicKey;
        // Validate payload and import the key.
        if (!publicKeyBase64) { return { action: 'RESET', reason: 'Invalid Type 4 received (missing key).' }; }
        const importedKey = await this.cryptoModule.importPublicKeyBase64(publicKeyBase64);
        if (!importedKey) { return { action: 'RESET', reason: 'Failed to import peer key.' }; }
        // Store the imported key.
        if (!this.setPeerPublicKey(importedKey)) { return { action: 'RESET', reason: 'Failed to store peer key.' }; }
        // Update state and request SessionManager to send the encrypted challenge.
        this.updateState(manager.STATE_RECEIVED_INITIATOR_KEY);
        return { action: 'SEND_TYPE_5' };
    }

    /**
     * Handles KEY_CONFIRMATION_CHALLENGE (Type 5) message from the peer.
     * Decrypts the challenge using own private key.
     * @param {object} payload - Expected: { encryptedHash: string (Base64) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'SEND_TYPE_6', challengeData: ArrayBuffer } on success, { action: 'RESET', reason: string } on failure.
     */
    async _handleKeyConfirmationChallenge(payload, manager) {
        const encryptedChallengeBase64 = payload.encryptedHash;
        // Validate payload.
        if (!encryptedChallengeBase64) { return { action: 'RESET', reason: 'Invalid Type 5 received (missing data).' }; }
        // Convert Base64 to buffer and decrypt using own private RSA key.
        const encryptedChallengeBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedChallengeBase64);
        const decryptedChallengeBuffer = await this.cryptoModule.decryptRSA(encryptedChallengeBuffer);
        if (!decryptedChallengeBuffer) { return { action: 'RESET', reason: 'Failed to decrypt challenge (security check failed).' }; }
        // Store the decrypted challenge data.
        this.challengeReceived = decryptedChallengeBuffer;
        // Log decrypted text for debugging (remove in production if sensitive).
        const challengeText = this.cryptoModule.decodeText(decryptedChallengeBuffer);
        console.log(`Challenge decrypted successfully. Received text (for debug): "${challengeText}"`);
        // Update state and request SessionManager to send back the encrypted response.
        this.updateState(manager.STATE_RECEIVED_CHALLENGE);
        return { action: 'SEND_TYPE_6', challengeData: this.challengeReceived };
    }

    /**
     * Handles KEY_CONFIRMATION_RESPONSE (Type 6) message from the peer (their response to our Type 5 Challenge).
     * Decrypts the response and verifies it matches the original challenge sent.
     * @param {object} payload - Expected: { encryptedHash: string (Base64) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'SEND_TYPE_7' } on success, { action: 'RESET', reason: string } on failure/mismatch.
     */
    async _handleKeyConfirmationResponse(payload, manager) {
        const encryptedResponseBase64 = payload.encryptedHash;
        // Validate payload and ensure we actually sent a challenge.
        if (!encryptedResponseBase64) { return { action: 'RESET', reason: 'Invalid Type 6 received (missing data).' }; }
        if (!this.challengeSent) { return { action: 'RESET', reason: 'Received unexpected Type 6.' }; }
        // Convert Base64 to buffer and decrypt using own private RSA key.
        const encryptedResponseBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedResponseBase64);
        const decryptedResponseBuffer = await this.cryptoModule.decryptRSA(encryptedResponseBuffer);
        if (!decryptedResponseBuffer) { return { action: 'RESET', reason: 'Failed to decrypt challenge response (security check failed).' }; }

        // --- Verify Challenge Match ---
        // Compare the byte length first for quick check.
        let match = decryptedResponseBuffer.byteLength === this.challengeSent.byteLength;
        if (match) {
            // If lengths match, perform a byte-by-byte comparison.
            const view1 = new Uint8Array(this.challengeSent);
            const view2 = new Uint8Array(decryptedResponseBuffer);
            for (let i = 0; i < view1.length; i++) {
                if (view1[i] !== view2[i]) {
                    match = false;
                    break;
                }
            }
        }
        // If buffers don't match, reset the session (security failure).
        if (!match) { return { action: 'RESET', reason: 'Challenge response verification failed!' }; }
        // --- Verification Success ---
        console.log("Challenge response verified successfully!");
        this.challengeSent = null; // Clear the sent challenge.
        // Update state and request SessionManager send the final confirmation.
        this.updateState(manager.STATE_HANDSHAKE_COMPLETE);
        return { action: 'SEND_TYPE_7' };
    }

    /**
     * Handles SESSION_ESTABLISHED (Type 7) message from the peer (final confirmation).
     * Marks the session as active.
     * @param {object} payload - Expected: { message: string } (optional confirmation message)
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {object} Action object: { action: 'SESSION_ACTIVE' }
     */
    _handleSessionEstablished(payload, manager) {
        // Update state to active.
        this.updateState(manager.STATE_ACTIVE_SESSION);
        this.challengeReceived = null; // Clear received challenge.
        // Request SessionManager to update UI for the active session.
        return { action: 'SESSION_ACTIVE' };
    }

    /**
     * Handles ENCRYPTED_CHAT_MESSAGE (Type 8) message from the peer.
     * Decrypts the AES key using own private RSA key, then decrypts the message data using the AES key.
     * @param {object} payload - Expected: { encryptedKey: string (Base64), iv: string (Base64), data: string (Base64) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'DISPLAY_MESSAGE', ... } on success, { action: 'DISPLAY_SYSTEM_MESSAGE', ... } or { action: 'NONE' } on failure/wrong state.
     */
    async _handleEncryptedMessage(payload, manager) {
        const encryptedKeyBase64 = payload.encryptedKey;
        const ivBase64 = payload.iv;
        const encryptedDataBase64 = payload.data;

        // Ignore messages if the session isn't fully active.
        if (this.state !== manager.STATE_ACTIVE_SESSION) {
             console.warn(`Session [${this.peerId}] Received Type 8 message in non-active state (${this.state}). Ignoring.`);
             return { action: 'NONE' };
        }
        // Validate payload structure.
        if (!encryptedKeyBase64 || !ivBase64 || !encryptedDataBase64) {
            return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Received malformed message from ${this.peerId}.` };
        }

        try {
            // 1. Decrypt the AES key (sent encrypted with our public RSA key).
            const encryptedKeyBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedKeyBase64);
            const decryptedKeyBuffer = await this.cryptoModule.decryptRSA(encryptedKeyBuffer);
            if (!decryptedKeyBuffer) { return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Error processing key from ${this.peerId}.` }; }

            // 2. Import the decrypted raw AES key into a CryptoKey object.
            const decryptedKeyBase64 = this.cryptoModule.arrayBufferToBase64(decryptedKeyBuffer);
            const aesKey = await this.cryptoModule.importSymmetricKeyBase64(decryptedKeyBase64);
            if (!aesKey) { return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Error processing key from ${this.peerId}.` }; }

            // 3. Decode the IV and encrypted message data from Base64.
            const iv = this.cryptoModule.base64ToArrayBuffer(ivBase64);
            const encryptedDataBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedDataBase64);

            // 4. Decrypt the message data using the imported AES key and IV.
            const decryptedDataBuffer = await this.cryptoModule.decryptAES(encryptedDataBuffer, aesKey, new Uint8Array(iv));
            if (!decryptedDataBuffer) { return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Failed to decrypt message from ${this.peerId}.` }; }

            // 5. Decode the decrypted buffer (UTF-8) into a string.
            const messageText = this.cryptoModule.decodeText(decryptedDataBuffer);

            // Log and add to history.
            console.log(`%c[${this.peerId}]: ${messageText}`, "color: purple;"); // Style console output
            this.addMessageToHistory(this.peerId, messageText, 'peer');

            // Request SessionManager display the message.
            return { action: 'DISPLAY_MESSAGE', sender: this.peerId, text: messageText, msgType: 'peer' };

        } catch (error) {
            console.error(`Error handling encrypted message from ${this.peerId}:`, error);
            return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Error decrypting message from ${this.peerId}.` };
        }
    }

    /**
     * Handles SESSION_END (Type 9) message from the peer.
     * @param {object} payload - Expected: {} (no specific data needed)
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {object} Action object: { action: 'RESET', reason: string, notifyUser: boolean }
     */
    _handleSessionEnd(payload, manager) {
        const message = `Session ended by ${this.peerId}.`;
        console.log(message);
        // Request SessionManager reset this session and notify the user.
        return { action: 'RESET', reason: message, notifyUser: true };
    }

    // --- NEW: Handle Typing Start (Type 10) ---
    /**
     * Handles TYPING_START (Type 10) message from the peer.
     * @param {object} payload - Expected: {} (no specific data needed)
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {object} Action object: { action: 'SHOW_TYPING' } or { action: 'NONE' } if not in active state.
     */
    _handleTypingStart(payload, manager) {
        // Only process typing indicators if the session is active.
        if (this.state !== manager.STATE_ACTIVE_SESSION) {
            console.warn(`Session [${this.peerId}] Ignoring Type 10 in state ${this.state}`);
            return { action: 'NONE' };
        }
        console.log(`Session [${this.peerId}] Peer started typing.`);
        this.peerIsTyping = true; // Mark peer as typing.
        // Request SessionManager show the typing indicator (it will handle the timeout).
        return { action: 'SHOW_TYPING' };
    }

    // --- NEW: Handle Typing Stop (Type 11) ---
    /**
     * Handles TYPING_STOP (Type 11) message from the peer.
     * @param {object} payload - Expected: {} (no specific data needed)
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {object} Action object: { action: 'HIDE_TYPING' } or { action: 'NONE' } if not in active state.
     */
    _handleTypingStop(payload, manager) {
        // Only process typing indicators if the session is active.
        if (this.state !== manager.STATE_ACTIVE_SESSION) {
            console.warn(`Session [${this.peerId}] Ignoring Type 11 in state ${this.state}`);
            return { action: 'NONE' };
        }
        console.log(`Session [${this.peerId}] Peer stopped typing.`);
        this.peerIsTyping = false; // Mark peer as not typing.
        // Request SessionManager hide the typing indicator (it will clear the timeout).
        return { action: 'HIDE_TYPING' };
    }
}
