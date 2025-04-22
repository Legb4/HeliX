// client/js/Session.js

/**
 * Represents a single chat session with a specific peer.
 * Manages the state of the session (e.g., initiating, active, denied),
 * holds cryptographic keys relevant to this session (via its own CryptoModule instance
 * implementing ECDH for PFS), stores message history, handles timeouts,
 * and processes incoming messages for this peer.
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
        this.cryptoModule = cryptoModuleInstance; // Dedicated crypto handler for this session's keys (ECDH + AES).
        this.peerPublicKey = null; // Stores the imported CryptoKey object of the peer's public ECDH key.
        // Note: The derived AES session key is stored within the cryptoModuleInstance (cryptoModule.derivedSessionKey).
        this.challengeSent = null; // Stores the ArrayBuffer of the challenge sent to the peer during handshake.
        // challengeReceived can store:
        // - null: Challenge not yet received or processed.
        // - { isBuffered: true, iv: ArrayBuffer, encryptedData: ArrayBuffer }: Raw challenge data received before key derivation completed.
        // - ArrayBuffer: Decrypted challenge data after successful processing.
        this.challengeReceived = null;
        // keyDerivationPromise: Stores the promise returned by the key derivation process.
        // Used to ensure challenge decryption only happens after derivation completes.
        this.keyDerivationPromise = null;
        this.messages = []; // Array to store message history objects { sender, text, type }.
        this.handshakeTimeoutId = null; // Stores the ID of the handshake timeout timer.
        this.requestTimeoutId = null; // Stores the ID of the initial request timeout timer.

        // --- Typing Indicator State ---
        this.peerIsTyping = false;
        this.typingIndicatorTimeoutId = null;
        // ---------------------------------

        console.log(`New session created for peer: ${this.peerId}, initial state: ${this.state}`);
    }

    /**
     * Updates the state of the session.
     * @param {string} newState - The new state identifier.
     */
    updateState(newState) {
        // Avoid logging redundant state updates if the state isn't actually changing.
        if (this.state !== newState) {
            console.log(`Session [${this.peerId}] State transition: ${this.state} -> ${newState}`);
            this.state = newState;
        } else {
            console.log(`Session [${this.peerId}] State update attempted to same state: ${newState}`);
        }
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
         this.challengeReceived = null; // Clear any buffered or decrypted challenge
         this.peerPublicKey = null;
         this.keyDerivationPromise = null; // Clear derivation promise
         this.cryptoModule.wipeKeys(); // Tell the dedicated crypto module to wipe its ECDH keys and derived key.
         this.messages = []; // Clear message history.
         this.peerIsTyping = false; // Reset peer typing status.
    }

    /**
     * Stores the imported peer's public ECDH key (CryptoKey object).
     * @param {CryptoKey} keyObject - The peer's public CryptoKey.
     * @returns {boolean} True if the key was stored successfully, false otherwise.
     */
    setPeerPublicKey(keyObject) {
        // Basic validation: ensure it's a non-null object (CryptoKey).
        if (keyObject && typeof keyObject === 'object') {
            this.peerPublicKey = keyObject;
            console.log(`Session [${this.peerId}] Stored peer public ECDH key.`);
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

    // --- Key Derivation Helper ---
    /**
     * Internal helper to perform the ECDH secret derivation and session key derivation.
     * Stores the promise for this operation in `this.keyDerivationPromise`.
     * Updates state upon successful completion.
     * @param {string} successState - The state to transition to upon successful derivation.
     * @returns {Promise<boolean>} True if derivation succeeded, false otherwise.
     */
    async _deriveKeysAndHandleBufferedChallenge(successState) {
        if (!this.cryptoModule.privateKey || !this.peerPublicKey) {
            console.error(`Session [${this.peerId}] Cannot derive keys: Own or peer key missing.`);
            return false;
        }

        // Store the promise immediately.
        this.keyDerivationPromise = (async () => {
            console.log(`Session [${this.peerId}] Deriving shared secret...`);
            const sharedSecretBits = await this.cryptoModule.deriveSharedSecret(this.peerPublicKey);
            if (!sharedSecretBits) throw new Error('Failed to derive shared secret.');

            console.log(`Session [${this.peerId}] Deriving session key...`);
            const keyDerived = await this.cryptoModule.deriveSessionKey(sharedSecretBits);
            if (!keyDerived) throw new Error('Failed to derive session key.');

            console.log(`Session [${this.peerId}] Key derivation successful.`);
            return true; // Indicate success
        })();

        try {
            await this.keyDerivationPromise; // Wait for derivation to complete
            this.updateState(successState); // Update state only after successful derivation

            // --- Check for and process buffered challenge ---
            if (this.challengeReceived && this.challengeReceived.isBuffered) {
                console.log(`Session [${this.peerId}] Processing buffered challenge after key derivation.`);
                const decryptedBuffer = await this.cryptoModule.decryptAES(
                    this.challengeReceived.encryptedData,
                    new Uint8Array(this.challengeReceived.iv)
                );
                if (!decryptedBuffer) {
                    throw new Error('Failed to decrypt buffered challenge.');
                }
                this.challengeReceived = decryptedBuffer; // Replace buffer with decrypted data
                console.log(`Session [${this.peerId}] Buffered challenge decrypted successfully.`);
                // If we are the initiator, we now need to send Type 6
                if (this.state === manager.STATE_KEY_DERIVED_INITIATOR) { // Use the successState passed in
                     this.updateState(manager.STATE_RECEIVED_CHALLENGE); // Update state again
                     // We need SessionManager to send Type 6, but this helper returns boolean.
                     // The caller (_handleAccept or _handlePublicKeyResponse) needs to handle this.
                     // Let's signal this back via a specific return value or by setting a flag?
                     // Simpler: The caller will check challengeReceived status after awaiting this promise.
                }
            }
            return true; // Overall success
        } catch (error) {
            console.error(`Session [${this.peerId}] Key derivation or buffered challenge processing failed:`, error);
            this.keyDerivationPromise = null; // Clear promise on failure
            // Don't reset here, let the caller handle the reset action
            return false;
        }
    }


    // --- Central Message Processor for this Session ---

    /**
     * Processes an incoming message payload relevant to this specific session.
     * Routes the message to the appropriate internal handler based on its type.
     * Handles the ECDH key exchange and derivation logic.
     * @param {number} type - The message type identifier (e.g., 2 for ACCEPT, 8 for MESSAGE).
     * @param {object} payload - The message payload object.
     * @param {SessionManager} manager - The SessionManager instance (provides access to states, etc.).
     * @returns {Promise<object>} An action object for the SessionManager (e.g., { action: 'SEND_TYPE_5' }).
     */
    async processMessage(type, payload, manager) {
        console.log(`Session [${this.peerId}] Processing message type ${type} in state ${this.state}`);

        // Route based on message type.
        switch (type) {
            // Handshake & Session Management Messages
            case 2: return await this._handleAccept(payload, manager); // Peer accepted our request
            case 3: return this._handleDeny(payload, manager);         // Peer denied our request
            case 4: return await this._handlePublicKeyResponse(payload, manager); // Peer sent their public key (response to our accept OR our request)
            case 5: return await this._handleKeyConfirmationChallenge(payload, manager); // Peer sent encrypted challenge
            case 6: return await this._handleKeyConfirmationResponse(payload, manager); // Peer sent response to our challenge
            case 7: return this._handleSessionEstablished(payload, manager); // Peer confirmed session establishment
            case 9: return this._handleSessionEnd(payload, manager); // Peer initiated session end

            // Data Message
            case 8: return await this._handleEncryptedMessage(payload, manager); // Encrypted chat message

            // Typing Indicators
            case 10: return this._handleTypingStart(payload, manager); // Peer started typing
            case 11: return this._handleTypingStop(payload, manager);  // Peer stopped typing

            default:
                // Log unhandled message types for debugging.
                console.warn(`Session [${this.peerId}] Received unhandled message type in processMessage: ${type}`);
                return { action: 'NONE' }; // No action needed for unknown types.
        }
    }

    // --- Internal Handlers (return action objects for SessionManager) ---

    /**
     * Handles SESSION_ACCEPT (Type 2) message from the peer (Responder -> Initiator).
     * Imports the peer's public ECDH key, starts key derivation, and requests sending Type 4.
     * @param {object} payload - Expected: { publicKey: string (Base64 SPKI) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'SEND_TYPE_4' } on success, { action: 'RESET', reason: string } on failure.
     */
    async _handleAccept(payload, manager) {
        // This is received by the Initiator
        if (this.state !== manager.STATE_INITIATING_SESSION) {
             console.warn(`Session [${this.peerId}] Received unexpected Type 2 in state ${this.state}. Ignoring.`);
             return { action: 'NONE' };
        }
        const publicKeyBase64 = payload.publicKey;
        // Validate payload and import the key.
        if (!publicKeyBase64) { return { action: 'RESET', reason: 'Invalid Type 2 received (missing key).' }; }
        const importedKey = await this.cryptoModule.importPublicKeyBase64(publicKeyBase64);
        if (!importedKey) { return { action: 'RESET', reason: 'Failed to import peer ECDH key.' }; }
        // Store the imported key.
        if (!this.setPeerPublicKey(importedKey)) { return { action: 'RESET', reason: 'Failed to store peer ECDH key.' }; }

        // --- Start Key Derivation (Initiator) ---
        this.updateState(manager.STATE_DERIVING_KEY_INITIATOR); // New state
        const derivationSuccess = await this._deriveKeysAndHandleBufferedChallenge(manager.STATE_KEY_DERIVED_INITIATOR); // New state
        if (!derivationSuccess) {
            return { action: 'RESET', reason: 'Key derivation failed.' };
        }
        // --- End Key Derivation ---

        // Key derivation started (and potentially completed). Request sending Type 4.
        // If a buffered challenge was processed, the state might already be RECEIVED_CHALLENGE.
        // The SessionManager will handle sending Type 6 in that case based on the result of this function.
        // We still need to send Type 4 regardless.
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
     * Handles PUBLIC_KEY_RESPONSE (Type 4) message from the peer (Initiator -> Responder).
     * Imports the peer's public ECDH key, starts key derivation, and requests sending Type 5.
     * @param {object} payload - Expected: { publicKey: string (Base64 SPKI) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'SEND_TYPE_5' } on success, { action: 'RESET', reason: string } on failure.
     */
    async _handlePublicKeyResponse(payload, manager) {
        // This is received by the Responder
        if (this.state !== manager.STATE_AWAITING_CHALLENGE) { // Responder should be waiting for Initiator's key
             console.warn(`Session [${this.peerId}] Received unexpected Type 4 in state ${this.state}. Ignoring.`);
             return { action: 'NONE' };
        }
        const publicKeyBase64 = payload.publicKey;
        // Validate payload and import the key.
        if (!publicKeyBase64) { return { action: 'RESET', reason: 'Invalid Type 4 received (missing key).' }; }
        const importedKey = await this.cryptoModule.importPublicKeyBase64(publicKeyBase64);
        if (!importedKey) { return { action: 'RESET', reason: 'Failed to import peer ECDH key.' }; }
        // Store the imported key.
        if (!this.setPeerPublicKey(importedKey)) { return { action: 'RESET', reason: 'Failed to store peer ECDH key.' }; }

        // --- Start Key Derivation (Responder) ---
        this.updateState(manager.STATE_DERIVING_KEY_RESPONDER); // New state
        const derivationSuccess = await this._deriveKeysAndHandleBufferedChallenge(manager.STATE_RECEIVED_INITIATOR_KEY); // Success state
        if (!derivationSuccess) {
            return { action: 'RESET', reason: 'Key derivation failed.' };
        }
        // --- End Key Derivation ---

        // Key derivation successful. Request sending Type 5 (Challenge).
        return { action: 'SEND_TYPE_5' };
    }


    /**
     * Handles KEY_CONFIRMATION_CHALLENGE (Type 5) message from the peer (Responder -> Initiator).
     * If the session key is already derived, decrypts the challenge.
     * If the key is not yet derived (derivation in progress), buffers the raw challenge data.
     * @param {object} payload - Expected: { iv: string (Base64), encryptedChallenge: string (Base64) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'SEND_TYPE_6', challengeData: ArrayBuffer } or 'NONE' on success, { action: 'RESET', reason: string } on failure.
     */
    async _handleKeyConfirmationChallenge(payload, manager) {
        // This is received by the Initiator
        const ivBase64 = payload.iv;
        const encryptedChallengeBase64 = payload.encryptedChallenge;
        // Validate payload.
        if (!ivBase64 || !encryptedChallengeBase64) { return { action: 'RESET', reason: 'Invalid Type 5 received (missing data).' }; }

        // Check if key derivation is complete or still in progress.
        if (!this.cryptoModule.derivedSessionKey) {
            // Check if derivation has started (promise exists)
            if (this.keyDerivationPromise) {
                // Key derivation is in progress. Buffer the challenge.
                console.warn(`Session [${this.peerId}] Received Type 5 challenge while key derivation is in progress. Buffering challenge.`);
                try {
                    this.challengeReceived = {
                        isBuffered: true, // Flag indicating this is raw data
                        iv: this.cryptoModule.base64ToArrayBuffer(ivBase64),
                        encryptedData: this.cryptoModule.base64ToArrayBuffer(encryptedChallengeBase64)
                    };
                    // State remains DERIVING_KEY_INITIATOR
                    return { action: 'NONE' }; // Wait for derivation to complete
                } catch (e) {
                     console.error("Error buffering challenge data:", e);
                     return { action: 'RESET', reason: 'Failed to buffer challenge data.' };
                }
            } else {
                // Type 5 received but derivation hasn't even started (shouldn't happen after Type 2).
                console.error(`Session [${this.peerId}] Received Type 5 but key derivation not started! State: ${this.state}`);
                return { action: 'RESET', reason: 'Internal error: Challenge received before key derivation initiated.' };
            }
        }

        // --- Key is derived, proceed with decryption ---
        console.log(`Session [${this.peerId}] Session key is derived. Processing received challenge (Type 5).`);
        try {
            const iv = this.cryptoModule.base64ToArrayBuffer(ivBase64);
            const encryptedChallengeBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedChallengeBase64);

            // Decrypt using the derived AES session key.
            const decryptedChallengeBuffer = await this.cryptoModule.decryptAES(encryptedChallengeBuffer, new Uint8Array(iv));
            if (!decryptedChallengeBuffer) { return { action: 'RESET', reason: 'Failed to decrypt challenge (security check failed).' }; }

            // Store the decrypted challenge data (as ArrayBuffer).
            this.challengeReceived = decryptedChallengeBuffer;
            // Log decrypted text for debugging (remove in production if sensitive).
            const challengeText = this.cryptoModule.decodeText(decryptedChallengeBuffer);
            console.log(`Challenge decrypted successfully. Received text (for debug): "${challengeText}"`);

            // Update state and request SessionManager to send back the encrypted response (Type 6).
            this.updateState(manager.STATE_RECEIVED_CHALLENGE);
            return { action: 'SEND_TYPE_6', challengeData: this.challengeReceived };
        } catch (error) {
            console.error(`Session [${this.peerId}] Error handling Type 5:`, error);
            return { action: 'RESET', reason: 'Error processing challenge.' };
        }
    }


    /**
     * Handles KEY_CONFIRMATION_RESPONSE (Type 6) message from the peer (Initiator -> Responder).
     * Decrypts the response using the derived session key and verifies it matches the original challenge sent.
     * @param {object} payload - Expected: { iv: string (Base64), encryptedResponse: string (Base64) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'SEND_TYPE_7' } on success, { action: 'RESET', reason: string } on failure/mismatch.
     */
    async _handleKeyConfirmationResponse(payload, manager) {
        // This is received by the Responder
        const ivBase64 = payload.iv;
        const encryptedResponseBase64 = payload.encryptedResponse;
        // Validate payload and ensure we actually sent a challenge.
        if (!ivBase64 || !encryptedResponseBase64) { return { action: 'RESET', reason: 'Invalid Type 6 received (missing data).' }; }
        if (!this.challengeSent) { return { action: 'RESET', reason: 'Received unexpected Type 6.' }; }
        // Ensure session key is derived.
        if (!this.cryptoModule.derivedSessionKey) {
             // Should not happen if Type 5 was sent correctly after key derivation.
             console.error(`Session [${this.peerId}] Received Type 6 but session key not derived! State: ${this.state}`);
             return { action: 'RESET', reason: 'Internal error: Session key missing when receiving challenge response.' };
        }

        try {
            const iv = this.cryptoModule.base64ToArrayBuffer(ivBase64);
            const encryptedResponseBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedResponseBase64);

            // Decrypt using the derived AES session key.
            const decryptedResponseBuffer = await this.cryptoModule.decryptAES(encryptedResponseBuffer, new Uint8Array(iv));
            if (!decryptedResponseBuffer) { return { action: 'RESET', reason: 'Failed to decrypt challenge response (security check failed).' }; }

            // --- Verify Challenge Match ---
            let match = decryptedResponseBuffer.byteLength === this.challengeSent.byteLength;
            if (match) {
                const view1 = new Uint8Array(this.challengeSent);
                const view2 = new Uint8Array(decryptedResponseBuffer);
                for (let i = 0; i < view1.length; i++) {
                    if (view1[i] !== view2[i]) {
                        match = false;
                        break;
                    }
                }
            }
            if (!match) { return { action: 'RESET', reason: 'Challenge response verification failed!' }; }
            // --- Verification Success ---
            console.log("Challenge response verified successfully!");
            this.challengeSent = null; // Clear the sent challenge.
            // Update state and request SessionManager send the final confirmation (Type 7).
            this.updateState(manager.STATE_HANDSHAKE_COMPLETE); // Responder considers handshake complete here
            return { action: 'SEND_TYPE_7' };
        } catch (error) {
             console.error(`Session [${this.peerId}] Error handling Type 6:`, error);
             return { action: 'RESET', reason: 'Error processing challenge response.' };
        }
    }

    /**
     * Handles SESSION_ESTABLISHED (Type 7) message from the peer (Responder -> Initiator).
     * Marks the session as active from the Initiator's perspective.
     * @param {object} payload - Expected: { message: string } (optional confirmation message)
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {object} Action object: { action: 'SESSION_ACTIVE' }
     */
    _handleSessionEstablished(payload, manager) {
        // This is received by the Initiator
        // Ensure we were expecting this state transition (after sending Type 6)
        if (this.state !== manager.STATE_AWAITING_FINAL_CONFIRMATION && this.state !== manager.STATE_RECEIVED_CHALLENGE) {
             console.warn(`Session [${this.peerId}] Received Type 7 in unexpected state ${this.state}. Proceeding to ACTIVE.`);
        }
        // Update state to active.
        this.updateState(manager.STATE_ACTIVE_SESSION);
        this.challengeReceived = null; // Clear received challenge data.
        // Request SessionManager to update UI for the active session.
        return { action: 'SESSION_ACTIVE' };
    }

    /**
     * Handles ENCRYPTED_CHAT_MESSAGE (Type 8) message from the peer.
     * Decrypts the message data using the derived AES session key.
     * @param {object} payload - Expected: { iv: string (Base64), data: string (Base64) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'DISPLAY_MESSAGE', ... } on success, { action: 'DISPLAY_SYSTEM_MESSAGE', ... } or { action: 'NONE' } on failure/wrong state.
     */
    async _handleEncryptedMessage(payload, manager) {
        const ivBase64 = payload.iv;
        const encryptedDataBase64 = payload.data;

        // Ignore messages if the session isn't fully active.
        if (this.state !== manager.STATE_ACTIVE_SESSION) {
             console.warn(`Session [${this.peerId}] Received Type 8 message in non-active state (${this.state}). Ignoring.`);
             return { action: 'NONE' };
        }
        // Validate payload structure.
        if (!ivBase64 || !encryptedDataBase64) {
            return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Received malformed message from ${this.peerId}.` };
        }
        // Ensure session key is derived.
        if (!this.cryptoModule.derivedSessionKey) {
             console.error(`Session [${this.peerId}] Received Type 8 message but session key is not derived! State: ${this.state}`);
             return { action: 'RESET', reason: 'Internal error: Session key missing for active session.' };
        }

        try {
            // 1. Decode the IV and encrypted message data from Base64.
            const iv = this.cryptoModule.base64ToArrayBuffer(ivBase64);
            const encryptedDataBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedDataBase64);

            // 2. Decrypt the message data using the derived AES session key and IV.
            const decryptedDataBuffer = await this.cryptoModule.decryptAES(encryptedDataBuffer, new Uint8Array(iv));
            if (!decryptedDataBuffer) { return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Failed to decrypt message from ${this.peerId}.` }; }

            // 3. Decode the decrypted buffer (UTF-8) into a string.
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

    // --- Typing Indicator Handlers (Remain the same) ---
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
