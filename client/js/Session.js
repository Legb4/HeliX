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

        // --- Payload Size Limits (for incoming Base64 strings) ---
        // Define maximum acceptable lengths for various Base64 encoded fields received from the network.
        // These are safety limits to prevent client-side DoS or excessive memory use from malicious payloads.
        this.MAX_PUBLIC_KEY_LENGTH = 512; // Generous limit for Base64 SPKI P-256 key (~120 bytes raw -> ~160 Base64)
        this.MAX_IV_LENGTH = 32;          // Generous limit for Base64 IV (12 bytes raw -> 16 Base64)
        this.MAX_ENCRYPTED_DATA_LENGTH = 1024 * 128; // Limit for Base64 encrypted data (challenge, response, message) - 128KB Base64 (~96KB raw)
        // ---------------------------------------------------------

        // Log session creation (not wrapped in DEBUG as it's fundamental)
        console.log(`New session created for peer: ${this.peerId}, initial state: ${this.state}`);
    }

    /**
     * Updates the state of the session.
     * @param {string} newState - The new state identifier.
     */
    updateState(newState) {
        // Avoid logging redundant state updates if the state isn't actually changing.
        if (this.state !== newState) {
            // Log state transitions only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`Session [${this.peerId}] State transition: ${this.state} -> ${newState}`);
            }
            this.state = newState;
        } else {
            // Log attempted update to same state only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`Session [${this.peerId}] State update attempted to same state: ${newState}`);
            }
        }
    }


    /**
     * Resets the session state, clearing keys, challenges, messages, and timeouts.
     * Called when a session ends, is denied, times out, or encounters a critical error.
     */
    resetState() {
         // Log reset attempt only if DEBUG is enabled.
         if (config.DEBUG) {
             console.log(`Resetting state for session [${this.peerId}]`);
         }
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
            // Log key storage only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`Session [${this.peerId}] Stored peer public ECDH key.`);
            }
            return true;
        } else {
            // Always log this error.
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
        // No console log here by default, UIController handles display.
    }

    // --- Key Derivation Helper ---
    /**
     * Internal helper to perform the ECDH secret derivation and session key derivation.
     * Stores the promise for this operation in `this.keyDerivationPromise`.
     * Updates state upon successful completion.
     * @param {string} successState - The state to transition to upon successful derivation.
     * @returns {Promise<boolean>} True if derivation succeeded, false otherwise.
     * @throws {Error} Throws specific errors on failure for the caller to handle.
     */
    async _deriveKeysAndHandleBufferedChallenge(successState) {
        if (!this.cryptoModule.privateKey || !this.peerPublicKey) {
            // Always log this error.
            console.error(`Session [${this.peerId}] Cannot derive keys: Own or peer key missing.`);
            // Throw error instead of returning false, caller will catch and create action object.
            throw new Error('Key derivation pre-check failed: Own or peer key missing.');
        }

        // Store the promise immediately.
        this.keyDerivationPromise = (async () => {
            // Log derivation steps only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Session [${this.peerId}] Deriving shared secret...`);
            const sharedSecretBits = await this.cryptoModule.deriveSharedSecret(this.peerPublicKey);
            // Throw specific error if secret derivation fails
            if (!sharedSecretBits) throw new Error('Failed to derive shared secret.');

            if (config.DEBUG) console.log(`Session [${this.peerId}] Deriving session key...`);
            const keyDerived = await this.cryptoModule.deriveSessionKey(sharedSecretBits);
            // Throw specific error if key derivation fails
            if (!keyDerived) throw new Error('Failed to derive session key.');

            if (config.DEBUG) console.log(`Session [${this.peerId}] Key derivation successful.`);
            return true; // Indicate success
        })();

        try {
            await this.keyDerivationPromise; // Wait for derivation to complete
            this.updateState(successState); // Update state only after successful derivation

            // --- Check for and process buffered challenge ---
            if (this.challengeReceived && this.challengeReceived.isBuffered) {
                if (config.DEBUG) console.log(`Session [${this.peerId}] Processing buffered challenge after key derivation.`);
                // Note: Size validation for buffered challenge data happened when it was received in _handleKeyConfirmationChallenge
                const decryptedBuffer = await this.cryptoModule.decryptAES(
                    this.challengeReceived.encryptedData,
                    new Uint8Array(this.challengeReceived.iv)
                );
                // Throw specific error if challenge decryption fails
                if (!decryptedBuffer) {
                    throw new Error('Failed to decrypt buffered challenge.');
                }
                this.challengeReceived = decryptedBuffer; // Replace buffer with decrypted data
                if (config.DEBUG) console.log(`Session [${this.peerId}] Buffered challenge decrypted successfully.`);
                // If we are the initiator, we now need to send Type 6
                // The caller (_handleAccept or _handlePublicKeyResponse) needs to handle this.
                // The caller will check challengeReceived status after awaiting this promise.
            }
            return true; // Overall success
        } catch (error) {
            // Catch errors from derivation or buffered challenge processing.
            // Always log the error.
            console.error(`Session [${this.peerId}] Key derivation or buffered challenge processing failed:`, error);
            this.keyDerivationPromise = null; // Clear promise on failure
            // Re-throw the error so the caller can create the appropriate RESET action with reason.
            throw error;
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
        // Log processing attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Session [${this.peerId}] Processing message type ${type} in state ${this.state}`);
        }

        // Route based on message type.
        try {
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
                    // Always log unhandled message types as a warning.
                    console.warn(`Session [${this.peerId}] Received unhandled message type in processMessage: ${type}`);
                    return { action: 'NONE' }; // No action needed for unknown types.
            }
        } catch (error) {
            // Catch unexpected errors within the handler functions themselves.
            // Always log these errors.
            console.error(`Session [${this.peerId}] Unexpected error processing message type ${type}:`, error);
            // Return a generic RESET action with the error message.
            return { action: 'RESET', reason: `Internal error processing message: ${error.message}` };
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
             // Always log unexpected state warnings.
             console.warn(`Session [${this.peerId}] Received unexpected Type 2 in state ${this.state}. Ignoring.`);
             return { action: 'NONE' };
        }
        const publicKeyBase64 = payload.publicKey;

        // --- Payload Validation ---
        if (!publicKeyBase64 || typeof publicKeyBase64 !== 'string') {
            return { action: 'RESET', reason: 'Handshake Error: Invalid acceptance message received (missing or invalid key).' };
        }
        // Check key length against defined limit.
        if (publicKeyBase64.length > this.MAX_PUBLIC_KEY_LENGTH) {
            return { action: 'RESET', reason: `Handshake Error: Received excessively large public key (>${this.MAX_PUBLIC_KEY_LENGTH} chars).` };
        }
        // --- End Validation ---

        try {
            // Import the key.
            const importedKey = await this.cryptoModule.importPublicKeyBase64(publicKeyBase64);
            if (!importedKey) { throw new Error('Failed to import peer public key.'); } // Throw on failure
            // Store the imported key.
            if (!this.setPeerPublicKey(importedKey)) { throw new Error('Failed to store peer public key.'); } // Throw on failure

            // --- Start Key Derivation (Initiator) ---
            this.updateState(manager.STATE_DERIVING_KEY_INITIATOR); // New state
            // Await the derivation helper, which now throws on error.
            await this._deriveKeysAndHandleBufferedChallenge(manager.STATE_KEY_DERIVED_INITIATOR);
            // --- End Key Derivation ---

            // Key derivation successful. Request sending Type 4.
            return { action: 'SEND_TYPE_4' };

        } catch (error) {
            // Catch errors from key import, storage, or derivation.
            // Always log these errors.
            console.error(`Session [${this.peerId}] Error handling Type 2 (Accept):`, error);
            // Return RESET action with a more specific reason.
            return { action: 'RESET', reason: `Handshake Error: ${error.message}` };
        }
    }

    /**
     * Handles SESSION_DENY (Type 3) message from the peer.
     * @param {object} payload - Expected: {} (no specific data needed)
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {object} Action object: { action: 'SHOW_INFO', message: string, showRetry: boolean }
     */
    _handleDeny(payload, manager) {
        const message = `Session request denied by ${this.peerId}.`;
        // Log denial (not wrapped in DEBUG as it's a significant event).
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
             // Always log unexpected state warnings.
             console.warn(`Session [${this.peerId}] Received unexpected Type 4 in state ${this.state}. Ignoring.`);
             return { action: 'NONE' };
        }
        const publicKeyBase64 = payload.publicKey;

        // --- Payload Validation ---
        if (!publicKeyBase64 || typeof publicKeyBase64 !== 'string') {
            return { action: 'RESET', reason: 'Handshake Error: Invalid key response received (missing or invalid key).' };
        }
        // Check key length against defined limit.
        if (publicKeyBase64.length > this.MAX_PUBLIC_KEY_LENGTH) {
            return { action: 'RESET', reason: `Handshake Error: Received excessively large public key (>${this.MAX_PUBLIC_KEY_LENGTH} chars).` };
        }
        // --- End Validation ---

        try {
            // Import the key.
            const importedKey = await this.cryptoModule.importPublicKeyBase64(publicKeyBase64);
            if (!importedKey) { throw new Error('Failed to import peer public key.'); } // Throw on failure
            // Store the imported key.
            if (!this.setPeerPublicKey(importedKey)) { throw new Error('Failed to store peer public key.'); } // Throw on failure

            // --- Start Key Derivation (Responder) ---
            this.updateState(manager.STATE_DERIVING_KEY_RESPONDER); // New state
            // Await the derivation helper, which now throws on error.
            await this._deriveKeysAndHandleBufferedChallenge(manager.STATE_RECEIVED_INITIATOR_KEY);
            // --- End Key Derivation ---

            // Key derivation successful. Request sending Type 5 (Challenge).
            return { action: 'SEND_TYPE_5' };

        } catch (error) {
            // Catch errors from key import, storage, or derivation.
            // Always log these errors.
            console.error(`Session [${this.peerId}] Error handling Type 4 (Key Response):`, error);
            // Return RESET action with a more specific reason.
            return { action: 'RESET', reason: `Handshake Error: ${error.message}` };
        }
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

        // --- Payload Validation ---
        if (!ivBase64 || typeof ivBase64 !== 'string' || !encryptedChallengeBase64 || typeof encryptedChallengeBase64 !== 'string') {
            return { action: 'RESET', reason: 'Handshake Error: Invalid challenge message received (missing or invalid data).' };
        }
        // Check lengths against defined limits.
        if (ivBase64.length > this.MAX_IV_LENGTH) {
            return { action: 'RESET', reason: `Handshake Error: Received excessively large IV (>${this.MAX_IV_LENGTH} chars).` };
        }
        if (encryptedChallengeBase64.length > this.MAX_ENCRYPTED_DATA_LENGTH) {
            return { action: 'RESET', reason: `Handshake Error: Received excessively large challenge data (>${this.MAX_ENCRYPTED_DATA_LENGTH} chars).` };
        }
        // --- End Validation ---

        // Check if key derivation is complete or still in progress.
        if (!this.cryptoModule.derivedSessionKey) {
            // Check if derivation has started (promise exists)
            if (this.keyDerivationPromise) {
                // Key derivation is in progress. Buffer the challenge.
                // Always log this warning.
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
                     // Always log this error.
                     console.error("Error buffering challenge data:", e);
                     // Return RESET action with a specific reason.
                     return { action: 'RESET', reason: 'Handshake Error: Failed to buffer challenge data.' };
                }
            } else {
                // Type 5 received but derivation hasn't even started (shouldn't happen after Type 2).
                // Always log this critical error.
                console.error(`Session [${this.peerId}] Received Type 5 but key derivation not started! State: ${this.state}`);
                return { action: 'RESET', reason: 'Internal Error: Challenge received before key derivation initiated.' };
            }
        }

        // --- Key is derived, proceed with decryption ---
        if (config.DEBUG) console.log(`Session [${this.peerId}] Session key is derived. Processing received challenge (Type 5).`);
        try {
            const iv = this.cryptoModule.base64ToArrayBuffer(ivBase64);
            const encryptedChallengeBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedChallengeBase64);

            // Decrypt using the derived AES session key.
            const decryptedChallengeBuffer = await this.cryptoModule.decryptAES(encryptedChallengeBuffer, new Uint8Array(iv));
            // Throw specific error if decryption fails
            if (!decryptedChallengeBuffer) { throw new Error('Failed to decrypt challenge (security check failed).'); }

            // Store the decrypted challenge data (as ArrayBuffer).
            this.challengeReceived = decryptedChallengeBuffer;
            // Log decrypted text only if DEBUG is enabled.
            if (config.DEBUG) {
                const challengeText = this.cryptoModule.decodeText(decryptedChallengeBuffer);
                console.log(`Challenge decrypted successfully. Received text (for debug): "${challengeText}"`);
            }

            // Update state and request SessionManager to send back the encrypted response (Type 6).
            this.updateState(manager.STATE_RECEIVED_CHALLENGE);
            return { action: 'SEND_TYPE_6', challengeData: this.challengeReceived };
        } catch (error) {
            // Always log errors during challenge handling.
            console.error(`Session [${this.peerId}] Error handling Type 5 (Challenge):`, error);
            // Return RESET action with a specific reason.
            return { action: 'RESET', reason: `Handshake Error: ${error.message}` };
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

        // --- Payload Validation ---
        if (!ivBase64 || typeof ivBase64 !== 'string' || !encryptedResponseBase64 || typeof encryptedResponseBase64 !== 'string') {
            return { action: 'RESET', reason: 'Handshake Error: Invalid challenge response received (missing or invalid data).' };
        }
        // Check lengths against defined limits.
        if (ivBase64.length > this.MAX_IV_LENGTH) {
            return { action: 'RESET', reason: `Handshake Error: Received excessively large IV (>${this.MAX_IV_LENGTH} chars).` };
        }
        if (encryptedResponseBase64.length > this.MAX_ENCRYPTED_DATA_LENGTH) {
            return { action: 'RESET', reason: `Handshake Error: Received excessively large response data (>${this.MAX_ENCRYPTED_DATA_LENGTH} chars).` };
        }
        // --- End Validation ---

        // Ensure we actually sent a challenge.
        if (!this.challengeSent) { return { action: 'RESET', reason: 'Handshake Error: Received unexpected challenge response.' }; }
        // Ensure session key is derived.
        if (!this.cryptoModule.derivedSessionKey) {
             // Always log this critical error.
             console.error(`Session [${this.peerId}] Received Type 6 but session key not derived! State: ${this.state}`);
             return { action: 'RESET', reason: 'Internal Error: Session key missing when receiving challenge response.' };
        }

        try {
            const iv = this.cryptoModule.base64ToArrayBuffer(ivBase64);
            const encryptedResponseBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedResponseBase64);

            // Decrypt using the derived AES session key.
            const decryptedResponseBuffer = await this.cryptoModule.decryptAES(encryptedResponseBuffer, new Uint8Array(iv));
            // Throw specific error if decryption fails
            if (!decryptedResponseBuffer) { throw new Error('Failed to decrypt challenge response (security check failed).'); }

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
            // Throw specific error if verification fails
            if (!match) { throw new Error('Challenge response verification failed!'); }
            // --- Verification Success ---
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) console.log("Challenge response verified successfully!");
            this.challengeSent = null; // Clear the sent challenge.
            // Update state and request SessionManager send the final confirmation (Type 7).
            this.updateState(manager.STATE_HANDSHAKE_COMPLETE); // Responder considers handshake complete here
            return { action: 'SEND_TYPE_7' };
        } catch (error) {
             // Always log errors during response handling.
             console.error(`Session [${this.peerId}] Error handling Type 6 (Response):`, error);
             // Return RESET action with a specific reason.
             return { action: 'RESET', reason: `Handshake Error: ${error.message}` };
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
             // Always log unexpected state warnings.
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
             // Always log this warning.
             console.warn(`Session [${this.peerId}] Received Type 8 message in non-active state (${this.state}). Ignoring.`);
             return { action: 'NONE' };
        }

        // --- Payload Validation ---
        if (!ivBase64 || typeof ivBase64 !== 'string' || !encryptedDataBase64 || typeof encryptedDataBase64 !== 'string') {
            // Return action to display system message about malformed data
            return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Received malformed message from ${this.peerId}.` };
        }
        // Check lengths against defined limits.
        if (ivBase64.length > this.MAX_IV_LENGTH) {
            return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Received message with excessively large IV from ${this.peerId}.` };
        }
        if (encryptedDataBase64.length > this.MAX_ENCRYPTED_DATA_LENGTH) {
            return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Received excessively large message data from ${this.peerId}.` };
        }
        // --- End Validation ---

        // Ensure session key is derived.
        if (!this.cryptoModule.derivedSessionKey) {
             // Always log this critical error.
             console.error(`Session [${this.peerId}] Received Type 8 message but session key is not derived! State: ${this.state}`);
             // Return RESET action for critical key error
             return { action: 'RESET', reason: 'Internal Error: Session key missing for active session.' };
        }

        try {
            // 1. Decode the IV and encrypted message data from Base64.
            const iv = this.cryptoModule.base64ToArrayBuffer(ivBase64);
            const encryptedDataBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedDataBase64);

            // 2. Decrypt the message data using the derived AES session key and IV.
            const decryptedDataBuffer = await this.cryptoModule.decryptAES(encryptedDataBuffer, new Uint8Array(iv));
            // If decryption fails, return action to display system message
            if (!decryptedDataBuffer) {
                return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Failed to decrypt message from ${this.peerId}. (Possible key mismatch or data corruption)` };
            }

            // 3. Decode the decrypted buffer (UTF-8) into a string.
            const messageText = this.cryptoModule.decodeText(decryptedDataBuffer);

            // Log received message only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`%c[${this.peerId}]: ${messageText}`, "color: purple;"); // Style console output
            }
            this.addMessageToHistory(this.peerId, messageText, 'peer');

            // Request SessionManager display the message.
            return { action: 'DISPLAY_MESSAGE', sender: this.peerId, text: messageText, msgType: 'peer' };

        } catch (error) {
            // Always log errors during message handling.
            console.error(`Error handling encrypted message from ${this.peerId}:`, error);
            // Return action to display system message for other errors during processing
            return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Error processing message from ${this.peerId}: ${error.message}` };
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
        // Log session end (not wrapped in DEBUG as it's significant).
        console.log(message);
        // Request SessionManager reset this session and notify the user.
        // notifyUser=true ensures the info pane is shown.
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
            // Always log this warning.
            console.warn(`Session [${this.peerId}] Ignoring Type 10 in state ${this.state}`);
            return { action: 'NONE' };
        }
        // Log typing start only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${this.peerId}] Peer started typing.`);
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
            // Always log this warning.
            console.warn(`Session [${this.peerId}] Ignoring Type 11 in state ${this.state}`);
            return { action: 'NONE' };
        }
        // Log typing stop only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${this.peerId}] Peer stopped typing.`);
        this.peerIsTyping = false; // Mark peer as not typing.
        // Request SessionManager hide the typing indicator (it will clear the timeout).
        return { action: 'HIDE_TYPING' };
    }
}
