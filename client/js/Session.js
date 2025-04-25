// client/js/Session.js

/**
 * Represents a single chat session with a specific peer.
 * Manages the state of the session (e.g., initiating, active, denied),
 * holds cryptographic keys relevant to this session (via its own CryptoModule instance
 * implementing ECDH for PFS), stores message history, handles timeouts,
 * processes incoming messages for this peer, and manages file transfer states.
 */
class Session {
    /**
     * Creates a new Session instance.
     * @param {string} peerId - The unique identifier of the peer for this session.
     * @param {string} initialState - The initial state of the session (e.g., 'INITIATING_SESSION', 'REQUEST_RECEIVED').
     * @param {CryptoModule} cryptoModuleInstance - A dedicated instance of CryptoModule for this session's keys.
     * @throws {Error} If required arguments are missing.
     */
    constructor(peerId, initialState, cryptoModuleInstance) {
        // Validate required constructor arguments.
        if (!peerId || !initialState || !cryptoModuleInstance) {
            throw new Error("Session requires peerId, initialState, and cryptoModuleInstance");
        }

        // --- Session Properties ---
        this.peerId = peerId; // Identifier of the remote peer.
        this.state = initialState; // Current state of the session handshake/chat (e.g., 'INITIATING_SESSION', 'ACTIVE_SESSION').
        this.cryptoModule = cryptoModuleInstance; // Dedicated crypto handler instance for this session's keys (ECDH + AES).
        this.peerPublicKey = null; // Stores the imported CryptoKey object of the peer's public ECDH key.
        // Note: The derived AES session key is stored within the cryptoModuleInstance (cryptoModule.derivedSessionKey).
        this.challengeSent = null; // Stores the ArrayBuffer of the challenge sent to the peer during handshake verification.
        // challengeReceived stores the state of the challenge received from the peer:
        // - null: Challenge not yet received or processed.
        // - { isBuffered: true, iv: ArrayBuffer, encryptedData: ArrayBuffer }: Raw challenge data received before key derivation completed.
        // - ArrayBuffer: Decrypted challenge data after successful processing.
        this.challengeReceived = null;
        // keyDerivationPromise: Stores the promise returned by the key derivation process (_deriveKeysAndHandleBufferedChallenge).
        // Used to ensure challenge decryption only happens after derivation completes.
        this.keyDerivationPromise = null;
        // Array to store message history objects for this session: { sender: string, text: string, type: string }.
        // Type can be 'peer', 'own', 'system', 'me-action', or potentially 'file' (though file messages aren't stored here currently).
        this.messages = [];
        this.handshakeTimeoutId = null; // Stores the ID of the handshake timeout timer (setTimeout).
        this.requestTimeoutId = null; // Stores the ID of the initial request timeout timer (setTimeout).

        // --- Typing Indicator State ---
        this.peerIsTyping = false; // Flag indicating if the peer is currently marked as typing.
        this.typingIndicatorTimeoutId = null; // Timeout ID for automatically hiding the peer's typing indicator.
        // ---------------------------------

        // --- File Transfer State ---
        // Map storing the state of active file transfers for this session, keyed by transferId.
        // Example state object: { file: File, status: string, progress: number, fileName: string, fileSize: number, fileType: string, isSender: boolean, senderId?: string, blobUrl?: string }
        this.transferStates = new Map();
        // --------------------------------

        // --- Payload Size Limits (for incoming Base64 strings) ---
        // Define maximum acceptable lengths for various Base64 encoded fields received from the network.
        // These act as basic sanity checks to prevent client-side DoS or excessive memory use from malicious payloads.
        this.MAX_PUBLIC_KEY_LENGTH = 512; // Generous limit for Base64 SPKI P-256 key (~160 Base64 chars).
        this.MAX_IV_LENGTH = 32;          // Generous limit for Base64 IV (16 Base64 chars).
        this.MAX_ENCRYPTED_DATA_LENGTH = 1024 * 128; // Limit for Base64 encrypted data (challenge, response, message) - 128KB Base64 (~96KB raw).
        this.MAX_FILENAME_LENGTH = 255;   // Limit for filename string length.
        this.MAX_FILETYPE_LENGTH = 100;   // Limit for file type (MIME type) string length.
        // Note: Chunk data size is implicitly limited by WebSocket message size limit on server and client.
        // ---------------------------------------------------------

        // Log session creation confirmation.
        console.log(`New session created for peer: ${this.peerId}, initial state: ${this.state}`);
    }

    /**
     * Updates the state of the session and logs the transition if DEBUG is enabled.
     * Avoids logging if the state is not actually changing.
     * @param {string} newState - The new state identifier (e.g., 'ACTIVE_SESSION').
     */
    updateState(newState) {
        // Only log and update if the state is actually changing.
        if (this.state !== newState) {
            // Log state transitions only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`Session [${this.peerId}] State transition: ${this.state} -> ${newState}`);
            }
            this.state = newState;
        } else {
            // Log attempted update to the same state only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log(`Session [${this.peerId}] State update attempted to same state: ${newState}`);
            }
        }
    }


    /**
     * Resets the session state completely.
     * Clears cryptographic keys, challenges, message history, timeouts, typing status,
     * and file transfer states associated with this session.
     * Called when a session ends, is denied, times out, or encounters a critical error.
     */
    resetState() {
         // Log reset attempt only if DEBUG is enabled.
         if (config.DEBUG) {
             console.log(`Resetting state for session [${this.peerId}]`);
         }
         // Clear any pending timers to prevent them from firing after reset.
         if (this.handshakeTimeoutId) { clearTimeout(this.handshakeTimeoutId); this.handshakeTimeoutId = null; }
         if (this.requestTimeoutId) { clearTimeout(this.requestTimeoutId); this.requestTimeoutId = null; }
         if (this.typingIndicatorTimeoutId) { clearTimeout(this.typingIndicatorTimeoutId); this.typingIndicatorTimeoutId = null; }

         // Clear session-specific cryptographic materials and handshake state.
         this.challengeSent = null;
         this.challengeReceived = null; // Clear any buffered or decrypted challenge.
         this.peerPublicKey = null;
         this.keyDerivationPromise = null; // Clear the reference to the derivation promise.
         this.cryptoModule.wipeKeys(); // Tell the dedicated crypto module to wipe its ECDH keys and derived AES key.
         this.messages = []; // Clear message history array.
         this.peerIsTyping = false; // Reset peer typing status.

         // Clear File Transfer States.
         // Note: Actual cleanup (DB, Object URLs) is handled by SessionManager calling resetSession,
         // which iterates through this map before clearing it.
         this.transferStates.clear();
    }

    /**
     * Stores the imported peer's public ECDH key (CryptoKey object) in the session.
     * @param {CryptoKey} keyObject - The peer's public CryptoKey object.
     * @returns {boolean} True if the key was stored successfully, false otherwise (if keyObject is invalid).
     */
    setPeerPublicKey(keyObject) {
        // Basic validation: ensure it's a non-null object (assumed to be CryptoKey).
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
     * Adds a message object to the session's message history array.
     * @param {string} sender - The identifier of the sender ('System', own ID, or peer ID).
     * @param {string} text - The message content or action text.
     * @param {string} type - The message type ('system', 'own', 'peer', 'me-action').
     */
    addMessageToHistory(sender, text, type) {
        // Log history add only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${this.peerId}] Adding to history: {sender: ${sender}, type: ${type}, text: ${text.substring(0, 50)}...}`);
        this.messages.push({ sender, text, type });
        // The UIController is responsible for actually displaying the message from history when needed.
    }

    // --- File Transfer State Management ---

    /**
     * Adds or updates the state data for a specific file transfer within this session.
     * Merges new data with existing state if the transferId already exists.
     * @param {string} transferId - The unique ID of the transfer.
     * @param {object} stateData - An object containing the state properties to store or update (e.g., { status: 'uploading', progress: 10 }).
     */
    addTransferState(transferId, stateData) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${this.peerId}] Adding/Updating transfer state for ${transferId}:`, stateData);
        // Get existing state or an empty object if it's new.
        const existingState = this.transferStates.get(transferId) || {};
        // Merge existing state with new data and store it back in the map.
        this.transferStates.set(transferId, { ...existingState, ...stateData });
    }

    /**
     * Retrieves the state data object for a specific file transfer.
     * @param {string} transferId - The unique ID of the transfer.
     * @returns {object | undefined} The state object, or undefined if the transferId is not found in this session.
     */
    getTransferState(transferId) {
        return this.transferStates.get(transferId);
    }

    /**
     * Removes the state data for a specific file transfer from this session's map.
     * @param {string} transferId - The unique ID of the transfer to remove.
     */
    removeTransferState(transferId) {
        // Log action only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${this.peerId}] Removing transfer state for ${transferId}`);
        this.transferStates.delete(transferId);
    }
    // -----------------------------------------

    // --- Key Derivation Helper ---
    /**
     * Internal helper function to perform the ECDH shared secret derivation and subsequent
     * HKDF session key derivation. Stores the promise for this asynchronous operation
     * in `this.keyDerivationPromise`. After successful derivation, it checks for and processes
     * any buffered challenge data received earlier. Updates the session state upon success.
     * Throws specific errors on failure for the caller (processMessage) to handle.
     *
     * @param {string} successState - The state identifier to transition to upon successful derivation.
     * @returns {Promise<boolean>} Resolves to true if derivation and buffered challenge processing succeeded.
     * @throws {Error} Throws specific errors on failure (missing keys, derivation failure, challenge decryption failure).
     * @private
     */
    async _deriveKeysAndHandleBufferedChallenge(successState) {
        // Pre-check: Ensure necessary keys are available.
        if (!this.cryptoModule.privateKey || !this.peerPublicKey) {
            // Always log this error.
            console.error(`Session [${this.peerId}] Cannot derive keys: Own private key or peer public key is missing.`);
            throw new Error('Key derivation pre-check failed: Own or peer key missing.');
        }

        // Store the promise for the derivation process immediately.
        // This allows checking if derivation is in progress.
        this.keyDerivationPromise = (async () => {
            // Log derivation steps only if DEBUG is enabled.
            if (config.DEBUG) console.log(`Session [${this.peerId}] Deriving shared secret...`);
            const sharedSecretBits = await this.cryptoModule.deriveSharedSecret(this.peerPublicKey);
            // Throw specific error if secret derivation fails.
            if (!sharedSecretBits) throw new Error('Failed to derive shared secret.');

            if (config.DEBUG) console.log(`Session [${this.peerId}] Deriving session key...`);
            const keyDerived = await this.cryptoModule.deriveSessionKey(sharedSecretBits);
            // Throw specific error if session key derivation fails.
            if (!keyDerived) throw new Error('Failed to derive session key.');

            if (config.DEBUG) console.log(`Session [${this.peerId}] Key derivation successful.`);
            return true; // Indicate success of the derivation part.
        })();

        try {
            // Wait for the asynchronous key derivation process to complete.
            await this.keyDerivationPromise;
            // Update the session state only after successful derivation.
            this.updateState(successState);

            // --- Check for and process buffered challenge ---
            // If a challenge was received before keys were derived, it's stored in challengeReceived.
            if (this.challengeReceived && this.challengeReceived.isBuffered) {
                if (config.DEBUG) console.log(`Session [${this.peerId}] Processing buffered challenge after key derivation.`);
                // Note: Size validation for buffered challenge data happened when it was received.
                // Decrypt the buffered challenge data using the now-available session key.
                const decryptedBuffer = await this.cryptoModule.decryptAES(
                    this.challengeReceived.encryptedData,
                    new Uint8Array(this.challengeReceived.iv)
                );
                // Throw specific error if challenge decryption fails.
                if (!decryptedBuffer) {
                    throw new Error('Failed to decrypt buffered challenge.');
                }
                // Replace the buffered object with the decrypted ArrayBuffer.
                this.challengeReceived = decryptedBuffer;
                if (config.DEBUG) console.log(`Session [${this.peerId}] Buffered challenge decrypted successfully.`);
                // The caller (_handleAccept or _handlePublicKeyResponse) needs to check
                // the status of challengeReceived after awaiting this promise to potentially send Type 6.
            }
            return true; // Overall success (derivation + optional buffered challenge processing).
        } catch (error) {
            // Catch errors from derivation or buffered challenge processing.
            // Always log the error.
            console.error(`Session [${this.peerId}] Key derivation or buffered challenge processing failed:`, error);
            this.keyDerivationPromise = null; // Clear the promise reference on failure.
            // Re-throw the error so the caller (processMessage) can create the appropriate RESET action.
            throw error;
        }
    }


    // --- Central Message Processor for this Session ---

    /**
     * Processes an incoming message payload relevant to this specific session.
     * Routes the message to the appropriate internal handler (_handle...) based on its type.
     * Handles the ECDH key exchange, challenge/response verification, and message decryption logic.
     * NOTE: File transfer messages (Types 12-17) are handled by SessionManager directly.
     *
     * @param {number} type - The message type identifier (e.g., 2 for ACCEPT, 8 for MESSAGE).
     * @param {object} payload - The message payload object.
     * @param {SessionManager} manager - The SessionManager instance (provides access to state constants, etc.).
     * @returns {Promise<object>} An action object for the SessionManager (e.g., { action: 'SEND_TYPE_5' }, { action: 'RESET', reason: '...' }).
     */
    async processMessage(type, payload, manager) {
        // Log processing attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log(`Session [${this.peerId}] Processing message type ${type} in state ${this.state}`);
        }

        // Route based on message type. Use try-catch for unexpected errors within handlers.
        try {
            switch (type) {
                // Handshake & Session Management Messages
                case 2: return await this._handleAccept(payload, manager); // Peer accepted our request (Initiator receives)
                case 3: return this._handleDeny(payload, manager);         // Peer denied our request (Initiator receives)
                case 4: return await this._handlePublicKeyResponse(payload, manager); // Peer sent their public key (Responder receives)
                case 5: return await this._handleKeyConfirmationChallenge(payload, manager); // Peer sent encrypted challenge (Initiator receives)
                case 6: return await this._handleKeyConfirmationResponse(payload, manager); // Peer sent response to our challenge (Responder receives)
                case 7: return this._handleSessionEstablished(payload, manager); // Peer confirmed session establishment (Initiator receives)
                case 9: return this._handleSessionEnd(payload, manager); // Peer initiated session end (Either receives)

                // Data Message
                case 8: return await this._handleEncryptedMessage(payload, manager); // Encrypted chat message or action (Either receives)

                // Typing Indicators
                case 10: return this._handleTypingStart(payload, manager); // Peer started typing (Either receives)
                case 11: return this._handleTypingStop(payload, manager);  // Peer stopped typing (Either receives)

                // File transfer messages (12-17) are handled by SessionManager.processFileTransferMessage
                case 12: // FILE_TRANSFER_REQUEST
                case 13: // FILE_TRANSFER_ACCEPT
                case 14: // FILE_TRANSFER_REJECT
                case 15: // FILE_CHUNK
                case 16: // FILE_TRANSFER_COMPLETE
                case 17: // FILE_TRANSFER_ERROR
                    // This block should ideally not be reached if SessionManager routes correctly.
                    // Always log this warning.
                    console.warn(`Session [${this.peerId}] Received file transfer message type ${type} in Session.processMessage. Should be handled by SessionManager.`);
                    return { action: 'NONE' }; // No action needed here.

                default:
                    // Always log unhandled message types as a warning.
                    console.warn(`Session [${this.peerId}] Received unhandled message type in processMessage: ${type}`);
                    return { action: 'NONE' }; // No action needed for unknown types.
            }
        } catch (error) {
            // Catch unexpected errors within the specific _handle... functions themselves.
            // Always log these errors.
            console.error(`Session [${this.peerId}] Unexpected error processing message type ${type}:`, error);
            // Return a generic RESET action with the error message for SessionManager to handle.
            return { action: 'RESET', reason: `Internal error processing message: ${error.message}` };
        }
    }

    // --- Internal Handlers (return action objects for SessionManager) ---

    /**
     * Handles SESSION_ACCEPT (Type 2) message from the peer (Responder -> Initiator).
     * Imports the peer's public ECDH key, starts key derivation, and requests sending Type 4 (own public key).
     *
     * @param {object} payload - Expected: { publicKey: string (Base64 SPKI) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'SEND_TYPE_4' } on success, { action: 'RESET', reason: string } on failure.
     * @private
     */
    async _handleAccept(payload, manager) {
        // This message is received by the Initiator. Check if the state is appropriate.
        if (this.state !== manager.STATE_INITIATING_SESSION) {
             // Always log unexpected state warnings.
             console.warn(`Session [${this.peerId}] Received unexpected Type 2 (Accept) in state ${this.state}. Ignoring.`);
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
            // Import the peer's public key.
            const importedKey = await this.cryptoModule.importPublicKeyBase64(publicKeyBase64);
            if (!importedKey) { throw new Error('Failed to import peer public key.'); } // Throw specific error on failure.
            // Store the imported key object in the session.
            if (!this.setPeerPublicKey(importedKey)) { throw new Error('Failed to store peer public key.'); } // Throw specific error on failure.

            // --- Start Key Derivation (Initiator) ---
            this.updateState(manager.STATE_DERIVING_KEY_INITIATOR); // Update state to indicate derivation start.
            // Await the derivation helper. It handles state updates on success and throws on error.
            await this._deriveKeysAndHandleBufferedChallenge(manager.STATE_KEY_DERIVED_INITIATOR);
            // --- End Key Derivation ---

            // Key derivation successful. Request SessionManager to send Type 4 (own public key).
            return { action: 'SEND_TYPE_4' };

        } catch (error) {
            // Catch errors from key import, storage, or derivation.
            // Always log these errors.
            console.error(`Session [${this.peerId}] Error handling Type 2 (Accept):`, error);
            // Return RESET action with a specific reason for SessionManager.
            return { action: 'RESET', reason: `Handshake Error: ${error.message}` };
        }
    }

    /**
     * Handles SESSION_DENY (Type 3) message from the peer (Responder -> Initiator).
     * Updates state and requests SessionManager show an info message.
     *
     * @param {object} payload - Expected: {} (no specific data needed)
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {object} Action object: { action: 'SHOW_INFO', message: string, showRetry: boolean }
     * @private
     */
    _handleDeny(payload, manager) {
        const message = `Session request denied by ${this.peerId}.`;
        // Log denial (significant event, not wrapped in DEBUG).
        console.log(message);
        // Update session state to DENIED.
        this.updateState(manager.STATE_DENIED);
        // Request SessionManager to show an info message to the user. No retry option for explicit denial.
        return { action: 'SHOW_INFO', message: message, showRetry: false };
    }

    /**
     * Handles PUBLIC_KEY_RESPONSE (Type 4) message from the peer (Initiator -> Responder).
     * Imports the peer's public ECDH key, starts key derivation, and requests sending Type 5 (challenge).
     *
     * @param {object} payload - Expected: { publicKey: string (Base64 SPKI) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'SEND_TYPE_5' } on success, { action: 'RESET', reason: string } on failure.
     * @private
     */
    async _handlePublicKeyResponse(payload, manager) {
        // This message is received by the Responder. Check if the state is appropriate.
        if (this.state !== manager.STATE_AWAITING_CHALLENGE) { // Responder should be waiting for Initiator's key after sending Type 2.
             // Always log unexpected state warnings.
             console.warn(`Session [${this.peerId}] Received unexpected Type 4 (Key Response) in state ${this.state}. Ignoring.`);
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
            // Import the peer's public key.
            const importedKey = await this.cryptoModule.importPublicKeyBase64(publicKeyBase64);
            if (!importedKey) { throw new Error('Failed to import peer public key.'); } // Throw specific error on failure.
            // Store the imported key object in the session.
            if (!this.setPeerPublicKey(importedKey)) { throw new Error('Failed to store peer public key.'); } // Throw specific error on failure.

            // --- Start Key Derivation (Responder) ---
            this.updateState(manager.STATE_DERIVING_KEY_RESPONDER); // Update state to indicate derivation start.
            // Await the derivation helper. It handles state updates on success and throws on error.
            await this._deriveKeysAndHandleBufferedChallenge(manager.STATE_RECEIVED_INITIATOR_KEY);
            // --- End Key Derivation ---

            // Key derivation successful. Request SessionManager to send Type 5 (Challenge).
            return { action: 'SEND_TYPE_5' };

        } catch (error) {
            // Catch errors from key import, storage, or derivation.
            // Always log these errors.
            console.error(`Session [${this.peerId}] Error handling Type 4 (Key Response):`, error);
            // Return RESET action with a specific reason for SessionManager.
            return { action: 'RESET', reason: `Handshake Error: ${error.message}` };
        }
    }


    /**
     * Handles KEY_CONFIRMATION_CHALLENGE (Type 5) message from the peer (Responder -> Initiator).
     * If the session key is already derived, decrypts the challenge and requests sending Type 6 (response).
     * If the key is not yet derived (derivation in progress), buffers the raw challenge data.
     *
     * @param {object} payload - Expected: { iv: string (Base64), encryptedChallenge: string (Base64) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'SEND_TYPE_6', challengeData: ArrayBuffer } or 'NONE' on success, { action: 'RESET', reason: string } on failure.
     * @private
     */
    async _handleKeyConfirmationChallenge(payload, manager) {
        // This message is received by the Initiator.
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
            // Check if derivation has started (promise exists).
            if (this.keyDerivationPromise) {
                // Key derivation is in progress. Buffer the challenge data.
                // Always log this warning.
                console.warn(`Session [${this.peerId}] Received Type 5 challenge while key derivation is in progress. Buffering challenge.`);
                try {
                    // Store the raw IV and encrypted data for later processing.
                    this.challengeReceived = {
                        isBuffered: true, // Flag indicating this is raw, unprocessed data.
                        iv: this.cryptoModule.base64ToArrayBuffer(ivBase64),
                        encryptedData: this.cryptoModule.base64ToArrayBuffer(encryptedChallengeBase64)
                    };
                    // State remains DERIVING_KEY_INITIATOR. No action needed yet.
                    return { action: 'NONE' }; // Wait for derivation to complete.
                } catch (e) {
                     // Always log this error (e.g., Base64 decoding error).
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

        // --- Key is derived, proceed with immediate decryption ---
        if (config.DEBUG) console.log(`Session [${this.peerId}] Session key is derived. Processing received challenge (Type 5).`);
        try {
            // Decode Base64 IV and encrypted data.
            const iv = this.cryptoModule.base64ToArrayBuffer(ivBase64);
            const encryptedChallengeBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedChallengeBase64);

            // Decrypt using the derived AES session key.
            const decryptedChallengeBuffer = await this.cryptoModule.decryptAES(encryptedChallengeBuffer, new Uint8Array(iv));
            // Throw specific error if decryption fails (indicates key mismatch or data corruption).
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
            // Pass the decrypted challenge data back to SessionManager so it can be encrypted for the response.
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
     * If verification succeeds, requests sending Type 7 (session established).
     *
     * @param {object} payload - Expected: { iv: string (Base64), encryptedResponse: string (Base64) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'SEND_TYPE_7' } on success, { action: 'RESET', reason: string } on failure/mismatch.
     * @private
     */
    async _handleKeyConfirmationResponse(payload, manager) {
        // This message is received by the Responder.
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

        // Ensure we actually sent a challenge and are expecting a response.
        if (!this.challengeSent) {
            // Always log this warning.
            console.warn(`Session [${this.peerId}] Received unexpected Type 6 (Response) when no challenge was sent. Ignoring.`);
            return { action: 'NONE' };
        }
        // Ensure session key is derived.
        if (!this.cryptoModule.derivedSessionKey) {
             // Always log this critical error.
             console.error(`Session [${this.peerId}] Received Type 6 but session key not derived! State: ${this.state}`);
             return { action: 'RESET', reason: 'Internal Error: Session key missing when receiving challenge response.' };
        }

        try {
            // Decode Base64 IV and encrypted data.
            const iv = this.cryptoModule.base64ToArrayBuffer(ivBase64);
            const encryptedResponseBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedResponseBase64);

            // Decrypt using the derived AES session key.
            const decryptedResponseBuffer = await this.cryptoModule.decryptAES(encryptedResponseBuffer, new Uint8Array(iv));
            // Throw specific error if decryption fails.
            if (!decryptedResponseBuffer) { throw new Error('Failed to decrypt challenge response (security check failed).'); }

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
            // Throw specific error if verification fails.
            if (!match) { throw new Error('Challenge response verification failed!'); }
            // --- Verification Success ---
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) console.log("Challenge response verified successfully!");
            this.challengeSent = null; // Clear the stored sent challenge.
            // Update state and request SessionManager send the final confirmation (Type 7).
            this.updateState(manager.STATE_HANDSHAKE_COMPLETE); // Responder considers handshake complete here.
            return { action: 'SEND_TYPE_7' };
        } catch (error) {
             // Always log errors during response handling or verification.
             console.error(`Session [${this.peerId}] Error handling Type 6 (Response):`, error);
             // Return RESET action with a specific reason.
             return { action: 'RESET', reason: `Handshake Error: ${error.message}` };
        }
    }

    /**
     * Handles SESSION_ESTABLISHED (Type 7) message from the peer (Responder -> Initiator).
     * Marks the session as active from the Initiator's perspective.
     *
     * @param {object} payload - Expected: { message: string } (optional confirmation message, currently unused).
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {object} Action object: { action: 'SESSION_ACTIVE' }
     * @private
     */
    _handleSessionEstablished(payload, manager) {
        // This message is received by the Initiator.
        // Ensure we were expecting this state transition (after sending Type 6).
        if (this.state !== manager.STATE_AWAITING_FINAL_CONFIRMATION && this.state !== manager.STATE_RECEIVED_CHALLENGE) {
             // Always log unexpected state warnings.
             console.warn(`Session [${this.peerId}] Received Type 7 (Established) in unexpected state ${this.state}. Proceeding to ACTIVE.`);
        }
        // Update state to active.
        this.updateState(manager.STATE_ACTIVE_SESSION);
        this.challengeReceived = null; // Clear any stored received challenge data.
        // Request SessionManager to update UI for the active session (plays sound, shows chat).
        return { action: 'SESSION_ACTIVE' };
    }

    /**
     * Handles ENCRYPTED_CHAT_MESSAGE (Type 8) message from the peer.
     * Decrypts the message data using the derived AES session key.
     * Attempts to parse the decrypted data as JSON to check for /me actions or regular messages.
     * Adds the message/action to history and requests UI update.
     *
     * @param {object} payload - Expected: { iv: string (Base64), data: string (Base64 containing encrypted JSON) }
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {Promise<object>} Action object: { action: 'DISPLAY_MESSAGE', ... } or { action: 'DISPLAY_ME_ACTION', ... } on success,
     *                            { action: 'DISPLAY_SYSTEM_MESSAGE', ... } or { action: 'NONE' } on failure/wrong state.
     * @private
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
            // Return action to display system message about malformed data.
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
             // Return RESET action for critical key error.
             return { action: 'RESET', reason: 'Internal Error: Session key missing for active session.' };
        }

        try {
            // 1. Decode the IV and encrypted message data from Base64.
            const iv = this.cryptoModule.base64ToArrayBuffer(ivBase64);
            const encryptedDataBuffer = this.cryptoModule.base64ToArrayBuffer(encryptedDataBase64);

            // 2. Decrypt the message data using the derived AES session key and IV.
            const decryptedDataBuffer = await this.cryptoModule.decryptAES(encryptedDataBuffer, new Uint8Array(iv));
            // If decryption fails, return action to display system message.
            if (!decryptedDataBuffer) {
                return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Failed to decrypt message from ${this.peerId}. (Possible key mismatch or data corruption)` };
            }

            // 3. Decode the decrypted buffer (UTF-8) into a string (expected to be JSON).
            const decryptedJsonString = this.cryptoModule.decodeText(decryptedDataBuffer);

            // --- Handle /me Action vs Regular Message ---
            let messagePayload;
            try {
                // 4. Attempt to parse the decrypted string as JSON.
                messagePayload = JSON.parse(decryptedJsonString);
            } catch (e) {
                // If JSON parsing fails, assume it's corrupted JSON or potentially legacy plain text.
                // Log this warning only if DEBUG is enabled.
                if (config.DEBUG) console.log(`Session [${this.peerId}] Received non-JSON or corrupted JSON message payload. Treating as plain text.`);
                messagePayload = null; // Indicate parsing failed.
            }

            // 5. Check the parsed payload structure or handle parsing failure.
            if (messagePayload && messagePayload.isAction === true && typeof messagePayload.text === 'string') {
                // It's a /me action message.
                const actionText = messagePayload.text;
                // Log received action only if DEBUG is enabled.
                if (config.DEBUG) {
                    console.log(`%c* ${this.peerId} ${actionText}`, "color: orange;"); // Style console output for actions.
                }
                // Add to history with 'me-action' type.
                this.addMessageToHistory(this.peerId, actionText, 'me-action');
                // Request SessionManager display the action message.
                return { action: 'DISPLAY_ME_ACTION', sender: this.peerId, text: actionText };
            } else {
                // It's either a regular message (isAction: false or missing) or parsing failed.
                // Extract text from payload if parsing succeeded, otherwise use the raw decrypted string.
                const messageText = messagePayload ? messagePayload.text : decryptedJsonString;
                // Ensure messageText is a string, falling back to the raw string if payload.text was missing/invalid.
                const finalMessageText = typeof messageText === 'string' ? messageText : decryptedJsonString;

                // Log received message only if DEBUG is enabled.
                if (config.DEBUG) {
                    console.log(`%c[${this.peerId}]: ${finalMessageText}`, "color: purple;"); // Style console output for messages.
                }
                // Add to history with 'peer' type.
                this.addMessageToHistory(this.peerId, finalMessageText, 'peer');
                // Request SessionManager display the regular message.
                return { action: 'DISPLAY_MESSAGE', sender: this.peerId, text: finalMessageText, msgType: 'peer' };
            }
            // --- End /me Action vs Regular Message Handling ---

        } catch (error) {
            // Always log errors during message handling (e.g., Base64 decoding, text decoding).
            console.error(`Error handling encrypted message from ${this.peerId}:`, error);
            // Return action to display system message for other errors during processing.
            return { action: 'DISPLAY_SYSTEM_MESSAGE', text: `Error processing message from ${this.peerId}: ${error.message}` };
        }
    }


    /**
     * Handles SESSION_END (Type 9) message from the peer.
     * Requests SessionManager reset this session and notify the user via the info pane.
     *
     * @param {object} payload - Expected: {} (no specific data needed)
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {object} Action object: { action: 'RESET', reason: string, notifyUser: boolean }
     * @private
     */
    _handleSessionEnd(payload, manager) {
        const message = `Session ended by ${this.peerId}.`;
        // Log session end (significant event, not wrapped in DEBUG).
        console.log(message);
        // Request SessionManager reset this session.
        // notifyUser=true ensures the info pane is shown with the reason.
        return { action: 'RESET', reason: message, notifyUser: true };
    }

    // --- Typing Indicator Handlers ---
    /**
     * Handles TYPING_START (Type 10) message from the peer.
     * Marks the peer as typing and requests the UI show the indicator.
     *
     * @param {object} payload - Expected: {} (no specific data needed)
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {object} Action object: { action: 'SHOW_TYPING' } or { action: 'NONE' } if not in active state.
     * @private
     */
    _handleTypingStart(payload, manager) {
        // Only process typing indicators if the session is fully active.
        if (this.state !== manager.STATE_ACTIVE_SESSION) {
            // Always log this warning.
            console.warn(`Session [${this.peerId}] Ignoring Type 10 (Typing Start) in state ${this.state}`);
            return { action: 'NONE' };
        }
        // Log typing start only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${this.peerId}] Peer started typing.`);
        this.peerIsTyping = true; // Mark peer as typing in session state.
        // Request SessionManager show the typing indicator in the UI (it will handle the timeout).
        return { action: 'SHOW_TYPING' };
    }

    /**
     * Handles TYPING_STOP (Type 11) message from the peer.
     * Marks the peer as not typing and requests the UI hide the indicator.
     *
     * @param {object} payload - Expected: {} (no specific data needed)
     * @param {SessionManager} manager - SessionManager instance.
     * @returns {object} Action object: { action: 'HIDE_TYPING' } or { action: 'NONE' } if not in active state.
     * @private
     */
    _handleTypingStop(payload, manager) {
        // Only process typing indicators if the session is fully active.
        if (this.state !== manager.STATE_ACTIVE_SESSION) {
            // Always log this warning.
            console.warn(`Session [${this.peerId}] Ignoring Type 11 (Typing Stop) in state ${this.state}`);
            return { action: 'NONE' };
        }
        // Log typing stop only if DEBUG is enabled.
        if (config.DEBUG) console.log(`Session [${this.peerId}] Peer stopped typing.`);
        this.peerIsTyping = false; // Mark peer as not typing in session state.
        // Request SessionManager hide the typing indicator in the UI (it will clear the timeout).
        return { action: 'HIDE_TYPING' };
    }
}
