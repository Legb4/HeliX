// client/js/CryptoModule.js

/**
 * Handles all client-side cryptographic operations using the Web Crypto API.
 * This includes generating ECDH key pairs for session key agreement,
 * deriving shared secrets and session keys using HKDF, encrypting/decrypting data with AES-GCM,
 * and handling key import/export.
 * This version implements Perfect Forward Secrecy (PFS) using ECDH.
 */
class CryptoModule {
    /**
     * Initializes the CryptoModule.
     * Checks for Web Crypto API availability and sets up algorithm parameters.
     */
    constructor() {
        // Check if the Web Crypto API (specifically the subtle interface) is available.
        if (!window.crypto || !window.crypto.subtle) {
            const errorMsg = "Web Crypto API (subtle) not available. Please use a secure context (HTTPS or localhost).";
            console.error(errorMsg);
            alert(errorMsg); // Alert the user as this is critical
            throw new Error(errorMsg); // Stop execution if crypto is unavailable
        }

        // --- Cryptographic Key Storage ---
        // Holds the generated ephemeral ECDH public key (CryptoKey object) for this client session.
        this.publicKey = null;
        // Holds the generated ephemeral ECDH private key (CryptoKey object) for this client session.
        this.privateKey = null;
        // Holds the derived AES-GCM session key (CryptoKey object) after successful ECDH key agreement.
        this.derivedSessionKey = null;

        // --- Algorithm Configuration ---
        // Configuration for ECDH (Elliptic Curve Diffie-Hellman) key generation and derivation.
        // Curve P-256 is a standard, widely supported elliptic curve.
        this.ecdhAlgorithm = {
            name: "ECDH",
            namedCurve: "P-256",
        };
        // Configuration for the Key Derivation Function (HKDF - HMAC-based KDF).
        // Used to turn the raw shared secret from ECDH into usable cryptographic keys.
        // We use SHA-256 as the underlying hash function.
        this.hkdfAlgorithm = {
            name: "HKDF",
            hash: "SHA-256",
            // Salt and Info are important for domain separation in HKDF.
            // For simplicity here, we use empty values, but these could be derived
            // from handshake messages or other context in a more complex implementation.
            salt: new Uint8Array(), // Use an empty salt for now
            info: new Uint8Array(), // Use empty info for now
        };
        // Configuration for the derived AES-GCM session key.
        // Used for encrypting the actual chat messages.
        this.derivedKeyAlgorithm = {
            name: "AES-GCM",
            length: 256, // AES key length in bits (strong)
        };
        // Standard Initialization Vector (IV) length for AES-GCM in bytes (96 bits).
        // A unique IV must be used for each encryption with the same key.
        this.aesIVLength = 12;

        // --- Key Property Configuration ---
        // Determines if ECDH keys can be exported from the CryptoKey object (needed for public key).
        this.ecdhKeyIsExtractable = true; // Public key needs to be exported
        // Defines what the ECDH keys can be used for (deriving shared secret bits).
        this.ecdhKeyUsages = ["deriveBits"];
        // Defines what the derived AES session key can be used for (encrypting/decrypting messages).
        this.derivedKeyUsages = ["encrypt", "decrypt"];

        // Log initialization (not wrapped in DEBUG as it's a one-time info message)
        console.log("CryptoModule initialized (ECDH Mode).");
    }

    // --- ECDH Key Pair Management ---

    /**
     * Generates a new ephemeral ECDH public/private key pair asynchronously.
     * Stores the generated keys in `this.publicKey` and `this.privateKey`.
     * @returns {Promise<boolean>} True if key generation was successful, false otherwise.
     */
    async generateECDHKeys() {
        // Log key generation attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Generating ephemeral ECDH key pair (P-256)...");
        }
        try {
            // Use the Web Crypto API to generate the ECDH key pair.
            const keyPair = await window.crypto.subtle.generateKey(
                this.ecdhAlgorithm,       // Algorithm details (ECDH, P-256)
                this.ecdhKeyIsExtractable,// Whether the keys can be exported (needed for public)
                this.ecdhKeyUsages        // Key usages (deriveBits)
            );
            // Store the generated keys.
            this.publicKey = keyPair.publicKey;
            this.privateKey = keyPair.privateKey;
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("Ephemeral ECDH key pair generated successfully.");
            }
            return true; // Indicate success
        } catch (error) {
            // Always log errors.
            console.error("Error generating ECDH keys:", error);
            // Clear any potentially partially generated keys on error.
            this.publicKey = null;
            this.privateKey = null;
            return false; // Indicate failure
        }
    }

    /**
     * Exports the stored public ECDH key to the SPKI format and encodes it as Base64.
     * SPKI (SubjectPublicKeyInfo) is a standard format suitable for sharing public keys.
     * Base64 encoding makes it suitable for transmission in JSON.
     * @returns {Promise<string|null>} The Base64 encoded public key, or null on failure/if no key exists.
     */
    async getPublicKeyBase64() {
        // Ensure a public key exists before trying to export.
        if (!this.publicKey) {
            // Always log this error as it indicates a programming mistake.
            console.error("Cannot export public key: No public key generated or stored.");
            return null;
        }
        // Log export attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Exporting ECDH public key to Base64 (SPKI format)...");
        }
        try {
            // Export the key in SPKI format (returns an ArrayBuffer).
            const exportedSpki = await window.crypto.subtle.exportKey(
                "spki", // Standard format for public keys
                this.publicKey
            );
            // Convert the ArrayBuffer to a Base64 string.
            const base64Key = this.arrayBufferToBase64(exportedSpki);
            // Log success (truncated key) only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("ECDH Public key exported successfully (Base64):", base64Key.substring(0, 30) + "..."); // Log prefix
            }
            return base64Key;
        } catch (error) {
            // Always log errors.
            console.error("Error exporting ECDH public key:", error);
            return null;
        }
    }

    /**
     * Imports a peer's ECDH public key from a Base64 encoded SPKI string.
     * @param {string} base64Key - The Base64 encoded SPKI public key string.
     * @returns {Promise<CryptoKey|null>} The imported CryptoKey object representing the peer's public key, or null on failure.
     */
    async importPublicKeyBase64(base64Key) {
        // Log import attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Importing peer ECDH public key from Base64 (SPKI format)...");
        }
        // Basic validation of the input.
        if (!base64Key || typeof base64Key !== 'string') {
             // Always log this error.
             console.error("Invalid Base64 key provided for import.");
             return null;
        }
        try {
            // Convert the Base64 string back to an ArrayBuffer.
            const spkiBuffer = this.base64ToArrayBuffer(base64Key);
            // Import the key using the Web Crypto API.
            const importedKey = await window.crypto.subtle.importKey(
                "spki",             // Format of the key being imported
                spkiBuffer,         // The key data as an ArrayBuffer
                this.ecdhAlgorithm, // Algorithm details (must match the key type - ECDH P-256)
                true,               // Mark the imported key as extractable (standard practice)
                []                  // IMPORTANT: Peer's public key usage is empty. It's only used as input to deriveBits, not for direct crypto operations by this module.
            );
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("Peer ECDH public key imported successfully.");
            }
            return importedKey; // Return the CryptoKey object
        } catch (error) {
            // Always log errors.
            console.error("Error importing peer ECDH public key:", error);
            return null;
        }
    }

    // --- Shared Secret and Session Key Derivation ---

    /**
     * Derives the raw shared secret bits using ECDH.
     * Combines this client's private ECDH key with the peer's public ECDH key.
     * @param {CryptoKey} peerPublicKey - The imported CryptoKey object of the peer's public ECDH key.
     * @returns {Promise<ArrayBuffer|null>} The raw shared secret as an ArrayBuffer, or null on failure.
     */
    async deriveSharedSecret(peerPublicKey) {
        // Log derivation attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Deriving shared secret using ECDH...");
        }
        if (!this.privateKey) {
            // Always log this error.
            console.error("Cannot derive secret: Own private key not available.");
            return null;
        }
        if (!peerPublicKey) {
            // Always log this error.
            console.error("Cannot derive secret: Peer public key not provided.");
            return null;
        }

        try {
            // Use deriveBits with own private key and peer's public key.
            const sharedSecretBits = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: peerPublicKey, // Peer's public key
                },
                this.privateKey, // Own private key
                256 // Desired length of the derived secret in bits (can be adjusted, 256 is common)
            );
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("Shared secret derived successfully (raw bits).");
            }
            return sharedSecretBits;
        } catch (error) {
            // Always log errors.
            console.error("Error deriving shared secret:", error);
            return null;
        }
    }

    /**
     * Derives a usable AES-GCM session key from the raw shared secret bits using HKDF.
     * Stores the derived key in `this.derivedSessionKey`.
     * @param {ArrayBuffer} sharedSecretBits - The raw shared secret obtained from deriveSharedSecret.
     * @returns {Promise<boolean>} True if key derivation was successful, false otherwise.
     */
    async deriveSessionKey(sharedSecretBits) {
        // Log derivation attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Deriving AES-GCM session key from shared secret using HKDF...");
        }
        if (!sharedSecretBits) {
            // Always log this error.
            console.error("Cannot derive session key: Shared secret bits not provided.");
            return false;
        }

        try {
            // Import the raw shared secret as the base key material for HKDF.
            // It's treated like a pre-shared key for the derivation process.
            // Usages are empty as it's only used for derivation input.
            const baseKey = await window.crypto.subtle.importKey(
                "raw",
                sharedSecretBits,
                { name: "HKDF" }, // Indicate this key is for HKDF
                false,            // Not extractable
                ["deriveKey"]     // Usage is to derive other keys
            );

            // Derive the AES-GCM key using HKDF.
            this.derivedSessionKey = await window.crypto.subtle.deriveKey(
                this.hkdfAlgorithm,      // HKDF parameters (hash, salt, info)
                baseKey,                 // The imported shared secret as the base key material
                this.derivedKeyAlgorithm,// Desired output key algorithm (AES-GCM)
                true,                    // Make the derived key extractable (optional, but can be useful)
                this.derivedKeyUsages    // Usages for the derived key (encrypt, decrypt)
            );

            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("AES-GCM session key derived and stored successfully.");
            }
            return true;
        } catch (error) {
            // Always log errors.
            console.error("Error deriving session key:", error);
            this.derivedSessionKey = null; // Clear any partial result
            return false;
        }
    }

    // --- RSA Methods Removed ---
    // encryptRSA and decryptRSA are no longer needed with ECDH key agreement.

    // --- AES Symmetric Key Handling (Now uses derivedSessionKey) ---

    // generateSymmetricKey is removed - the key is now derived, not generated per message.
    // exportSymmetricKeyBase64 is removed - the derived key isn't exported directly.
    // importSymmetricKeyBase64 is removed - the key is derived, not imported after RSA decryption.

    /**
     * Encrypts data (e.g., chat message text or challenge data) using AES-GCM
     * with the derived session key stored in `this.derivedSessionKey`.
     * Generates a new, random Initialization Vector (IV) for each encryption operation.
     * @param {ArrayBuffer | ArrayBufferView} dataBuffer - The data to encrypt (e.g., encoded text).
     * @returns {Promise<{encryptedBuffer: ArrayBuffer, iv: Uint8Array}|null>} An object containing the encrypted data (ArrayBuffer) and the IV (Uint8Array) used, or null on failure. The IV must be sent alongside the ciphertext.
     */
    async encryptAES(dataBuffer) {
        // Use the derived session key stored in the instance.
        if (!this.derivedSessionKey) {
            // Always log this error.
            console.error("Cannot encrypt AES: Derived session key not available.");
            return null;
        }
        try {
            // Generate a cryptographically random IV of the configured length.
            const iv = window.crypto.getRandomValues(new Uint8Array(this.aesIVLength));
            // Log encryption attempt only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("Encrypting data with derived AES-GCM session key...");
            }
            // Encrypt the data using AES-GCM.
            const encryptedBuffer = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv }, // Specify algorithm and the unique IV
                this.derivedSessionKey,     // The derived AES key
                dataBuffer                  // The data to encrypt
            );
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("AES-GCM encryption successful.");
            }
            // Return both the encrypted data and the IV, as the IV is needed for decryption.
            return { encryptedBuffer, iv };
        } catch (error) {
            // Always log errors.
            console.error("Error during AES encryption:", error);
            return null;
        }
    }

    /**
     * Decrypts data using AES-GCM with the derived session key stored in
     * `this.derivedSessionKey` and the provided Initialization Vector (IV).
     * @param {ArrayBuffer | ArrayBufferView} encryptedBuffer - The encrypted data received.
     * @param {Uint8Array} iv - The Initialization Vector (IV) that was used during encryption.
     * @returns {Promise<ArrayBuffer|null>} Decrypted data as an ArrayBuffer, or null on failure (e.g., wrong key, wrong IV, corrupted data).
     */
    async decryptAES(encryptedBuffer, iv) {
        // Use the derived session key stored in the instance.
        if (!this.derivedSessionKey) {
            // Always log this error.
            console.error("Cannot decrypt AES: Derived session key not available.");
            return null;
        }
        // Validate the IV length.
        if (!iv || iv.length !== this.aesIVLength) {
            // Always log this error.
            console.error("Cannot decrypt AES: Invalid IV provided.");
            return null;
        }
        // Log decryption attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Decrypting data with derived AES-GCM session key...");
        }
        try {
            // Decrypt the data using AES-GCM.
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv }, // Specify algorithm and the IV used for encryption
                this.derivedSessionKey,     // The derived AES key
                encryptedBuffer             // The encrypted data
            );
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("AES-GCM decryption successful.");
            }
            return decryptedBuffer; // Return the original data buffer
        } catch (error) {
            // Decryption errors are common if the key, IV, or data is incorrect/tampered.
            // AES-GCM provides authenticity, so errors often indicate integrity issues.
            // Always log decryption errors.
            console.error("Error during AES decryption:", error);
            return null;
        }
    }
    // --------------------------------------

    // --- Hashing (Remains the same, potentially useful for challenge/info in KDF later) ---
    /**
     * Hashes data using SHA-256.
     * @param {ArrayBuffer | ArrayBufferView} data - The data to hash.
     * @returns {Promise<ArrayBuffer|null>} The SHA-256 hash as an ArrayBuffer, or null on failure.
     */
    async hashData(data) {
        // Log hashing attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Hashing data with SHA-256...");
        }
        try {
            // Calculate the SHA-256 digest of the data.
            const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("Data hashed successfully.");
            }
            return hashBuffer;
        } catch (error) {
            // Always log errors.
            console.error("Error during hashing:", error);
            return null;
        }
    }

    // --- Key Wiping ---
    /**
     * Clears the stored ECDH public/private keys and the derived AES session key from memory.
     * Important for ephemeral sessions to remove keys when no longer needed.
     */
    wipeKeys() {
        // Log wiping attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Wiping ECDH and derived cryptographic keys...");
        }
        this.publicKey = null;
        this.privateKey = null;
        this.derivedSessionKey = null; // Also clear the derived key
        // Potentially add memory clearing techniques if supported/needed,
        // but setting to null removes the primary reference.
        // Log completion only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Keys wiped.");
        }
    }

    // --- Helper Functions (Remain the same) ---

    /**
     * Converts an ArrayBuffer to a Base64 encoded string.
     * @param {ArrayBuffer} buffer - The ArrayBuffer to convert.
     * @returns {string} The Base64 encoded string.
     */
    arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        // Use browser's built-in btoa function for Base64 encoding.
        return window.btoa(binary);
    }

    /**
     * Converts a Base64 encoded string back to an ArrayBuffer.
     * @param {string} base64 - The Base64 encoded string.
     * @returns {ArrayBuffer} The resulting ArrayBuffer.
     */
    base64ToArrayBuffer(base64) {
        // Use browser's built-in atob function to decode Base64.
        const binary_string = window.atob(base64);
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // --- Text Encoding/Decoding Helpers (Remain the same) ---

    /**
     * Encodes a JavaScript string into a UTF-8 ArrayBuffer.
     * @param {string} str - The string to encode.
     * @returns {ArrayBuffer} The UTF-8 encoded ArrayBuffer.
     */
    encodeText(str) {
        return new TextEncoder().encode(str);
    }

    /**
     * Decodes a UTF-8 ArrayBuffer (or view) back into a JavaScript string.
     * @param {ArrayBuffer | ArrayBufferView} buffer - The buffer to decode.
     * @returns {string} The decoded string.
     */
    decodeText(buffer) {
        return new TextDecoder().decode(buffer);
    }
}
