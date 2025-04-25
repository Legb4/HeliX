// client/js/CryptoModule.js

/**
 * Handles all client-side cryptographic operations using the Web Crypto API.
 * This includes generating ECDH key pairs for session key agreement,
 * deriving shared secrets and session keys using HKDF, encrypting/decrypting data with AES-GCM,
 * and handling key import/export. Implements Perfect Forward Secrecy (PFS) using ECDH.
 */
class CryptoModule {
    /**
     * Initializes the CryptoModule.
     * Checks for Web Crypto API availability and sets up algorithm parameters.
     * Throws an error if the Web Crypto API is unavailable.
     */
    constructor() {
        // Check if the Web Crypto API (specifically the subtle interface) is available.
        if (!window.crypto || !window.crypto.subtle) {
            const errorMsg = "Web Crypto API (subtle) not available. Please use a secure context (HTTPS or localhost).";
            console.error(errorMsg);
            alert(errorMsg); // Alert the user as this is critical for functionality.
            throw new Error(errorMsg); // Stop execution if crypto is unavailable.
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
        // Curve P-256 is a standard, widely supported elliptic curve providing strong security.
        this.ecdhAlgorithm = {
            name: "ECDH",
            namedCurve: "P-256",
        };
        // Configuration for the Key Derivation Function (HKDF - HMAC-based KDF).
        // Used to turn the raw shared secret from ECDH into a cryptographically strong session key.
        // SHA-256 is used as the underlying hash function.
        this.hkdfAlgorithm = {
            name: "HKDF",
            hash: "SHA-256",
            // Salt and Info are parameters for HKDF. Using empty values is acceptable for this use case,
            // but they could be derived from handshake context for domain separation in more complex protocols.
            salt: new Uint8Array(), // Empty salt.
            info: new Uint8Array(), // Empty info.
        };
        // Configuration for the derived AES-GCM session key.
        // AES-GCM provides authenticated encryption (confidentiality and integrity).
        this.derivedKeyAlgorithm = {
            name: "AES-GCM",
            length: 256, // AES key length in bits (256-bit provides strong security).
        };
        // Standard Initialization Vector (IV) length for AES-GCM in bytes (96 bits).
        // A unique IV must be generated for each encryption operation with the same key.
        this.aesIVLength = 12;

        // --- Key Property Configuration ---
        // Determines if ECDH keys can be exported from the CryptoKey object.
        // Public keys need to be exportable (in SPKI format) to be shared.
        this.ecdhKeyIsExtractable = true;
        // Defines what the ECDH keys can be used for (deriving shared secret bits via ECDH).
        this.ecdhKeyUsages = ["deriveBits"];
        // Defines what the derived AES session key can be used for (encrypting/decrypting messages).
        this.derivedKeyUsages = ["encrypt", "decrypt"];

        // Log initialization confirmation.
        console.log("CryptoModule initialized (ECDH Mode).");
    }

    // --- ECDH Key Pair Management ---

    /**
     * Generates a new ephemeral ECDH public/private key pair asynchronously using the P-256 curve.
     * Stores the generated keys in `this.publicKey` and `this.privateKey`.
     * These keys are used only for the duration of the session handshake to establish a shared secret.
     *
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
                this.ecdhAlgorithm,       // Algorithm details (ECDH, P-256).
                this.ecdhKeyIsExtractable,// Allow keys (specifically public) to be exported.
                this.ecdhKeyUsages        // Specify allowed usage (deriving bits).
            );
            // Store the generated public and private keys.
            this.publicKey = keyPair.publicKey;
            this.privateKey = keyPair.privateKey;
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("Ephemeral ECDH key pair generated successfully.");
            }
            return true; // Indicate success.
        } catch (error) {
            // Always log errors during key generation.
            console.error("Error generating ECDH keys:", error);
            // Clear any potentially partially generated keys on error.
            this.publicKey = null;
            this.privateKey = null;
            return false; // Indicate failure.
        }
    }

    /**
     * Exports the stored public ECDH key to the SPKI format and encodes it as Base64.
     * SPKI (SubjectPublicKeyInfo) is a standard format suitable for sharing public keys.
     * Base64 encoding makes the binary key data suitable for transmission in JSON payloads.
     *
     * @returns {Promise<string|null>} The Base64 encoded public key string, or null on failure or if no key exists.
     */
    async getPublicKeyBase64() {
        // Ensure a public key exists before trying to export.
        if (!this.publicKey) {
            // Always log this error as it indicates a programming mistake (calling export before generate).
            console.error("Cannot export public key: No public key generated or stored.");
            return null;
        }
        // Log export attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Exporting ECDH public key to Base64 (SPKI format)...");
        }
        try {
            // Export the key in SPKI format, which returns an ArrayBuffer.
            const exportedSpki = await window.crypto.subtle.exportKey(
                "spki", // Standard format for public keys.
                this.publicKey
            );
            // Convert the ArrayBuffer containing the binary key data to a Base64 string.
            const base64Key = this.arrayBufferToBase64(exportedSpki);
            // Log success (truncated key) only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("ECDH Public key exported successfully (Base64):", base64Key.substring(0, 30) + "..."); // Log prefix for brevity.
            }
            return base64Key;
        } catch (error) {
            // Always log errors during key export.
            console.error("Error exporting ECDH public key:", error);
            return null;
        }
    }

    /**
     * Imports a peer's ECDH public key from a Base64 encoded SPKI string.
     * This converts the received key string back into a CryptoKey object usable for key agreement.
     *
     * @param {string} base64Key - The Base64 encoded SPKI public key string received from the peer.
     * @returns {Promise<CryptoKey|null>} The imported CryptoKey object representing the peer's public key, or null on failure.
     */
    async importPublicKeyBase64(base64Key) {
        // Log import attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Importing peer ECDH public key from Base64 (SPKI format)...");
        }
        // Basic validation of the input key string.
        if (!base64Key || typeof base64Key !== 'string') {
             // Always log this error.
             console.error("Invalid Base64 key provided for import.");
             return null;
        }
        try {
            // Convert the Base64 string back to an ArrayBuffer containing the binary key data.
            const spkiBuffer = this.base64ToArrayBuffer(base64Key);
            // Import the key using the Web Crypto API.
            const importedKey = await window.crypto.subtle.importKey(
                "spki",             // Format of the key being imported (SubjectPublicKeyInfo).
                spkiBuffer,         // The key data as an ArrayBuffer.
                this.ecdhAlgorithm, // Algorithm details (must match the key type - ECDH P-256).
                true,               // Mark the imported key as extractable (standard practice, though not strictly needed here).
                []                  // Key usages for the imported peer public key are empty. It's only used as input to deriveBits, not for direct crypto operations by this module.
            );
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("Peer ECDH public key imported successfully.");
            }
            return importedKey; // Return the CryptoKey object.
        } catch (error) {
            // Always log errors during key import (e.g., invalid format, wrong curve).
            console.error("Error importing peer ECDH public key:", error);
            return null;
        }
    }

    // --- Shared Secret and Session Key Derivation ---

    /**
     * Derives the raw shared secret bits using the Elliptic Curve Diffie-Hellman (ECDH) algorithm.
     * Combines this client's stored private ECDH key with the peer's imported public ECDH key.
     * The resulting shared secret is the same for both peers but is never transmitted directly.
     *
     * @param {CryptoKey} peerPublicKey - The imported CryptoKey object of the peer's public ECDH key.
     * @returns {Promise<ArrayBuffer|null>} The raw shared secret as an ArrayBuffer, or null on failure.
     */
    async deriveSharedSecret(peerPublicKey) {
        // Log derivation attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Deriving shared secret using ECDH...");
        }
        // Ensure necessary keys are available before proceeding.
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
            // Use the deriveBits function with own private key and the peer's public key.
            // The length parameter specifies the desired output length in bits (256 bits is common for AES-256).
            const sharedSecretBits = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: peerPublicKey, // Provide the peer's public key.
                },
                this.privateKey, // Use own private key.
                256 // Desired length of the derived secret in bits.
            );
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("Shared secret derived successfully (raw bits).");
            }
            return sharedSecretBits;
        } catch (error) {
            // Always log errors during secret derivation.
            console.error("Error deriving shared secret:", error);
            return null;
        }
    }

    /**
     * Derives a usable AES-GCM session key from the raw shared secret bits using HKDF.
     * HKDF enhances the cryptographic strength and properties of the raw secret.
     * Stores the derived key in `this.derivedSessionKey` for later encryption/decryption.
     *
     * @param {ArrayBuffer} sharedSecretBits - The raw shared secret obtained from deriveSharedSecret.
     * @returns {Promise<boolean>} True if key derivation was successful and key is stored, false otherwise.
     */
    async deriveSessionKey(sharedSecretBits) {
        // Log derivation attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Deriving AES-GCM session key from shared secret using HKDF...");
        }
        // Ensure shared secret input is provided.
        if (!sharedSecretBits) {
            // Always log this error.
            console.error("Cannot derive session key: Shared secret bits not provided.");
            return false;
        }

        try {
            // 1. Import the raw shared secret as the base key material (Input Keying Material - IKM) for HKDF.
            //    It's treated like a pre-shared key for the derivation process itself.
            //    Usages are limited to 'deriveKey' as it's only used as input to HKDF.
            const baseKey = await window.crypto.subtle.importKey(
                "raw",            // Format is raw binary data.
                sharedSecretBits, // The shared secret ArrayBuffer.
                { name: "HKDF" }, // Indicate this key is intended for HKDF.
                false,            // Not extractable.
                ["deriveKey"]     // Usage is solely to derive other keys.
            );

            // 2. Derive the actual AES-GCM key using HKDF.
            this.derivedSessionKey = await window.crypto.subtle.deriveKey(
                this.hkdfAlgorithm,      // HKDF parameters (hash, salt, info).
                baseKey,                 // The imported shared secret as the base key material.
                this.derivedKeyAlgorithm,// Desired output key algorithm (AES-GCM, 256-bit).
                true,                    // Make the derived key extractable (optional, can be useful for debugging but generally false for production).
                this.derivedKeyUsages    // Usages for the derived key (encrypt, decrypt).
            );

            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("AES-GCM session key derived and stored successfully.");
            }
            return true; // Indicate success.
        } catch (error) {
            // Always log errors during session key derivation.
            console.error("Error deriving session key:", error);
            this.derivedSessionKey = null; // Clear any partial result on failure.
            return false; // Indicate failure.
        }
    }

    // --- AES Symmetric Encryption/Decryption (using derivedSessionKey) ---

    /**
     * Encrypts data (e.g., chat message text, challenge data) using AES-GCM
     * with the derived session key stored in `this.derivedSessionKey`.
     * Generates a new, random Initialization Vector (IV) for each encryption operation,
     * which is crucial for AES-GCM security.
     *
     * @param {ArrayBuffer | ArrayBufferView} dataBuffer - The data to encrypt (e.g., UTF-8 encoded text).
     * @returns {Promise<{encryptedBuffer: ArrayBuffer, iv: Uint8Array}|null>} An object containing the encrypted data (ArrayBuffer)
     *          and the unique IV (Uint8Array) used for this encryption, or null on failure. The IV must be sent alongside the ciphertext.
     */
    async encryptAES(dataBuffer) {
        // Ensure the derived session key is available before attempting encryption.
        if (!this.derivedSessionKey) {
            // Always log this error.
            console.error("Cannot encrypt AES: Derived session key not available.");
            return null;
        }
        try {
            // Generate a cryptographically random IV of the configured length (12 bytes for AES-GCM).
            const iv = window.crypto.getRandomValues(new Uint8Array(this.aesIVLength));
            // Log encryption attempt only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("Encrypting data with derived AES-GCM session key...");
            }
            // Encrypt the data using AES-GCM.
            const encryptedBuffer = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv }, // Specify algorithm and the unique IV.
                this.derivedSessionKey,     // The derived AES key.
                dataBuffer                  // The plaintext data to encrypt.
            );
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("AES-GCM encryption successful.");
            }
            // Return both the encrypted data and the IV, as the IV is required for decryption.
            return { encryptedBuffer, iv };
        } catch (error) {
            // Always log errors during AES encryption.
            console.error("Error during AES encryption:", error);
            return null;
        }
    }

    /**
     * Decrypts data using AES-GCM with the derived session key stored in
     * `this.derivedSessionKey` and the provided Initialization Vector (IV).
     * AES-GCM provides authenticity, so decryption will fail if the key, IV, or ciphertext is incorrect/tampered with.
     *
     * @param {ArrayBuffer | ArrayBufferView} encryptedBuffer - The encrypted data received from the peer.
     * @param {Uint8Array} iv - The Initialization Vector (IV) that was used during encryption (received alongside the ciphertext).
     * @returns {Promise<ArrayBuffer|null>} Decrypted data as an ArrayBuffer, or null on failure (e.g., wrong key, wrong IV, corrupted data, failed integrity check).
     */
    async decryptAES(encryptedBuffer, iv) {
        // Ensure the derived session key is available.
        if (!this.derivedSessionKey) {
            // Always log this error.
            console.error("Cannot decrypt AES: Derived session key not available.");
            return null;
        }
        // Validate the provided IV.
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
                { name: "AES-GCM", iv: iv }, // Specify algorithm and the IV used for encryption.
                this.derivedSessionKey,     // The derived AES key.
                encryptedBuffer             // The encrypted data.
            );
            // Log success only if DEBUG is enabled.
            if (config.DEBUG) {
                console.log("AES-GCM decryption successful.");
            }
            return decryptedBuffer; // Return the original plaintext data buffer.
        } catch (error) {
            // Decryption errors are expected if the key, IV, or data is incorrect/tampered.
            // AES-GCM's authenticity check causes decryption to fail in these cases.
            // Always log decryption errors.
            console.error("Error during AES decryption (key mismatch, data corruption, or integrity check failed):", error);
            return null; // Return null to indicate decryption failure.
        }
    }

    // --- Hashing ---
    /**
     * Hashes data using the SHA-256 algorithm.
     * Useful for various cryptographic purposes, though not directly used for encryption/decryption in this module.
     *
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
            // Always log errors during hashing.
            console.error("Error during hashing:", error);
            return null;
        }
    }

    // --- Key Wiping ---
    /**
     * Clears the stored ephemeral ECDH public/private keys and the derived AES session key from memory.
     * This is important for ephemeral sessions to ensure keys are removed when the session ends.
     * Setting references to null allows JavaScript's garbage collector to reclaim the memory.
     */
    wipeKeys() {
        // Log wiping attempt only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Wiping ECDH and derived cryptographic keys...");
        }
        this.publicKey = null;
        this.privateKey = null;
        this.derivedSessionKey = null; // Clear the derived AES key as well.
        // Log completion only if DEBUG is enabled.
        if (config.DEBUG) {
            console.log("Keys wiped.");
        }
    }

    // --- Helper Functions ---

    /**
     * Converts an ArrayBuffer containing binary data to a Base64 encoded string.
     * Useful for transmitting binary data (like keys or encrypted data) in JSON payloads.
     *
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
        // Use the browser's built-in btoa function for efficient Base64 encoding.
        return window.btoa(binary);
    }

    /**
     * Converts a Base64 encoded string back to an ArrayBuffer containing the original binary data.
     *
     * @param {string} base64 - The Base64 encoded string.
     * @returns {ArrayBuffer} The resulting ArrayBuffer.
     */
    base64ToArrayBuffer(base64) {
        // Use the browser's built-in atob function to decode the Base64 string into a binary string.
        const binary_string = window.atob(base64);
        const len = binary_string.length;
        // Create a Uint8Array to hold the bytes.
        const bytes = new Uint8Array(len);
        // Convert each character in the binary string to its byte value.
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        // Return the underlying ArrayBuffer.
        return bytes.buffer;
    }

    // --- Text Encoding/Decoding Helpers ---

    /**
     * Encodes a JavaScript string into a UTF-8 ArrayBuffer using the TextEncoder API.
     *
     * @param {string} str - The string to encode.
     * @returns {ArrayBuffer} The UTF-8 encoded ArrayBuffer.
     */
    encodeText(str) {
        return new TextEncoder().encode(str);
    }

    /**
     * Decodes a UTF-8 ArrayBuffer (or ArrayBufferView like Uint8Array) back into a JavaScript string
     * using the TextDecoder API.
     *
     * @param {ArrayBuffer | ArrayBufferView} buffer - The buffer to decode.
     * @returns {string} The decoded string.
     */
    decodeText(buffer) {
        return new TextDecoder().decode(buffer);
    }
}
