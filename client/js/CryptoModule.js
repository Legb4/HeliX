// client/js/CryptoModule.js

/**
 * Handles all client-side cryptographic operations using the Web Crypto API.
 * This includes generating RSA key pairs for session establishment,
 * generating AES keys for message encryption, encrypting/decrypting data,
 * and handling key import/export.
 */
class CryptoModule {
    /**
     * Initializes the CryptoModule.
     * Checks for Web Crypto API availability and sets up algorithm parameters.
     */
    constructor() {
        // Check if the Web Crypto API (specifically the subtle interface) is available.
        // This requires a secure context (HTTPS or localhost).
        if (!window.crypto || !window.crypto.subtle) {
            const errorMsg = "Web Crypto API (subtle) not available. Please use a secure context (HTTPS or localhost).";
            console.error(errorMsg);
            alert(errorMsg); // Alert the user as this is critical
            throw new Error(errorMsg); // Stop execution if crypto is unavailable
        }

        // --- Cryptographic Key Storage ---
        // Holds the generated RSA public key (CryptoKey object) for this client session.
        this.publicKey = null;
        // Holds the generated RSA private key (CryptoKey object) for this client session.
        this.privateKey = null;
        // Note: AES keys are generated per-message and not stored long-term in this module.

        // --- Algorithm Configuration ---
        // Configuration for RSA-OAEP key generation and encryption/decryption.
        // Used for securely exchanging the AES symmetric key.
        this.rsaAlgorithm = {
            name: "RSA-OAEP", // Algorithm name
            modulusLength: 2048, // Key size in bits (secure standard)
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // Standard public exponent (65537)
            hash: "SHA-256", // Hash algorithm used in OAEP padding
        };
        // Configuration for AES-GCM key generation and encryption/decryption.
        // Used for encrypting the actual chat messages.
        this.aesAlgorithm = {
            name: "AES-GCM", // Algorithm name (Galois/Counter Mode - provides authenticated encryption)
            length: 256, // AES key length in bits (strong)
        };
        // Standard Initialization Vector (IV) length for AES-GCM in bytes (96 bits).
        // A unique IV must be used for each encryption with the same key.
        this.aesIVLength = 12;

        // --- Key Property Configuration ---
        // Determines if RSA keys can be exported from the CryptoKey object (e.g., to send the public key).
        this.rsaKeyIsExtractable = true;
        // Defines what the RSA public key can be used for (encrypting the AES key).
        this.rsaKeyUsagesPublic = ["encrypt"];
        // Defines what the RSA private key can be used for (decrypting the AES key).
        this.rsaKeyUsagesPrivate = ["decrypt"];
        // Determines if AES keys can be exported (needed to wrap/encrypt it with RSA).
        this.aesKeyIsExtractable = true;
        // Defines what the AES key can be used for (encrypting/decrypting messages).
        this.aesKeyUsages = ["encrypt", "decrypt"];

        console.log("CryptoModule initialized.");
    }

    // --- RSA Key Pair Management ---

    /**
     * Generates a new RSA-OAEP public/private key pair asynchronously.
     * Stores the generated keys in `this.publicKey` and `this.privateKey`.
     * @returns {Promise<boolean>} True if key generation was successful, false otherwise.
     */
    async generateAsymmetricKeys() {
        console.log("Generating asymmetric RSA key pair...");
        try {
            // Use the Web Crypto API to generate the key pair.
            const keyPair = await window.crypto.subtle.generateKey(
                this.rsaAlgorithm, // Algorithm details defined in constructor
                this.rsaKeyIsExtractable, // Whether the keys can be exported
                // Combine public and private key usages for generation
                [...this.rsaKeyUsagesPublic, ...this.rsaKeyUsagesPrivate]
            );
            // Store the generated keys.
            this.publicKey = keyPair.publicKey;
            this.privateKey = keyPair.privateKey;
            console.log("Asymmetric RSA key pair generated successfully.");
            return true; // Indicate success
        } catch (error) {
            console.error("Error generating asymmetric keys:", error);
            // Clear any potentially partially generated keys on error.
            this.publicKey = null;
            this.privateKey = null;
            return false; // Indicate failure
        }
    }

    /**
     * Exports the stored public key to the SPKI format and encodes it as Base64.
     * SPKI (SubjectPublicKeyInfo) is a standard format for sharing public keys.
     * Base64 encoding makes it suitable for transmission in JSON.
     * @returns {Promise<string|null>} The Base64 encoded public key, or null on failure/if no key exists.
     */
    async getPublicKeyBase64() {
        // Ensure a public key exists before trying to export.
        if (!this.publicKey) {
            console.error("Cannot export public key: No public key generated or stored.");
            return null;
        }
        console.log("Exporting public key to Base64...");
        try {
            // Export the key in SPKI format (returns an ArrayBuffer).
            const exportedSpki = await window.crypto.subtle.exportKey(
                "spki", // Standard format for public keys
                this.publicKey
            );
            // Convert the ArrayBuffer to a Base64 string.
            const base64Key = this.arrayBufferToBase64(exportedSpki);
            console.log("Public key exported successfully (Base64):", base64Key.substring(0, 30) + "..."); // Log prefix
            return base64Key;
        } catch (error) {
            console.error("Error exporting public key:", error);
            return null;
        }
    }

    /**
     * Imports a peer's RSA public key from a Base64 encoded SPKI string.
     * @param {string} base64Key - The Base64 encoded SPKI public key string.
     * @returns {Promise<CryptoKey|null>} The imported CryptoKey object representing the peer's public key, or null on failure.
     */
    async importPublicKeyBase64(base64Key) {
        console.log("Importing peer public key from Base64...");
        // Basic validation of the input.
        if (!base64Key || typeof base64Key !== 'string') {
             console.error("Invalid Base64 key provided for import.");
             return null;
        }
        try {
            // Convert the Base64 string back to an ArrayBuffer.
            const spkiBuffer = this.base64ToArrayBuffer(base64Key);
            // Import the key using the Web Crypto API.
            const importedKey = await window.crypto.subtle.importKey(
                "spki", // Format of the key being imported
                spkiBuffer, // The key data as an ArrayBuffer
                this.rsaAlgorithm, // Algorithm details (must match the key type)
                true, // Mark the imported key as extractable (usually true for public keys)
                this.rsaKeyUsagesPublic // Specify what this imported key can be used for (encryption)
            );
            console.log("Peer public key imported successfully.");
            return importedKey; // Return the CryptoKey object
        } catch (error) {
            console.error("Error importing peer public key:", error);
            return null;
        }
    }

    // --- RSA Encryption/Decryption (Used for Symmetric Key Exchange) ---

    /**
     * Encrypts data (expected to be a raw AES key ArrayBuffer) using a target RSA public key.
     * This is used to securely send the AES key to the peer.
     * @param {ArrayBuffer} data - The raw data (AES key) to encrypt.
     * @param {CryptoKey} targetPublicKey - The recipient's RSA public CryptoKey object.
     * @returns {Promise<ArrayBuffer|null>} The encrypted data as an ArrayBuffer, or null on failure.
     */
    async encryptRSA(data, targetPublicKey) {
        // Ensure the target public key is valid.
        if (!targetPublicKey) {
            console.error("Cannot encrypt RSA: Target public key is not provided or invalid.");
            return null;
        }
        console.log("Encrypting data with provided target RSA public key...");
        try {
            // Encrypt the data using RSA-OAEP.
            const encryptedData = await window.crypto.subtle.encrypt(
                { name: "RSA-OAEP" }, // Specify RSA algorithm for encryption
                targetPublicKey,      // The public key of the recipient
                data                  // The data (AES key buffer) to encrypt
            );
            console.log("RSA encryption successful.");
            return encryptedData; // Return the encrypted ArrayBuffer
        } catch (error) {
            console.error("Error during RSA encryption:", error);
            return null;
        }
    }

    /**
     * Decrypts data (expected to be an RSA-encrypted AES key) using the client's own private key.
     * @param {ArrayBuffer} encryptedData - The encrypted data (AES key) received from the peer.
     * @returns {Promise<ArrayBuffer|null>} The decrypted raw data (AES key) as an ArrayBuffer, or null on failure.
     */
    async decryptRSA(encryptedData) {
        // Ensure the client's private key is available.
        if (!this.privateKey) {
            console.error("Cannot decrypt RSA: Private key is not available.");
            return null;
        }
        console.log("Decrypting data with own RSA private key...");
        try {
            // Decrypt the data using RSA-OAEP.
            const decryptedData = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" }, // Specify RSA algorithm for decryption
                this.privateKey,     // Use this client's own private key
                encryptedData        // The encrypted data received
            );
            console.log("RSA decryption successful.");
            return decryptedData; // Returns the original raw AES key buffer
        } catch (error) {
            console.error("Error during RSA decryption:", error);
            return null;
        }
    }

    // --- AES Symmetric Key Handling ---

    /**
     * Generates a new AES-GCM symmetric key asynchronously.
     * These keys are typically generated per message for enhanced security.
     * @returns {Promise<CryptoKey|null>} The generated AES CryptoKey object or null on failure.
     */
    async generateSymmetricKey() {
        console.log("Generating AES-GCM symmetric key...");
        try {
            // Generate the AES key using the Web Crypto API.
            const key = await window.crypto.subtle.generateKey(
                this.aesAlgorithm, // Algorithm details (AES-GCM, 256-bit)
                this.aesKeyIsExtractable, // Allow the key to be exported (for RSA encryption)
                this.aesKeyUsages // Specify key can be used for encrypt/decrypt
            );
            console.log("AES-GCM key generated successfully.");
            return key; // Return the CryptoKey object
        } catch (error) {
            console.error("Error generating symmetric key:", error);
            return null;
        }
    }

    /**
     * Exports a symmetric AES CryptoKey to raw bytes, then encodes it as Base64.
     * This is done so the raw key can be encrypted using RSA.
     * @param {CryptoKey} key - The AES CryptoKey to export.
     * @returns {Promise<string|null>} Base64 encoded raw key string or null on failure.
     */
    async exportSymmetricKeyBase64(key) {
        if (!key) { console.error("Cannot export symmetric key: No key provided."); return null; }
        console.log("Exporting symmetric key to Base64...");
        try {
            // Export the key in 'raw' format (just the key bytes).
            const rawKeyBuffer = await window.crypto.subtle.exportKey("raw", key);
            // Convert the raw bytes (ArrayBuffer) to a Base64 string.
            const base64Key = this.arrayBufferToBase64(rawKeyBuffer);
            console.log("Symmetric key exported successfully (Base64).");
            return base64Key;
        } catch (error) {
            console.error("Error exporting symmetric key:", error);
            return null;
        }
    }

    /**
     * Imports a symmetric AES key from a Base64 encoded raw key string.
     * This is used after decrypting the RSA-encrypted AES key received from the peer.
     * @param {string} base64Key - The Base64 encoded raw key string.
     * @returns {Promise<CryptoKey|null>} The imported AES CryptoKey object or null on failure.
     */
    async importSymmetricKeyBase64(base64Key) {
        if (!base64Key) { console.error("Cannot import symmetric key: No Base64 key provided."); return null; }
        console.log("Importing symmetric key from Base64...");
        try {
            // Convert the Base64 string back to an ArrayBuffer (raw key bytes).
            const rawKeyBuffer = this.base64ToArrayBuffer(base64Key);
            // Import the raw key bytes using the Web Crypto API.
            const key = await window.crypto.subtle.importKey(
                "raw",              // Format is raw bytes
                rawKeyBuffer,       // The key buffer
                this.aesAlgorithm,  // Algorithm name (AES-GCM)
                true,               // Mark key as extractable (optional, but consistent)
                this.aesKeyUsages   // Specify key can be used for encrypt/decrypt
            );
            console.log("Symmetric key imported successfully.");
            return key; // Return the CryptoKey object
        } catch (error) {
            console.error("Error importing symmetric key:", error);
            return null;
        }
    }

    // --- AES Encryption/Decryption (Used for Message Data) ---

    /**
     * Encrypts data (e.g., chat message text) using AES-GCM with a given key.
     * Generates a new, random Initialization Vector (IV) for each encryption operation.
     * @param {ArrayBuffer | ArrayBufferView} dataBuffer - The data to encrypt (e.g., encoded text).
     * @param {CryptoKey} key - The AES CryptoKey to use for encryption.
     * @returns {Promise<{encryptedBuffer: ArrayBuffer, iv: Uint8Array}|null>} An object containing the encrypted data (ArrayBuffer) and the IV (Uint8Array) used, or null on failure. The IV must be sent alongside the ciphertext.
     */
    async encryptAES(dataBuffer, key) {
        if (!key) { console.error("Cannot encrypt AES: Key not provided."); return null; }
        try {
            // Generate a cryptographically random IV of the configured length.
            const iv = window.crypto.getRandomValues(new Uint8Array(this.aesIVLength));
            console.log("Encrypting data with AES-GCM key...");
            // Encrypt the data using AES-GCM.
            const encryptedBuffer = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv }, // Specify algorithm and the unique IV
                key,                        // The AES key
                dataBuffer                  // The data to encrypt
            );
            console.log("AES-GCM encryption successful.");
            // Return both the encrypted data and the IV, as the IV is needed for decryption.
            return { encryptedBuffer, iv };
        } catch (error) {
            console.error("Error during AES encryption:", error);
            return null;
        }
    }

    /**
     * Decrypts data using AES-GCM with a given key and Initialization Vector (IV).
     * @param {ArrayBuffer | ArrayBufferView} encryptedBuffer - The encrypted data received.
     * @param {CryptoKey} key - The AES CryptoKey to use for decryption.
     * @param {Uint8Array} iv - The Initialization Vector (IV) that was used during encryption.
     * @returns {Promise<ArrayBuffer|null>} Decrypted data as an ArrayBuffer, or null on failure (e.g., wrong key, wrong IV, corrupted data).
     */
    async decryptAES(encryptedBuffer, key, iv) {
        if (!key) { console.error("Cannot decrypt AES: Key not provided."); return null; }
        // Validate the IV length.
        if (!iv || iv.length !== this.aesIVLength) { console.error("Cannot decrypt AES: Invalid IV provided."); return null; }
        console.log("Decrypting data with AES-GCM key...");
        try {
            // Decrypt the data using AES-GCM.
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv }, // Specify algorithm and the IV used for encryption
                key,                        // The AES key
                encryptedBuffer             // The encrypted data
            );
            console.log("AES-GCM decryption successful.");
            return decryptedBuffer; // Return the original data buffer
        } catch (error) {
            // Decryption errors are common if the key, IV, or data is incorrect/tampered.
            // AES-GCM provides authenticity, so errors often indicate integrity issues.
            console.error("Error during AES decryption:", error);
            return null;
        }
    }
    // --------------------------------------

    // --- Hashing (Example - Not directly used in core E2EE chat flow currently) ---
    /**
     * Hashes data using SHA-256.
     * @param {ArrayBuffer | ArrayBufferView} data - The data to hash.
     * @returns {Promise<ArrayBuffer|null>} The SHA-256 hash as an ArrayBuffer, or null on failure.
     */
    async hashData(data) {
        console.log("Hashing data with SHA-256...");
        try {
            // Calculate the SHA-256 digest of the data.
            const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
            console.log("Data hashed successfully.");
            return hashBuffer;
        } catch (error) {
            console.error("Error during hashing:", error);
            return null;
        }
    }

    // --- Key Wiping ---
    /**
     * Clears the stored RSA public and private keys from memory.
     * Important for ephemeral sessions to remove keys when no longer needed.
     * Note: AES keys are transient and not stored here, so they don't need explicit wiping.
     */
    wipeKeys() {
        console.log("Wiping RSA cryptographic keys...");
        this.publicKey = null;
        this.privateKey = null;
        // Potentially add memory clearing techniques if supported/needed,
        // but setting to null removes the primary reference.
        console.log("RSA keys wiped.");
    }

    // --- Helper Functions ---

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

    // --- Text Encoding/Decoding Helpers ---

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
