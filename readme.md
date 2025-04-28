# HeliX Chat

**Table of Contents**

*   [Introduction / Overview](#introduction--overview)
*   [How HeliX Works & Security](#how-helix-works--security)
*   [Prerequisites](#prerequisites)
*   [Installation & Setup](#installation--setup)
*   [Running HeliX](#running-helix)
*   [Usage Guide](#usage-guide)
*   [Troubleshooting](#troubleshooting)
*   [License](#license)

---

## Introduction / Overview

**What is HeliX?**

HeliX is a browser-based, end-to-end encrypted (E2EE), ephemeral chat system. It allows two users to establish a secure, temporary chat session directly between their browsers, with a simple Python server acting only as a relay for connection setup and encrypted messages.

**Core Features:**

*   **End-to-End Encryption:** Messages are encrypted in your browser and can only be decrypted by the intended recipient. The server cannot read your messages. Uses Web Crypto API (ECDH P-256 for key agreement, HKDF for key derivation, AES-GCM for messages).
*   **Perfect Forward Secrecy (PFS):** Uses ephemeral ECDH keys for each session, ensuring that even if long-term keys were compromised (though HeliX doesn't use long-term keys), past session messages cannot be decrypted.
*   **Connection Verification (SAS):** Uses Short Authentication Strings (Safety Numbers) derived from session keys, compared out-of-band, to verify connection integrity against Man-in-the-Middle attacks before chatting begins.
*   **Ephemeral:** Chat messages exist only in the browser's memory during an active session. They are lost when the session ends, the browser tab is closed, or the server restarts. No message history is stored on the server or persistently on the client.
*   **Serverless Message Storage:** The Python server only relays data; it does not store message content.
*   **Secure File Transfer:** Allows sending and receiving files directly between peers within an active chat session. The server cannot decrypt or access file content.
*   **Simple Identifier System:** Users register with a temporary, unique ID for the duration of their connection to the server. IDs must be shared out-of-band.
*   **Self-Hosted:** You run the server components yourself, giving you control over the relay infrastructure.
*   **Customizable Chat Appearance:** Allows users to adjust chat font family and size via a settings menu.
*   **Basic & Focused:** Designed for simple, secure, temporary peer-to-peer conversations and file sharing.

**Target Use Case:**

HeliX is ideal for situations where you need a quick, secure way to chat or share files with someone without relying on third-party services or leaving a persistent message history. Examples include sharing sensitive information temporarily, quick technical support sessions, or private coordination.

**Disclaimer:**

HeliX is currently experimental software. While it implements strong E2EE principles including PFS and SAS verification, it has not undergone a formal security audit. Use it at your own risk. The security of your communication depends heavily on the correct setup, the security of the devices used, the secure exchange of user identifiers, **correctly performing the out-of-band SAS comparison**, and trusting the `mkcert` local Certificate Authority if you install it.

---

## How HeliX Works & Security

**High-Level Architecture:**

1.  **Client:** Runs entirely in the user's web browser using HTML, CSS, and JavaScript. It handles:
    *   User Interface (UI) interactions, including settings, notifications, SAS verification, etc.
    *   Generating ephemeral cryptographic keys (ECDH and AES) via the browser's Web Crypto API.
    *   Performing key agreement (ECDH) and key derivation (HKDF).
    *   Deriving Short Authentication Strings (SAS) from exchanged public keys.
    *   Encrypting and decrypting messages using the derived session key.
    *   Communicating with the WSS server via Secure WebSockets.
2.  **HTTPS Server:** A simple Python server (integrated into `helix_manager.py`) serves the static client files (HTML, CSS, JS, audio) to the browser over HTTPS. This is **required** for the Web Crypto API and IndexedDB to function securely.
3.  **WSS Server:** A Python server using the `websockets` library. It acts as a signaling and relay server:
    *   Manages user registrations (mapping temporary IDs to connections).
    *   Relays handshake messages (public keys, challenges, SAS confirmations) between clients.
    *   Relays the **encrypted** chat messages between connected peers.
    *   Tracks active session pairings solely for notifying users of peer disconnections.
    *   **Crucially, the WSS server never sees the plaintext message content, derived session keys, SAS codes, or plaintext file content.**

**End-to-End Encryption (E2EE) with Perfect Forward Secrecy (PFS) and Connection Verification (SAS):**

HeliX ensures that only the sender and the intended recipient can read messages, that past sessions remain secure, and provides a mechanism to verify the connection against Man-in-the-Middle (MitM) attacks.

1.  **Session Handshake & Key Agreement:** When User A wants to chat with User B:
    *   Each user generates a new, temporary (ephemeral) ECDH key pair (using the P-256 curve).
    *   They exchange their public ECDH keys via the relay server.
    *   Each user independently computes the same shared secret using their own private ECDH key and the peer's public ECDH key. This secret is never transmitted directly.
    *   Both users process the raw shared secret through a Key Derivation Function (HKDF with SHA-256) to derive a strong, shared 256-bit AES-GCM symmetric session key.
    *   They perform a challenge-response verification: one user encrypts known challenge data using the *derived AES session key*, and the other must decrypt it and encrypt it back. This confirms both parties successfully derived the same session key from the exchanged public keys, authenticating the key agreement process.
2.  **Short Authentication String (SAS) Verification:**
    *   *After* the cryptographic handshake completes, each client independently computes a Short Authentication String (SAS) - typically a short sequence of numbers - derived from the public keys exchanged during *their specific* handshake instance.
    *   The clients display this SAS code to their respective users.
    *   **Crucially, users must compare these SAS codes using a separate, secure channel (e.g., phone call, video chat).** This comparison verifies the integrity of the key exchange. If the codes match, users can be confident they established a secure channel with each other and that no MitM attacker interfered with the key exchange. If the codes do *not* match, the connection should be aborted as it indicates a potential security issue.
    *   Users click "Confirm Match" in the UI only if the codes match OOB. Chatting is enabled only after *both* users have confirmed.
3.  **Message Encryption:** For each message sent during an active session (after SAS confirmation):
    *   The message text is encrypted using the *single derived AES-GCM session key* and a unique Initialization Vector (IV). AES-GCM provides both confidentiality and authenticity.
    *   The IV and the AES-encrypted message data are sent to the WSS server. (The derived key itself is never sent).
4.  **Server Relay:** The WSS server receives the IV and encrypted data bundle and relays it to the recipient *without* being able to decrypt any part of it (as it doesn't have the derived session key).
5.  **Message Decryption:** The recipient's client:
    *   Uses the derived AES-GCM session key (which they already computed during the handshake) and the received IV to decrypt the actual message data.

**Secure File Transfer:**

*   **Initiation:** Sender clicks the attach button, selects a file, and a request (containing filename, size, type, and a unique transfer ID) is sent to the peer via the relay server.
*   **Acceptance:** Receiver sees the request and clicks "Accept" or "Reject". Acceptance/rejection is relayed back.
*   **Chunking & Encryption:** Upon acceptance, the sender's browser reads the file in chunks. Each chunk is encrypted using the *derived AES-GCM session key* and a unique IV.
*   **Relay:** Encrypted chunks (with IV and chunk index) are sent to the WSS server and relayed to the receiver. The server cannot decrypt the chunks.
*   **Temporary Storage:** The receiver's browser decrypts each chunk and temporarily stores it in IndexedDB (browser's local database).
*   **Reassembly & Download:** Once all chunks are received and decrypted, the receiver's browser reassembles them into a Blob. A temporary Blob URL is generated, and a "Download" link appears, allowing the user to save the file. The Blob URL is revoked after clicking or when the session ends/message is removed.

**Ephemeral Nature:**

*   Messages are not stored on the server disk or database.
*   Messages are not stored persistently in the browser (e.g., in `localStorage`). They only reside in active JavaScript memory.
*   File chunks are stored *temporarily* in the receiver's browser IndexedDB during transfer and are deleted after successful assembly or if the transfer fails/is cancelled/session ends. The final reassembled file exists only as a Blob until the user explicitly saves it via the download link.
*   Ephemeral ECDH keys are generated per session and discarded. The derived AES key exists only for the session duration. SAS codes are derived ephemerally and not stored.
*   Closing the browser tab, ending the session via the "Disconnect" button, or stopping the WSS server will cause the messages, session keys, SAS data, and any incomplete file transfer data to be lost.

**HTTPS Importance:**

Modern web browsers require a secure context (HTTPS or `localhost`) to grant access to the Web Crypto API (used for encryption) and IndexedDB (used for file transfer storage). The integrated HTTPS server provides this secure context. We use `mkcert` to easily generate locally-trusted TLS certificates for development and local network use.

**Identifier System:**

HeliX uses simple, temporary identifiers chosen by the user upon connecting.

*   These IDs are only valid while the user is connected to the WSS server.
*   IDs must be unique on the server at any given time.
*   **Crucially, you must share your ID with the person you want to chat with through a separate channel** (e.g., phone call, text message, in person, etc). HeliX does not provide a discovery mechanism.

**Security Considerations & Assumptions:**

*   **Server Trust:** You must trust the machine running the WSS and HTTPS servers. While the server cannot read messages or files, a compromised server could potentially interfere with connections or attempt more advanced attacks (though TLS and E2EE mitigate many risks).
*   **Client Trust:** Communication is only as secure as the endpoint devices. If a user's computer or browser is compromised, the E2EE can be bypassed locally.
*   **`mkcert` CA Trust:** For browsers to accept the HTTPS connection without warnings, the `mkcert` local Certificate Authority (CA) must be installed and trusted by your operating system/browser. The manager script offers to run `mkcert -install`, but this requires user confirmation and potentially administrator privileges. Accessing the client via an IP address or hostname not listed in the certificate (`localhost`, `127.0.0.1`) *will* result in browser warnings, even if the CA is installed. Trusting this CA is a security consideration.
*   **Identifier Exchange:** The security of initiating a conversation depends on how securely you exchange identifiers with your peer.
*   **SAS Verification Importance:** The protection against Man-in-the-Middle (MitM) attacks relies **entirely** on users comparing the Short Authentication String (SAS) codes out-of-band *before* confirming the match in the UI. If users skip this step or compare codes insecurely, the MitM protection is negated.
*   **Metadata Protection:** The server knows *who* is registered (`identifier` -> `connection`) and relays messages (including handshake, SAS confirmation, chat, and file transfer control messages) between peers based on `targetId`.
    *   **Disconnect Notifications:** To provide timely notifications when a chat partner disconnects, the server temporarily tracks active session pairings (e.g., `Alice123` <-> `Bob456`). This pairing information exists only while the session is considered active by the server and is deleted when a user disconnects or explicitly ends the session.
    *   **Implication:** This increases the *metadata* stored on the server. If the server is compromised, an attacker could gain a clearer real-time view of *who is actively chatting with whom* and potentially infer file transfer activity (though not content). This **does not** compromise the end-to-end encryption of the message or file *content*, which remains unreadable by the server.
*   **Perfect Forward Secrecy:** HeliX implements PFS using ephemeral ECDH keys for each session. This means that even if an attacker could somehow compromise keys used in one session, they could not use that information to decrypt messages or files from *past* sessions.

---

## Prerequisites

Before setting up HeliX, ensure you have the following:

*   **Operating System:** Windows, macOS, or Linux.
*   **Python:** Python 3.7 or newer recommended. Download from [python.org](https://www.python.org/downloads/). Ensure Python and Pip are added to your system's PATH during installation.
*   **Pip:** Python's package installer, usually included with Python 3.4+.
*   **`mkcert` Utility:** A tool for creating locally-trusted development certificates.
    *   Download from the [mkcert GitHub Releases page](https://github.com/FiloSottile/mkcert/releases).
    *   Follow the specific setup instructions in the "Installation & Setup" section below *before* running the HeliX manager's certificate option.
*   **Modern Web Browser:** Firefox, Chrome, Edge, or Safari recommended (supporting Web Crypto API, WebSockets, and IndexedDB).
*   **Out-of-Band Communication Channel:** A separate, secure way to communicate with your peer (e.g., phone call, video chat, another trusted messenger) is **required** to exchange IDs and verify SAS codes.

---

## Installation & Setup

1.  **Get the Code:**
    *   **Option A (Git):** Clone the repository:
        ```bash
        git clone https://github.com/DDeal/HeliX.git
        cd helix
        ```
    *   **Option B (Download):** Download the project ZIP file and extract it. Navigate into the extracted `helix` directory in your terminal.

2.  **Directory Structure:** The expected project structure is as follows:
    ```
    helix/
    ├── .gitignore             # Specifies intentionally untracked files for Git
    ├── helix_manager.py       # Main control script for starting/managing servers
    ├── readme.md              # This file
    │
    ├── certs/                 # Directory for TLS certificates
    │   └── .info.txt          # Placeholder file
    │
    ├── client/                # Contains all client-side browser code
    │   ├── index.html         # Main HTML file for the client interface
    │   ├── favicon.ico        # Browser tab/bookmark icon
    │   ├── audio/             # Directory for audio files
    │   │   ├── begin.mp3
    │   │   ├── end.mp3
    │   │   ├── error.mp3
    │   │   ├── notification.mp3
    │   │   ├── registered.mp3
    │   │   ├── receiverequest.mp3
    │   │   └── sendrequest.mp3
    │   ├── css/
    │   │   └── style.css      # Stylesheet for the client interface
    │   └── js/
    │       ├── config.js          # Client configuration (e.g., WebSocket URL, DEBUG flag)
    │       ├── CryptoModule.js    # Handles cryptographic operations (Web Crypto API)
    │       ├── main.js            # Main client execution script, initializes components
    │       ├── Session.js         # Represents a single chat session with a peer
    │       ├── SessionManager.js  # Manages multiple chat sessions
    │       ├── UIController.js    # Handles updates to the HTML user interface
    │       └── WebSocketClient.js # Manages the WebSocket connection and message handling
    │
    └── logs/                  # Contains HTTPS server logs
    │   └── .info.txt          # Placeholder file
    |
    └── server/                # Contains all server-side Python code
        ├── config.py          # Server configuration (WSS/HTTPS Host/Port, DEBUG flag)
        ├── main.py            # Entry point for the WSS server process
        ├── requirements.txt   # Lists Python dependencies (currently just 'websockets')
        └── server.py          # Core WSS server logic (connection handling, message relay)
    ```

3.  **Run the Manager Script (Initial Run):**
    *   Open your terminal or command prompt, navigate to the `helix` directory.
    *   Run the manager script:
        ```bash
        python helix_manager.py
        ```

4.  **Dependency Check:**
    *   The script will automatically check if the required Python packages listed in `server/requirements.txt` are installed.
    *   If not found, it will prompt you to install them using `pip`. Enter `y` to allow installation.

5.  **Install `mkcert` & Generate Certificates (Using Menu Option 7):**
    *   The manager script requires TLS certificates (`cert.pem`, `key.pem`) in the `certs/` directory to run the HTTPS server. Use **Menu Option 7** ("Manage TLS Certificates") to handle this *before* starting the servers.
    *   **`mkcert` Setup (Do this *before* selecting Menu Option 7):**
        *   **Windows:** Install via `winget install mkcert` or `choco install mkcert`, OR download `mkcert-vX.Y.Z-windows-amd64.exe`, rename it to `mkcert.exe`, and place it **inside the `helix/certs/` directory**. Ensure it's runnable.
        *   **Linux/macOS:** Install `mkcert` using your system's package manager so it's available in your PATH. Examples:
            *   macOS (using Homebrew): `brew install mkcert`
            *   Linux (Debian/Ubuntu): `sudo apt update && sudo apt install mkcert`
            *   Linux (Other): Consult your distribution's package manager or the mkcert documentation.
    *   **Running Menu Option 7:**
        *   Select option 7 from the manager menu.
        *   The script will find `mkcert`.
        *   It will display the `mkcert` version found.
        *   **CA Installation:** It will ask if you want to run `mkcert -install`. **Recommended:** Enter `y`. This installs the `mkcert` local CA into your trust stores, preventing most browser warnings for `https://localhost` or `https://127.0.0.1`. Requires Admin/Sudo privileges.
        *   **Certificate Overwrite/Backup:** Handles existing certificates.
        *   **Generation:** Generates `cert.pem` and `key.pem` for `localhost` and `127.0.0.1`.

6.  **Network Configuration for External Access (Optional):**
    *   By default, the servers listen on `0.0.0.0`, meaning they accept connections from `localhost` and other devices on your local network (LAN).
    *   To allow connections from *outside* your local network (e.g., over the internet), you typically need to configure:
        *   **Firewall:** Allow incoming connections on the WSS and HTTPS ports (default: TCP 5678, 8888).
        *   **Router Port Forwarding:** Forward external ports to the internal IP of the HeliX server machine.
        *   **Certificate Warnings:** Accessing via IP or external hostname *will* cause browser certificate warnings with the default `mkcert` certificates. You'll need to bypass these warnings. For seamless access, consider a reverse proxy setup (advanced).

---

## Running HeliX

1.  **Start the Servers:**
    *   Run the manager script: `python helix_manager.py`
    *   Use the menu (options 1-6) to configure ports, hosts, or debug modes if desired.
        *   **Options 1-2:** Configure WSS Host/Port (saved to `server/config.py`).
        *   **Options 3-4:** Configure HTTPS Host/Port (for this manager session only).
        *   **Option 5:** Toggle Server Debug Logging (saved to `server/config.py`). Enables verbose server console logs.
        *   **Option 6:** Toggle Client Debug Logging (saved to `client/js/config.js`). Enables verbose browser console logs.
    *   Ensure certificates exist (use Menu Option 7 if needed).
    *   Choose **Option 8** Start Servers. This will:
        *   Silently save the current WSS Host, WSS Port, and Server Debug settings to `server/config.py`.
        *   Silently save the current Client Debug setting to `client/js/config.js`.
        *   Start both the WSS and HTTPS servers using the current settings.

2.  **Expected Output:**
    *   You will see messages indicating the HTTPS server thread and WSS server subprocess are starting.
    *   Real-time logs from the WSS server (connections, disconnections, errors, and potentially more if Server Debug is enabled) will be printed, prefixed with `[WSS]`.
    *   HTTPS server activity is logged to `logs/https_server.log`.

3.  **Access the Client:**
    *   Open your web browser (Firefox, Chrome, Edge recommended).
    *   Navigate to the HTTPS URL corresponding to the configured HTTPS Host/Port. Defaults:
        *   `https://localhost:8888`
        *   `https://127.0.0.1:8888`
    *   If accessing from another device on your LAN, use `https://<helix-server-lan-ip>:8888`.
    *   **Browser Warnings:**
        *   You *may* still see a security warning page (e.g., "Your connection is not private") if the `mkcert` CA wasn't installed/trusted correctly.
        *   If accessing locally via IP address, you *will* see the warning.
        *   For local/trusted use, you can typically bypass this warning: click "Advanced", then look for an option like "Proceed to ... (unsafe)" or "Accept the Risk and Continue".

4.  **Stop the Servers:**
    *   Go back to the terminal where `helix_manager.py` is running.
    *   Press `Ctrl+C`.
    *   The manager script will intercept this signal and attempt to gracefully shut down both the WSS process and the HTTPS server thread.

---

## Usage Guide

1.  **Access Client:** Open the correct `https://...` URL in your browser (see "Running HeliX").
2.  **Registration:** Choose a unique temporary ID (3-30 chars, letters, numbers, -, \_) and click "Register".
3.  **Main Interface:** Familiarize yourself with the Sidebar, Main Content area, and Status Bar.
4.  **Sidebar Controls:**
    *   **Mute Button (🔊/🔇):** Click the speaker icon to toggle notification sounds on or off.
    *   **Settings Button (⚙️):** Click the gear icon to open the settings pane.
5.  **Settings Pane:**
    *   **Font Family:** Select a different font for the chat message area from the dropdown.
    *   **Font Size:** Enter or use the arrows to change the font size (in pixels) for the chat message area.
    *   Click "Close" to save and exit the settings pane.
6.  **Share Your ID:** Securely communicate your registered ID (shown in the sidebar) to your peer **out-of-band** (e.g., phone call, video chat, another trusted messenger). This is the first OOB step.
7.  **Starting a Chat:** Enter your peer's ID in the sidebar input field and click "Start Chat".
8.  **Receiving a Chat Request:** If someone requests a chat with you, click "Accept" or "Deny".
9.  **SAS Verification (IMPORTANT):**
    *   After the initial handshake completes (Accept/Deny), a **"Verify Connection"** pane will appear, displaying a Short Authentication String (SAS) code (e.g., `123 456`).
    *   **You MUST compare this code with the code shown on your peer's screen using a separate, secure communication channel** (e.g., read it aloud over a phone call or video chat). This verifies the connection against Man-in-the-Middle attacks. This is the second OOB step.
    *   If the codes **match exactly**, both users should click **"Confirm Match"**.
    *   If the codes **do not match**, click **"Deny / Abort"**. Do not proceed with the chat.
    *   If you click "Confirm Match" but your peer hasn't yet, a "Cancel" button will appear, allowing you to abort while waiting.
    *   **Chatting is only enabled after BOTH users have confirmed the SAS match.**
10. **Active Chatting:** Once SAS verification is complete, the chat input becomes active. Type messages in the input field at the bottom of the chat view and press Enter or click "Send".
11. **Slash Commands:** Type the following commands into the message input field during an active chat session:
    *   `/me <action text>`: Displays "* YourID action text" to both users (e.g., `/me waves`).
    *   `/end`: Ends the current chat session (same as clicking the "End Session" button).
    *   `/version`: Displays the HeliX client version information in your chat window.
    *   `/info`: Displays information about the current connection and session in your chat window.
    *   `/help`: Displays this list of available commands in your chat window.
12. **Sending a File:**
    *   During an active chat, click the paperclip (📎) button next to the message input field.
    *   Select the file you wish to send using your system's file browser.
    *   A file transfer request message will appear in the chat for both users.
    *   The sender will see progress updates and a "Cancel" button.
    *   The receiver will see "Accept" and "Reject" buttons.
    *   **Note:** There is a file size limit (default 100 MB, configurable).
13. **Receiving a File:**
    *   When a peer sends a file request, click "Accept" to start the transfer or "Reject" to deny it.
    *   If accepted, you will see progress updates.
    *   Once the transfer is complete, a "Download" link will appear. Click it to save the file to your computer.
14. **Ending a Session:** Click the "Disconnect" button in the chat header or use the `/end` command.
15. **Switching Between Sessions:** Click peer IDs in the sidebar list to switch between active or pending sessions.
16. **Understanding Info Panes:** Read messages about errors, denials, or timeouts that appear in the main content area.

---

## Troubleshooting

*   **Dependency Check Fails:** Ensure `server/requirements.txt` exists and is readable. Ensure `pip` is installed and in your PATH. Try running `pip install -r server/requirements.txt` manually.
*   **`mkcert` not found:** Ensure `mkcert` is installed correctly and accessible. See "Installation & Setup" section 5.
*   **Browser Certificate Warnings (NET::ERR_CERT_AUTHORITY_INVALID, etc.):**
    *   **Cause:** Browser doesn't trust `mkcert` CA, or accessing via IP/hostname not in cert.
    *   **Solution 1 (Recommended):** Use Menu Option 7 -> `mkcert -install` (requires admin/sudo). Restart browser. Best for `localhost`/`127.0.0.1`.
    *   **Solution 2 (Bypass):** Click "Advanced" -> "Proceed to..." or "Accept Risk...".
    *   **Solution 3 (External/Domain):** Use a reverse proxy (advanced).
*   **Cannot Connect to Server:**
    *   Verify servers started successfully in manager console.
    *   Check WSS/HTTPS ports match browser URL and client config (`js/config.js`).
    *   Check OS firewall rules on server.
    *   If using LAN IP, ensure it's correct.
*   **Cannot Connect from Outside LAN:** Verify firewall rules *and* router port forwarding. See "Installation & Setup" section 6.
*   **Registration Failed ("Identifier already taken" or "Invalid identifier format"):** Choose a different temporary ID matching the required format (3-30 chars, letters, numbers, -, \_). An error sound may play.
*   **Chat Request Failed ("User '...' is unavailable."):** Verify peer's ID and ensure they are online and registered. The peer might have disconnected. An error sound may play.
*   **Port Conflict ("Address already in use"):** Stop the other application or configure HeliX to use different ports via the manager menu (Options 1-4).
*   **Handshake Timeout:** If the connection hangs during initiation or verification, check console logs on both clients (enable Client Debug via manager option 6) and the server (enable Server Debug via manager option 5) for errors. Network latency or firewall issues could interfere. An error sound may play.
*   **SAS Verification Fails / Codes Don't Match:**
    *   **Cause:** This indicates a potential security issue, likely a Man-in-the-Middle (MitM) attack, or a bug in the application.
    *   **Action:** **DO NOT CLICK "Confirm Match".** Click **"Deny / Abort"**. Securely communicate with your intended peer out-of-band to confirm their ID and try establishing the connection again. If the problem persists, investigate potential network interference or report the issue.
*   **Stuck on SAS Verification Pane:**
    *   **Cause:** You clicked "Confirm Match", but your peer hasn't yet, or they clicked "Deny / Abort", or they disconnected.
    *   **Action:** Wait a reasonable amount of time for your peer to confirm. If they don't, or if you suspect an issue, click the **"Cancel"** button to abort the session attempt. You can then try re-initiating the session.
*   **Disconnected by Server (Rate Limit):** If you see an alert about being disconnected for exceeding the rate limit, you sent too many messages too quickly. Wait a moment and reconnect. An error sound will play.
*   **File Transfer Fails:**
    *   **Size Limit:** Ensure the file does not exceed the configured maximum size (default 100 MB).
    *   **Peer Disconnects:** If the peer disconnects during the transfer, it will fail.
    *   **Network Issues:** Unstable connections can cause chunk transfer failures.
    *   **Browser Storage:** The receiver needs sufficient temporary storage space (IndexedDB). Check browser settings or clear site data if issues persist. Errors during chunk storage or reassembly will be reported.
    *   **Console Logs:** Check browser console (F12) on both sender and receiver for specific error messages related to encryption, IndexedDB, or network sends/receives.
*   **File Download Link Doesn't Work:**
    *   The temporary Blob URL might have expired or been revoked (e.g., if the session ended or the message was removed before clicking). Try having the sender resend the file.
    *   Check browser console for errors related to Blob URLs or downloads.
*   **No Sound Playing:**
    *   Check if sounds are muted using the mute button (🔇) in the sidebar.
    *   Ensure your system/browser volume is not muted or too low.
    *   Check the browser console (F12) for errors related to loading or playing audio files (e.g., file not found, format not supported, autoplay blocked). Autoplay might require user interaction with the page first in some browsers.
    *   Verify the audio files exist in the `client/audio/` directory.
*   **Chat Font/Size Not Changing:**
    *   Ensure you are clicking the "Close" button in the settings pane after making changes (though changes should apply live).
    *   Check the browser console (F12) for any JavaScript errors related to applying styles.

---

## License

MIT License

Copyright (c) 2025 DigitalMafia / HeliX E2EE Chat

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.