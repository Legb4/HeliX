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
*   **Ephemeral:** Chat messages exist only in the browser's memory during an active session. They are lost when the session ends, the browser tab is closed, or the server restarts. No message history is stored on the server or persistently on the client.
*   **Serverless Message Storage:** The Python server only relays data; it does not store message content.
*   **Simple Identifier System:** Users register with a temporary, unique ID for the duration of their connection to the server. IDs must be shared out-of-band.
*   **Self-Hosted:** You run the server components yourself, giving you control over the relay infrastructure.
*   **Basic & Focused:** Designed for simple, secure, temporary peer-to-peer conversations.

**Target Use Case:**

HeliX is ideal for situations where you need a quick, secure way to chat with someone without relying on third-party services or leaving a persistent message history. Examples include sharing sensitive information temporarily, quick technical support sessions, or private coordination.

**Disclaimer:**

HeliX is currently experimental software. While it implements strong E2EE principles including PFS, it has not undergone a formal security audit. Use it at your own risk. The security of your communication depends heavily on the correct setup, the security of the devices used, the secure exchange of user identifiers, and trusting the `mkcert` local Certificate Authority if you install it.

---

## How HeliX Works & Security

**High-Level Architecture:**

1.  **Client:** Runs entirely in the user's web browser using HTML, CSS, and JavaScript. It handles:
    *   User Interface (UI) interactions.
    *   Generating ephemeral cryptographic keys (ECDH and AES) via the browser's Web Crypto API.
    *   Performing key agreement (ECDH) and key derivation (HKDF).
    *   Encrypting and decrypting messages using the derived session key.
    *   Communicating with the WSS server via Secure WebSockets.
2.  **HTTPS Server:** A simple Python server (integrated into `helix_manager.py`) serves the static client files (HTML, CSS, JS) to the browser over HTTPS. This is **required** for the Web Crypto API to function securely.
3.  **WSS Server:** A Python server using the `websockets` library. It acts as a signaling and relay server:
    *   Manages user registrations (mapping temporary IDs to connections).
    *   Relays handshake messages (public keys, challenges) between clients.
    *   Relays the **encrypted** chat messages between connected peers.
    *   Tracks active session pairings solely for notifying users of peer disconnections.
    *   **Crucially, the WSS server never sees the plaintext message content or the derived session keys.**

**End-to-End Encryption (E2EE) with Perfect Forward Secrecy (PFS):**

HeliX ensures that only the sender and the intended recipient can read messages, and that past sessions remain secure even if future keys were somehow compromised. This is achieved through:

1.  **Session Handshake & Key Agreement:** When User A wants to chat with User B:
    *   Each user generates a new, temporary (ephemeral) ECDH key pair (using the P-256 curve).
    *   They exchange their public ECDH keys via the relay server.
    *   Each user independently computes the same shared secret using their own private ECDH key and the peer's public ECDH key. This secret is never transmitted directly.
    *   Both users process the raw shared secret through a Key Derivation Function (HKDF with SHA-256) to derive a strong, shared 256-bit AES-GCM symmetric session key.
    *   They perform a challenge-response verification: one user encrypts known challenge data using the *derived AES session key*, and the other must decrypt it and encrypt it back. This confirms both parties successfully derived the same session key from the exchanged public keys, authenticating the key agreement process.
2.  **Message Encryption:** For each message sent during an active session:
    *   The message text is encrypted using the *single derived AES-GCM session key* and a unique Initialization Vector (IV). AES-GCM provides both confidentiality and authenticity.
    *   The IV and the AES-encrypted message data are sent to the WSS server. (The derived key itself is never sent).
3.  **Server Relay:** The WSS server receives the IV and encrypted data bundle and relays it to the recipient *without* being able to decrypt any part of it (as it doesn't have the derived session key).
4.  **Message Decryption:** The recipient's client:
    *   Uses the derived AES-GCM session key (which they already computed during the handshake) and the received IV to decrypt the actual message data.

**Ephemeral Nature:**

*   Messages are not stored on the server disk or database.
*   Messages are not stored persistently in the browser (e.g., in `localStorage`). They only reside in active JavaScript memory.
*   Ephemeral ECDH keys are generated per session and discarded. The derived AES key exists only for the session duration.
*   Closing the browser tab, ending the session via the "Disconnect" button, or stopping the WSS server will cause the messages and session keys to be lost.

**HTTPS Importance:**

Modern web browsers require a secure context (HTTPS or `localhost`) to grant access to the Web Crypto API, which HeliX relies on for all its cryptographic operations. The integrated HTTPS server provides this secure context. We use `mkcert` to easily generate locally-trusted TLS certificates for development and local network use.

**Identifier System:**

HeliX uses simple, temporary identifiers chosen by the user upon connecting.

*   These IDs are only valid while the user is connected to the WSS server.
*   IDs must be unique on the server at any given time.
*   **Crucially, you must share your ID with the person you want to chat with through a separate channel** (e.g., phone call, text message, in person, etc). HeliX does not provide a discovery mechanism.

**Security Considerations & Assumptions:**

*   **Server Trust:** You must trust the machine running the WSS and HTTPS servers. While the server cannot read messages, a compromised server could potentially interfere with connections or attempt more advanced attacks (though TLS and E2EE mitigate many risks).
*   **Client Trust:** Communication is only as secure as the endpoint devices. If a user's computer or browser is compromised, the E2EE can be bypassed locally.
*   **`mkcert` CA Trust:** For browsers to accept the HTTPS connection without warnings, the `mkcert` local Certificate Authority (CA) must be installed and trusted by your operating system/browser. The manager script offers to run `mkcert -install`, but this requires user confirmation and potentially administrator privileges. Accessing the client via an IP address or hostname not listed in the certificate (`localhost`, `127.0.0.1`) *will* result in browser warnings, even if the CA is installed. Trusting this CA is a security consideration.
*   **Identifier Exchange:** The security of initiating a conversation depends on how securely you exchange identifiers with your peer.
*   **Metadata Protection:** The server knows *who* is registered (`identifier` -> `connection`) and relays messages between peers based on `targetId`.
    *   **Disconnect Notifications:** To provide timely notifications when a chat partner disconnects, the server temporarily tracks active session pairings (e.g., `Alice123` <-> `Bob456`). This pairing information exists only while the session is considered active by the server and is deleted when a user disconnects or explicitly ends the session.
    *   **Implication:** This increases the *metadata* stored on the server. If the server is compromised, an attacker could gain a clearer real-time view of *who is actively chatting with whom*. This **does not** compromise the end-to-end encryption of the message *content*, which remains unreadable by the server.
*   **Perfect Forward Secrecy:** HeliX implements PFS using ephemeral ECDH keys for each session. This means that even if an attacker could somehow compromise keys used in one session, they could not use that information to decrypt messages from *past* sessions.

---

## Prerequisites

Before setting up HeliX, ensure you have the following:

*   **Operating System:** Windows, macOS, or Linux.
*   **Python:** Python 3.7 or newer recommended. Download from [python.org](https://www.python.org/downloads/). Ensure Python and Pip are added to your system's PATH during installation.
*   **Pip:** Python's package installer, usually included with Python 3.4+.
*   **`mkcert` Utility:** A tool for creating locally-trusted development certificates.
    *   Download from the [mkcert GitHub Releases page](https://github.com/FiloSottile/mkcert/releases).
    *   Follow the specific setup instructions in the "Installation & Setup" section below *before* running the HeliX manager's certificate option.

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
    │   └── mkcert.exe         # (Windows Only, Optional) Place downloaded mkcert here if not in PATH
    │
    ├── client/                # Contains all client-side browser code
    │   ├── index.html         # Main HTML file for the client interface
    │   ├── css/
    │   │   └── style.css      # Stylesheet for the client interface
    │   └── js/
    │       ├── config.js          # Client configuration (e.g., WebSocket URL)
    │       ├── CryptoModule.js    # Handles cryptographic operations (Web Crypto API)
    │       ├── main.js            # Main client execution script, initializes components
    │       ├── Session.js         # Represents a single chat session with a peer
    │       ├── SessionManager.js  # Manages multiple chat sessions
    │       ├── UIController.js    # Handles updates to the HTML user interface
    │       └── WebSocketClient.js # Manages the WebSocket connection and message handling
    │
    └── server/                # Contains all server-side Python code
        ├── config.py          # Server configuration (WSS/HTTPS Host/Port)
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
    *   The script will automatically check if the required `websockets` Python library is installed.
    *   If not found, it will prompt you to install it using `pip`. Enter `y` to allow installation.

5.  **Install `mkcert` & Generate Certificates (Using Menu Option 5):**
    *   The manager script requires TLS certificates (`cert.pem`, `key.pem`) in the `certs/` directory to run the HTTPS server. Use **Menu Option 5** ("Manage TLS Certificates") to handle this *before* starting the servers.
    *   **`mkcert` Setup (Do this *before* selecting Menu Option 5):**
        *   **Windows:** Install via `winget install mkcert` or `choco install mkcert`, OR download `mkcert-vX.Y.Z-windows-amd64.exe`, rename it to `mkcert.exe`, and place it **inside the `helix/certs/` directory**. Ensure it's runnable.
        *   **Linux/macOS:** Install `mkcert` using your system's package manager so it's available in your PATH. Examples:
            *   macOS (using Homebrew): `brew install mkcert`
            *   Linux (Debian/Ubuntu): `sudo apt update && sudo apt install mkcert`
            *   Linux (Other): Consult your distribution's package manager or the mkcert documentation.
    *   **Running Menu Option 5:**
        *   Select option 5 from the manager menu.
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
    *   Use the menu (options 1-4) to configure ports/hosts if desired.
    *   Ensure certificates exist (use Menu Option 5 if needed).
    *   Choose a start option:
        *   **Option 6:** Save current config to `server/config.py` and start servers.
        *   **Option 7:** Start servers using current settings without saving.

2.  **Expected Output:**
    *   You will see messages indicating the HTTPS server thread and WSS server subprocess are starting.
    *   Real-time logs from the WSS server (connections, registrations, relays) will be printed, prefixed with `[WSS]`.
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

*(This section remains the same as it describes the client-side interaction)*

1.  **Access Client:** Open the correct `https://...` URL in your browser (see "Running HeliX").
2.  **Registration:** Choose a unique temporary ID (3-30 chars, letters, numbers, -, \_) and click "Register".
3.  **Main Interface:** Familiarize yourself with the Sidebar, Main Content area, and Status Bar.
4.  **Share Your ID:** Securely communicate your registered ID to your peer out-of-band.
5.  **Starting a Chat:** Enter peer's ID in the sidebar, click "Start Chat".
6.  **Receiving a Chat Request:** Accept or Deny the prompt in the main content area or by clicking the session in the sidebar.
7.  **Active Chatting:** Type messages in the chat view.
8.  **Ending a Session:** Click "Disconnect" in the chat header. Your peer will be notified.
9.  **Switching Between Sessions:** Click peer IDs in the sidebar.
10. **Understanding Info Panes:** Read messages about errors, denials, or timeouts.

---

## Troubleshooting

*   **`websockets` library not found:** Run `python helix_manager.py`. Allow install (`y`) or run `pip install websockets`.
*   **`mkcert` not found:** Ensure `mkcert` is installed correctly and accessible. See "Installation & Setup" section 5.
*   **Browser Certificate Warnings (NET::ERR_CERT_AUTHORITY_INVALID, etc.):**
    *   **Cause:** Browser doesn't trust `mkcert` CA, or accessing via IP/hostname not in cert.
    *   **Solution 1 (Recommended):** Use Menu Option 5 -> `mkcert -install` (requires admin/sudo). Restart browser. Best for `localhost`/`127.0.0.1`.
    *   **Solution 2 (Bypass):** Click "Advanced" -> "Proceed to..." or "Accept Risk...".
    *   **Solution 3 (External/Domain):** Use a reverse proxy (advanced).
*   **Cannot Connect to Server:**
    *   Verify servers started successfully in manager console.
    *   Check WSS/HTTPS ports match browser URL and client config (`js/config.js`).
    *   Check OS firewall rules on server.
    *   If using LAN IP, ensure it's correct.
*   **Cannot Connect from Outside LAN:** Verify firewall rules *and* router port forwarding. See "Installation & Setup" section 7.
*   **Registration Failed ("Identifier already taken" or "Invalid identifier format"):** Choose a different temporary ID matching the required format (3-30 chars, letters, numbers, -, \_).
*   **Chat Request Failed ("User '...' is unavailable."):** Verify peer's ID and ensure they are online and registered. The peer might have disconnected.
*   **Port Conflict ("Address already in use"):** Stop the other application or configure HeliX to use different ports via the manager menu (Options 1-4).
*   **Handshake Timeout:** If the connection hangs during initiation, check console logs on both clients and the server for errors. Network latency or firewall issues could interfere.
*   **Disconnected by Server (Rate Limit):** If you see an alert about being disconnected for exceeding the rate limit, you sent too many messages too quickly. Wait a moment and reconnect.

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
