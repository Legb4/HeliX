# HeliX Chat

**Table of Contents**

*   [Introduction / Overview](#introduction--overview)
*   [Prerequisites](#prerequisites)
*   [Installation & Setup](#installation--setup)
*   [Running HeliX](#running-helix)
*   [Usage Guide](#usage-guide)
*   [How HeliX Works & Security](#how-helix-works--security)
*   [Troubleshooting](#troubleshooting)
*   [License](#license)

---

## Introduction / Overview

**HeliX** is a browser-based chat application focused on secure, ephemeral, end-to-end encrypted communication directly between two users. It uses a simple self-hosted Python server solely for relaying connection setup messages and encrypted data, ensuring the server cannot access plaintext message content.

**Core Features:**

*   **End-to-End Encryption (E2EE):** All messages and file contents are encrypted in your browser using AES-GCM. Only the intended recipient, holding the shared session key, can decrypt them.
*   **Perfect Forward Secrecy (PFS):** Achieved using ephemeral Elliptic Curve Diffie-Hellman (ECDH P-256) key pairs for each session. Compromise of keys from one session does not compromise past sessions.
*   **Connection Verification (SAS):** Implements Short Authentication Strings (Safety Numbers). Users compare a short code derived from the session's keys via an out-of-band channel to verify the connection's integrity and protect against Man-in-the-Middle (MitM) attacks.
*   **Ephemeral by Design:** Messages, session keys, and temporary file data exist only in the browser's memory or temporary storage (IndexedDB) during an active session. No chat history or user data is stored persistently on the server or client.
*   **Secure File Transfer:** Allows direct peer-to-peer transfer of files, encrypted using the session key. The server relays encrypted chunks but cannot access file content.
*   **Temporary Identifiers:** Users register with a unique, temporary ID (valid only while connected) which must be shared securely out-of-band to initiate contact.
*   **Self-Hosted:** Requires running the Python server components, giving you control over the relay infrastructure.

**Target Use Case:**

HeliX is suited for situations requiring quick, secure, private conversations or file sharing without reliance on third-party services or leaving a persistent digital footprint. Examples include sharing temporary sensitive information, quick support sessions, or private coordination.

**Disclaimer:**

HeliX is currently experimental software. While it implements strong security principles (E2EE, PFS, SAS), it has not undergone a formal security audit. Use it at your own risk. The security of your communication relies heavily on the correct setup of the server, the security of the endpoint devices used, the secure out-of-band exchange of user identifiers, **the correct out-of-band comparison of SAS codes**, and trusting the `mkcert` local Certificate Authority if you choose to install it.

---

## Prerequisites

Ensure you have the following before setting up HeliX:

*   **Operating System:** Windows, macOS, or Linux.
*   **Python:** Version 3.7 or newer recommended, with the `pip` package installer included and accessible in your system's PATH. ([python.org](https://www.python.org/downloads/))
*   **`mkcert` Utility:** Required for generating locally-trusted TLS certificates for the HTTPS server. Download from [mkcert releases](https://github.com/FiloSottile/mkcert/releases) and follow setup instructions in the next section.
*   **Modern Web Browser:** Firefox, Chrome, Edge, or Safari recommended, with support for Web Crypto API, WebSockets, and IndexedDB.
*   **Secure Out-of-Band Channel:** A separate, trusted method (e.g., phone call, video chat, in-person) to communicate temporary IDs and compare SAS codes with your peer is **essential** for secure usage.

---

## Installation & Setup

1.  **Get the Code:**
    *   Clone the repository using Git: `git clone https://github.com/DDeal/HeliX.git` and `cd helix`
    *   Alternatively, download and extract the project ZIP file and navigate into the `helix` directory in your terminal.

2.  **Install `mkcert`:** (Perform this step *before* step 4)
    *   **Windows:** Use a package manager (`winget install mkcert` or `choco install mkcert`) OR download the `.exe` from the mkcert releases page, rename it to `mkcert.exe`, and place it inside the `helix/certs/` directory.
    *   **Linux/macOS:** Use your system's package manager to install `mkcert` so it's available in your PATH (e.g., `brew install mkcert` on macOS, `sudo apt install mkcert` on Debian/Ubuntu).

3.  **Run Manager & Install Dependencies:**
    *   In your terminal, inside the `helix` directory, run: `python helix_manager.py`
    *   The script will check for Python dependencies listed in `server/requirements.txt`. If missing, it will prompt for installation via `pip`. Enter `y` to proceed.

4.  **Generate TLS Certificates:**
    *   From the manager script's menu, select **Option 7** ("Manage TLS Certificates").
    *   The script will locate `mkcert`.
    *   **CA Installation:** You'll be asked if you want to run `mkcert -install`. It's **highly recommended** to enter `y` (requires Admin/Sudo privileges). This installs the `mkcert` local Certificate Authority (CA) into your system/browser trust stores, preventing most browser security warnings when accessing `https://localhost` or `https://127.0.0.1`.
    *   **Certificate Generation:** Follow the prompts to generate the necessary `cert.pem` and `key.pem` files within the `certs/` directory. Backup options for existing certificates are provided.

5.  **Network Configuration (Optional - For External Access):**
    *   To allow connections from outside your local network, you'll need to configure your **firewall** to allow incoming TCP traffic on the WSS and HTTPS ports (default: 5678, 8888) and potentially configure **port forwarding** on your router to direct external traffic to the machine running HeliX.
    *   **Note:** Accessing the client via an external IP address or domain name will likely trigger browser certificate warnings with the default `mkcert` certificates (as they are only issued for `localhost` and `127.0.0.1`). Users will need to manually bypass these warnings.

---

## Running HeliX

1.  **Start the Servers:**
    *   Run `python helix_manager.py` in your terminal from the `helix` directory.
    *   Use menu options 1-6 to review or modify server/client settings (like ports or debug modes) if desired. Settings are saved when starting the servers.
    *   Ensure TLS certificates exist in the `certs/` directory (use menu option 7 if needed).
    *   Choose **Option 8** ("Start HTTPS/WSS Servers").
2.  **Monitor Output:**
    *   The terminal will show logs indicating server startup.
    *   Real-time logs from the WSS server (connections, errors, etc.) will be prefixed with `[WSS]`.
    *   HTTPS server activity is logged separately to the `logs/https_server.log` file.
3.  **Access the Client:**
    *   Open your web browser.
    *   Navigate to the HTTPS URL provided by the manager script (e.g., `https://localhost:8888` or `https://127.0.0.1:8888`). Use the server's LAN IP if accessing from another device on the network.
    *   **Certificate Warnings:** If you didn't install the `mkcert` CA or are accessing via IP, you might see a browser security warning ("Your connection is not private", etc.). You typically need to click "Advanced" and then "Proceed" or "Accept the Risk" to continue.
4.  **Stop the Servers:** Return to the terminal running the manager and press `Ctrl+C`. The script will attempt a graceful shutdown.

---

## Usage Guide

1.  **Access Client & Register:** Open the HeliX URL in your browser. Choose a unique temporary ID (3-30 chars: `a-z`, `A-Z`, `0-9`, `-`, `_`) and click "Register".
2.  **Share ID (OOB - Step 1):** Securely communicate your registered ID (shown in the sidebar) to your intended peer using a separate channel (phone, video, etc.). *(On smaller screens, use the `☰` button to access the sidebar).*
3.  **Initiate or Accept Chat:**
    *   **To Initiate:** Enter your peer's ID in the sidebar input field and click "Start Chat". *(Use `☰` on smaller screens to access the sidebar).*
    *   **To Accept:** If you receive a request notification, click "Accept" (or "Deny"). You might need to click the peer's ID in the session list first if another chat is active. *(Use `☰` on smaller screens to access the sidebar and session list).*
4.  **SAS Verification (OOB - Step 2 - CRITICAL):**
    *   After the initial connection, the **"Verify Connection"** pane appears, showing a code (e.g., `123 456`).
    *   **You MUST compare this code** with your peer's code **out-of-band** (e.g., read it aloud over a phone call). This verifies you have a secure connection directly with your peer and protects against Man-in-the-Middle attacks.
    *   If the codes **match exactly**, BOTH users click **"Confirm Match"**.
    *   If the codes **DO NOT MATCH**, click **"Deny / Abort"** and do not proceed.
    *   The chat input is enabled only after **both** users confirm the match.
5.  **Chat:** Once verified, type messages in the input field and press Enter or click "Send".
6.  **File Transfer:** Click the paperclip (📎) to select a file. The peer must "Accept" the request. Progress is shown, and a "Download" link appears for the receiver upon completion. Use the "Cancel" button if needed during sending.
7.  **Slash Commands:** Type in the message input:
    *   `/me <action>`: Display action text (e.g., `/me waves`).
    *   `/end`: End the current session.
    *   `/version`: Show client version.
    *   `/info`: Show connection details.
    *   `/help`: Show this list.
8.  **Controls:** Use sidebar buttons (🔊/🔇, ⚙️) for mute/settings. Click peer IDs in the list to switch sessions. Use the "End Session" button in the chat header to disconnect. *(Use `☰` on smaller screens to access the sidebar controls and session list).*

---

## How HeliX Works & Security

**Architecture Overview:**

HeliX uses three main components:

1.  **Client (Browser):** The user interface runs entirely in the browser using HTML/CSS/JavaScript. It handles all user interactions, cryptographic operations (via the Web Crypto API), SAS derivation, and WebSocket communication with the server.
2.  **HTTPS Server (`helix_manager.py`):** A simple, integrated Python server that serves the static client files (HTML, JS, CSS, images, audio) over HTTPS. This secure context is necessary for the browser's Web Crypto API and IndexedDB features to function.
3.  **WSS Server (`server.py`):** A Python server using the `websockets` library that acts purely as a signaling and message relay. It manages temporary ID registrations, forwards handshake messages between clients, and relays the encrypted chat messages and file chunks. **Crucially, the WSS server cannot decrypt or access the content of user communications.**

**Security Flow Details:**

HeliX establishes a secure, end-to-end encrypted channel with Perfect Forward Secrecy and Man-in-the-Middle detection using the following steps:

1.  **Ephemeral Key Exchange (ECDH):** When a session starts, each client generates a temporary Elliptic Curve Diffie-Hellman (ECDH P-256) key pair. Public keys are exchanged via the WSS server.
2.  **Shared Secret & Session Key Derivation (HKDF, AES-GCM):** Each client uses their private key and the peer's public key to compute a shared secret. This secret is processed through HKDF (with SHA-256) to derive a strong, unique 256-bit AES-GCM symmetric session key. This key is known only to the two clients and never transmitted.
3.  **Handshake Challenge:** A challenge-response mechanism (encrypting/decrypting known data with the derived AES key) verifies that both clients successfully derived the same session key.
4.  **Short Authentication String (SAS) Derivation & Comparison:** After the cryptographic handshake, each client computes a short SAS code (e.g., `123 456`) by hashing their own public key and the public key they received from their peer. **Users MUST compare these codes out-of-band.** A match confirms the integrity of the key exchange against MitM attacks. A mismatch indicates a potential problem, and the session should be aborted.
5.  **Encrypted Communication:** Only after successful SAS confirmation by both parties is the chat enabled. All subsequent messages and file chunks are encrypted using the derived AES-GCM session key and a unique IV before being sent to the server for relaying. AES-GCM provides both confidentiality and authenticity.

**Secure File Transfer:** Uses the established AES-GCM session key to encrypt file chunks before relaying them through the server. Chunks are temporarily stored in the receiver's browser IndexedDB, decrypted, reassembled into a Blob, and made available via a temporary download link.

**Ephemeral Nature:** HeliX is designed to leave minimal traces. Session keys, SAS codes, messages, and temporary file data are discarded when the session ends or the browser tab is closed. No user data or message content is stored on the server.

**HTTPS Importance:** Required by browsers to enable the Web Crypto API (for E2EE) and IndexedDB (for file transfer).

**Identifier System:** Temporary IDs are used only for initiating connections via the server relay. They must be exchanged securely out-of-band.

**Security Considerations & Assumptions:**

*   **Server Trust:** You must trust the integrity of the machine running the HeliX server software, although the server cannot read encrypted content.
*   **Client Trust:** The security of the communication depends on the security of the users' endpoint devices and browsers.
*   **`mkcert` CA Trust:** If you install the `mkcert` local CA, you are trusting it to issue certificates for `localhost`. This is generally safe for local development but is a security consideration.
*   **Out-of-Band Security:** The secure exchange of temporary IDs and the correct comparison of SAS codes via a trusted out-of-band channel are critical user responsibilities. **Failure to compare SAS codes correctly defeats the MitM protection.**
*   **Metadata:** The server knows which IDs are connected and relays messages between them. It also temporarily tracks active pairings (`Alice` <-> `Bob`) to notify users if their peer disconnects unexpectedly. This metadata does not expose message content but could reveal communication patterns if the server were compromised.

---

## Troubleshooting

*   **Dependency Check Fails:** Ensure `server/requirements.txt` exists. Ensure `pip` is installed and in PATH. Try `pip install -r server/requirements.txt` manually.
*   **`mkcert` Not Found:** Ensure `mkcert` is installed correctly and accessible in PATH or placed in `certs/` (Windows). See Installation section.
*   **Browser Certificate Warnings:** Likely cause: `mkcert` CA not installed/trusted, or accessing via IP/hostname not in the cert (`localhost`, `127.0.0.1`). Solution 1 (Recommended): Run `mkcert -install` via manager Option 7. Solution 2: Bypass warning ("Advanced" -> "Proceed").
*   **Cannot Connect to Server:** Verify servers started in manager. Check WSS/HTTPS ports match client config/URL. Check OS firewall. Check LAN IP if applicable.
*   **Cannot Connect from Outside LAN:** Verify firewall rules *and* router port forwarding.
*   **Registration Failed:** ID taken or invalid format (3-30 chars: `a-z, A-Z, 0-9, -, _`). Choose a different ID.
*   **Chat Request Failed ("User unavailable"):** Peer ID incorrect, or peer offline/disconnected. Verify ID OOB.
*   **Handshake/Verification Timeout:** Check console logs (F12) on both clients (enable Client Debug) and server logs (enable Server Debug) for errors. Could be network latency or firewall issues.
*   **SAS Verification Fails / Codes Don't Match:** **CRITICAL.** Click **"Deny / Abort"**. This likely indicates a Man-in-the-Middle attack or a bug. **Do not proceed.** Verify ID with peer OOB and try again. Report persistent issues.
*   **Stuck on SAS Verification Pane:** Your peer hasn't clicked "Confirm Match", or they clicked "Deny / Abort", or they disconnected. Wait briefly, then use the "Cancel" button if needed.
*   **Disconnected (Rate Limit):** You sent too many messages too quickly. Wait and reconnect.
*   **File Transfer Fails:** Check size limit (default 100MB), peer connection status, browser storage space (IndexedDB), and console logs for specific errors.
*   **File Download Link Doesn't Work:** Temporary URL may have expired (e.g., session ended before clicking). Ask sender to resend. Check console logs.
*   **No Sound:** Check UI mute button (🔇), system/browser volume, console logs for audio loading/playback errors. Verify audio files exist.
*   **Font/Size Not Changing:** Check console logs for errors. Ensure settings pane is closed.

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