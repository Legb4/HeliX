# server/config.py
# This file centralizes configuration settings for the Python WebSocket server component of HeliX.

import os # Import the 'os' module to help construct file paths reliably across different operating systems.

# --- Network Configuration ---

# HOST: The IP address the WebSocket server should listen on.
# - '0.0.0.0': Listen on all available network interfaces (recommended for accessibility from other devices on the network).
# - '127.0.0.1' or 'localhost': Listen only on the local machine (only accessible from the same computer).
HOST = '0.0.0.0'

# PORT: The TCP port number the WebSocket server should listen on.
# This must match the port specified in the client's configuration (`client/js/config.js` -> `webSocketUrl`).
PORT = 5678

# --- SSL Configuration ---
# Settings related to enabling Secure WebSockets (WSS) using TLS/SSL certificates.

# CERT_DIR: The directory where SSL certificate files (cert.pem, key.pem) are expected to be located.
# Calculated relative to this config file's location (server/ -> ../certs/).
CERT_DIR = os.path.join(os.path.dirname(__file__), '..', 'certs')

# CERT_FILE: The expected filename for the SSL certificate file (containing the public key and chain).
# This file must exist in CERT_DIR if ENABLE_SSL is True.
CERT_FILE = os.path.join(CERT_DIR, 'cert.pem')

# KEY_FILE: The expected filename for the SSL private key file.
# This file must exist in CERT_DIR and correspond to the certificate if ENABLE_SSL is True.
KEY_FILE = os.path.join(CERT_DIR, 'key.pem')

# ENABLE_SSL: Master switch to enable or disable Secure WebSockets (WSS).
# - Set to True to use WSS (requires valid CERT_FILE and KEY_FILE to exist).
# - Set to False to use unencrypted WebSockets (WS) (generally only for local testing without HTTPS).
ENABLE_SSL = True

# --- Rate Limiting Configuration ---
# Helps mitigate potential denial-of-service or abuse by limiting connection and message frequency.

# Connection Rate Limiting (per IP address)
# MAX_CONNECTIONS_PER_IP: Maximum number of new connection attempts allowed from a single IP address within the CONNECTION_WINDOW_SECONDS.
MAX_CONNECTIONS_PER_IP = 10
# CONNECTION_WINDOW_SECONDS: Time window (in seconds) over which connection attempts are counted for rate limiting.
CONNECTION_WINDOW_SECONDS = 60

# Message Rate Limiting (per connection)
# MAX_MESSAGES_PER_CONNECTION: Maximum number of messages allowed from a single established WebSocket connection within the MESSAGE_WINDOW_SECONDS.
MAX_MESSAGES_PER_CONNECTION = 20
# MESSAGE_WINDOW_SECONDS: Time window (in seconds) over which messages are counted for rate limiting per connection.
MESSAGE_WINDOW_SECONDS = 5

# --- File Transfer Configuration ---

# MAX_FILE_SIZE_BYTES: Maximum file size allowed for transfer, specified in bytes.
# This provides an optional server-side check when a file transfer request (Type 12) is received.
# Client-side validation (MAX_FILE_SIZE in SessionManager.js) is also performed.
# Example: 100 MB = 100 * 1024 * 1024 bytes.
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024

# --- Debugging Configuration ---

# DEBUG: Debug Flag for Server Console Logging.
# - Set to `True` to enable detailed console logging on the server for development and debugging.
#   This will output verbose information, such as the content of relayed messages (excluding sensitive data if possible).
# - Set to `False` for production deployments to minimize information exposure
#   and keep the server console cleaner. Essential logs (connections, errors, warnings)
#   will still be logged regardless of this flag's value.
DEBUG = False
