# server/config.py
# This file centralizes configuration settings for the Python WebSocket server.

import os # Import the 'os' module to help construct file paths reliably.

# --- Network Configuration ---

# The IP address the WebSocket server should listen on.
# '0.0.0.0' means listen on all available network interfaces (e.g., localhost, LAN IP).
# Use '127.0.0.1' or 'localhost' to only allow connections from the same machine.
HOST = '0.0.0.0'

# The port number the WebSocket server should listen on.
# This must match the port specified in the client's 'config.js' (webSocketUrl).
PORT = 5678

# --- SSL Configuration ---
# Settings related to enabling Secure WebSockets (WSS) using TLS/SSL certificates.

# Define the directory where SSL certificate files are expected to be located.
# os.path.dirname(__file__) gets the directory containing this config.py file.
# os.path.join then constructs a path like '<parent_directory>/certs/'.
CERT_DIR = os.path.join(os.path.dirname(__file__), '..', 'certs')

# Define the expected filename for the SSL certificate file (public key).
# This should be the certificate generated (e.g., by mkcert).
CERT_FILE = os.path.join(CERT_DIR, 'cert.pem')

# Define the expected filename for the SSL private key file.
# This should be the private key corresponding to the certificate.
KEY_FILE = os.path.join(CERT_DIR, 'key.pem')

# Master switch to enable or disable SSL/WSS.
# Set to True to use WSS (requires valid CERT_FILE and KEY_FILE).
# Set to False to use WS (unencrypted, generally only for local testing).
ENABLE_SSL = True

# --- Rate Limiting Configuration ---

# Connection Rate Limiting (per IP address)
# Maximum number of connection attempts allowed from a single IP within the specified time window.
MAX_CONNECTIONS_PER_IP = 10
# Time window in seconds for connection rate limiting.
CONNECTION_WINDOW_SECONDS = 60

# Message Rate Limiting (per connection)
# Maximum number of messages allowed from a single connection within the specified time window.
MAX_MESSAGES_PER_CONNECTION = 20
# Time window in seconds for message rate limiting.
MESSAGE_WINDOW_SECONDS = 5

# --- File Transfer Configuration ---

# Maximum file size allowed for transfer, in bytes.
# This provides an optional server-side check for Type 12 messages.
# Client-side validation (MAX_FILE_SIZE in SessionManager.js) is still essential.
# Example: 100 MB = 100 * 1024 * 1024
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024

# --- Debugging Configuration ---

# Debug Flag for Console Logging.
# - Set to `True` to enable detailed console logging for development and debugging.
#   This will output verbose information like raw message contents being relayed.
# - Set to `False` for production deployments to minimize information leakage
#   and keep the console cleaner. Essential logs (connections, errors, warnings)
#   will still be logged regardless of this flag.
DEBUG = False
