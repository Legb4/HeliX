# server/server.py
# This file contains the core logic for the HeliX WebSocket server,
# including client registration, message relaying, connection handling, SSL setup,
# rate limiting, message validation, identifier sanitization,
# and active session tracking for disconnect notifications.

import asyncio          # For asynchronous operations (coroutines, event loop).
import websockets       # The WebSocket library used for server and client handling.
import logging          # For logging server events, warnings, and errors.
import json             # For parsing and serializing JSON messages between client and server.
import ssl              # For creating SSL contexts if WSS (Secure WebSockets) is enabled.
import time             # For rate limiting timestamps
import re               # For identifier validation using regex
import config           # Imports server configuration (HOST, PORT, SSL settings, Rate Limits).


# Configure basic logging (can also be done in main.py, ensures it's set).
# Level INFO means INFO, WARNING, ERROR, CRITICAL messages will be shown.
# Format includes timestamp, log level, and the message itself.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Identifier Validation ---
# Regex pattern for valid identifiers:
# - Starts with a letter or number (^[a-zA-Z0-9])
# - Contains only letters, numbers, underscores, hyphens ([a-zA-Z0-9_-]*)
# - Is between 3 and 30 characters long ({2,29}$) - Note: {2,29} because the first char is already matched.
VALID_IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{2,29}$")

# --- Global Registries ---

# CLIENTS: A dictionary mapping registered client identifiers (strings) to their
# corresponding WebSocket connection objects. Allows looking up a connection by ID.
# Example: {'Alice123': <WebSocketConnection object for Alice>, 'Bob456': <WebSocketConnection object for Bob>}
CLIENTS = {}

# CONNECTIONS: A reverse lookup dictionary mapping active WebSocket connection objects
# to their registered client identifiers (strings). Allows finding a client's ID from their connection.
# Example: {<WebSocketConnection object for Alice>: 'Alice123', <WebSocketConnection object for Bob>: 'Bob456'}
CONNECTIONS = {}

# --- Rate Limiting State ---
# CONNECTION_ATTEMPTS: Tracks recent connection timestamps per IP address.
# Structure: { 'ip_address': [timestamp1, timestamp2, ...], ... }
CONNECTION_ATTEMPTS = {}

# MESSAGE_TIMESTAMPS: Tracks recent message timestamps per active WebSocket connection.
# Structure: { <websocket object>: [timestamp1, timestamp2, ...], ... }
MESSAGE_TIMESTAMPS = {}

# --- Active Session Tracking ---
# ACTIVE_SESSIONS: Maps an identifier to their current active chat peer's identifier.
# Used for disconnect notifications. Ensures bidirectional mapping (A->B and B->A).
# Example: {'Alice123': 'Bob456', 'Bob456': 'Alice123'}
ACTIVE_SESSIONS = {}


# --- Helper function to send JSON messages ---
async def send_json(websocket, message_type, payload):
    """
    Helper function to format a message as JSON and send it over a WebSocket connection.
    Handles JSON serialization and logs the outgoing message.
    Includes basic error handling for closed connections during send.

    Args:
        websocket: The websockets.WebSocketServerProtocol object representing the client connection.
        message_type: The numeric type identifier for the message (e.g., 0.1, 0.2, -1, -2, 9).
        payload: The dictionary containing the message data.
    """
    try:
        # Create the message dictionary.
        message_dict = {"type": message_type, "payload": payload}
        # Serialize the dictionary to a JSON string.
        message = json.dumps(message_dict)
        # Log the message being sent, including recipient address and ID (if registered).
        logging.info(f"Sending to {websocket.remote_address} ({CONNECTIONS.get(websocket, 'N/A')}): {message}")
        # Send the JSON string over the WebSocket.
        await websocket.send(message)
    except websockets.exceptions.ConnectionClosed as e:
        # Log a warning specifically if the send fails because the connection is already closed.
        logging.warning(f"Failed to send to {websocket.remote_address} ({CONNECTIONS.get(websocket, 'N/A')}) because connection is closed: {e}")
    except Exception as e:
        # Catch other exceptions during json.dumps or websocket.send (less common)
        logging.exception(f"Unexpected error sending JSON to {websocket.remote_address} ({CONNECTIONS.get(websocket, 'N/A')})")


# --- Registration Logic ---
async def handle_registration(websocket, identifier):
    """
    Handles a client's registration request (Type 0 message).
    Validates the identifier using regex, checks if it's already taken or if the client is already registered,
    and updates the global CLIENTS and CONNECTIONS registries if successful.
    Sends a success (Type 0.1) or failure (Type 0.2) response back to the client.
    Assumes basic validation (type, existence, format) happened before calling this.

    Args:
        websocket: The WebSocket connection object of the client attempting to register.
        identifier: The validated identifier string provided by the client.
    """
    client_address = websocket.remote_address
    logging.info(f"Handling registration request for '{identifier}' from {client_address}")

    # --- Check Availability ---
    # Check if the requested identifier is already present in the CLIENTS registry.
    if identifier in CLIENTS:
        logging.warning(f"Identifier '{identifier}' already taken. Denying request from {client_address}.")
        # Send failure message (Type 0.2) indicating the ID is taken.
        await send_json(websocket, 0.2, {"identifier": identifier, "error": "Identifier already taken."})
    # Check if this specific WebSocket connection is already registered in the CONNECTIONS registry.
    elif websocket in CONNECTIONS:
         # This prevents a single client from registering multiple IDs.
         existing_id = CONNECTIONS[websocket]
         logging.warning(f"Client {client_address} tried to register '{identifier}' but is already registered as '{existing_id}'. Denying.")
         # Send failure message (Type 0.2) indicating they are already registered.
         await send_json(websocket, 0.2, {"identifier": identifier, "error": f"You are already registered as '{existing_id}'."})
    else:
        # --- Registration Success ---
        # Add the identifier -> websocket mapping to CLIENTS.
        CLIENTS[identifier] = websocket
        # Add the websocket -> identifier mapping to CONNECTIONS.
        CONNECTIONS[websocket] = identifier
        logging.info(f"Identifier '{identifier}' registered successfully for {client_address}")
        # Send success message (Type 0.1) back to the client.
        await send_json(websocket, 0.1, {"identifier": identifier, "message": "Registration successful."})


# --- Unregistration Logic ---
def unregister_client(websocket):
    """
    Removes a client's registration information from the global registries (CLIENTS and CONNECTIONS).
    If the client was in an active session, attempts to notify the peer (Type 9).
    Also cleans up session tracking in ACTIVE_SESSIONS.

    Args:
        websocket: The WebSocket connection object of the client that disconnected.
    """
    peer_id = None # Initialize peer_id
    identifier = None # Initialize identifier

    # Check if the disconnecting client was actually registered (i.e., present in CONNECTIONS).
    if websocket in CONNECTIONS:
        # Retrieve the identifier associated with this connection.
        identifier = CONNECTIONS[websocket]
        logging.info(f"Unregistering client {websocket.remote_address} with ID '{identifier}'")

        # --- BEGIN Disconnect Notification Logic ---
        # Check if this client was in an active session.
        if identifier in ACTIVE_SESSIONS:
            peer_id = ACTIVE_SESSIONS.pop(identifier, None) # Get peer and remove sender's entry
            if peer_id and peer_id in ACTIVE_SESSIONS:
                ACTIVE_SESSIONS.pop(peer_id, None) # Remove peer's entry if it exists
            logging.info(f"Cleared active session tracking for {identifier} and {peer_id}")

            # If a peer was found, try to notify them.
            if peer_id:
                peer_websocket = CLIENTS.get(peer_id)
                if peer_websocket: # Check if the peer is still connected
                    logging.info(f"Notifying peer {peer_id} about {identifier}'s disconnection.")
                    # Construct the Type 9 payload (Session End)
                    notification_payload = {"targetId": peer_id, "senderId": identifier}
                    # Schedule the send operation as a task so it doesn't block unregister_client
                    asyncio.create_task(send_json(peer_websocket, 9, notification_payload))
                else:
                    logging.info(f"Peer {peer_id} was already disconnected. No notification sent.")
        # --- END Disconnect Notification Logic ---

        # Remove the entry from the CLIENTS registry (ID -> connection).
        if identifier in CLIENTS:
            del CLIENTS[identifier]
        # Remove the entry from the CONNECTIONS registry (connection -> ID).
        del CONNECTIONS[websocket] # Do this after potentially using the identifier

    else:
        # Log if a client disconnects without ever registering an ID.
        logging.info(f"Client {websocket.remote_address} disconnected but had no registered ID.")


# --- Main Connection Handler ---
async def connection_handler(websocket):
    """
    The main asynchronous function that handles an individual client's WebSocket connection lifecycle.
    Implements connection rate limiting, listens for incoming messages, validates and rate limits them,
    routes messages (registration or relay), updates active session tracking,
    and handles errors and disconnection cleanup.

    Args:
        websocket: The websockets.WebSocketServerProtocol object representing the connected client.
    """
    client_ip = websocket.remote_address[0] # Get IP address (index 0 of the tuple)
    logging.info(f"Client attempting connection from {client_ip}:{websocket.remote_address[1]}")

    # --- Connection Rate Limiting ---
    current_time = time.time()
    # Get the list of recent connection timestamps for this IP, default to empty list if none.
    connection_times = CONNECTION_ATTEMPTS.get(client_ip, [])
    # Filter out timestamps older than the defined window.
    valid_attempts = [t for t in connection_times if current_time - t < config.CONNECTION_WINDOW_SECONDS]
    # Check if the number of valid recent attempts exceeds the limit.
    if len(valid_attempts) >= config.MAX_CONNECTIONS_PER_IP:
        logging.warning(f"Connection rate limit exceeded for IP {client_ip}. Closing connection.")
        # Close the connection immediately with a specific code (e.g., 1008 Policy Violation).
        await websocket.close(code=1008, reason="Connection rate limit exceeded")
        # Update the list in the dictionary (optional, helps keep it trimmed)
        CONNECTION_ATTEMPTS[client_ip] = valid_attempts
        return # Exit the handler, preventing further processing for this connection.
    else:
        # If limit not exceeded, add the current timestamp and update the dictionary.
        valid_attempts.append(current_time)
        CONNECTION_ATTEMPTS[client_ip] = valid_attempts
        logging.info(f"Connection accepted from {client_ip}:{websocket.remote_address[1]}")
        # Initialize message timestamp tracking for this new connection
        MESSAGE_TIMESTAMPS[websocket] = []

    try:
        # --- Message Receiving Loop ---
        # Continuously listen for messages from this client.
        # The loop breaks automatically if the connection is closed.
        async for message in websocket:
            current_time = time.time() # Get time for message rate limiting

            # --- Message Rate Limiting ---
            message_times = MESSAGE_TIMESTAMPS.get(websocket, [])
            # Filter out old message timestamps.
            valid_message_times = [t for t in message_times if current_time - t < config.MESSAGE_WINDOW_SECONDS]
            # Check if the limit is exceeded.
            if len(valid_message_times) >= config.MAX_MESSAGES_PER_CONNECTION:
                logging.warning(f"Message rate limit exceeded for {websocket.remote_address} ({CONNECTIONS.get(websocket, 'Unregistered')}). Sending notification and closing connection.")
                # Send Type -2 error message to the client before closing.
                error_payload = {"error": "Message rate limit exceeded. Disconnecting."}
                await send_json(websocket, -2, error_payload)
                # Now close the connection.
                await websocket.close(code=1008, reason="Message rate limit exceeded")
                break # Exit the message loop.
            else:
                # If limit not exceeded, add current timestamp.
                valid_message_times.append(current_time)
                MESSAGE_TIMESTAMPS[websocket] = valid_message_times

            # Log the raw message received, including the client's ID if registered.
            logging.info(f"Raw message received from {websocket.remote_address} ({CONNECTIONS.get(websocket, 'Unregistered')}): {message}")

            try:
                # --- Message Parsing and Stricter Validation ---
                data = None # Initialize data to None
                try:
                    data = json.loads(message)
                except json.JSONDecodeError:
                    logging.warning(f"Invalid JSON received from {websocket.remote_address}. Ignoring.")
                    continue # Skip to the next message

                # Basic structure validation
                if not isinstance(data, dict):
                    logging.warning(f"Received non-dictionary data from {websocket.remote_address}. Ignoring: {data}")
                    continue
                message_type = data.get("type")
                payload = data.get("payload")
                if message_type is None or payload is None:
                    logging.warning(f"Missing 'type' or 'payload' in message from {websocket.remote_address}. Ignoring: {data}")
                    continue
                if not isinstance(message_type, (int, float)): # Allow numeric types
                    logging.warning(f"Invalid 'type' (not a number) in message from {websocket.remote_address}. Ignoring: {data}")
                    continue
                if not isinstance(payload, dict):
                     # Allow non-dict payloads only for specific types if needed in future, otherwise enforce dict
                     logging.warning(f"Invalid 'payload' (not a dictionary) in message from {websocket.remote_address}. Ignoring: {data}")
                     continue

                # Type-specific payload validation
                validation_passed = True
                sender_id = CONNECTIONS.get(websocket) # Get sender ID if registered
                target_id = payload.get("targetId") if isinstance(payload, dict) else None

                if message_type == 0: # Registration
                    identifier = payload.get("identifier")
                    # Check type and existence first
                    if not identifier or not isinstance(identifier, str):
                         logging.warning(f"Invalid identifier type in Type 0 payload from {websocket.remote_address}. Ignoring: {payload}")
                         validation_passed = False
                         # Send error back immediately if basic type is wrong
                         await send_json(websocket, 0.2, {"identifier": identifier, "error": "Identifier must be a non-empty string."})
                    # Then check format using regex
                    elif not VALID_IDENTIFIER_REGEX.match(identifier):
                        logging.warning(f"Invalid identifier format in Type 0 payload from {websocket.remote_address}. Sending error back.")
                        # --- BEGIN FIX ---
                        # Send Type 0.2 error immediately upon detecting invalid format
                        error_msg = "Invalid identifier format. Must be 3-30 characters, start with a letter/number, and contain only letters, numbers, underscores, or hyphens."
                        await send_json(websocket, 0.2, {"identifier": identifier, "error": error_msg})
                        # --- END FIX ---
                        validation_passed = False # Ensure we still skip further processing
                elif message_type in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]: # Relayable message types
                    # Check targetId
                    if not target_id or not isinstance(target_id, str) or len(target_id.strip()) == 0 or len(target_id) > 50:
                        logging.warning(f"Invalid 'targetId' in Type {message_type} payload from {websocket.remote_address}. Ignoring: {payload}")
                        validation_passed = False
                    # Check senderId consistency if client is registered
                    elif sender_id:
                        payload_sender_id = payload.get("senderId")
                        if not payload_sender_id or payload_sender_id != sender_id:
                             logging.warning(f"Mismatched or missing 'senderId' in Type {message_type} from registered client {sender_id}. Ignoring: {payload}")
                             validation_passed = False
                    # Additional checks for Type 8 (Encrypted Message)
                    elif message_type == 8:
                        if not all(k in payload and isinstance(payload[k], str) and payload[k] for k in ['encryptedKey', 'iv', 'data']):
                            logging.warning(f"Missing or invalid fields in Type 8 payload from {websocket.remote_address}. Ignoring: {payload}")
                            validation_passed = False
                # Add checks for other types if they have specific payload requirements

                if not validation_passed:
                    continue # Skip processing this invalid message

                # --- Message Routing (Post-Validation) ---
                if message_type == 0: # Registration Request
                    # Call the registration handler (identifier already validated above)
                    await handle_registration(websocket, payload["identifier"])
                # --- Message Relaying (for registered clients) ---
                elif sender_id: # Check if the sender is registered.
                    # Target ID already extracted and validated above.
                    logging.info(f"Attempting to relay message type {message_type} from '{sender_id}' to '{target_id}'")
                    # Look up the target client's WebSocket connection using their ID.
                    target_websocket = CLIENTS.get(target_id)

                    # --- Relay Logic ---
                    if target_websocket: # Check if the target client is currently connected and registered.
                        try:
                            logging.info(f"Relaying message to {target_id} ({target_websocket.remote_address})")
                            # Send the original, validated JSON message string to the target client.
                            await target_websocket.send(message)

                            # --- BEGIN Session Tracking Update ---
                            # If a Type 2 (Accept) is successfully relayed, record the session.
                            if message_type == 2:
                                logging.info(f"Recording active session between {sender_id} and {target_id}")
                                ACTIVE_SESSIONS[sender_id] = target_id
                                ACTIVE_SESSIONS[target_id] = sender_id # Record the reverse mapping too

                            # If a Type 9 (End Session) is successfully relayed, clear the session.
                            elif message_type == 9:
                                logging.info(f"Clearing active session between {sender_id} and {target_id} due to Type 9 message relay.")
                                if sender_id in ACTIVE_SESSIONS:
                                    # Check if the stored peer matches the target before deleting
                                    if ACTIVE_SESSIONS[sender_id] == target_id:
                                        del ACTIVE_SESSIONS[sender_id]
                                if target_id in ACTIVE_SESSIONS:
                                     # Check if the stored peer matches the sender before deleting
                                    if ACTIVE_SESSIONS[target_id] == sender_id:
                                        del ACTIVE_SESSIONS[target_id]
                            # --- END Session Tracking Update ---

                        except websockets.exceptions.ConnectionClosed:
                            # Handle the case where the target client disconnected *during* the send attempt.
                            logging.warning(f"Relay failed: Target user '{target_id}' connection closed during send attempt.")
                            # Send an error message (Type -1) back to the original sender.
                            error_payload = {"targetId": target_id, "message": f"User '{target_id}' disconnected during send."}
                            await send_json(websocket, -1, error_payload)
                        except Exception as e:
                             # Catch any other unexpected errors during the relay send.
                             logging.exception(f"Unexpected error relaying message to {target_id}")
                             # Consider sending an error back to the sender here as well, if appropriate.
                    else:
                        # Target client ID not found in the CLIENTS registry (not online or never registered).
                        logging.warning(f"Target user '{target_id}' not found. Sending error back to '{sender_id}'.")
                        # Send an error message (Type -1) back to the original sender.
                        error_payload = {"targetId": target_id, "message": f"User '{target_id}' not found or disconnected."}
                        await send_json(websocket, -1, error_payload)
                else:
                    # Received a non-registration message from a client that hasn't registered yet.
                    logging.warning(f"Received non-registration message type {message_type} from unregistered client {websocket.remote_address}. Ignoring.")

            except Exception as e:
                # Catch any other errors that occur during the processing of a single message
                # (e.g., unexpected payload structure, errors in handlers).
                logging.exception(f"Error processing message from {websocket.remote_address} ({CONNECTIONS.get(websocket, 'Unregistered')}): {message}")
                # Consider sending a generic error back to the client if appropriate.

    # --- Connection Closed Handling ---
    except websockets.exceptions.ConnectionClosedOK:
        # Log when a client disconnects cleanly (e.g., browser closed, client called disconnect).
        logging.info(f"Client {websocket.remote_address} disconnected gracefully.")
    except websockets.exceptions.ConnectionClosedError as e:
        # Log when a client disconnects due to an error (e.g., network interruption).
        logging.info(f"Client {websocket.remote_address} disconnected with error: {e}")
    except Exception as e:
        # Catch any unexpected errors in the main connection handling loop itself
        # (outside the message processing loop).
        logging.exception(f"An unexpected error occurred handling client {websocket.remote_address}")
    finally:
        # --- Cleanup ---
        # Remove message rate limiting data for this connection
        if websocket in MESSAGE_TIMESTAMPS:
            del MESSAGE_TIMESTAMPS[websocket]
            logging.debug(f"Removed message timestamp tracking for {websocket.remote_address}")
        # Ensure the client is unregistered from the global registries AND handle disconnect notification.
        unregister_client(websocket) # This now includes the notification logic
        logging.info(f"Connection closed for {websocket.remote_address}")
        # Optional: Log exit from the handler for clarity during debugging.
        # logging.info(f"--- Exiting connection_handler for {websocket.remote_address} ---")


# --- Server Startup Function ---
async def start_server(host, port):
    """
    Initializes and starts the WebSocket server.
    Configures SSL context if enabled in the config file.
    Runs the server indefinitely until stopped.

    Args:
        host: The hostname or IP address to bind the server to.
        port: The port number to bind the server to.
    """
    ssl_context = None # Initialize ssl_context to None (no SSL by default).
    protocol = "ws" # Default protocol is unencrypted WebSocket.

    # Check if SSL is enabled in the configuration.
    if config.ENABLE_SSL:
        try:
            # Log the paths being used for certificate and key files.
            logging.info(f"Attempting to load SSL cert: {config.CERT_FILE}")
            logging.info(f"Attempting to load SSL key: {config.KEY_FILE}")
            # Create an SSL context for a TLS server.
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # Load the certificate chain (cert file) and private key (key file).
            # These files must exist and be valid for WSS to work.
            ssl_context.load_cert_chain(config.CERT_FILE, config.KEY_FILE)
            protocol = "wss" # Update protocol string if SSL is successfully loaded.
            logging.info("SSL context created successfully.")
        except FileNotFoundError:
            # Handle error if certificate or key file is not found at the specified path.
            logging.error("SSL Error: Certificate or Key file not found. Disabling SSL.")
            ssl_context = None # Ensure ssl_context is None to fall back to WS.
        except Exception as e:
            # Handle any other errors during SSL context creation or loading (e.g., invalid format, permissions).
            logging.exception("SSL Error: Failed to create SSL context. Disabling SSL.")
            ssl_context = None # Ensure ssl_context is None to fall back to WS.

    # Determine the effective protocol based on whether SSL context was successfully created.
    effective_protocol = "wss" if ssl_context else "ws"
    logging.info(f"Starting server on {effective_protocol}://{host}:{port}")
    logging.info(f"Connection Rate Limit: {config.MAX_CONNECTIONS_PER_IP} per {config.CONNECTION_WINDOW_SECONDS}s per IP")
    logging.info(f"Message Rate Limit: {config.MAX_MESSAGES_PER_CONNECTION} per {config.MESSAGE_WINDOW_SECONDS}s per Connection")


    try:
        # Start the WebSocket server using websockets.serve.
        # - connection_handler: The function to call for each new client connection.
        # - host: The host address to listen on.
        # - port: The port number to listen on.
        # - ssl: Pass the created SSL context here if using WSS, otherwise None for WS.
        async with websockets.serve(
            connection_handler,
            host,
            port,
            ssl=ssl_context # Pass the context (or None)
        ) as server_instance:
            # Keep the server running indefinitely by awaiting a Future that never completes.
            # The server will run until the process is interrupted (e.g., Ctrl+C).
            await asyncio.Future()
    except OSError as e:
        # Catch common OS-level errors during server startup.
        # e.g., "Address already in use" if the port is taken, or permission errors.
        logging.exception(f"OSError starting server on {host}:{port}")
    except Exception as e:
        # Catch any other unexpected errors during server startup or runtime.
        logging.exception(f"Error occurred during websockets.serve or server runtime ({effective_protocol})")
        raise # Re-raise the exception to potentially be caught by main.py

# Note: The actual execution start (asyncio.run) is handled in main.py
