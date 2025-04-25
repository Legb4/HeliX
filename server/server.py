# server/server.py
# This file contains the core logic for the HeliX WebSocket server.
# Responsibilities include:
# - Handling client connections and disconnections.
# - Managing client registration with unique identifiers.
# - Validating incoming messages for structure, type, and basic payload integrity.
# - Implementing rate limiting for connections and messages to prevent abuse.
# - Relaying messages between connected and registered clients based on target identifiers.
# - Tracking active chat sessions for disconnect notifications.
# - Setting up SSL context for Secure WebSockets (WSS) if configured.

import asyncio          # For asynchronous operations (coroutines, event loop, tasks).
import websockets       # The WebSocket library used for server implementation.
import logging          # For logging server events, warnings, and errors.
import json             # For parsing and serializing JSON messages.
import ssl              # For creating SSL contexts for WSS.
import time             # For timestamping in rate limiting logic.
import re               # For regular expression matching (identifier validation).
import config           # Imports server configuration (HOST, PORT, SSL settings, Rate Limits, DEBUG).


# Configure basic logging (ensures it's set if not already done in main.py).
# Level INFO means INFO, WARNING, ERROR, CRITICAL messages will be shown.
# Format includes timestamp, log level, and the message itself.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Identifier Validation ---
# Regex pattern for validating client identifiers during registration:
# - `^`: Asserts position at the start of the string.
# - `[a-zA-Z0-9]`: Matches the first character (must be alphanumeric).
# - `[a-zA-Z0-9_-]{2,29}`: Matches the next 2 to 29 characters (alphanumeric, underscore, or hyphen).
# - `$`: Asserts position at the end of the string.
# Ensures identifiers are 3-30 characters long and use a restricted character set.
VALID_IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{2,29}$")

# --- Global Registries ---

# CLIENTS: Dictionary mapping registered client identifiers (string) to their
# corresponding WebSocket connection objects (websockets.WebSocketServerProtocol).
# Allows looking up a connection using the client's unique ID.
# Example: {'Alice123': <WebSocket object for Alice>, 'Bob456': <WebSocket object for Bob>}
CLIENTS = {}

# CONNECTIONS: Reverse lookup dictionary mapping active WebSocket connection objects
# to their registered client identifiers (string). Allows finding a client's ID from their connection object.
# Example: {<WebSocket object for Alice>: 'Alice123', <WebSocket object for Bob>: 'Bob456'}
CONNECTIONS = {}

# --- Rate Limiting State ---
# CONNECTION_ATTEMPTS: Dictionary tracking recent connection timestamps per IP address.
# Used to limit the number of connection attempts from a single IP within a time window.
# Structure: { 'ip_address' (string): [timestamp1 (float), timestamp2, ...], ... }
CONNECTION_ATTEMPTS = {}

# MESSAGE_TIMESTAMPS: Dictionary tracking recent message timestamps per active WebSocket connection object.
# Used to limit the number of messages received from a single client within a time window.
# Structure: { <websocket object>: [timestamp1 (float), timestamp2, ...], ... }
MESSAGE_TIMESTAMPS = {}

# --- Active Session Tracking ---
# ACTIVE_SESSIONS: Dictionary mapping an identifier (string) to their current active chat peer's identifier (string).
# Used primarily to notify a user if their chat partner disconnects unexpectedly.
# Ensures bidirectional mapping (if A is chatting with B, A->B and B->A are stored).
# Example: {'Alice123': 'Bob456', 'Bob456': 'Alice123'}
ACTIVE_SESSIONS = {}


# --- Helper function to send JSON messages ---
async def send_json(websocket, message_type, payload):
    """
    Helper function to format a message as JSON and send it over a WebSocket connection.
    Handles JSON serialization and logs the outgoing message if server DEBUG mode is enabled.
    Includes basic error handling for attempting to send on a closed connection.

    Args:
        websocket (websockets.WebSocketServerProtocol): The client's WebSocket connection object.
        message_type (int | float): The numeric type identifier for the message (e.g., 0.1, -1, 9).
        payload (dict): The dictionary containing the message data.
    """
    try:
        # Create the standard message dictionary structure.
        message_dict = {"type": message_type, "payload": payload}
        # Serialize the dictionary to a JSON formatted string.
        message = json.dumps(message_dict)
        # Log the message being sent only if server DEBUG mode is enabled in config.
        if config.DEBUG:
            logging.info(f"Sending to {websocket.remote_address} ({CONNECTIONS.get(websocket, 'N/A')}): {message}")
        # Send the JSON string over the WebSocket connection.
        await websocket.send(message)
    except websockets.exceptions.ConnectionClosed:
        # Log a warning specifically if the send fails because the connection is already closed.
        # This is an expected condition if the client disconnects abruptly.
        logging.warning(f"Failed to send to {websocket.remote_address} ({CONNECTIONS.get(websocket, 'N/A')}) because connection is closed.")
    except Exception as e:
        # Catch other potential exceptions during json.dumps or websocket.send.
        # Always log unexpected exceptions.
        logging.exception(f"Unexpected error sending JSON to {websocket.remote_address} ({CONNECTIONS.get(websocket, 'N/A')})")


# --- Registration Logic ---
async def handle_registration(websocket, identifier):
    """
    Handles a client's registration request (received as Type 0 message).
    Validates the identifier format using regex, checks if the identifier is already taken,
    checks if the client's connection is already registered with a different ID,
    and updates the global CLIENTS and CONNECTIONS registries if registration is successful.
    Sends a success (Type 0.1) or failure (Type 0.2) response message back to the client.

    Args:
        websocket (websockets.WebSocketServerProtocol): The WebSocket connection object of the client attempting to register.
        identifier (str): The identifier string provided by the client (already passed basic type/length checks).
    """
    client_address = websocket.remote_address
    # Log handling attempt only if DEBUG is enabled.
    if config.DEBUG:
        logging.info(f"Handling registration request for '{identifier}' from {client_address}")

    # --- Identifier Format Validation ---
    if not VALID_IDENTIFIER_REGEX.match(identifier):
        # Always log warnings about failed registrations due to invalid format.
        logging.warning(f"Invalid identifier format '{identifier}'. Denying request from {client_address}.")
        # Send failure message (Type 0.2) indicating invalid format.
        await send_json(websocket, 0.2, {"identifier": identifier, "error": "Invalid identifier format (3-30 chars, letters, numbers, _, -)."})
        return # Stop processing registration.

    # --- Check Availability and Existing Registration ---
    # Check if the requested identifier is already present in the CLIENTS registry.
    if identifier in CLIENTS:
        # Always log warnings about failed registrations due to ID being taken.
        logging.warning(f"Identifier '{identifier}' already taken. Denying request from {client_address}.")
        # Send failure message (Type 0.2) indicating the ID is taken.
        await send_json(websocket, 0.2, {"identifier": identifier, "error": "Identifier already taken."})
    # Check if this specific WebSocket connection object is already registered in the CONNECTIONS registry.
    elif websocket in CONNECTIONS:
         # This prevents a single client connection from registering multiple identifiers.
         existing_id = CONNECTIONS[websocket]
         # Always log warnings about failed registrations due to client already being registered.
         logging.warning(f"Client {client_address} tried to register '{identifier}' but is already registered as '{existing_id}'. Denying.")
         # Send failure message (Type 0.2) indicating they are already registered.
         await send_json(websocket, 0.2, {"identifier": identifier, "error": f"You are already registered as '{existing_id}'."})
    else:
        # --- Registration Success ---
        # Add the identifier -> websocket mapping to CLIENTS registry.
        CLIENTS[identifier] = websocket
        # Add the websocket -> identifier mapping to CONNECTIONS registry.
        CONNECTIONS[websocket] = identifier
        # Log successful registration (important event, not wrapped in DEBUG).
        logging.info(f"Identifier '{identifier}' registered successfully for {client_address}")
        # Send success message (Type 0.1) back to the client.
        await send_json(websocket, 0.1, {"identifier": identifier, "message": "Registration successful."})


# --- Unregistration Logic ---
def unregister_client(websocket):
    """
    Removes a client's registration information from the global registries (CLIENTS and CONNECTIONS)
    when their WebSocket connection closes.
    If the disconnecting client was in an active chat session (tracked in ACTIVE_SESSIONS),
    it attempts to notify the peer of the disconnection by sending a Type 9 message.
    Cleans up the session tracking in ACTIVE_SESSIONS for both the disconnecting client and their peer.

    Args:
        websocket (websockets.WebSocketServerProtocol): The WebSocket connection object of the client that disconnected.
    """
    peer_id = None # Initialize peer_id to None.
    identifier = None # Initialize identifier to None.

    # Check if the disconnecting client connection was actually registered (i.e., present in CONNECTIONS).
    if websocket in CONNECTIONS:
        # Retrieve the identifier associated with this connection.
        identifier = CONNECTIONS[websocket]
        # Log unregistration (important event, not wrapped in DEBUG).
        logging.info(f"Unregistering client {websocket.remote_address} with ID '{identifier}'")

        # --- Disconnect Notification Logic ---
        # Check if this client was tracked as being in an active session.
        if identifier in ACTIVE_SESSIONS:
            peer_id = ACTIVE_SESSIONS.pop(identifier, None) # Get the peer's ID and remove the entry for the disconnecting client.
            if peer_id and peer_id in ACTIVE_SESSIONS:
                # If the peer also had an entry pointing back, remove it as well.
                ACTIVE_SESSIONS.pop(peer_id, None)
            # Log session clearing only if DEBUG is enabled.
            if config.DEBUG:
                logging.info(f"Cleared active session tracking involving {identifier}")

            # If a peer was found associated with the disconnecting client...
            if peer_id:
                # Look up the peer's WebSocket connection object.
                peer_websocket = CLIENTS.get(peer_id)
                # Check if the peer is still connected and registered.
                if peer_websocket:
                    # Log notification attempt only if DEBUG is enabled.
                    if config.DEBUG:
                        logging.info(f"Notifying peer {peer_id} about {identifier}'s disconnection.")
                    # Construct the Type 9 (Session End) payload to send to the peer.
                    notification_payload = {"targetId": peer_id, "senderId": identifier, "message": f"{identifier} disconnected."}
                    # Schedule the send_json operation as an asyncio task so it doesn't block the unregister_client function.
                    # This allows the cleanup to proceed quickly even if sending takes time or fails.
                    asyncio.create_task(send_json(peer_websocket, 9, notification_payload))
                else:
                    # Log if the peer was already disconnected (no notification needed). Only if DEBUG is enabled.
                    if config.DEBUG:
                        logging.info(f"Peer {peer_id} was already disconnected. No notification sent for {identifier}'s disconnect.")
        # --- End Disconnect Notification Logic ---

        # Remove the entry from the CLIENTS registry (ID -> connection). Check existence first.
        if identifier in CLIENTS:
            del CLIENTS[identifier]
        # Remove the entry from the CONNECTIONS registry (connection -> ID).
        del CONNECTIONS[websocket] # Do this after potentially using the identifier for notification.

    else:
        # Log if a client disconnects without ever successfully registering an ID (important event, not wrapped).
        logging.info(f"Client {websocket.remote_address} disconnected but had no registered ID.")


# --- Main Connection Handler ---
async def connection_handler(websocket):
    """
    The main asynchronous function that handles an individual client's WebSocket connection lifecycle.
    This function is executed for each new connection established with the server.
    It performs:
    1. Connection Rate Limiting based on client IP.
    2. Enters a loop to listen for incoming messages.
    3. For each message:
        - Performs Message Rate Limiting based on the connection.
        - Parses and validates the JSON message structure and payload content.
        - Routes the message:
            - To `handle_registration` if it's a Type 0 message.
            - Relays the message to the target client if it's a valid session message (Types 1-17, excluding 0).
            - Updates active session tracking upon successful relay of Type 2 (Accept) or Type 9 (End).
            - Sends error messages (Type -1, -2) back to the sender if the target is unavailable or limits are exceeded.
    4. Handles WebSocket closure events (clean or error) and ensures client unregistration and cleanup.

    Args:
        websocket (websockets.WebSocketServerProtocol): The WebSocket connection object representing the connected client.
    """
    client_ip = websocket.remote_address[0] # Get client IP address from the connection object.
    # Log connection attempt (important event, not wrapped).
    logging.info(f"Client attempting connection from {client_ip}:{websocket.remote_address[1]}")

    # --- Connection Rate Limiting ---
    current_time = time.time()
    # Get the list of recent connection timestamps for this IP, default to an empty list if IP not seen before.
    connection_times = CONNECTION_ATTEMPTS.get(client_ip, [])
    # Filter out timestamps older than the defined window (CONNECTION_WINDOW_SECONDS).
    valid_attempts = [t for t in connection_times if current_time - t < config.CONNECTION_WINDOW_SECONDS]
    # Check if the number of valid recent attempts exceeds the configured limit.
    if len(valid_attempts) >= config.MAX_CONNECTIONS_PER_IP:
        # Always log rate limit warnings.
        logging.warning(f"Connection rate limit exceeded for IP {client_ip}. Closing connection.")
        # Close the connection immediately with a policy violation code.
        await websocket.close(code=1008, reason="Connection rate limit exceeded")
        # Update the list in the dictionary (removes expired entries).
        CONNECTION_ATTEMPTS[client_ip] = valid_attempts
        return # Exit the handler, preventing further processing for this connection.
    else:
        # If limit not exceeded, add the current timestamp and update the tracking dictionary.
        valid_attempts.append(current_time)
        CONNECTION_ATTEMPTS[client_ip] = valid_attempts
        # Log connection acceptance (important event, not wrapped).
        logging.info(f"Connection accepted from {client_ip}:{websocket.remote_address[1]}")
        # Initialize message timestamp tracking for this new connection.
        MESSAGE_TIMESTAMPS[websocket] = []

    try:
        # --- Message Receiving Loop ---
        # Asynchronously iterate through messages received on this WebSocket connection.
        # The loop continues as long as the connection is open and messages are received.
        # It breaks automatically if the connection is closed by either end.
        async for message in websocket:
            current_time = time.time() # Get time for message rate limiting check.

            # --- Message Rate Limiting ---
            # Retrieve the list of recent message timestamps for this specific connection.
            message_times = MESSAGE_TIMESTAMPS.get(websocket, [])
            # Filter out timestamps older than the defined window (MESSAGE_WINDOW_SECONDS).
            valid_message_times = [t for t in message_times if current_time - t < config.MESSAGE_WINDOW_SECONDS]
            # Check if the number of valid recent messages exceeds the configured limit.
            if len(valid_message_times) >= config.MAX_MESSAGES_PER_CONNECTION:
                # Always log rate limit warnings.
                logging.warning(f"Message rate limit exceeded for {websocket.remote_address} ({CONNECTIONS.get(websocket, 'Unregistered')}). Sending notification and closing connection.")
                # Send a specific error message (Type -2) to the client before closing.
                error_payload = {"error": "Message rate limit exceeded. Disconnecting."}
                await send_json(websocket, -2, error_payload)
                # Close the connection due to policy violation.
                await websocket.close(code=1008, reason="Message rate limit exceeded")
                break # Exit the message receiving loop for this connection.
            else:
                # If limit not exceeded, add the current timestamp to the list for this connection.
                valid_message_times.append(current_time)
                MESSAGE_TIMESTAMPS[websocket] = valid_message_times

            # Log the raw message received only if server DEBUG mode is enabled.
            if config.DEBUG:
                logging.info(f"Raw message received from {websocket.remote_address} ({CONNECTIONS.get(websocket, 'Unregistered')}): {message}")

            # --- Message Parsing and Stricter Validation ---
            data = None # Initialize data variable.
            try:
                # Attempt to parse the received message string as JSON.
                data = json.loads(message)
            except json.JSONDecodeError:
                # Always log JSON parsing errors as warnings.
                logging.warning(f"Invalid JSON received from {websocket.remote_address}. Ignoring.")
                continue # Skip to the next message in the loop.

            # Basic structure validation: Ensure the parsed data is a dictionary.
            if not isinstance(data, dict):
                # Always log structure errors as warnings.
                logging.warning(f"Received non-dictionary data from {websocket.remote_address}. Ignoring: {data}")
                continue
            # Extract 'type' and 'payload' fields. Check for their existence.
            message_type = data.get("type")
            payload = data.get("payload")
            if message_type is None or payload is None:
                # Always log structure errors as warnings.
                logging.warning(f"Missing 'type' or 'payload' in message from {websocket.remote_address}. Ignoring: {data}")
                continue
            # Validate 'type' is a number.
            if not isinstance(message_type, (int, float)):
                # Always log type errors as warnings.
                logging.warning(f"Invalid 'type' (not a number) in message from {websocket.remote_address}. Ignoring: {data}")
                continue
            # Validate 'payload' is a dictionary.
            if not isinstance(payload, dict):
                 # Always log payload type errors as warnings.
                 logging.warning(f"Invalid 'payload' (not a dictionary) in message from {websocket.remote_address}. Ignoring: {data}")
                 continue

            # --- Type-Specific Payload Validation ---
            validation_passed = True # Assume valid initially.
            sender_id = CONNECTIONS.get(websocket) # Get sender's registered ID, if any.
            target_id = payload.get("targetId") # Extract targetId from payload.

            # Helper function for common string validation (non-empty, within max length).
            def is_valid_string(value, max_len=50):
                return isinstance(value, str) and 0 < len(value.strip()) <= max_len

            # Helper function for basic Base64-like string validation (checks characters and length).
            # This is not a full Base64 validation but catches many obvious format errors.
            def is_valid_base64_like(value, max_len=config.MAX_ENCRYPTED_DATA_LENGTH): # Use config value if available, else default
                return isinstance(value, str) and 0 < len(value) <= max_len and re.match(r"^[A-Za-z0-9+/=]+$", value)

            # Validate payload content based on message type.
            if message_type == 0: # Registration (Type 0)
                identifier = payload.get("identifier")
                # Check if identifier is a string within length limits (handled further in handle_registration).
                if not isinstance(identifier, str) or not (0 < len(identifier) <= 30):
                    logging.warning(f"Invalid identifier type/length in Type 0 payload from {websocket.remote_address}. Ignoring: {payload}")
                    validation_passed = False
                    # Send error back immediately for basic type/length issues.
                    await send_json(websocket, 0.2, {"identifier": identifier, "error": "Identifier must be a non-empty string (max 30 chars)."})
                # Regex format check happens inside handle_registration.

            elif message_type in [1, 3, 7, 9, 10, 11]: # Messages primarily needing targetId and senderId consistency.
                if not is_valid_string(target_id, 30): # Validate targetId format/length.
                    logging.warning(f"Invalid 'targetId' in Type {message_type} payload from {websocket.remote_address}. Ignoring: {payload}")
                    validation_passed = False
                # If sender is registered, ensure senderId in payload matches the registered ID.
                elif sender_id and payload.get("senderId") != sender_id:
                    logging.warning(f"Mismatched 'senderId' in Type {message_type} from registered client {sender_id}. Ignoring: {payload}")
                    validation_passed = False

            elif message_type in [2, 4]: # Messages containing a public key.
                if not is_valid_string(target_id, 30): validation_passed = False
                # Validate the publicKey field (Base64 SPKI format).
                elif not is_valid_base64_like(payload.get("publicKey"), 512): # SPKI keys are relatively short.
                    logging.warning(f"Invalid 'publicKey' format/length in Type {message_type} payload from {websocket.remote_address}. Ignoring.")
                    validation_passed = False
                elif sender_id and payload.get("senderId") != sender_id: validation_passed = False

            elif message_type == 5: # Key Confirmation Challenge.
                if not is_valid_string(target_id, 30): validation_passed = False
                elif not is_valid_base64_like(payload.get("iv"), 32): validation_passed = False # IV is short.
                elif not is_valid_base64_like(payload.get("encryptedChallenge")): validation_passed = False # Check encrypted data field.
                elif sender_id and payload.get("senderId") != sender_id: validation_passed = False
                if not validation_passed: logging.warning(f"Invalid Type 5 payload from {websocket.remote_address}. Ignoring.")

            elif message_type == 6: # Key Confirmation Response.
                if not is_valid_string(target_id, 30): validation_passed = False
                elif not is_valid_base64_like(payload.get("iv"), 32): validation_passed = False
                elif not is_valid_base64_like(payload.get("encryptedResponse")): validation_passed = False # Check encrypted data field.
                elif sender_id and payload.get("senderId") != sender_id: validation_passed = False
                if not validation_passed: logging.warning(f"Invalid Type 6 payload from {websocket.remote_address}. Ignoring.")

            elif message_type == 8: # Encrypted Chat Message.
                if not is_valid_string(target_id, 30): validation_passed = False
                elif not is_valid_base64_like(payload.get("iv"), 32): validation_passed = False
                elif not is_valid_base64_like(payload.get("data")): validation_passed = False # Check 'data' field containing encrypted JSON.
                elif sender_id and payload.get("senderId") != sender_id: validation_passed = False
                if not validation_passed: logging.warning(f"Invalid Type 8 payload from {websocket.remote_address}. Ignoring.")

            # File Transfer Validation
            elif message_type == 12: # FILE_TRANSFER_REQUEST
                file_size = payload.get("fileSize")
                if not is_valid_string(target_id, 30): validation_passed = False
                elif not is_valid_string(payload.get("transferId"), 64): validation_passed = False # UUID length + buffer.
                elif not is_valid_string(payload.get("fileName"), 255): validation_passed = False # Max filename length.
                elif not isinstance(file_size, int) or file_size < 0: validation_passed = False # Must be non-negative integer.
                # Optional server-side file size check against config.
                elif hasattr(config, 'MAX_FILE_SIZE_BYTES') and file_size > config.MAX_FILE_SIZE_BYTES:
                    logging.warning(f"File size {file_size} exceeds server limit ({config.MAX_FILE_SIZE_BYTES}). Rejecting Type 12 from {sender_id}.")
                    # Send specific error back to sender.
                    await send_json(websocket, 17, {"transferId": payload.get("transferId"), "targetId": sender_id, "senderId": "Server", "error": "File exceeds maximum allowed size."})
                    validation_passed = False # Prevent relaying the request.
                elif not is_valid_string(payload.get("fileType"), 100): validation_passed = False # MIME type length.
                elif sender_id and payload.get("senderId") != sender_id: validation_passed = False
                if not validation_passed: logging.warning(f"Invalid Type 12 payload from {websocket.remote_address}. Ignoring.")

            elif message_type in [13, 14, 16]: # FILE_TRANSFER_ACCEPT / REJECT / COMPLETE
                if not is_valid_string(target_id, 30): validation_passed = False
                elif not is_valid_string(payload.get("transferId"), 64): validation_passed = False
                elif sender_id and payload.get("senderId") != sender_id: validation_passed = False
                if not validation_passed: logging.warning(f"Invalid Type {message_type} payload from {websocket.remote_address}. Ignoring.")

            elif message_type == 15: # FILE_CHUNK
                if not is_valid_string(target_id, 30): validation_passed = False
                elif not is_valid_string(payload.get("transferId"), 64): validation_passed = False
                elif not isinstance(payload.get("chunkIndex"), int) or payload.get("chunkIndex") < 0: validation_passed = False # Index must be non-negative int.
                elif not is_valid_base64_like(payload.get("iv"), 32): validation_passed = False
                # Data length check relies on WebSocket max_size setting configured in start_server.
                elif not is_valid_base64_like(payload.get("data")): validation_passed = False
                elif sender_id and payload.get("senderId") != sender_id: validation_passed = False
                if not validation_passed: logging.warning(f"Invalid Type 15 payload from {websocket.remote_address}. Ignoring.")

            elif message_type == 17: # FILE_TRANSFER_ERROR
                if not is_valid_string(target_id, 30): validation_passed = False
                elif not is_valid_string(payload.get("transferId"), 64): validation_passed = False
                # Error message string is optional but must be a string if present.
                elif "error" in payload and not isinstance(payload.get("error"), str): validation_passed = False
                elif sender_id and payload.get("senderId") != sender_id: validation_passed = False
                if not validation_passed: logging.warning(f"Invalid Type 17 payload from {websocket.remote_address}. Ignoring.")
            # --- End File Transfer Validation ---

            # If any validation check failed, skip processing this message.
            if not validation_passed:
                continue

            # --- Message Routing (Post-Validation) ---
            if message_type == 0: # Registration Request
                # Call the registration handler (identifier format checked again internally).
                await handle_registration(websocket, payload["identifier"])
            # --- Message Relaying (for registered clients) ---
            elif sender_id: # Check if the sender is registered before relaying.
                # Target ID already extracted and validated above.
                # Log relay attempt only if DEBUG is enabled.
                if config.DEBUG:
                    # Avoid logging full chunk data in debug mode for performance/readability.
                    log_payload = payload if message_type != 15 else {**payload, "data": f"<Chunk {payload.get('chunkIndex', '?')} Data Omitted>"}
                    logging.info(f"Attempting to relay message type {message_type} from '{sender_id}' to '{target_id}': {log_payload}")
                # Look up the target client's WebSocket connection object using their ID.
                target_websocket = CLIENTS.get(target_id)

                # --- Relay Logic ---
                if target_websocket: # Check if the target client is currently connected and registered.
                    try:
                        # Log successful relay only if DEBUG is enabled.
                        if config.DEBUG:
                            logging.info(f"Relaying message to {target_id} ({target_websocket.remote_address})")
                        # Send the original, validated JSON message string to the target client.
                        await target_websocket.send(message)

                        # --- Active Session Tracking Update ---
                        # If a Type 2 (Accept) is successfully relayed, record the session initiation.
                        if message_type == 2:
                            # Log session recording only if DEBUG is enabled.
                            if config.DEBUG:
                                logging.info(f"Recording active session between {sender_id} and {target_id}")
                            # Store bidirectional mapping in ACTIVE_SESSIONS.
                            ACTIVE_SESSIONS[sender_id] = target_id
                            ACTIVE_SESSIONS[target_id] = sender_id

                        # If a Type 9 (End Session) is successfully relayed, clear the session tracking.
                        elif message_type == 9:
                            # Log session clearing only if DEBUG is enabled.
                            if config.DEBUG:
                                logging.info(f"Clearing active session between {sender_id} and {target_id} due to Type 9 message relay.")
                            # Remove entries for both participants if they exist and match.
                            if sender_id in ACTIVE_SESSIONS and ACTIVE_SESSIONS[sender_id] == target_id:
                                del ACTIVE_SESSIONS[sender_id]
                            if target_id in ACTIVE_SESSIONS and ACTIVE_SESSIONS[target_id] == sender_id:
                                del ACTIVE_SESSIONS[target_id]
                        # --- End Active Session Tracking Update ---

                    except websockets.exceptions.ConnectionClosed:
                        # Handle the case where the target client disconnected *during* the send attempt.
                        # Always log this warning.
                        logging.warning(f"Relay failed: Target user '{target_id}' connection closed during send attempt.")
                        # Send standardized error message (Type -1) back to the original sender.
                        error_payload = {"targetId": target_id, "message": f"User '{target_id}' is unavailable."}
                        await send_json(websocket, -1, error_payload)
                    except Exception as e:
                         # Catch any other unexpected errors during the relay send operation.
                         # Always log unexpected exceptions.
                         logging.exception(f"Unexpected error relaying message to {target_id}")
                         # Consider sending a generic error back to the sender here as well.
                else:
                    # Target client ID not found in the CLIENTS registry (not online or never registered).
                    # Always log this warning.
                    logging.warning(f"Target user '{target_id}' not found. Sending error back to '{sender_id}'.")
                    # Send standardized error message (Type -1) back to the original sender.
                    error_payload = {"targetId": target_id, "message": f"User '{target_id}' is unavailable."}
                    await send_json(websocket, -1, error_payload)
            else:
                # Received a non-registration message from a client that hasn't registered yet.
                # Always log this warning.
                logging.warning(f"Received non-registration message type {message_type} from unregistered client {websocket.remote_address}. Ignoring.")

    # --- Connection Closed Handling ---
    # These exceptions are raised by the `async for message in websocket:` loop when the connection closes.
    except websockets.exceptions.ConnectionClosedOK:
        # Log when a client disconnects cleanly (e.g., browser closed, client called disconnect). (Important event, not wrapped).
        logging.info(f"Client {websocket.remote_address} disconnected gracefully.")
    except websockets.exceptions.ConnectionClosedError as e:
        # Log when a client disconnects due to an error (e.g., network issue, process killed). (Important event, not wrapped).
        logging.info(f"Client {websocket.remote_address} disconnected with error: {e}")
    except Exception as e:
        # Catch any other unexpected errors in the main connection handling loop itself.
        # Always log unexpected exceptions.
        logging.exception(f"An unexpected error occurred handling client {websocket.remote_address}")
    finally:
        # --- Cleanup ---
        # This block executes regardless of how the connection handling loop exited (clean close, error, exception).
        # Remove message rate limiting data for this connection to free memory.
        if websocket in MESSAGE_TIMESTAMPS:
            del MESSAGE_TIMESTAMPS[websocket]
            # Log cleanup only if DEBUG is enabled.
            if config.DEBUG:
                logging.info(f"Removed message timestamp tracking for {websocket.remote_address}")
        # Ensure the client is unregistered from the global registries AND handle disconnect notification if needed.
        unregister_client(websocket) # This function now includes the notification logic.
        # Log connection closed confirmation (important event, not wrapped).
        logging.info(f"Connection closed for {websocket.remote_address}")


# --- Server Startup Function ---
async def start_server(host, port):
    """
    Initializes and starts the WebSocket server, listening on the specified host and port.
    Configures SSL context for WSS if enabled in the config file.
    Sets the maximum message size allowed.
    Runs the server indefinitely until the process is stopped.

    Args:
        host (str): The hostname or IP address to bind the server to (from config).
        port (int): The port number to bind the server to (from config).
    """
    ssl_context = None # Initialize ssl_context to None (default to WS - unencrypted).
    protocol = "ws" # Default protocol string.

    # Check if SSL (for WSS) is enabled in the configuration.
    if config.ENABLE_SSL:
        try:
            # Log the paths being used for certificate and key files for verification.
            logging.info(f"Attempting to load SSL cert: {config.CERT_FILE}")
            logging.info(f"Attempting to load SSL key: {config.KEY_FILE}")
            # Create an SSL context configured for a TLS server.
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # Load the certificate chain file (cert.pem) and the corresponding private key file (key.pem).
            # These files must exist at the paths specified in config.py and be valid.
            ssl_context.load_cert_chain(config.CERT_FILE, config.KEY_FILE)
            protocol = "wss" # Update protocol string to indicate WSS will be used.
            logging.info("SSL context created successfully. Server will use WSS.")
        except FileNotFoundError:
            # Handle error if certificate or key file is not found at the specified path.
            logging.error(f"SSL Error: Certificate or Key file not found (Cert: '{config.CERT_FILE}', Key: '{config.KEY_FILE}'). Disabling SSL, falling back to WS.")
            ssl_context = None # Ensure ssl_context is None to fall back to unencrypted WS.
        except Exception as e:
            # Handle any other errors during SSL context creation or loading (e.g., invalid format, permissions).
            logging.exception("SSL Error: Failed to create SSL context. Disabling SSL, falling back to WS.")
            ssl_context = None # Ensure ssl_context is None to fall back to unencrypted WS.

    # Determine the effective protocol (ws or wss) based on whether SSL context was successfully created.
    effective_protocol = "wss" if ssl_context else "ws"
    # Log essential server startup information.
    logging.info(f"Starting server on {effective_protocol}://{host}:{port}")
    logging.info(f"Connection Rate Limit: {config.MAX_CONNECTIONS_PER_IP} per {config.CONNECTION_WINDOW_SECONDS}s per IP")
    logging.info(f"Message Rate Limit: {config.MAX_MESSAGES_PER_CONNECTION} per {config.MESSAGE_WINDOW_SECONDS}s per Connection")

    # Define the maximum incoming WebSocket message size (in bytes).
    # This needs to be large enough to accommodate the largest expected message type,
    # which is likely a file chunk (Type 15) including Base64 encoding overhead.
    # Example calculation: Chunk size (e.g., 256KB) + IV + index + overhead. Set slightly larger for buffer.
    MAX_MESSAGE_SIZE = 300 * 1024 # Example: 300KB limit. Adjust based on client CHUNK_SIZE + overhead.
    logging.info(f"Maximum WebSocket message size set to: {MAX_MESSAGE_SIZE} bytes") # Log the max size being used.
    # Log server debug status.
    logging.info(f"Server Debug Logging: {'ENABLED' if config.DEBUG else 'DISABLED'}")


    try:
        # Start the WebSocket server using websockets.serve().
        # - connection_handler: The function to execute for each new client connection.
        # - host: The host address to listen on.
        # - port: The port number to listen on.
        # - ssl: Pass the created SSL context here if using WSS, otherwise None for WS.
        # - max_size: Set the maximum allowed size for incoming WebSocket messages in bytes.
        async with websockets.serve(
            connection_handler,
            host,
            port,
            ssl=ssl_context, # Pass the SSL context (or None).
            max_size=MAX_MESSAGE_SIZE # Apply the maximum message size limit.
        ) as server_instance:
            # Keep the server running indefinitely by awaiting a Future that never completes.
            # The server will continue handling connections until the process is interrupted (e.g., Ctrl+C).
            await asyncio.Future() # This runs forever.
    except OSError as e:
        # Catch common OS-level errors during server startup, like "Address already in use".
        logging.exception(f"OSError starting server on {host}:{port} - Is the port already in use?")
    except Exception as e:
        # Catch any other unexpected errors during server startup or the main server runtime.
        logging.exception(f"Unexpected error occurred during server startup or runtime ({effective_protocol})")
        raise # Re-raise the exception so it can be caught by main.py if needed.

# Note: The actual execution start (asyncio.run(start_server(...))) is handled in server/main.py.
