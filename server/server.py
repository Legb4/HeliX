# server/server.py
# This file contains the core logic for the HeliX WebSocket server,
# including client registration, message relaying, connection handling, and SSL setup.

import asyncio          # For asynchronous operations (coroutines, event loop).
import websockets       # The WebSocket library used for server and client handling.
import logging          # For logging server events, warnings, and errors.
import json             # For parsing and serializing JSON messages between client and server.
import ssl              # For creating SSL contexts if WSS (Secure WebSockets) is enabled.
import config           # Imports server configuration (HOST, PORT, SSL settings).


# Configure basic logging (can also be done in main.py, ensures it's set).
# Level INFO means INFO, WARNING, ERROR, CRITICAL messages will be shown.
# Format includes timestamp, log level, and the message itself.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Global Registries ---

# CLIENTS: A dictionary mapping registered client identifiers (strings) to their
# corresponding WebSocket connection objects. Allows looking up a connection by ID.
# Example: {'Alice123': <WebSocketConnection object for Alice>, 'Bob456': <WebSocketConnection object for Bob>}
CLIENTS = {}

# CONNECTIONS: A reverse lookup dictionary mapping active WebSocket connection objects
# to their registered client identifiers (strings). Allows finding a client's ID from their connection.
# Example: {<WebSocketConnection object for Alice>: 'Alice123', <WebSocketConnection object for Bob>: 'Bob456'}
CONNECTIONS = {}

# --- Helper function to send JSON messages ---
async def send_json(websocket, message_type, payload):
    """
    Helper function to format a message as JSON and send it over a WebSocket connection.
    Handles JSON serialization and logs the outgoing message.
    Includes basic error handling for closed connections during send.

    Args:
        websocket: The websockets.WebSocketServerProtocol object representing the client connection.
        message_type: The numeric type identifier for the message (e.g., 0.1, -1).
        payload: The dictionary containing the message data.
    """
    # Note: The check 'if websocket.open:' was removed. Relying on the 'await websocket.send()'
    # call itself to raise ConnectionClosed exceptions is generally more robust in asyncio,
    # as the state could potentially change between the check and the send operation.
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
        # This is expected if the client disconnects abruptly.
        logging.warning(f"Failed to send to {websocket.remote_address} ({CONNECTIONS.get(websocket, 'N/A')}) because connection is closed: {e}")
    # Other exceptions during json.dumps or websocket.send (less common) will propagate
    # up to the main handler's try/except block for more general error logging.

# --- Registration Logic ---
async def handle_registration(websocket, identifier):
    """
    Handles a client's registration request (Type 0 message).
    Validates the identifier, checks if it's already taken or if the client is already registered,
    and updates the global CLIENTS and CONNECTIONS registries if successful.
    Sends a success (Type 0.1) or failure (Type 0.2) response back to the client.

    Args:
        websocket: The WebSocket connection object of the client attempting to register.
        identifier: The identifier string provided by the client.
    """
    client_address = websocket.remote_address
    logging.info(f"Handling registration request for '{identifier}' from {client_address}")

    # --- Input Validation ---
    # Check if identifier is missing, not a string, or too long.
    if not identifier or not isinstance(identifier, str) or len(identifier) > 50:
         # Send failure message (Type 0.2) back to the client.
         await send_json(websocket, 0.2, {"identifier": identifier, "error": "Invalid identifier format."})
         logging.warning(f"Invalid identifier format from {client_address}: '{identifier}'")
         return # Stop processing this registration request.

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
    This is typically called when a client disconnects.

    Args:
        websocket: The WebSocket connection object of the client that disconnected.
    """
    # Check if the disconnecting client was actually registered (i.e., present in CONNECTIONS).
    if websocket in CONNECTIONS:
        # Retrieve the identifier associated with this connection.
        identifier = CONNECTIONS[websocket]
        logging.info(f"Unregistering client {websocket.remote_address} with ID '{identifier}'")
        # Remove the entry from the CLIENTS registry (ID -> connection).
        if identifier in CLIENTS:
            del CLIENTS[identifier]
        # Remove the entry from the CONNECTIONS registry (connection -> ID).
        del CONNECTIONS[websocket]
    else:
        # Log if a client disconnects without ever registering an ID.
        logging.info(f"Client {websocket.remote_address} disconnected but had no registered ID.")


# --- Main Connection Handler ---
async def connection_handler(websocket):
    """
    The main asynchronous function that handles an individual client's WebSocket connection lifecycle.
    It listens for incoming messages, parses them, routes them (registration or relay),
    and handles errors and disconnection cleanup.

    Args:
        websocket: The websockets.WebSocketServerProtocol object representing the connected client.
    """
    client_address = websocket.remote_address
    logging.info(f"Client connected from {client_address}")

    try:
        # --- Message Receiving Loop ---
        # Continuously listen for messages from this client.
        # The loop breaks automatically if the connection is closed.
        async for message in websocket:
            # Log the raw message received, including the client's ID if registered.
            logging.info(f"Raw message received from {client_address} ({CONNECTIONS.get(websocket, 'Unregistered')}): {message}")
            try:
                # --- Message Parsing and Basic Validation ---
                # Attempt to parse the incoming message string as JSON.
                data = json.loads(message)
                # Extract the message type and payload. Use .get() for safety if keys might be missing.
                message_type = data.get("type")
                payload = data.get("payload")

                # --- Message Routing ---
                if message_type == 0: # Registration Request
                    # Check if payload exists and contains the 'identifier' key.
                    if payload and "identifier" in payload:
                        # Call the registration handler.
                        await handle_registration(websocket, payload["identifier"])
                    else:
                         # Log malformed registration requests.
                         logging.warning(f"Malformed registration request from {client_address}: {message}")
                # --- Message Relaying (for registered clients) ---
                elif websocket in CONNECTIONS: # Check if the sender is registered.
                    # Get the sender's registered identifier.
                    sender_id = CONNECTIONS[websocket]
                    # Extract the target identifier from the payload.
                    target_id = payload.get("targetId") if payload else None

                    # Validate that a targetId exists for relayable messages.
                    if not target_id:
                        logging.warning(f"Received message type {message_type} without targetId from {sender_id}: {message}")
                        continue # Skip processing this message.

                    logging.info(f"Attempting to relay message type {message_type} from '{sender_id}' to '{target_id}'")
                    # Look up the target client's WebSocket connection using their ID.
                    target_websocket = CLIENTS.get(target_id)

                    # --- Relay Logic ---
                    if target_websocket: # Check if the target client is currently connected and registered.
                        try:
                            logging.info(f"Relaying message to {target_id} ({target_websocket.remote_address})")
                            # Send the original, unmodified JSON message string to the target client.
                            # The server does not need to understand the payload content for E2EE chat messages.
                            await target_websocket.send(message)
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
                    logging.warning(f"Received non-registration message from unregistered client {client_address}. Ignoring.")

            except json.JSONDecodeError:
                # Handle errors if the received message is not valid JSON.
                logging.error(f"Could not decode JSON from {client_address}: {message}")
            except Exception as e:
                # Catch any other errors that occur during the processing of a single message
                # (e.g., unexpected payload structure, errors in handlers).
                logging.exception(f"Error processing message from {client_address} ({CONNECTIONS.get(websocket, 'Unregistered')}): {message}")
                # Consider sending a generic error back to the client if appropriate.

    # --- Connection Closed Handling ---
    except websockets.exceptions.ConnectionClosedOK:
        # Log when a client disconnects cleanly (e.g., browser closed, client called disconnect).
        logging.info(f"Client {client_address} disconnected gracefully.")
    except websockets.exceptions.ConnectionClosedError as e:
        # Log when a client disconnects due to an error (e.g., network interruption).
        logging.info(f"Client {client_address} disconnected with error: {e}")
    except Exception as e:
        # Catch any unexpected errors in the main connection handling loop itself
        # (outside the message processing loop).
        logging.exception(f"An unexpected error occurred handling client {client_address}")
    finally:
        # --- Cleanup ---
        # This block executes regardless of how the 'try' block exits (normal close, error, etc.).
        # Ensure the client is unregistered from the global registries.
        unregister_client(websocket)
        logging.info(f"Connection closed for {client_address}")
        # Optional: Log exit from the handler for clarity during debugging.
        # logging.info(f"--- Exiting connection_handler for {client_address} ---")


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
