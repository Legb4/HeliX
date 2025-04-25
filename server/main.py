# server/main.py
# This script serves as the main entry point for starting the HeliX WebSocket server.
# It imports necessary modules, sets up basic logging, reads configuration,
# and initiates the server startup process defined in server.py.

import asyncio  # For running the asynchronous server event loop.
import config   # Imports server configuration variables (HOST, PORT, SSL settings).
import server   # Imports the main server logic (start_server function, handlers).
import logging  # Imports the logging module for status and error messages.

# Configure basic logging settings for the server.
# - level=logging.INFO: Sets the minimum severity level to log (INFO, WARNING, ERROR, CRITICAL).
# - format='...': Defines the format for log messages, including timestamp, level, and message content.
# This configuration applies globally unless overridden elsewhere.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Standard Python entry point check.
# Ensures the code inside this block only runs when the script is executed directly
# (not when imported as a module).
if __name__ == "__main__":
    logging.info("Attempting to start server from main.py...")
    try:
        # Log the host and port being used, read from the config module.
        logging.info(f"Using HOST={config.HOST}, PORT={config.PORT}")

        # Start the asyncio event loop and run the main server startup function.
        # asyncio.run() manages the event loop lifecycle.
        # server.start_server() (defined in server.py) contains the core logic
        # to initialize and run the websockets server.
        asyncio.run(server.start_server(config.HOST, config.PORT))

    except KeyboardInterrupt:
        # Handle graceful shutdown if the user presses Ctrl+C.
        logging.info("Server stopped manually via KeyboardInterrupt.")
    except Exception as e:
        # Catch any other unexpected exceptions during server startup or runtime
        # that might propagate up to this level.
        # logging.exception automatically includes traceback information.
        logging.exception("Server failed to start or crashed in main.py")
