# server/main.py
# This script serves as the main entry point for starting the HeliX WebSocket server.
# It imports necessary modules (asyncio, config, server, logging), sets up basic logging configuration,
# reads configuration settings from the 'config' module, and initiates the asynchronous
# server startup process defined in the 'server' module.

import asyncio  # Provides infrastructure for writing single-threaded concurrent code using coroutines. Used for the server's event loop.
import config   # Imports server configuration variables (HOST, PORT, SSL settings, etc.) defined in server/config.py.
import server   # Imports the main server logic, including the start_server function and connection handler, from server/server.py.
import logging  # Imports the standard Python logging module for recording server events and errors.

# Configure basic logging settings for the server application.
# - level=logging.INFO: Sets the minimum severity level to log (INFO, WARNING, ERROR, CRITICAL). DEBUG messages are ignored unless level is set to DEBUG.
# - format='...': Defines the format for log messages, including timestamp, log level name, and the message content.
# This basic configuration applies globally unless more specific loggers are configured elsewhere (e.g., in server.py if needed).
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Standard Python entry point check.
# Ensures the code inside this block only runs when the script is executed directly
# (e.g., `python server/main.py`), not when it's imported as a module into another script.
if __name__ == "__main__":
    # Log the attempt to start the server from this entry point.
    logging.info("Attempting to start server from main.py...")
    try:
        # Log the host and port configuration being used, read from the imported config module.
        logging.info(f"Using HOST={config.HOST}, PORT={config.PORT}")

        # Start the asyncio event loop and run the main server startup function until it completes.
        # asyncio.run() simplifies running the top-level asynchronous function (server.start_server).
        # server.start_server() (defined in server.py) contains the core logic
        # to initialize and run the underlying websockets server, listening for connections.
        asyncio.run(server.start_server(config.HOST, config.PORT))

    except KeyboardInterrupt:
        # Handle graceful shutdown if the user presses Ctrl+C in the terminal where the server is running.
        logging.info("Server stopped manually via KeyboardInterrupt.")
    except Exception as e:
        # Catch any other unexpected exceptions during server startup or runtime
        # that might propagate up to this top level (e.g., port already in use, critical errors in server logic).
        # logging.exception automatically includes traceback information for detailed debugging.
        logging.exception("Server failed to start or crashed in main.py")
