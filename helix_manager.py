#!/usr/bin/env python3
# helix_manager.py - Main control script for HeliX Chat
#
# This script provides a command-line interface to manage the HeliX chat application:
# - Checks for the required 'websockets' library and offers installation.
# - Provides a menu option to manage TLS certificates using 'mkcert':
#   - Checks for 'mkcert' utility (in PATH or ./certs/mkcert.exe on Windows).
#   - Offers to install the mkcert CA for browser trust.
#   - Generates/overwrites local TLS certificates (cert.pem, key.pem) for localhost/127.0.0.1.
#   - Offers to back up existing certificates before overwriting.
# - Allows viewing and modifying configuration settings (WSS Host/Port, HTTPS Host/Port).
# - Saves WSS configuration changes persistently to server/config.py.
# - Starts both the WebSocket Secure (WSS) server (as a subprocess) and
#   an integrated HTTPS server (in a separate thread) to serve client files.
#   (Requires certificates to exist before starting).
# - Displays real-time logs from the WSS server to the console.
# - Logs HTTPS server activity to a file (logs/https_server.log).
# - Handles graceful shutdown of both servers on Ctrl+C.

import subprocess         # For running external processes (WSS server, pip, mkcert).
import sys                # For accessing Python interpreter path and exiting.
import os                 # For path manipulation (finding files, creating dirs, renaming).
import re                 # For regular expressions used in config file parsing.
import importlib.util     # For checking if a library is installed without importing it.
import threading          # For running the HTTPS server and WSS logger concurrently.
import time               # For pausing execution (e.g., in wait loops).
import ssl                # For setting up the SSL context for the HTTPS server.
import http.server        # For the basic HTTPS file server implementation.
import logging            # For logging HTTPS server activity to a file.
import platform           # For detecting the operating system (Windows, Linux, Darwin).
import shutil             # For finding executables in PATH (shutil.which).
from socketserver import ThreadingMixIn # To make the HTTPS server handle requests in threads.

# --- Constants ---
# Define file paths relative to the location of this script for portability.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) # Absolute path to script's directory.
WSS_CONFIG_PATH = os.path.join(SCRIPT_DIR, 'server', 'config.py') # Path to WSS server config.
HTTPS_CLIENT_DIR = os.path.join(SCRIPT_DIR, 'client') # Path to the client files directory.
CERT_DIR = os.path.join(SCRIPT_DIR, 'certs') # Path to the SSL certificates directory.
CERT_FILE = os.path.join(CERT_DIR, 'cert.pem') # Expected SSL certificate filename.
KEY_FILE = os.path.join(CERT_DIR, 'key.pem') # Expected SSL private key filename.
CERT_OLD_FILE = os.path.join(CERT_DIR, 'cert_old.pem') # Backup certificate filename.
KEY_OLD_FILE = os.path.join(CERT_DIR, 'key_old.pem') # Backup key filename.
LOG_DIR = os.path.join(SCRIPT_DIR, 'logs') # Directory to store log files.
HTTPS_LOG_FILE = os.path.join(LOG_DIR, 'https_server.log') # Log file for the HTTPS server.

# --- Global Variables for Server Management ---
# These variables hold references to the running processes and threads
# to allow for proper management and shutdown.
wss_process = None      # Holds the subprocess.Popen object for the WSS server.
https_server = None     # Holds the http.server.HTTPServer instance.
https_thread = None     # Holds the threading.Thread object for the HTTPS server.
wss_log_thread = None   # Holds the threading.Thread object for the WSS logger.
stop_event = threading.Event() # A synchronization primitive used to signal threads (like the WSS logger) to stop gracefully.

# --- Logging Setup for HTTPS Server ---
# Configure a dedicated logger for the HTTPS server to write to a file.
https_logger = logging.getLogger('HTTPServer') # Get a specific logger instance.
https_logger.setLevel(logging.INFO) # Set the minimum logging level.
# Ensure the log directory exists before trying to write to it.
os.makedirs(LOG_DIR, exist_ok=True)
# Create a file handler to write logs to the specified file in append mode ('a').
https_file_handler = logging.FileHandler(HTTPS_LOG_FILE, mode='a', encoding='utf-8')
# Define the format for log messages written to the file.
https_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
# Add the file handler to our dedicated logger.
https_logger.addHandler(https_file_handler)
# Prevent messages logged here from propagating up to the root logger (which might log to console).
https_logger.propagate = False

# --- Dependency Management ---
def check_or_install_websockets():
    """
    Checks if the 'websockets' library is installed using importlib.
    If not found, it prompts the user for confirmation and attempts to install
    it using pip associated with the current Python interpreter. Exits if
    installation is declined or fails.
    """
    print("Checking for 'websockets' library...")
    # Use find_spec for a lightweight check without importing the module.
    spec = importlib.util.find_spec("websockets")
    if spec is None:
        # Library not found.
        print("'websockets' library not found.")
        confirm = input("Attempt to install it using pip? (y/n): ").lower().strip()
        if confirm == 'y':
            print("Installing 'websockets'...")
            try:
                # Run pip as a subprocess using the current Python interpreter's path.
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "websockets"],
                    check=True,        # Raise error if pip fails
                    capture_output=True,# Hide pip output unless error
                    text=True          # Decode output as text
                )
                print("'websockets' installed successfully.")
            except subprocess.CalledProcessError as e:
                # Handle pip installation errors.
                print(f"Error installing 'websockets': {e}")
                print("--- PIP Error Output ---")
                print(e.stderr) # Print captured stderr
                print("----------------------")
                print("Please install 'websockets' manually (e.g., 'pip install websockets') and restart.")
                sys.exit(1) # Exit manager script.
            except FileNotFoundError:
                # Handle error if 'pip' itself isn't found.
                print("Error: 'pip' command not found. Is Python installed correctly and in your PATH?")
                sys.exit(1) # Exit manager script.
        else:
            # User declined installation.
            print("Installation declined. Please install 'websockets' manually and restart.")
            sys.exit(1) # Exit manager script.
    else:
        # Library already installed.
        print("'websockets' library found.")

# --- Certificate Generation ---
def generate_certificates():
    """
    Manages TLS certificate generation using mkcert.
    - Finds mkcert executable based on OS.
    - Displays mkcert version.
    - Prompts user to install the mkcert local CA.
    - Checks for existing certificates and prompts for overwrite/backup.
    - Generates new certificates for 'localhost' and '127.0.0.1'.

    Returns:
        bool: True if certificates exist or were successfully generated/handled, False otherwise.
    """
    print("\n--- Certificate Management ---")
    os.makedirs(CERT_DIR, exist_ok=True) # Ensure certs directory exists

    # 1. Find mkcert executable based on OS
    mkcert_path = None
    system = platform.system()
    print(f"Detected OS: {system}")
    if system == "Windows":
        # On Windows, expect mkcert.exe in the ./certs directory relative to this script
        expected_path = os.path.join(CERT_DIR, "mkcert.exe")
        if os.path.exists(expected_path):
            mkcert_path = expected_path
            print(f"Found mkcert at expected Windows location: {mkcert_path}")
        else:
            print(f"Error: 'mkcert.exe' not found in '{CERT_DIR}'.")
            print("Please download mkcert for Windows from https://github.com/FiloSottile/mkcert/releases")
            print(f"and place 'mkcert.exe' inside the '{CERT_DIR}' directory.")
            return False # Cannot proceed without mkcert
    elif system in ["Linux", "Darwin"]: # Linux or macOS
        # On Linux/macOS, expect mkcert in the system PATH
        print("Searching for 'mkcert' in system PATH...")
        mkcert_path = shutil.which("mkcert")
        if mkcert_path is None:
            print("Error: 'mkcert' command not found in your system PATH.")
            if system == "Darwin":
                print("Suggestion: Install it using Homebrew ('brew install mkcert')")
            else: # Linux
                print("Suggestion: Install it using your package manager (e.g., apt, yum, pacman)")
            print("Alternatively, download from https://github.com/FiloSottile/mkcert/releases")
            print("and ensure the executable is in your system's PATH.")
            return False # Cannot proceed without mkcert
        else:
             print(f"Found mkcert in PATH: {mkcert_path}")
    else:
        print(f"Unsupported operating system for automatic mkcert handling: {system}")
        return False # Cannot proceed

    # 2. Display mkcert version
    try:
        print("Checking mkcert version...")
        # Run mkcert -version command
        result = subprocess.run([mkcert_path, "-version"], capture_output=True, text=True, check=True, timeout=10)
        print(f"mkcert version info:\n{result.stdout.strip()}")
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"Warning: Could not get mkcert version: {e}")
        # Continue anyway, maybe version command failed but others work

    # 3. Offer to install CA
    install_ca = input("Attempt to install the mkcert local CA (needed for browser trust)? (Requires admin/sudo) (y/n): ").lower().strip()
    if install_ca == 'y':
        print("Running 'mkcert -install'. You might be prompted for your password.")
        try:
            # Run without capturing output so user sees prompts directly (like password)
            # Use check=True to detect if the command fails
            subprocess.run([mkcert_path, "-install"], check=True, timeout=30) # Increased timeout for potential user interaction
            print("mkcert CA installation command executed (check output above for success/failure).")
            # Note: Success here doesn't guarantee the CA is trusted, only that the command ran without error code.
        except subprocess.CalledProcessError as e:
            print(f"Warning: 'mkcert -install' command failed (Error code: {e.returncode}).")
            print("The local CA might not be installed or trusted by your browser.")
            print("You may need to run 'mkcert -install' manually with administrator/sudo privileges.")
        except FileNotFoundError:
             print(f"Error: Could not execute mkcert at {mkcert_path} for CA install.")
        except subprocess.TimeoutExpired:
             print("Warning: 'mkcert -install' timed out. It might be waiting for input.")
        except Exception as e:
             print(f"An unexpected error occurred during 'mkcert -install': {e}")

    # 4. Check for existing certificates and handle overwrite/backup
    certs_exist = os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)
    generate_new = True # Assume we need to generate unless certs exist and user declines overwrite

    if certs_exist:
        print(f"\nExisting certificate files found:\n  {CERT_FILE}\n  {KEY_FILE}")
        overwrite = input("Overwrite existing certificates? (y/n): ").lower().strip()
        if overwrite == 'y':
            # User wants to overwrite, now ask about backup.
            backup = input("Backup existing files to cert_old.pem/key_old.pem? (y/n): ").lower().strip()
            if backup == 'y':
                try:
                    print("Backing up existing certificates...")
                    # Use os.replace for atomic rename/overwrite if _old files exist
                    if os.path.exists(CERT_FILE): os.replace(CERT_FILE, CERT_OLD_FILE)
                    if os.path.exists(KEY_FILE): os.replace(KEY_FILE, KEY_OLD_FILE)
                    print(f"Backup complete: {CERT_OLD_FILE}, {KEY_OLD_FILE}")
                except OSError as e:
                    print(f"Warning: Failed to back up existing certificates: {e}")
                    # Continue with generation even if backup failed
            else:
                print("Skipping backup.")
            # Proceed to generate new ones (generate_new remains True)
        else:
            # User chose not to overwrite existing certs.
            print("Using existing certificates.")
            generate_new = False # Do not generate new ones.
    else:
        # Certificates don't exist or are incomplete.
        print("\nCertificate files missing or incomplete. Will attempt to generate new ones.")
        # Proceed to generate new ones (generate_new remains True)

    # 5. Generate new certificates if needed
    if generate_new:
        print("Generating new certificates for 'localhost' and '127.0.0.1'...")
        try:
            # Define the command arguments for mkcert generation
            mkcert_command = [
                mkcert_path,
                "-cert-file", CERT_FILE, # Specify output certificate file path
                "-key-file", KEY_FILE,   # Specify output key file path
                "localhost",             # Hostname to include in the certificate
                "127.0.0.1"              # Loopback IP address to include
            ]
            # Run the mkcert generation command
            result = subprocess.run(mkcert_command, check=True, capture_output=True, text=True, timeout=30)
            print("mkcert generation command executed.")
            # Print mkcert output for confirmation/debugging
            if result.stdout: print(f"mkcert output:\n{result.stdout.strip()}")
            # stderr should be empty on success, but print if not
            if result.stderr: print(f"mkcert error output (should be empty on success):\n{result.stderr.strip()}")

            # Verify files were actually created after the command ran
            if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
                print("New certificate and key files generated successfully.")
            else:
                # This indicates an unexpected issue if mkcert reported success but files are missing.
                print("Error: mkcert command seemed to succeed but output files are missing!")
                return False # Generation failed

        except subprocess.CalledProcessError as e:
            # Handle errors if mkcert command returns a non-zero exit code.
            print(f"Error: mkcert generation failed (Error code: {e.returncode}).")
            print("--- mkcert Error Output ---")
            print(e.stderr) # Print captured stderr
            print("-------------------------")
            return False # Generation failed
        except FileNotFoundError:
             # Handle error if the mkcert executable path is suddenly invalid.
             print(f"Error: Could not execute mkcert at {mkcert_path} for certificate generation.")
             return False # Generation failed
        except subprocess.TimeoutExpired:
             print("Error: mkcert generation timed out.")
             return False # Generation failed
        except Exception as e:
             # Catch any other unexpected errors.
             print(f"An unexpected error occurred during certificate generation: {e}")
             return False # Generation failed

    # 6. Final check and return status
    # Return True if the files exist at the end of the process (either pre-existing or newly generated/verified)
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        print("Certificate check passed.")
        return True
    else:
        # This case should ideally not be reached if logic above is correct, but check defensively.
        print("Error: Certificate files not found after completion of management process.")
        return False

# --- Configuration Management ---
def read_config():
    """
    Reads WSS HOST and PORT from the server/config.py file using regex.
    Sets default values for HTTPS HOST and PORT internally.

    Returns:
        dict: A dictionary containing the configuration settings:
              {'wss_host', 'wss_port', 'https_host', 'https_port'}.
              Uses defaults if the config file is missing or values aren't found.
    """
    # Initialize with default values.
    settings = {
        'wss_host': '0.0.0.0',
        'wss_port': 5678,
        'https_host': '0.0.0.0',
        'https_port': 8888
    }
    try:
        print(f"Reading WSS configuration from: {WSS_CONFIG_PATH}")
        with open(WSS_CONFIG_PATH, 'r', encoding='utf-8') as f:
            content = f.read() # Read the entire file content.

            # Search for the HOST assignment line using regex. Handles single/double quotes.
            host_match = re.search(r"^HOST\s*=\s*['\"]([^'\"]+)['\"]", content, re.MULTILINE)
            # Search for the PORT assignment line using regex. Captures digits.
            port_match = re.search(r"^PORT\s*=\s*(\d+)", content, re.MULTILINE)

            # Update settings if matches were found.
            if host_match:
                settings['wss_host'] = host_match.group(1)
            else:
                print(f"Warning: Could not find HOST setting in {WSS_CONFIG_PATH}, using default '{settings['wss_host']}'.")

            if port_match:
                settings['wss_port'] = int(port_match.group(1))
            else:
                print(f"Warning: Could not find PORT setting in {WSS_CONFIG_PATH}, using default {settings['wss_port']}.")

    except FileNotFoundError:
        print(f"Warning: {WSS_CONFIG_PATH} not found. Using default WSS settings.")
    except Exception as e:
        # Catch other potential errors during file reading or regex parsing.
        print(f"Warning: Error reading {WSS_CONFIG_PATH}: {e}. Using default WSS settings.")

    print("Initial settings loaded.")
    return settings

def write_wss_config(settings):
    """
    Writes the WSS host and port settings back to the server/config.py file.
    It reads the existing file, modifies the relevant lines using regex substitution,
    and overwrites the file with the modified content.

    Args:
        settings (dict): The dictionary containing the current settings, including
                         'wss_host' and 'wss_port'.

    Returns:
        bool: True if writing was successful, False otherwise.
    """
    try:
        print(f"Attempting to update WSS configuration in: {WSS_CONFIG_PATH}")
        # Read existing lines first to preserve other content and comments.
        with open(WSS_CONFIG_PATH, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        new_lines = []
        host_updated = False
        port_updated = False

        # Iterate through each line and attempt to update HOST and PORT.
        for line in lines:
            # Use re.match to check if the line STARTS with 'HOST =' (allowing whitespace).
            # Check host_updated flag to only replace the first occurrence found.
            if re.match(r"^HOST\s*=", line) and not host_updated:
                # Replace the line with the new setting, ensuring quotes for the host string.
                new_lines.append(f"HOST = '{settings['wss_host']}'\n")
                host_updated = True
            # Check if the line STARTS with 'PORT ='. Check port_updated flag.
            elif re.match(r"^PORT\s*=", line) and not port_updated:
                # Replace the line with the new setting (port is an integer).
                new_lines.append(f"PORT = {settings['wss_port']}\n")
                port_updated = True
            else:
                # Keep lines that don't match HOST or PORT assignments unchanged.
                new_lines.append(line)

        # Basic handling if HOST or PORT lines were not found in the original file:
        # Append them to the end.
        if not host_updated:
            print("Warning: HOST line not found in config, appending.")
            new_lines.append(f"\nHOST = '{settings['wss_host']}' # Added by helix_manager\n")
        if not port_updated:
            print("Warning: PORT line not found in config, appending.")
            new_lines.append(f"PORT = {settings['wss_port']} # Added by helix_manager\n")

        # Write the modified lines back to the file, overwriting the original content.
        with open(WSS_CONFIG_PATH, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        print(f"WSS configuration updated successfully.")
        return True
    except FileNotFoundError:
        print(f"Error: {WSS_CONFIG_PATH} not found. Cannot save WSS configuration.")
        return False
    except Exception as e:
        print(f"Error writing WSS configuration to {WSS_CONFIG_PATH}: {e}")
        return False

def config_menu(settings):
    """
    Displays the main configuration menu, allowing the user to view/change
    WSS and HTTPS settings, manage certificates, save WSS settings, start the servers, or exit.

    Args:
        settings (dict): The dictionary holding the current configuration values.

    Returns:
        bool: True if the user chose to start the servers, False if they chose to exit.
    """
    while True:
        # Display current settings and menu options.
        print("\n--- HeliX Configuration & Management ---")
        print(f"1. WSS Host:    {settings['wss_host']}")
        print(f"2. WSS Port:    {settings['wss_port']}")
        print(f"3. HTTPS Host:  {settings['https_host']}")
        print(f"4. HTTPS Port:  {settings['https_port']}")
        print("------------------------------------")
        print("5. Manage TLS Certificates (Check/Generate/Install CA)") # New Option
        print("6. Save WSS Config and Start Servers")
        print("7. Start Servers (Use Current Settings without Saving)")
        print("8. Exit")
        print("------------------------------------")

        choice = input("Enter choice: ").strip()

        # Handle user input for changing settings.
        if choice == '1':
            new_val = input(f"Enter new WSS Host [{settings['wss_host']}]: ").strip()
            if new_val: settings['wss_host'] = new_val
        elif choice == '2':
            new_val = input(f"Enter new WSS Port [{settings['wss_port']}]: ").strip()
            if new_val:
                try:
                    port_int = int(new_val)
                    if not (0 < port_int < 65536):
                         print("Invalid port number (must be 1-65535).")
                    else:
                         settings['wss_port'] = port_int
                except ValueError:
                    print("Invalid port. Please enter a number.")
        elif choice == '3':
            new_val = input(f"Enter new HTTPS Host [{settings['https_host']}]: ").strip()
            if new_val: settings['https_host'] = new_val
        elif choice == '4':
            new_val = input(f"Enter new HTTPS Port [{settings['https_port']}]: ").strip()
            if new_val:
                try:
                    port_int = int(new_val)
                    if not (0 < port_int < 65536):
                         print("Invalid port number (must be 1-65535).")
                    else:
                         settings['https_port'] = port_int
                except ValueError:
                    print("Invalid port. Please enter a number.")
        elif choice == '5': # Manage Certificates
            if generate_certificates():
                print("Certificate process completed successfully.")
            else:
                print("Certificate process failed or was aborted. See messages above.")
            input("Press Enter to return to menu...")
            continue # Go back to menu display
        elif choice == '6': # Save WSS Config and Start
            # *** Pre-start Certificate Check ***
            if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
                print("\nError: Certificate files (cert.pem, key.pem) are missing in './certs/'.")
                print("Please use option 5 ('Manage TLS Certificates') to generate them first.")
                input("Press Enter to return to menu...")
                continue # Stay in menu
            # *** End Check ***
            if write_wss_config(settings):
                return True # Signal to main loop to start servers.
            else:
                # Stay in the menu if saving failed.
                input("Failed to save WSS config. Press Enter to return to menu...")
                continue # Stay in menu
        elif choice == '7': # Start without Saving
            # *** Pre-start Certificate Check ***
            if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
                print("\nError: Certificate files (cert.pem, key.pem) are missing in './certs/'.")
                print("Please use option 5 ('Manage TLS Certificates') to generate them first.")
                input("Press Enter to return to menu...")
                continue # Stay in menu
            # *** End Check ***
            print("Proceeding without saving WSS config...")
            return True # Signal to main loop to start servers.
        elif choice == '8': # Exit
            return False # Signal to main loop to exit.
        else:
            print("Invalid choice. Please try again.")

# --- HTTPS Server Implementation ---
class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP request handler that overrides logging methods
    to write to the dedicated 'https_logger' (file logger).
    """
    def __init__(self, *args, **kwargs):
        # Serve files from the current working directory (set via os.chdir later)
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        """Overrides the default log_message to use our file logger."""
        https_logger.info("%s - %s" % (self.address_string(), format % args))

    def log_error(self, format, *args):
        """Overrides the default log_error to use our file logger."""
        https_logger.error("%s - %s" % (self.address_string(), format % args))

class ThreadingHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    """HTTPServer that uses threads to handle requests."""
    allow_reuse_address = True # Allow reusing the address quickly after shutdown
    disable_request_handler_dns_lookup = True # Prevent DNS lookups for logging

def run_https_server(host, port, client_dir):
    """
    Target function executed in a separate thread to run the HTTPS server.
    Sets up SSL, changes directory, starts the server, and handles cleanup.

    Args:
        host (str): The hostname or IP address to bind the server to.
        port (int): The port number to bind the server to.
        client_dir (str): The absolute path to the directory containing client files.
    """
    global https_server # Reference the global variable to store the server instance.
    original_cwd = os.getcwd() # Store CWD to restore it later.
    server_started_successfully = False
    try:
        # 1. Setup SSL Context
        print(f"[HTTPS Thread] Setting up SSL context using:\n  Cert: {CERT_FILE}\n  Key:  {KEY_FILE}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # load_cert_chain requires existing, valid files. Menu logic ensures this.
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        print(f"[HTTPS Thread] SSL context loaded.")

        # 2. Change Directory
        # SimpleHTTPRequestHandler serves files relative to the CWD.
        print(f"[HTTPS Thread] Changing CWD to client directory: {client_dir}")
        os.chdir(client_dir)

        # 3. Create and Start Server
        print(f"[HTTPS Thread] Attempting to bind HTTPS server to {host}:{port}...")
        https_server = ThreadingHTTPServer((host, port), QuietHTTPRequestHandler)
        # Wrap the server's socket with the SSL context to enable HTTPS.
        https_server.socket = context.wrap_socket(https_server.socket, server_side=True)
        server_started_successfully = True # Mark server as successfully initialized

        # Log startup messages (to console and file via logger).
        startup_msg = f"Serving HTTPS on {host}:{port} from {client_dir}..."
        print(f"[HTTPS Thread] {startup_msg}")
        https_logger.info(f"HTTPS Server starting on {host}:{port}, serving {client_dir}")
        print(f"[HTTPS Thread] Access client at: https://localhost:{port} or https://127.0.0.1:{port}")

        # 4. Run Server Loop
        # This call blocks the thread until https_server.shutdown() is called from another thread.
        https_server.serve_forever()

    except FileNotFoundError as e:
        # Should not happen if menu logic is correct, but handle defensively.
        print(f"\n[HTTPS Thread] ERROR: File not found during server setup (Cert/Key/ClientDir?): {e}")
        https_logger.error(f"FileNotFoundError during server setup: {e}")
    except OSError as e:
        # Handle OS errors like "Address already in use" or permission errors.
        print(f"\n[HTTPS Thread] ERROR starting HTTPS server: {e}")
        https_logger.error(f"OSError starting HTTPS server: {e}")
    except Exception as e:
        # Catch any other unexpected errors in the thread.
        print(f"\n[HTTPS Thread] An unexpected error occurred: {e}")
        https_logger.exception("Unexpected error in HTTPS server thread")
    finally:
        # --- Cleanup ---
        # This block runs when serve_forever() returns (after shutdown()) or if an exception occurred.
        if https_server and server_started_successfully:
            # Ensure the server socket is closed properly if it was successfully created.
            https_server.server_close()
        # Change back to the original working directory. Important for subsequent script runs.
        os.chdir(original_cwd)
        print(f"[HTTPS Thread] Restored CWD to: {original_cwd}")
        print("[HTTPS Thread] Server stopped.")
        https_logger.info("HTTPS Server stopped.")
        # Clear the global reference now that the server is stopped.
        https_server = None

# --- WSS Server Logging ---
def log_wss_output(process):
    """
    Target function executed in a separate thread to continuously read stdout
    from the WSS server subprocess and print it to the console.

    Args:
        process (subprocess.Popen): The Popen object for the WSS server process.
    """
    print("[WSS Log Thread] Started.")
    try:
        # Loop as long as the main program hasn't signaled to stop.
        while not stop_event.is_set():
            if process.stdout:
                 # Read one line from the WSS process's standard output.
                 line = process.stdout.readline()
                 if line:
                     # If a line was read, print it to the console, stripping whitespace.
                     print(f"[WSS] {line.strip()}")
                 # Check if the process has terminated *after* trying to read.
                 elif process.poll() is not None:
                     print("[WSS Log Thread] WSS process terminated, exiting logger.")
                     break # Exit the loop if the process has ended.
            else:
                # stdout might become None if the process closes it unexpectedly.
                print("[WSS Log Thread] WSS process stdout closed, exiting logger.")
                break # Exit the loop.

            # Small sleep to prevent the loop from consuming 100% CPU.
            time.sleep(0.01)

    except Exception as e:
        # Log errors encountered during reading, but only if we aren't shutting down.
        if not stop_event.is_set():
             print(f"[WSS Log Thread] Error reading WSS output: {e}")
    finally:
        print("[WSS Log Thread] Exiting.")


# --- Server Startup and Management ---
def start_servers(settings):
    """
    Starts the HTTPS server in a thread and the WSS server as a subprocess.
    Manages their logging threads and handles graceful shutdown on Ctrl+C.
    Assumes certificates have already been verified/generated via the menu.

    Args:
        settings (dict): The dictionary containing the current WSS and HTTPS settings.
    """
    # Make global variables accessible for modification/reference within this function.
    global wss_process, https_thread, wss_log_thread, https_server, stop_event

    stop_event.clear() # Ensure the stop event is initially False for this run.

    # Certificate check is now done in the menu before calling this function.
    # We proceed directly to starting servers.

    # 1. Start HTTPS Server Thread
    print("\nStarting HTTPS server thread...")
    https_thread = threading.Thread(
        target=run_https_server, # Function to run in the thread.
        args=(settings['https_host'], settings['https_port'], HTTPS_CLIENT_DIR), # Arguments for the function.
        daemon=True # Set as daemon.
    )
    https_thread.start() # Start the thread execution.

    # Brief pause to allow the HTTPS server thread to initialize and potentially fail early.
    time.sleep(1.5)
    # Check if the thread is alive AND the server object was successfully created inside the thread.
    if not https_thread.is_alive() or https_server is None:
         print("\nError: HTTPS server thread failed to start properly. Check logs/config/permissions.")
         # No WSS process to clean up yet.
         return # Abort starting servers.

    # 2. Start WSS Server Subprocess
    print("Starting WSS server subprocess...")
    wss_script_path = os.path.join(SCRIPT_DIR, 'server', 'main.py')
    try:
        # Launch server/main.py using the same Python interpreter that's running this script.
        wss_process = subprocess.Popen(
            [sys.executable, wss_script_path],
            stdout=subprocess.PIPE,         # Capture standard output.
            stderr=subprocess.STDOUT,       # Redirect standard error to standard output.
            text=True,                      # Decode output as text (UTF-8 by default).
            bufsize=1,                      # Use line buffering for stdout/stderr.
            cwd=SCRIPT_DIR                  # Set working directory to ensure relative paths in server work.
        )
        print(f"WSS server process started (PID: {wss_process.pid}). Output will follow:")
    except Exception as e:
        print(f"Error starting WSS server process: {e}")
        # If WSS fails, we need to shut down the already running HTTPS server.
        if https_server:
            print("Shutting down HTTPS server due to WSS startup failure...")
            https_server.shutdown()
        if https_thread:
            https_thread.join() # Wait for HTTPS thread to finish cleanup.
        return # Abort.

    # 3. Start WSS Logging Thread
    print("Starting WSS logging thread...")
    wss_log_thread = threading.Thread(target=log_wss_output, args=(wss_process,))
    wss_log_thread.start() # Start reading and printing WSS output.

    # 4. Wait for termination signal (Ctrl+C)
    print("\nServers are running. Press Ctrl+C to stop.")
    try:
        # Keep the main thread alive while servers run in background threads/processes.
        # Periodically check if the servers/threads have died unexpectedly.
        while not stop_event.is_set():
            if wss_process.poll() is not None: # poll() returns exit code if terminated, None otherwise.
                print("\nError: WSS server process terminated unexpectedly.")
                https_logger.error("WSS server process terminated unexpectedly.")
                stop_event.set() # Signal other threads to stop.
                break # Exit wait loop
            if not https_thread.is_alive():
                 # Check if the server object exists; if not, it likely failed during startup in its thread.
                 if https_server is not None:
                     print("\nError: HTTPS server thread terminated unexpectedly.")
                     https_logger.error("HTTPS server thread terminated unexpectedly.")
                     stop_event.set() # Signal other threads to stop.
                     break # Exit wait loop
                 else:
                      # Server likely failed during startup within its thread, error already printed.
                      print("\nError: HTTPS server failed during startup (see previous messages).")
                      stop_event.set()
                      break
            time.sleep(0.5) # Sleep briefly to avoid busy-waiting. Check status twice per second.
    except KeyboardInterrupt:
        # User pressed Ctrl+C.
        print("\nShutdown signal (Ctrl+C) received...")
        stop_event.set() # Signal threads to stop gracefully.
    except Exception as e:
        # Catch any other unexpected errors in this main wait loop.
        print(f"\nUnexpected error in main wait loop: {e}")
        stop_event.set() # Signal threads to stop.
    finally:
        # 5. Graceful Shutdown Sequence
        # This block executes after the loop ends (normally or via exception/Ctrl+C).
        print("Initiating server shutdown...")

        # --- Shutdown HTTPS Server ---
        if https_server:
            print("Shutting down HTTPS server...")
            try:
                https_server.shutdown() # Signal the serve_forever loop to stop.
            except Exception as e:
                print(f"Error during https_server.shutdown(): {e}") # Log potential errors.
        # Wait for the HTTPS server thread to complete its cleanup.
        if https_thread and https_thread.is_alive():
            print("Waiting for HTTPS thread to finish...")
            https_thread.join(timeout=5) # Wait up to 5 seconds.
            if https_thread.is_alive():
                print("Warning: HTTPS thread did not exit gracefully.")

        # --- Shutdown WSS Process ---
        if wss_process and wss_process.poll() is None: # Check if process exists and is running.
            print("Terminating WSS server process...")
            try:
                wss_process.terminate() # Send SIGTERM (allows potential cleanup).
                wss_process.wait(timeout=5) # Wait up to 5 seconds for termination.
                print("WSS server process terminated.")
            except subprocess.TimeoutExpired:
                # If terminate didn't work within the timeout, force kill.
                print("WSS process did not terminate gracefully, killing.")
                wss_process.kill() # Send SIGKILL (forceful).
            except Exception as e:
                print(f"Error terminating WSS process: {e}")

        # --- Shutdown WSS Logging Thread ---
        # The stop_event should have signaled the thread to exit its loop.
        # We wait for it to finish printing any remaining buffered output.
        if wss_log_thread and wss_log_thread.is_alive():
            print("Waiting for WSS logging thread to finish...")
            wss_log_thread.join(timeout=2) # Wait up to 2 seconds.
            if wss_log_thread.is_alive():
                 print("Warning: WSS logging thread did not exit.")

        print("Shutdown complete.")

# --- Main Execution ---
def main():
    """
    Main function to orchestrate the manager script execution:
    1. Check dependencies ('websockets').
    2. Read initial configuration (WSS from file, HTTPS defaults).
    3. Run the configuration menu loop (includes certificate management option).
    4. If the user chooses to start (and certs exist), call start_servers.
    """
    print("--- Starting HeliX Manager ---")
    # Ensure 'websockets' library is available.
    check_or_install_websockets()
    # Load current WSS settings from file, use defaults for HTTPS.
    current_settings = read_config()

    # Run the configuration menu. It returns True if servers should start.
    if config_menu(current_settings):
        # Start the servers using the (potentially modified) settings.
        # Certificate check happens within the menu before returning True here.
        start_servers(current_settings)
    else:
        # User chose to exit from the menu.
        print("Exiting HeliX Manager.")

# Standard Python idiom: Run the main function only when the script is executed directly.
if __name__ == "__main__":
    main()
