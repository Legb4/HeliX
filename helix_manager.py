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
# - Saves WSS and HTTPS configuration changes persistently to server/config.py.
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
from functools import partial # Used for creating the HTTPS request handler with directory

# --- Constants ---
# Define file paths relative to the location of this script for portability.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) # Absolute path to script's directory.
# CONFIG_FILE_PATH replaces WSS_CONFIG_PATH as it now handles more settings.
CONFIG_FILE_PATH = os.path.join(SCRIPT_DIR, 'server', 'config.py') # Path to server config file.
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
    Finds mkcert, displays version, offers CA install, handles overwrite/backup, generates certs.

    Returns:
        bool: True if certificates exist or were successfully generated/handled, False otherwise.
    """
    print("\n--- Certificate Management ---")
    os.makedirs(CERT_DIR, exist_ok=True) # Ensure certs directory exists

    # 1. Find mkcert executable
    mkcert_path = None
    system = platform.system()
    print(f"Detected OS: {system}")
    if system == "Windows":
        mkcert_path = shutil.which("mkcert")
        if not mkcert_path:
            expected_path = os.path.join(CERT_DIR, "mkcert.exe")
            if os.path.exists(expected_path): mkcert_path = expected_path
            else:
                 print(f"Error: 'mkcert.exe' not found in PATH or '{CERT_DIR}'. Install or place it correctly.")
                 return False
        print(f"Found mkcert at: {mkcert_path}")
    elif system in ["Linux", "Darwin"]:
        mkcert_path = shutil.which("mkcert")
        if mkcert_path is None:
            print("Error: 'mkcert' command not found in your system PATH. Please install it.")
            return False
        print(f"Found mkcert in PATH: {mkcert_path}")
    else:
        print(f"Unsupported OS for mkcert handling: {system}")
        return False

    # 2. Display mkcert version
    try:
        print("Checking mkcert version...")
        result = subprocess.run([mkcert_path, "-version"], capture_output=True, text=True, check=True, timeout=10)
        print(f"mkcert version info:\n{result.stdout.strip()}")
    except Exception as e: print(f"Warning: Could not get mkcert version: {e}")

    # 3. Offer to install CA
    install_ca = input("Attempt to install the mkcert local CA (requires admin/sudo)? (y/n): ").lower().strip()
    if install_ca == 'y':
        print("Running 'mkcert -install'. You might be prompted for your password.")
        try:
            subprocess.run([mkcert_path, "-install"], check=True, timeout=30)
            print("mkcert CA installation command executed.")
        except Exception as e: print(f"Warning: 'mkcert -install' command failed: {e}")

    # 4. Check for existing certificates and handle overwrite/backup
    certs_exist = os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)
    generate_new = True
    if certs_exist:
        print(f"\nExisting certificate files found:\n  {CERT_FILE}\n  {KEY_FILE}")
        overwrite = input("Overwrite existing certificates? (y/n): ").lower().strip()
        if overwrite == 'y':
            backup = input("Backup existing files to cert_old.pem/key_old.pem? (y/n): ").lower().strip()
            if backup == 'y':
                try:
                    print("Backing up existing certificates...")
                    if os.path.exists(CERT_FILE): os.replace(CERT_FILE, CERT_OLD_FILE)
                    if os.path.exists(KEY_FILE): os.replace(KEY_FILE, KEY_OLD_FILE)
                    print(f"Backup complete: {CERT_OLD_FILE}, {KEY_OLD_FILE}")
                except OSError as e: print(f"Warning: Failed to back up existing certificates: {e}")
            else: print("Skipping backup.")
        else:
            print("Using existing certificates.")
            generate_new = False
    else: print("\nCertificate files missing or incomplete. Will attempt to generate new ones.")

    # 5. Generate new certificates if needed
    if generate_new:
        print("Generating new certificates for 'localhost' and '127.0.0.1'...")
        try:
            mkcert_command = [mkcert_path, "-cert-file", CERT_FILE, "-key-file", KEY_FILE, "localhost", "127.0.0.1"]
            result = subprocess.run(mkcert_command, check=True, capture_output=True, text=True, timeout=30)
            print("mkcert generation command executed.")
            if result.stdout: print(f"mkcert output:\n{result.stdout.strip()}")
            if result.stderr: print(f"mkcert error output:\n{result.stderr.strip()}")
            if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
                print("Error: mkcert command seemed to succeed but output files are missing!")
                return False
            print("New certificate and key files generated successfully.")
        except Exception as e:
            print(f"Error during certificate generation: {e}")
            if hasattr(e, 'stderr') and e.stderr: print(f"--- mkcert Error Output ---\n{e.stderr}\n-------------------------")
            return False

    # 6. Final check and return status
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        print("Certificate check passed.")
        return True
    else:
        print("Error: Certificate files not found after completion.")
        return False

# --- Configuration Management ---
def read_config():
    """
    Reads WSS (HOST, PORT) and HTTPS (HTTPS_HOST, HTTPS_PORT) settings
    from the server/config.py file using regular expressions.
    Sets default values internally if the config file is missing or specific
    settings are not found within the file.

    Returns:
        dict: A dictionary containing the configuration settings:
              {'wss_host', 'wss_port', 'https_host', 'https_port'}.
              Uses defaults if the config file is missing or values aren't found.
    """
    # Initialize settings with default values.
    settings = {
        'wss_host': '0.0.0.0',
        'wss_port': 5678,
        'https_host': '0.0.0.0',
        'https_port': 8888
    }
    config_file_path = CONFIG_FILE_PATH

    try:
        print(f"Reading configuration from: {config_file_path}")
        with open(config_file_path, 'r', encoding='utf-8') as f:
            content = f.read()

            # --- WSS Settings Parsing ---
            wss_host_match = re.search(r"^HOST\s*=\s*['\"]([^'\"]+)['\"]", content, re.MULTILINE)
            wss_port_match = re.search(r"^PORT\s*=\s*(\d+)", content, re.MULTILINE)

            if wss_host_match: settings['wss_host'] = wss_host_match.group(1)
            else: print(f"Warning: Could not find WSS HOST setting in {config_file_path}, using default '{settings['wss_host']}'.")

            if wss_port_match: settings['wss_port'] = int(wss_port_match.group(1))
            else: print(f"Warning: Could not find WSS PORT setting in {config_file_path}, using default {settings['wss_port']}.")

            # --- HTTPS Settings Parsing ---
            https_host_match = re.search(r"^HOST\s*=\s*['\"]([^'\"]+)['\"]", content, re.MULTILINE)

            if https_host_match: settings['https_host'] = https_host_match.group(1)
            else: print(f"Warning: Could not find HTTPS_HOST setting in {config_file_path}, using default '{settings['https_host']}'.")

    except FileNotFoundError: print(f"Warning: {config_file_path} not found. Using default settings for WSS and HTTPS.")
    except Exception as e: print(f"Warning: Error reading {config_file_path}: {e}. Using default settings.")

    print("Initial settings loaded.")
    return settings

def write_config(settings):
    """
    Writes the WSS (HOST, PORT) and HTTPS (HTTPS_HOST, HTTPS_PORT) settings
    back to the server/config.py file.
    Reads existing file, modifies relevant lines, preserves others, and overwrites.
    Appends settings if not found. Creates file if it doesn't exist.

    Args:
        settings (dict): Dictionary with 'wss_host', 'wss_port', 'https_host', 'https_port'.

    Returns:
        bool: True if writing was successful, False otherwise.
    """
    config_file_path = CONFIG_FILE_PATH
    try:
        print(f"Attempting to update configuration in: {config_file_path}")
        lines = []
        try:
            with open(config_file_path, 'r', encoding='utf-8') as f: lines = f.readlines()
        except FileNotFoundError: print(f"Info: {config_file_path} not found. Creating new file.")

        new_lines = []
        updated_flags = {'wss_host': False, 'wss_port': False, 'https_host': False, 'https_port': False}
        setting_patterns = {
            re.compile(r"^HOST\s*="): ('wss_host', "HOST = '{value}'\n"),
            re.compile(r"^PORT\s*="): ('wss_port', "PORT = {value}\n"),
            re.compile(r"^HTTPS_HOST\s*="): ('https_host', "HTTPS_HOST = '{value}'\n"),
            re.compile(r"^HTTPS_PORT\s*="): ('https_port', "HTTPS_PORT = {value}\n")
        }

        for line in lines:
            line_updated = False
            for pattern, (key, format_str) in setting_patterns.items():
                if pattern.match(line) and not updated_flags[key]:
                    new_lines.append(format_str.format(value=settings[key]))
                    updated_flags[key], line_updated = True, True
                    break
            if not line_updated: new_lines.append(line)

        appended_header = False
        for pattern, (key, format_str) in setting_patterns.items():
            if not updated_flags[key]:
                if not appended_header:
                    if new_lines and not new_lines[-1].endswith('\n'): new_lines.append('\n')
                    new_lines.append("\n# --- Settings added/updated by helix_manager ---\n")
                    appended_header = True
                print(f"Warning: {key.upper()} line not found in config, appending.")
                new_lines.append(format_str.format(value=settings[key]))

        with open(config_file_path, 'w', encoding='utf-8') as f: f.writelines(new_lines)
        print(f"Configuration updated successfully in {config_file_path}.")
        return True
    except Exception as e:
        print(f"Error writing configuration to {config_file_path}: {e}")
        return False

# Note: update_client_config and revert_client_config functions removed as they were part of the tunnel feature.

def config_menu(settings):
    """
    Displays the main configuration menu.

    Args:
        settings (dict): The current configuration values.

    Returns:
        bool: True if servers should start, False if exiting.
    """
    while True:
        print("\n--- HeliX Configuration & Management ---")
        print(f"1. WSS Host:    {settings['wss_host']}")
        print(f"2. WSS Port:    {settings['wss_port']}")
        print(f"3. HTTPS Host:  {settings['https_host']}")
        print(f"4. HTTPS Port:  {settings['https_port']}")
        print("------------------------------------")
        print("5. Manage TLS Certificates (Check/Generate/Install CA)")
        print("6. Save Config and Start Servers") # Renamed from "Start Locally"
        print("7. Start Servers (Use Current Settings without Saving)") # Renamed from "Start Locally"
        print("8. Exit") # Renumbered Exit option
        print("------------------------------------")
        choice = input("Enter choice: ").strip()

        if choice == '1':
            new_val = input(f"Enter new WSS Host [{settings['wss_host']}]: ").strip()
            if new_val: settings['wss_host'] = new_val
        elif choice == '2':
            new_val = input(f"Enter new WSS Port [{settings['wss_port']}]: ").strip()
            if new_val:
                try:
                    port_int = int(new_val)
                    if not (0 < port_int < 65536): print("Invalid port number (1-65535).")
                    else: settings['wss_port'] = port_int
                except ValueError: print("Invalid port. Enter a number.")
        elif choice == '3':
            new_val = input(f"Enter new HTTPS Host [{settings['https_host']}]: ").strip()
            if new_val: settings['https_host'] = new_val
        elif choice == '4':
            new_val = input(f"Enter new HTTPS Port [{settings['https_port']}]: ").strip()
            if new_val:
                try:
                    port_int = int(new_val)
                    if not (0 < port_int < 65536): print("Invalid port number (1-65535).")
                    else: settings['https_port'] = port_int
                except ValueError: print("Invalid port. Enter a number.")
        elif choice == '5':
            if generate_certificates(): print("Certificate process completed successfully.")
            else: print("Certificate process failed or aborted.")
            input("Press Enter to return...")
            continue
        elif choice == '6': # Save Config and Start
            if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
                print("\nError: Certificate files missing. Use option 5 first.")
                input("Press Enter to return...")
                continue
            if write_config(settings): return True # Signal to start servers
            else: input("Failed to save config. Press Enter to return...")
            continue
        elif choice == '7': # Start without Saving
            if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
                print("\nError: Certificate files missing. Use option 5 first.")
                input("Press Enter to return...")
                continue
            print("Proceeding without saving config...")
            return True # Signal to start servers
        elif choice == '8': # Exit
            return False # Signal to exit
        else: print("Invalid choice.")

# --- HTTPS Server Implementation ---
class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP handler logging to file via https_logger."""
    def __init__(self, *args, directory=None, **kwargs):
        if directory is None: directory = os.getcwd()
        super().__init__(*args, directory=directory, **kwargs)
    def log_message(self, format, *args): https_logger.info("%s - %s" % (self.address_string(), format % args))
    def log_error(self, format, *args): https_logger.error("%s - %s" % (self.address_string(), format % args))

class ThreadingHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    """HTTPServer using threads."""
    allow_reuse_address = True

def _start_https_server_thread(host, port, client_dir):
    """Internal helper to start the HTTPS server thread."""
    global https_server, https_thread
    print("\nStarting HTTPS server thread...")
    Handler = partial(QuietHTTPRequestHandler, directory=client_dir)
    try:
        https_server = ThreadingHTTPServer((host, port), Handler)
        print(f"[HTTPS Setup] Setting up SSL context...")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        https_server.socket = context.wrap_socket(https_server.socket, server_side=True)
        print(f"[HTTPS Setup] SSL context loaded and socket wrapped.")
        https_thread = threading.Thread(target=_run_https_server_loop, args=(https_server,), daemon=True)
        https_thread.start()
        print(f"[HTTPS Thread] Serving HTTPS on {host}:{port} from {client_dir}")
        https_logger.info(f"HTTPS Server starting on {host}:{port}, serving {client_dir}")
        print(f"[HTTPS Thread] Access client at: https://localhost:{port} or https://127.0.0.1:{port}")
        return https_thread
    except Exception as e:
        print(f"\n[HTTPS Setup] ERROR starting HTTPS server: {e}")
        https_logger.exception("Error during HTTPS setup")
        https_server = None
        return None

def _run_https_server_loop(server_instance):
    """Target function for the HTTPS server thread loop."""
    global https_server
    try: server_instance.serve_forever()
    except Exception as e: https_logger.exception("Unexpected error in HTTPS serve_forever loop")
    finally:
        if server_instance:
            try: server_instance.server_close()
            except Exception: pass # Ignore errors during close
        print("[HTTPS Thread] Server loop stopped.")
        https_logger.info("HTTPS Server loop stopped.")
        https_server = None

# --- WSS Server Logging ---
def log_wss_output(process):
    """Target function for the WSS logging thread."""
    print("[WSS Log Thread] Started.")
    try:
        for line in iter(process.stdout.readline, ''):
            if stop_event.is_set(): break
            print(f"[WSS] {line.strip()}", flush=True)
        if not stop_event.is_set() and process.poll() is not None:
             print("[WSS Log Thread] WSS process stdout EOF or process terminated.", flush=True)
    except Exception as e:
        if not stop_event.is_set(): print(f"[WSS Log Thread] Error reading WSS output: {e}", flush=True)
    finally: print("[WSS Log Thread] Exiting.", flush=True)

def _start_wss_server_process():
    """Internal helper to start the WSS server process."""
    global wss_process, wss_log_thread
    print("Starting WSS server subprocess...")
    wss_script_path = os.path.join(SCRIPT_DIR, 'server', 'main.py')
    try:
        wss_process = subprocess.Popen(
            [sys.executable, wss_script_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', bufsize=1, cwd=SCRIPT_DIR
        )
        print(f"WSS server process started (PID: {wss_process.pid}). Output will follow:")
        wss_log_thread = threading.Thread(target=log_wss_output, args=(wss_process,), daemon=True)
        wss_log_thread.start()
        return wss_process
    except Exception as e:
        print(f"Error starting WSS server process: {e}")
        wss_process = None
        return None

# Note: _monitor_cloudflared_output and _start_cloudflared_tunnel functions removed.

# --- Server Startup and Management ---
def start_servers(settings): # Renamed from manage_running_servers, simplified
    """
    Starts the HTTPS server thread and WSS server process.
    Manages running servers and handles graceful shutdown.

    Args:
        settings (dict): The current configuration settings.
    """
    global wss_process, https_thread, wss_log_thread, https_server, stop_event

    # Reset global state before starting
    wss_process, https_thread, wss_log_thread, https_server = None, None, None, None
    stop_event.clear()

    servers_started_ok = False
    print("Starting local servers...")
    https_thread = _start_https_server_thread(
        settings['https_host'], settings['https_port'], HTTPS_CLIENT_DIR
    )
    time.sleep(1.0) # Allow HTTPS to bind/fail

    if https_thread and https_thread.is_alive():
        wss_process = _start_wss_server_process()
        if wss_process:
            servers_started_ok = True # Both servers started
        else: print("Failed to start WSS server process. Shutting down HTTPS server.")
    else: print("Failed to start HTTPS server thread.")

    # Trigger immediate cleanup if any part failed
    if not servers_started_ok:
         stop_event.set()
         # Call simplified shutdown logic directly
         _shutdown_servers()
         print("Exiting due to server startup failure.")
         sys.exit(1)

    # --- Manage Running Servers ---
    print("\nServers are running. Press Ctrl+C to stop.")
    try:
        while not stop_event.is_set():
            # Check WSS process
            if wss_process and wss_process.poll() is not None:
                print(f"\nError: WSS server process terminated unexpectedly (Exit Code: {wss_process.returncode}).")
                stop_event.set(); break
            # Check HTTPS thread
            if https_thread and not https_thread.is_alive():
                 if https_server is not None: print("\nError: HTTPS server thread terminated unexpectedly.")
                 else: print("\nError: HTTPS server failed during startup.")
                 stop_event.set(); break
            time.sleep(0.5) # Avoid busy-waiting
    except KeyboardInterrupt: print("\nShutdown signal (Ctrl+C) received..."); stop_event.set()
    except Exception as e: print(f"\nUnexpected error in main wait loop: {e}"); stop_event.set()
    finally:
        # --- Graceful Shutdown Sequence ---
        _shutdown_servers()

def _shutdown_servers():
    """Internal helper to perform the shutdown sequence."""
    global wss_process, https_thread, wss_log_thread, https_server

    print("Initiating server shutdown...")

    # Shutdown HTTPS Server
    if https_server: print("Shutting down HTTPS server..."); https_server.shutdown()
    if https_thread and https_thread.is_alive():
        print("Waiting for HTTPS thread..."); https_thread.join(timeout=5)
        if https_thread.is_alive(): print("Warning: HTTPS thread did not exit gracefully.")
    https_thread = None

    # Shutdown WSS Process
    if wss_process and wss_process.poll() is None:
        print("Terminating WSS server process...")
        try:
            wss_process.terminate(); wss_process.wait(timeout=5)
            print("WSS server process terminated.")
        except subprocess.TimeoutExpired:
            print("WSS process did not terminate gracefully, killing."); wss_process.kill()
            try: wss_process.wait(timeout=2)
            except Exception: pass
        except Exception as e: print(f"Error terminating WSS process: {e}")
        finally: wss_process = None

    # Shutdown WSS Logging Thread
    if wss_log_thread and wss_log_thread.is_alive():
        print("Waiting for WSS logging thread..."); wss_log_thread.join(timeout=2)
        if wss_log_thread.is_alive(): print("Warning: WSS logging thread did not exit.")
    wss_log_thread = None

    print("Shutdown complete.")


# --- Main Execution ---
def main():
    """Main function: Check deps, read config, run menu, start/manage servers."""
    print("--- Starting HeliX Manager ---")
    check_or_install_websockets()
    current_settings = read_config()
    should_start = config_menu(current_settings) # Returns True to start, False to exit

    if should_start:
        start_servers(current_settings) # Enter start/manage/shutdown loop
    else:
        print("Exiting HeliX Manager.") # Exited from menu

if __name__ == "__main__":
    main()
