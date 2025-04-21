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
#   an integrated HTTPS server (in a separate thread) to serve client files locally.
# - Optionally starts the servers with a Cloudflare Tunnel:
#   - Checks for 'cloudflared' executable and provides installation instructions if missing.
#   - Starts a temporary tunnel using 'cloudflared'.
#   - Captures the public tunnel URL.
#   - Automatically updates the client's config.js with the public WSS URL.
#   - Reverts the client's config.js on shutdown.
# - Displays real-time logs from the WSS server to the console.
# - Logs HTTPS server activity to a file (logs/https_server.log).
# - Handles graceful shutdown of all servers/processes on Ctrl+C.

import subprocess         # For running external processes (WSS server, pip, mkcert, cloudflared).
import sys                # For accessing Python interpreter path and exiting.
import os                 # For path manipulation (finding files, creating dirs, renaming).
import re                 # For regular expressions used in config file parsing and editing.
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
CONFIG_FILE_PATH = os.path.join(SCRIPT_DIR, 'server', 'config.py') # Path to server config file.
HTTPS_CLIENT_DIR = os.path.join(SCRIPT_DIR, 'client') # Path to the client files directory.
# Define the path to the client-side JavaScript configuration file. (NEW)
CLIENT_CONFIG_PATH = os.path.join(HTTPS_CLIENT_DIR, 'js', 'config.js')
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
cloudflared_process = None # Holds the subprocess.Popen object for the cloudflared tunnel. (NEW)
# Holds the original WebSocket URL from client/js/config.js before tunnel modification. (NEW)
original_client_wss_url = None
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

def check_cloudflared_availability():
    """
    Checks if the 'cloudflared' executable is available in the system PATH.
    If not found, provides OS-specific installation instructions.

    Returns:
        str | None: The full path to the 'cloudflared' executable if found, otherwise None.
    """
    print("Checking for 'cloudflared' executable...")
    # Use shutil.which to search the system's PATH environment variable.
    cloudflared_path = shutil.which("cloudflared")

    if cloudflared_path:
        # Executable found in PATH.
        print(f"Found 'cloudflared' executable at: {cloudflared_path}")
        return cloudflared_path
    else:
        # Executable not found. Provide instructions.
        print("\nError: 'cloudflared' command not found in your system PATH.")
        system = platform.system()
        print("Installation Instructions:")
        if system == "Linux":
            print("  Debian/Ubuntu: sudo apt update && sudo apt install cloudflared")
            print("  (Check your specific distribution's package manager if different)")
        elif system == "Windows":
            print("  Using Winget (Recommended): winget install --id Cloudflare.cloudflared")
            print("  Using Chocolatey: choco install cloudflared")
        elif system == "Darwin": # macOS
            print("  Using Homebrew (Recommended): brew install cloudflared")
        else:
            print(f"  Unsupported OS ({system}) for automatic instructions.")

        print("\nAlternatively, download directly or find instructions for other systems at:")
        print("  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")
        print("\nPlease install 'cloudflared' and ensure it's in your system PATH, then restart the manager.")
        return None # Indicate failure to find the executable.

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
        # On Windows, first check PATH, then the expected relative path for backward compatibility/manual placement.
        mkcert_path = shutil.which("mkcert")
        if not mkcert_path:
            expected_path = os.path.join(CERT_DIR, "mkcert.exe")
            if os.path.exists(expected_path):
                mkcert_path = expected_path
                print(f"Found mkcert at expected Windows location: {mkcert_path}")
            else:
                 print(f"Error: 'mkcert.exe' not found in PATH or '{CERT_DIR}'.")
                 print("Please install mkcert (e.g., 'winget install mkcert' or 'choco install mkcert')")
                 print("or download from https://github.com/FiloSottile/mkcert/releases")
                 print(f"and ensure 'mkcert.exe' is in your PATH or inside the '{CERT_DIR}' directory.")
                 return False
        else:
             print(f"Found mkcert in PATH: {mkcert_path}")
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
    Reads WSS (HOST, PORT) and HTTPS (HTTPS_HOST, HTTPS_PORT) settings
    from the server/config.py file using regular expressions.
    Sets default values internally if the config file is missing or specific
    settings are not found within the file.

    Returns:
        dict: A dictionary containing the configuration settings:
              {'wss_host', 'wss_port', 'https_host', 'https_port'}.
              Uses defaults if the config file is missing or values aren't found.
    """
    # Initialize settings with default values. These will be used if the
    # config file doesn't exist or doesn't contain the specific settings.
    settings = {
        'wss_host': '0.0.0.0',  # Default WSS host
        'wss_port': 5678,       # Default WSS port
        'https_host': '0.0.0.0', # Default HTTPS host
        'https_port': 8888      # Default HTTPS port
    }
    config_file_path = CONFIG_FILE_PATH # Use local variable for clarity within function

    try:
        # Use the unified config file path constant.
        print(f"Reading configuration from: {config_file_path}")
        # Open the configuration file for reading with UTF-8 encoding.
        with open(config_file_path, 'r', encoding='utf-8') as f:
            # Read the entire content of the file into a single string.
            content = f.read()

            # --- WSS Settings Parsing ---
            # Search for the WSS HOST assignment line using regex.
            wss_host_match = re.search(r"^HOST\s*=\s*['\"]([^'\"]+)['\"]", content, re.MULTILINE)
            # Search for the WSS PORT assignment line using regex.
            wss_port_match = re.search(r"^PORT\s*=\s*(\d+)", content, re.MULTILINE)

            # Update WSS settings dictionary if matches were found.
            if wss_host_match:
                settings['wss_host'] = wss_host_match.group(1)
            else:
                print(f"Warning: Could not find WSS HOST setting in {config_file_path}, using default '{settings['wss_host']}'.")

            if wss_port_match:
                settings['wss_port'] = int(wss_port_match.group(1))
            else:
                print(f"Warning: Could not find WSS PORT setting in {config_file_path}, using default {settings['wss_port']}.")

            # --- HTTPS Settings Parsing ---
            # Search for the HTTPS_HOST assignment line using regex.
            https_host_match = re.search(r"^HTTPS_HOST\s*=\s*['\"]([^'\"]+)['\"]", content, re.MULTILINE)
            # Search for the HTTPS_PORT assignment line using regex.
            https_port_match = re.search(r"^HTTPS_PORT\s*=\s*(\d+)", content, re.MULTILINE)

            # Update HTTPS settings dictionary if matches were found.
            if https_host_match:
                settings['https_host'] = https_host_match.group(1)
            else:
                print(f"Warning: Could not find HTTPS_HOST setting in {config_file_path}, using default '{settings['https_host']}'.")

            if https_port_match:
                settings['https_port'] = int(https_port_match.group(1))
            else:
                print(f"Warning: Could not find HTTPS_PORT setting in {config_file_path}, using default {settings['https_port']}.")

    except FileNotFoundError:
        # Handle the case where the configuration file does not exist.
        print(f"Warning: {config_file_path} not found. Using default settings for WSS and HTTPS.")
    except Exception as e:
        # Catch any other potential errors during file reading or regex processing.
        print(f"Warning: Error reading {config_file_path}: {e}. Using default settings.")

    print("Initial settings loaded.")
    return settings

def write_config(settings):
    """
    Writes the WSS (HOST, PORT) and HTTPS (HTTPS_HOST, HTTPS_PORT) settings
    back to the server/config.py file.
    It reads the existing file content, modifies the relevant assignment lines
    using regex substitution, preserves other lines, and overwrites the file.
    If a setting line is not found, it appends it to the end of the file.
    If the file doesn't exist, it creates a new one with the settings.

    Args:
        settings (dict): The dictionary containing the current settings, including
                         'wss_host', 'wss_port', 'https_host', 'https_port'.

    Returns:
        bool: True if writing was successful, False otherwise.
    """
    config_file_path = CONFIG_FILE_PATH # Use local variable for clarity
    try:
        print(f"Attempting to update configuration in: {config_file_path}")
        lines = []
        # Try to read existing lines first to preserve other content and comments.
        try:
            with open(config_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except FileNotFoundError:
            # If the file doesn't exist, inform the user and proceed with empty lines.
            print(f"Info: {config_file_path} not found. A new configuration file will be created.")
            lines = [] # Start with an empty list if the file is new

        new_lines = []
        # Flags to track if each setting was found and updated within the existing lines.
        updated_flags = {'wss_host': False, 'wss_port': False, 'https_host': False, 'https_port': False}

        # Define the patterns to match the start of setting lines and their corresponding
        # keys in the settings dictionary and the format string for writing the new line.
        setting_patterns = {
            re.compile(r"^HOST\s*="): ('wss_host', "HOST = '{value}'\n"),
            re.compile(r"^PORT\s*="): ('wss_port', "PORT = {value}\n"),
            re.compile(r"^HTTPS_HOST\s*="): ('https_host', "HTTPS_HOST = '{value}'\n"),
            re.compile(r"^HTTPS_PORT\s*="): ('https_port', "HTTPS_PORT = {value}\n")
        }

        # Iterate through each existing line (or empty list if file was new).
        for line in lines:
            line_updated = False
            # Check the current line against each setting pattern.
            for pattern, (key, format_str) in setting_patterns.items():
                # If the line starts with the pattern AND we haven't already updated this setting...
                if pattern.match(line) and not updated_flags[key]:
                    # Replace the line with the new setting value, formatted correctly.
                    new_lines.append(format_str.format(value=settings[key]))
                    updated_flags[key] = True # Mark this setting as updated.
                    line_updated = True # Mark that this line was processed.
                    break # Stop checking patterns for this line, move to the next line.

            # If the line didn't match any setting pattern, keep it as is.
            if not line_updated:
                new_lines.append(line)

        # After processing all existing lines, check if any settings were NOT updated.
        appended_header = False # Flag to add a header only once if appending settings.
        for pattern, (key, format_str) in setting_patterns.items():
            if not updated_flags[key]:
                # If this is the first setting being appended, add a newline and a comment header.
                if not appended_header:
                    if new_lines and not new_lines[-1].endswith('\n'):
                         new_lines.append('\n')
                    new_lines.append("\n# --- Settings added/updated by helix_manager ---\n")
                    appended_header = True
                # Append the missing setting line to the end of the new content.
                print(f"Warning: {key.upper()} line not found in config, appending.")
                new_lines.append(format_str.format(value=settings[key]))

        # Write the potentially modified list of lines back to the configuration file,
        # overwriting the original file content.
        with open(config_file_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

        print(f"Configuration updated successfully in {config_file_path}.")
        return True # Indicate success.

    except Exception as e:
        # Catch any errors during the file writing process.
        print(f"Error writing configuration to {config_file_path}: {e}")
        return False # Indicate failure.

def update_client_config(new_wss_url):
    """
    Updates the 'webSocketUrl' in the client/js/config.js file.
    Stores the original URL in a global variable for later restoration.

    Args:
        new_wss_url (str): The new WebSocket URL to write into the config file.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    global original_client_wss_url # Access the global variable to store the original URL.
    original_client_wss_url = None # Reset in case of previous failed attempts.

    print(f"Attempting to update client config: {CLIENT_CONFIG_PATH}")
    try:
        # Read the entire content of the client config file.
        with open(CLIENT_CONFIG_PATH, 'r', encoding='utf-8') as f:
            content = f.read()

        # Define the regex to find the webSocketUrl assignment line.
        # It captures:
        # Group 1: The part before the URL value (e.g., "webSocketUrl: '")
        # Group 2: The current URL value itself (e.g., "wss://localhost:5678")
        # Group 3: The part after the URL value (e.g., "'")
        pattern = re.compile(r"(webSocketUrl\s*:\s*['\"])([^'\"]+)(['\"])", re.MULTILINE)

        # Search for the pattern in the content.
        match = pattern.search(content)

        if not match:
            # If the pattern is not found, we cannot update the file automatically.
            print(f"Error: Could not find 'webSocketUrl' assignment in {CLIENT_CONFIG_PATH}.")
            print("Please ensure the file exists and contains a line like: webSocketUrl: '...'")
            return False

        # Store the original URL found in group 2.
        original_client_wss_url = match.group(2)
        print(f"  Original client WSS URL found: '{original_client_wss_url}'")

        # Construct the replacement string using the captured groups and the new URL.
        # This preserves the original quoting style and surrounding code.
        replacement = match.group(1) + new_wss_url + match.group(3)

        # Replace the first occurrence of the pattern with the new replacement string.
        new_content = pattern.sub(replacement, content, count=1)

        # Write the modified content back to the file, overwriting the original.
        with open(CLIENT_CONFIG_PATH, 'w', encoding='utf-8') as f:
            f.write(new_content)

        print(f"  Successfully updated client WSS URL to: '{new_wss_url}'")
        return True # Indicate success.

    except FileNotFoundError:
        print(f"Error: Client config file not found at {CLIENT_CONFIG_PATH}.")
        return False
    except Exception as e:
        # Catch any other errors during file I/O or regex operations.
        print(f"Error updating client config file {CLIENT_CONFIG_PATH}: {e}")
        original_client_wss_url = None # Ensure original URL is cleared if update fails.
        return False

def revert_client_config():
    """
    Reverts the 'webSocketUrl' in client/js/config.js back to the
    original value that was stored before the tunnel started.
    This is typically called during shutdown.
    """
    global original_client_wss_url # Access the stored original URL.

    # Only proceed if we have a stored original URL (meaning the config was likely modified).
    if original_client_wss_url is None:
        print("Skipping client config revert: No original URL stored.")
        return

    print(f"Attempting to revert client config: {CLIENT_CONFIG_PATH}")
    try:
        # Read the current content of the client config file.
        with open(CLIENT_CONFIG_PATH, 'r', encoding='utf-8') as f:
            content = f.read()

        # Use the same regex pattern as in the update function.
        pattern = re.compile(r"(webSocketUrl\s*:\s*['\"])([^'\"]+)(['\"])", re.MULTILINE)

        # Search for the pattern again.
        match = pattern.search(content)

        if not match:
            # If the pattern is somehow missing now, we cannot revert automatically.
            print(f"Error: Could not find 'webSocketUrl' assignment in {CLIENT_CONFIG_PATH} during revert.")
            print(f"Manual check recommended. Expected original URL was: '{original_client_wss_url}'")
            return # Don't attempt to write if the structure changed unexpectedly.

        # Construct the replacement string using the stored original URL.
        replacement = match.group(1) + original_client_wss_url + match.group(3)

        # Replace the first occurrence with the original value.
        new_content = pattern.sub(replacement, content, count=1)

        # Write the reverted content back to the file.
        with open(CLIENT_CONFIG_PATH, 'w', encoding='utf-8') as f:
            f.write(new_content)

        print(f"  Successfully reverted client WSS URL to: '{original_client_wss_url}'")

    except FileNotFoundError:
        # Handle case where file might have been deleted between start and stop.
        print(f"Warning: Client config file not found at {CLIENT_CONFIG_PATH} during revert.")
    except Exception as e:
        # Catch any other errors during the revert process.
        print(f"Error reverting client config file {CLIENT_CONFIG_PATH}: {e}")
        print(f"Manual check recommended. Expected original URL was: '{original_client_wss_url}'")
    finally:
        # Clear the stored original URL regardless of success or failure,
        # as the tunnel session is ending.
        original_client_wss_url = None


def config_menu(settings):
    """
    Displays the main configuration menu, allowing the user to view/change
    WSS and HTTPS settings, manage certificates, save settings, start servers
    locally or with Cloudflare Tunnel, or exit.

    Args:
        settings (dict): The dictionary holding the current configuration values.

    Returns:
        str | None: 'local' if starting locally, 'tunnel' if starting with tunnel,
                    None if exiting or staying in menu.
    """
    while True:
        # Display current settings and menu options.
        print("\n--- HeliX Configuration & Management ---")
        print(f"1. WSS Host:    {settings['wss_host']}")
        print(f"2. WSS Port:    {settings['wss_port']}")
        print(f"3. HTTPS Host:  {settings['https_host']}")
        print(f"4. HTTPS Port:  {settings['https_port']}")
        print("------------------------------------")
        print("5. Manage TLS Certificates (Check/Generate/Install CA)")
        print("6. Save Config and Start Servers Locally")
        print("7. Start Servers Locally (Use Current Settings without Saving)")
        print("8. Start Servers with Cloudflare Tunnel (Requires 'cloudflared')") # NEW Option
        print("9. Exit") # Renumbered Exit option
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
        elif choice == '6': # Save Config and Start Locally
            # *** Pre-start Certificate Check ***
            if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
                print("\nError: Certificate files (cert.pem, key.pem) are missing in './certs/'.")
                print("Please use option 5 ('Manage TLS Certificates') to generate them first.")
                input("Press Enter to return to menu...")
                continue # Stay in menu
            # *** End Check ***
            if write_config(settings):
                return 'local' # Signal to main loop to start servers locally.
            else:
                # Stay in the menu if saving failed.
                input("Failed to save config. Press Enter to return to menu...")
                continue # Stay in menu
        elif choice == '7': # Start Locally without Saving
            # *** Pre-start Certificate Check ***
            if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
                print("\nError: Certificate files (cert.pem, key.pem) are missing in './certs/'.")
                print("Please use option 5 ('Manage TLS Certificates') to generate them first.")
                input("Press Enter to return to menu...")
                continue # Stay in menu
            # *** End Check ***
            print("Proceeding without saving config...")
            return 'local' # Signal to main loop to start servers locally.
        elif choice == '8': # Start with Cloudflare Tunnel
            # *** Pre-start Certificate Check ***
            if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
                print("\nError: Certificate files (cert.pem, key.pem) are missing in './certs/'.")
                print("These are needed for the local HTTPS server that the tunnel points to.")
                print("Please use option 5 ('Manage TLS Certificates') to generate them first.")
                input("Press Enter to return to menu...")
                continue # Stay in menu
            # *** Pre-start cloudflared Check ***
            if not check_cloudflared_availability():
                 # Instructions are printed inside the check function.
                 input("Press Enter to return to menu...")
                 continue # Stay in menu
            # *** End Checks ***
            # No need to explicitly save config here, tunnel uses current settings.
            return 'tunnel' # Signal to main loop to start with tunnel.
        elif choice == '9': # Exit
            return None # Signal to main loop to exit.
        else:
            print("Invalid choice. Please try again.")

# --- HTTPS Server Implementation ---
class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP request handler that overrides logging methods
    to write to the dedicated 'https_logger' (file logger).
    Serves files from a specified directory.
    """
    def __init__(self, *args, directory=None, **kwargs):
        # Python 3.7+ allows specifying the directory directly.
        if directory is None:
            directory = os.getcwd() # Default behavior if not specified
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format, *args):
        """Overrides the default log_message to use our file logger."""
        https_logger.info("%s - %s" % (self.address_string(), format % args))

    def log_error(self, format, *args):
        """Overrides the default log_error to use our file logger."""
        https_logger.error("%s - %s" % (self.address_string(), format % args))

class ThreadingHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    """HTTPServer that uses threads to handle requests."""
    allow_reuse_address = True # Allow reusing the address quickly after shutdown

def _start_https_server_thread(host, port, client_dir):
    """
    Internal helper to start the HTTPS server in a separate thread.

    Args:
        host (str): The hostname or IP address to bind the server to.
        port (int): The port number to bind the server to.
        client_dir (str): The absolute path to the directory containing client files.

    Returns:
        threading.Thread | None: The thread object if startup initiated, None on immediate error.
    """
    global https_server, https_thread # Allow modification of global state

    print("\nStarting HTTPS server thread...")
    # Use functools.partial to create a handler instance with the directory pre-set.
    Handler = partial(QuietHTTPRequestHandler, directory=client_dir)

    try:
        # Create the server instance but don't start serve_forever yet.
        # This allows checking for binding errors before launching the thread.
        https_server = ThreadingHTTPServer((host, port), Handler)

        # Setup SSL Context (moved before thread start for early error detection)
        print(f"[HTTPS Setup] Setting up SSL context using:\n  Cert: {CERT_FILE}\n  Key:  {KEY_FILE}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        print(f"[HTTPS Setup] SSL context loaded.")
        # Wrap the server's socket with the SSL context to enable HTTPS.
        https_server.socket = context.wrap_socket(https_server.socket, server_side=True)
        print(f"[HTTPS Setup] Server socket wrapped with SSL.")

        # Now create and start the thread to run the server loop.
        https_thread = threading.Thread(
            target=_run_https_server_loop, # Target function is now the loop runner
            args=(https_server, host, port, client_dir), # Pass the created server instance
            daemon=True
        )
        https_thread.start()
        print(f"[HTTPS Thread] Thread started. Serving HTTPS on {host}:{port} from {client_dir}")
        https_logger.info(f"HTTPS Server starting on {host}:{port}, serving {client_dir}")
        print(f"[HTTPS Thread] Access client at: https://localhost:{port} or https://127.0.0.1:{port}")
        return https_thread

    except FileNotFoundError as e:
        print(f"\n[HTTPS Setup] ERROR: File not found during server setup (Cert/Key?): {e}")
        https_logger.error(f"FileNotFoundError during HTTPS setup: {e}")
        https_server = None # Ensure server object is None if setup failed
        return None
    except OSError as e:
        print(f"\n[HTTPS Setup] ERROR binding or setting up HTTPS server: {e}")
        https_logger.error(f"OSError during HTTPS setup: {e}")
        https_server = None
        return None
    except Exception as e:
        print(f"\n[HTTPS Setup] An unexpected error occurred: {e}")
        https_logger.exception("Unexpected error during HTTPS setup")
        https_server = None
        return None

def _run_https_server_loop(server_instance, host, port, client_dir):
    """
    Target function executed in the HTTPS server thread. Runs the main server loop.
    Handles cleanup specific to the thread's execution context.

    Args:
        server_instance (ThreadingHTTPServer): The pre-configured server instance.
        host (str): Hostname (for logging).
        port (int): Port number (for logging).
        client_dir (str): Client directory path (for logging).
    """
    global https_server # Reference global to clear it on exit
    try:
        # This call blocks the thread until server_instance.shutdown() is called.
        server_instance.serve_forever()
    except Exception as e:
        # Catch unexpected errors within the serve_forever loop itself.
        print(f"\n[HTTPS Thread] An unexpected error occurred during serve_forever: {e}")
        https_logger.exception("Unexpected error in HTTPS serve_forever loop")
    finally:
        # --- Thread-Specific Cleanup ---
        # This runs when serve_forever returns (after shutdown()) or if an exception occurred in the loop.
        if server_instance:
            try:
                # Ensure the server socket is closed properly.
                server_instance.server_close()
            except Exception as e:
                 print(f"[HTTPS Thread] Error during server_close(): {e}")
        print("[HTTPS Thread] Server loop stopped.")
        https_logger.info("HTTPS Server loop stopped.")
        # Clear the global reference from within the thread upon stopping.
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
        # Use iter and readline to block efficiently until a line is available or EOF.
        for line in iter(process.stdout.readline, ''):
            # Check if the stop event was set while waiting for readline.
            if stop_event.is_set():
                print("[WSS Log Thread] Stop event detected, exiting.")
                break
            # Print the received line, stripping whitespace.
            print(f"[WSS] {line.strip()}")

        # After the loop (EOF or break), check if the process terminated unexpectedly vs. normal stop.
        if not stop_event.is_set() and process.poll() is not None:
             print("[WSS Log Thread] WSS process stdout reached EOF or process terminated.")

    except Exception as e:
        # Log errors encountered during reading, but only if we aren't shutting down.
        if not stop_event.is_set():
             print(f"[WSS Log Thread] Error reading WSS output: {e}")
    finally:
        print("[WSS Log Thread] Exiting.")

def _start_wss_server_process():
    """
    Internal helper to start the WSS server as a subprocess.

    Returns:
        subprocess.Popen | None: The Popen object for the WSS process if successful, else None.
    """
    global wss_process, wss_log_thread # Allow modification of global state

    print("Starting WSS server subprocess...")
    wss_script_path = os.path.join(SCRIPT_DIR, 'server', 'main.py')
    try:
        # Launch server/main.py using the same Python interpreter.
        wss_process = subprocess.Popen(
            [sys.executable, wss_script_path],
            stdout=subprocess.PIPE,         # Capture standard output.
            stderr=subprocess.STDOUT,       # Redirect standard error to standard output.
            text=True,                      # Decode output as text.
            encoding='utf-8',               # Explicit encoding.
            bufsize=1,                      # Line buffering.
            cwd=SCRIPT_DIR                  # Set working directory.
        )
        print(f"WSS server process started (PID: {wss_process.pid}). Output will follow:")

        # Start the WSS Logging Thread
        print("Starting WSS logging thread...")
        wss_log_thread = threading.Thread(target=log_wss_output, args=(wss_process,), daemon=True)
        wss_log_thread.start()
        return wss_process

    except Exception as e:
        print(f"Error starting WSS server process: {e}")
        wss_process = None # Ensure process is None if startup failed.
        return None

def _start_cloudflared_tunnel(cloudflared_path, https_port):
    """
    Internal helper to start the cloudflared tunnel process, capture its URL,
    and update the client configuration.

    Args:
        cloudflared_path (str): Full path to the cloudflared executable.
        https_port (int): The local HTTPS port the tunnel should point to.

    Returns:
        subprocess.Popen | None: The Popen object for the cloudflared process if successful, else None.
    """
    global cloudflared_process # Allow modification of global state
    print(f"\nStarting Cloudflare tunnel for https://localhost:{https_port}...")
    # Construct the command to run cloudflared.
    # --url specifies the local service to tunnel.
    # We capture stdout to get the public URL. Stderr is also captured for errors.
    command = [cloudflared_path, "tunnel", "--url", f"https://localhost:{https_port}"]

    try:
        # Start the cloudflared process.
        cloudflared_process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, # Capture stderr separately
            text=True,
            encoding='utf-8',
            bufsize=1
        )
        print(f"Cloudflared process started (PID: {cloudflared_process.pid}). Waiting for URL...")

        # Monitor cloudflared's output to find the public URL.
        public_https_url = None
        # Regex to find the trycloudflare.com URL in the output lines.
        # Looks for lines containing https://...trycloudflare.com
        url_pattern = re.compile(r"(https://[\w-]+.trycloudflare.com)")
        timeout_seconds = 30 # Max time to wait for the URL.
        start_time = time.time()

        # Read output line by line until URL is found or timeout/error occurs.
        while time.time() - start_time < timeout_seconds:
            # Check if process died unexpectedly.
            if cloudflared_process.poll() is not None:
                 stderr_output = cloudflared_process.stderr.read()
                 print(f"Error: Cloudflared process terminated unexpectedly (Exit code: {cloudflared_process.returncode}).")
                 if stderr_output: print(f"Cloudflared STDERR:\n{stderr_output.strip()}")
                 cloudflared_process = None
                 return None # Tunnel startup failed.

            # Read the next line of output (non-blocking would be complex, use readline with timeout indirectly).
            # We rely on the overall loop timeout here.
            line = cloudflared_process.stdout.readline()
            if not line:
                # If readline returns empty string but process is running, wait briefly.
                time.sleep(0.1)
                continue

            print(f"[cloudflared] {line.strip()}") # Print cloudflared output for debugging.
            match = url_pattern.search(line)
            if match:
                # URL found!
                public_https_url = match.group(1)
                print(f"\n--- Cloudflare Tunnel Active ---")
                print(f"Public HTTPS URL: {public_https_url}")
                break # Exit the loop once URL is found.
        else:
            # Loop finished without finding URL (timeout).
            print(f"Error: Timed out waiting for Cloudflare tunnel URL after {timeout_seconds} seconds.")
            # Attempt to terminate the lingering process.
            if cloudflared_process.poll() is None:
                 cloudflared_process.terminate()
                 try: cloudflared_process.wait(timeout=2)
                 except subprocess.TimeoutExpired: cloudflared_process.kill()
            cloudflared_process = None
            return None # Tunnel startup failed.

        # Derive the public WSS URL from the HTTPS URL.
        public_wss_url = public_https_url.replace("https://", "wss://")
        print(f"Public WSS URL:   {public_wss_url}")
        print(f"------------------------------")

        # Update the client config file with the new WSS URL.
        if not update_client_config(public_wss_url):
            # If updating client config fails, we should stop the tunnel.
            print("Error: Failed to update client configuration. Stopping tunnel.")
            if cloudflared_process.poll() is None:
                 cloudflared_process.terminate()
                 try: cloudflared_process.wait(timeout=2)
                 except subprocess.TimeoutExpired: cloudflared_process.kill()
            cloudflared_process = None
            # Also revert any partial changes if original_client_wss_url was set.
            revert_client_config()
            return None # Tunnel startup effectively failed.

        # If URL found and client config updated, return the process object.
        return cloudflared_process

    except FileNotFoundError:
        print(f"Error: Could not execute cloudflared at '{cloudflared_path}'.")
        cloudflared_process = None
        return None
    except Exception as e:
        print(f"An unexpected error occurred starting cloudflared: {e}")
        # Clean up if process started partially.
        if cloudflared_process and cloudflared_process.poll() is None:
            cloudflared_process.terminate()
            try: cloudflared_process.wait(timeout=2)
            except subprocess.TimeoutExpired: cloudflared_process.kill()
        cloudflared_process = None
        return None

# --- Server Startup and Management ---
def manage_running_servers(run_mode):
    """
    Manages the running servers (WSS, HTTPS, potentially Cloudflared).
    Waits for termination signal (Ctrl+C) or unexpected server exit.
    Handles the graceful shutdown sequence for all active components.

    Args:
        run_mode (str): 'local' or 'tunnel', indicating which mode was started.
    """
    # Access global variables holding the process/thread objects.
    global wss_process, https_thread, wss_log_thread, https_server, cloudflared_process, stop_event

    print("\nServers are running. Press Ctrl+C to stop.")
    try:
        # Keep the main thread alive while servers run in background threads/processes.
        while not stop_event.is_set():
            # Check WSS process status.
            if wss_process and wss_process.poll() is not None:
                print(f"\nError: WSS server process terminated unexpectedly (Exit Code: {wss_process.returncode}).")
                https_logger.error(f"WSS server process terminated unexpectedly (Exit Code: {wss_process.returncode}).")
                stop_event.set() # Signal other threads/processes to stop.
                break # Exit wait loop

            # Check HTTPS thread status.
            if https_thread and not https_thread.is_alive():
                 # Check if the server object still exists; if not, it likely failed during startup.
                 if https_server is not None:
                     print("\nError: HTTPS server thread terminated unexpectedly.")
                     https_logger.error("HTTPS server thread terminated unexpectedly.")
                     stop_event.set()
                     break
                 else:
                      # Server likely failed during startup within its thread, error already printed.
                      print("\nError: HTTPS server failed during startup (see previous messages).")
                      stop_event.set()
                      break

            # Check Cloudflared process status (only if running in tunnel mode).
            if run_mode == 'tunnel' and cloudflared_process and cloudflared_process.poll() is not None:
                print(f"\nError: Cloudflared process terminated unexpectedly (Exit Code: {cloudflared_process.returncode}).")
                https_logger.error(f"Cloudflared process terminated unexpectedly (Exit Code: {cloudflared_process.returncode}).")
                stderr_output = cloudflared_process.stderr.read()
                if stderr_output: print(f"Cloudflared STDERR:\n{stderr_output.strip()}")
                stop_event.set()
                break

            # Sleep briefly to avoid busy-waiting.
            time.sleep(0.5)

    except KeyboardInterrupt:
        # User pressed Ctrl+C.
        print("\nShutdown signal (Ctrl+C) received...")
        stop_event.set() # Signal threads/processes to stop gracefully.
    except Exception as e:
        # Catch any other unexpected errors in this main wait loop.
        print(f"\nUnexpected error in main wait loop: {e}")
        stop_event.set() # Signal threads/processes to stop.
    finally:
        # --- Graceful Shutdown Sequence ---
        # This block executes after the loop ends (normally or via exception/Ctrl+C).
        print("Initiating server shutdown...")

        # --- Shutdown Cloudflared Process (if applicable) ---
        if run_mode == 'tunnel' and cloudflared_process and cloudflared_process.poll() is None:
            print("Terminating Cloudflared process...")
            try:
                cloudflared_process.terminate()
                cloudflared_process.wait(timeout=5)
                print("Cloudflared process terminated.")
            except subprocess.TimeoutExpired:
                print("Cloudflared process did not terminate gracefully, killing.")
                cloudflared_process.kill()
                try: cloudflared_process.wait(timeout=2)
                except Exception: pass
            except Exception as e:
                print(f"Error terminating Cloudflared process: {e}")
            finally:
                 cloudflared_process = None # Clear global reference

        # --- Revert Client Config (if applicable) ---
        # This should happen *after* cloudflared is stopped but before script exits.
        if run_mode == 'tunnel':
            revert_client_config() # Function handles check if revert is needed

        # --- Shutdown HTTPS Server ---
        if https_server: # Check if server object exists
            print("Shutting down HTTPS server...")
            try:
                https_server.shutdown() # Signal the serve_forever loop to stop.
            except Exception as e:
                print(f"Error during https_server.shutdown(): {e}")
        # Wait for the HTTPS server thread to complete its cleanup.
        if https_thread and https_thread.is_alive():
            print("Waiting for HTTPS thread to finish...")
            https_thread.join(timeout=5)
            if https_thread.is_alive():
                print("Warning: HTTPS thread did not exit gracefully.")
        https_thread = None # Clear global reference

        # --- Shutdown WSS Process ---
        if wss_process and wss_process.poll() is None:
            print("Terminating WSS server process...")
            try:
                wss_process.terminate()
                wss_process.wait(timeout=5)
                print("WSS server process terminated.")
            except subprocess.TimeoutExpired:
                print("WSS process did not terminate gracefully, killing.")
                wss_process.kill()
                try: wss_process.wait(timeout=2)
                except Exception: pass
            except Exception as e:
                print(f"Error terminating WSS process: {e}")
            finally:
                 wss_process = None # Clear global reference

        # --- Shutdown WSS Logging Thread ---
        # Stop event was set, now wait for thread to finish.
        if wss_log_thread and wss_log_thread.is_alive():
            print("Waiting for WSS logging thread to finish...")
            wss_log_thread.join(timeout=2)
            if wss_log_thread.is_alive():
                 print("Warning: WSS logging thread did not exit.")
        wss_log_thread = None # Clear global reference

        print("Shutdown complete.")

# --- Main Execution ---
def main():
    """
    Main function to orchestrate the manager script execution:
    1. Check dependencies ('websockets').
    2. Read initial configuration.
    3. Run the configuration menu loop.
    4. Based on menu choice, start servers locally or with tunnel.
    5. Manage the running servers until shutdown.
    """
    print("--- Starting HeliX Manager ---")
    # Ensure 'websockets' library is available.
    check_or_install_websockets()
    # Load current WSS and HTTPS settings from file.
    current_settings = read_config()

    # Run the configuration menu. It returns 'local', 'tunnel', or None.
    start_mode = config_menu(current_settings)

    # Reset global process/thread variables before starting.
    global wss_process, https_thread, wss_log_thread, https_server, cloudflared_process, stop_event, original_client_wss_url
    wss_process = None
    https_thread = None
    wss_log_thread = None
    https_server = None
    cloudflared_process = None
    original_client_wss_url = None
    stop_event.clear() # Ensure stop event is clear before starting

    # --- Start Servers Based on Mode ---
    servers_started_ok = False
    if start_mode == 'local' or start_mode == 'tunnel':
        # Start local servers (required for both modes)
        print("Starting local servers...")
        https_thread = _start_https_server_thread(
            current_settings['https_host'], current_settings['https_port'], HTTPS_CLIENT_DIR
        )
        # Allow HTTPS server to bind before starting WSS
        time.sleep(1.0)
        if https_thread and https_thread.is_alive():
            wss_process = _start_wss_server_process()
            if wss_process:
                # Local servers seem okay so far.
                if start_mode == 'local':
                    servers_started_ok = True # Ready for local mode management.
                elif start_mode == 'tunnel':
                    # Attempt to start the tunnel.
                    cloudflared_exe_path = check_cloudflared_availability() # Re-check just in case.
                    if cloudflared_exe_path:
                        cloudflared_process = _start_cloudflared_tunnel(
                            cloudflared_exe_path, current_settings['https_port']
                        )
                        if cloudflared_process:
                            servers_started_ok = True # Tunnel mode ready for management.
                        else:
                            print("Failed to start Cloudflare tunnel. Shutting down local servers.")
                    else:
                         print("Cloudflared became unavailable after menu selection? Shutting down.")

            else: # WSS failed
                 print("Failed to start WSS server process. Shutting down HTTPS server.")
        else: # HTTPS failed
             print("Failed to start HTTPS server thread.")

        # If anything failed during startup, trigger immediate shutdown.
        if not servers_started_ok:
             stop_event.set() # Signal any potentially running components (like HTTPS thread) to stop.
             manage_running_servers(start_mode) # Call manager to handle cleanup.
             print("Exiting due to server startup failure.")
             sys.exit(1)

    # --- Manage Running Servers ---
    if servers_started_ok:
        # If startup was successful, enter the main management loop.
        manage_running_servers(start_mode)
    else:
        # User chose to exit from the menu or startup failed before entering management loop.
        print("Exiting HeliX Manager.")

# Standard Python idiom: Run the main function only when the script is executed directly.
if __name__ == "__main__":
    main()
