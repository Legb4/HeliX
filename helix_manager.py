#!/usr/bin/env python3
# helix_manager.py - Main control script for HeliX Chat
#
# This script provides a command-line interface to manage the HeliX chat application:
# - Checks for required Python packages listed in server/requirements.txt and offers installation.
# - Provides a menu option to manage TLS certificates using 'mkcert':
#   - Checks for 'mkcert' utility (in PATH or ./certs/mkcert.exe on Windows).
#   - Offers to install the mkcert CA for browser trust.
#   - Generates/overwrites local TLS certificates (cert.pem, key.pem) for localhost/127.0.0.1.
#   - Offers to back up existing certificates before overwriting.
# - Allows viewing and modifying configuration settings:
#   - WSS Host/Port (Saved to server/config.py AND client/js/config.js for Port)
#   - HTTPS Host/Port (Manager session only)
#   - Server Debug Mode (Saved to server/config.py)
#   - Client Debug Mode (Saved to client/js/config.js)
# - Saves WSS config (HOST, PORT, DEBUG) persistently to server/config.py before starting.
# - Saves Client config (DEBUG, WSS_PORT) persistently to client/js/config.js before starting. # MODIFIED
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
# Path to the WSS server configuration file.
CONFIG_FILE_PATH = os.path.join(SCRIPT_DIR, 'server', 'config.py') # Path to server config file.
# Path to the client configuration file.
CLIENT_CONFIG_FILE_PATH = os.path.join(SCRIPT_DIR, 'client', 'js', 'config.js')
# Path to the server requirements file.
REQUIREMENTS_FILE_PATH = os.path.join(SCRIPT_DIR, 'server', 'requirements.txt')
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
def parse_package_name(requirement_line):
    """
    Parses a requirement line (e.g., 'websockets==11.0.3', 'requests>=2.0')
    to extract the base package name ('websockets', 'requests').
    Handles common version specifiers.

    Args:
        requirement_line (str): A line from requirements.txt.

    Returns:
        str or None: The extracted package name, or None if parsing fails or line is invalid.
    """
    line = requirement_line.strip()
    # Ignore empty lines and comments
    if not line or line.startswith('#'):
        return None
    # Find the first occurrence of a version specifier or end of string
    match = re.match(r"^[a-zA-Z0-9._-]+", line)
    if match:
        return match.group(0)
    return None # Return None if no valid package name start is found

def check_dependencies():
    """
    Checks if Python packages listed in server/requirements.txt are installed.
    If any are missing, prompts the user to install them using pip.
    Exits if installation is declined or fails.
    """
    print(f"Checking dependencies listed in {REQUIREMENTS_FILE_PATH}...")
    missing_packages = []
    try:
        # Read the requirements file.
        with open(REQUIREMENTS_FILE_PATH, 'r', encoding='utf-8') as f:
            requirements = f.readlines()

        # Check each requirement.
        for line in requirements:
            package_name = parse_package_name(line)
            if package_name:
                # Use find_spec for a lightweight check without importing.
                spec = importlib.util.find_spec(package_name)
                if spec is None:
                    print(f"  - Package '{package_name}' not found.")
                    missing_packages.append(package_name)
                # else: # Removed the debug logging for found packages here
                    # print(f"  - Package '{package_name}' found.") # Removed this line

        # If packages are missing, prompt for installation.
        if missing_packages:
            print("\nSome required packages are missing.")
            package_list = ", ".join(missing_packages)
            confirm = input(f"Attempt to install missing packages ({package_list}) using pip? (y/n): ").lower().strip()
            if confirm == 'y':
                print(f"Installing packages from {REQUIREMENTS_FILE_PATH}...")
                try:
                    # Run pip install -r using the current Python interpreter.
                    subprocess.run(
                        [sys.executable, "-m", "pip", "install", "-r", REQUIREMENTS_FILE_PATH],
                        check=True,        # Raise error if pip fails
                        capture_output=True,# Hide pip output unless error
                        text=True          # Decode output as text
                    )
                    print("Packages installed successfully.")
                except subprocess.CalledProcessError as e:
                    # Handle pip installation errors.
                    print(f"Error installing packages: {e}")
                    print("--- PIP Error Output ---")
                    print(e.stderr) # Print captured stderr
                    print("----------------------")
                    print(f"Please install packages manually (e.g., 'pip install -r {REQUIREMENTS_FILE_PATH}') and restart.")
                    sys.exit(1) # Exit manager script.
                except FileNotFoundError:
                    # Handle error if 'pip' itself isn't found.
                    print("Error: 'pip' command not found. Is Python installed correctly and in your PATH?")
                    sys.exit(1) # Exit manager script.
            else:
                # User declined installation.
                print("Installation declined. Please install required packages manually and restart.")
                sys.exit(1) # Exit manager script.
        else:
            # All packages found.
            print("All required packages found.")

    except FileNotFoundError:
        print(f"Error: {REQUIREMENTS_FILE_PATH} not found. Cannot check dependencies.")
        print("Please ensure the requirements file exists or install dependencies manually.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during dependency check: {e}")
        sys.exit(1)


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
    Reads WSS settings (HOST, PORT, DEBUG) from server/config.py and
    Client settings (DEBUG, WSS_PORT) from client/js/config.js using regex.
    Sets default values internally if files or settings are not found.
    Prioritizes client/js/config.js for WSS_PORT if found.

    Returns:
        dict: A dictionary containing the configuration settings:
              {'wss_host', 'wss_port', 'https_host', 'https_port',
               'server_debug', 'client_debug'}.
    """
    # Initialize settings with default values.
    settings = {
        'wss_host': '0.0.0.0',
        'wss_port': 5678,       # Default WSS port
        'https_host': '0.0.0.0', # Default HTTPS host (not read from file)
        'https_port': 8888,     # Default HTTPS port (not read from file)
        'server_debug': False,  # Default server debug mode
        'client_debug': False   # Default client debug mode
    }
    server_config_path = CONFIG_FILE_PATH
    client_config_path = CLIENT_CONFIG_FILE_PATH
    wss_port_from_client = None # Variable to store port read from client config

    # --- Read Client Config (client/js/config.js) FIRST for WSS Port ---
    try:
        # print(f"Reading Client configuration from: {client_config_path}") # Silent read
        with open(client_config_path, 'r', encoding='utf-8') as f:
            content = f.read()

            # Client Debug (Look for 'DEBUG: true' or 'DEBUG: false')
            # Allow for optional whitespace and comma
            client_debug_match = re.search(r"^\s*DEBUG:\s*(true|false)\s*,?", content, re.MULTILINE | re.IGNORECASE)
            if client_debug_match:
                # Convert JS boolean string to actual boolean
                settings['client_debug'] = client_debug_match.group(1).lower() == 'true'
            else: print(f"Warning: Could not find DEBUG setting in {client_config_path}, using default {settings['client_debug']}.")

            # NEW: Read WSS Port from client config
            # Look for 'webSocketPort: 5678,' or 'webSocketPort = 5678;'
            client_port_match = re.search(r"^\s*webSocketPort\s*[:=]\s*(\d+)\s*,?;?", content, re.MULTILINE | re.IGNORECASE)
            if client_port_match:
                try:
                    wss_port_from_client = int(client_port_match.group(1))
                    # Apply the client port immediately if found
                    settings['wss_port'] = wss_port_from_client
                    print(f"Info: Found WSS Port {wss_port_from_client} in {client_config_path}.")
                except ValueError:
                    print(f"Warning: Invalid WSS Port value found in {client_config_path}, ignoring.")
            else: print(f"Info: Could not find webSocketPort setting in {client_config_path}, will use server config or default.")

    except FileNotFoundError: print(f"Warning: {client_config_path} not found. Using default settings for Client.")
    except Exception as e: print(f"Warning: Error reading {client_config_path}: {e}. Using default settings for Client.")

    # --- Read Server Config (server/config.py) ---
    # Read server config, but WSS Port from client config takes precedence if found
    try:
        # print(f"Reading WSS configuration from: {server_config_path}") # Silent read
        with open(server_config_path, 'r', encoding='utf-8') as f:
            content = f.read()

            # WSS Host
            wss_host_match = re.search(r"^HOST\s*=\s*['\"]([^'\"]+)['\"]", content, re.MULTILINE)
            if wss_host_match: settings['wss_host'] = wss_host_match.group(1)
            else: print(f"Warning: Could not find WSS HOST setting in {server_config_path}, using default '{settings['wss_host']}'.")

            # WSS Port (Only use if not found in client config)
            if wss_port_from_client is None:
                wss_port_match = re.search(r"^PORT\s*=\s*(\d+)", content, re.MULTILINE)
                if wss_port_match:
                    try:
                        settings['wss_port'] = int(wss_port_match.group(1))
                    except ValueError:
                         print(f"Warning: Invalid WSS PORT value found in {server_config_path}, using default {settings['wss_port']}.")
                else: print(f"Warning: Could not find WSS PORT setting in {server_config_path}, using default {settings['wss_port']}.")

            # Server Debug
            server_debug_match = re.search(r"^DEBUG\s*=\s*(True|False)", content, re.MULTILINE)
            if server_debug_match:
                # Convert Python boolean string to actual boolean
                settings['server_debug'] = server_debug_match.group(1) == 'True'
            else: print(f"Warning: Could not find DEBUG setting in {server_config_path}, using default {settings['server_debug']}.")

    except FileNotFoundError: print(f"Warning: {server_config_path} not found. Using default settings for WSS Host/Server Debug.")
    except Exception as e: print(f"Warning: Error reading {server_config_path}: {e}. Using default settings for WSS Host/Server Debug.")

    print("Initial settings loaded.")
    return settings

def write_config(settings):
    """
    Writes the WSS settings (HOST, PORT, DEBUG) back to the server/config.py file silently.
    Reads existing file, modifies relevant lines, preserves others, and overwrites.
    Appends settings if not found. Creates file if it doesn't exist.
    Uses repr() for string/boolean values to ensure proper Python syntax.
    Does NOT write HTTPS settings or Client settings to this file.

    Args:
        settings (dict): Dictionary containing at least 'wss_host', 'wss_port', 'server_debug'.
                         Other keys are ignored here.

    Returns:
        bool: True if writing was successful, False otherwise.
    """
    config_file_path = CONFIG_FILE_PATH
    try:
        # print(f"Attempting to update Server configuration in: {config_file_path}") # Silent write
        lines = []
        try:
            # Read existing lines from the config file.
            with open(config_file_path, 'r', encoding='utf-8') as f: lines = f.readlines()
        except FileNotFoundError: pass # Silently proceed if file not found

        new_lines = [] # List to hold the modified lines.
        # Flags to track if WSS settings were found and updated.
        updated_flags = {'wss_host': False, 'wss_port': False, 'server_debug': False}

        # Define regex patterns and corresponding setting keys and format strings for WSS/Server Debug.
        # Use repr() for string and boolean values.
        setting_patterns = {
            re.compile(r"^HOST\s*="): ('wss_host', "HOST = {value}\n"),
            re.compile(r"^PORT\s*="): ('wss_port', "PORT = {value}\n"),
            re.compile(r"^DEBUG\s*="): ('server_debug', "DEBUG = {value}\n"), # Match DEBUG = True/False
        }

        # Iterate through the existing lines of the config file.
        for line in lines:
            line_updated = False
            # Check if the current line matches any of the setting patterns.
            for pattern, (key, format_str) in setting_patterns.items():
                # If a pattern matches and this setting hasn't been updated yet...
                if pattern.match(line) and not updated_flags[key]:
                    # Format the new value. Use repr() for strings and booleans.
                    value_to_write = repr(settings[key]) if isinstance(settings[key], (str, bool)) else settings[key]
                    # Append the updated line to the new_lines list.
                    new_lines.append(format_str.format(value=value_to_write))
                    # Mark this setting as updated and break the inner loop.
                    updated_flags[key], line_updated = True, True
                    break
            # If the line didn't match any setting pattern, append it unchanged.
            if not line_updated: new_lines.append(line)

        # Check for any settings that were not found in the existing file.
        appended_header = False
        for pattern, (key, format_str) in setting_patterns.items():
            if not updated_flags[key]:
                # Add a header comment if this is the first setting being appended.
                if not appended_header:
                    # Ensure there's a newline before the header if needed.
                    if new_lines and not new_lines[-1].endswith('\n'): new_lines.append('\n')
                    new_lines.append("\n# --- Settings added/updated by helix_manager ---\n")
                    appended_header = True
                # print(f"Warning: {key.upper()} line not found in config, appending.") # Silent write
                # Format the value using repr() for strings/booleans.
                value_to_write = repr(settings[key]) if isinstance(settings[key], (str, bool)) else settings[key]
                # Append the new setting line.
                new_lines.append(format_str.format(value=value_to_write))

        # Write the potentially modified lines back to the config file, overwriting it.
        with open(config_file_path, 'w', encoding='utf-8') as f: f.writelines(new_lines)
        # print(f"Server Configuration updated successfully in {config_file_path}.") # Silent write
        return True
    except Exception as e:
        # Handle any errors during file reading or writing.
        print(f"Error writing Server configuration to {config_file_path}: {e}")
        return False

def write_client_config(settings):
    """
    Writes the Client DEBUG setting and WSS Port back to the client/js/config.js file silently.
    Reads existing file, modifies the relevant lines, preserves others, and overwrites.
    Appends settings if not found. Creates file if it doesn't exist.

    Args:
        settings (dict): Dictionary containing at least 'client_debug' and 'wss_port'.

    Returns:
        bool: True if writing was successful, False otherwise.
    """
    config_file_path = CLIENT_CONFIG_FILE_PATH
    try:
        # print(f"Attempting to update Client configuration in: {config_file_path}") # Silent write
        lines = []
        try:
            # Read existing lines from the config file.
            with open(config_file_path, 'r', encoding='utf-8') as f: lines = f.readlines()
        except FileNotFoundError: pass # Silently proceed if file not found

        new_lines = [] # List to hold the modified lines.
        # Flags to track if settings were updated.
        updated_flags = {'client_debug': False, 'wss_port': False}

        # Define regex patterns and corresponding setting keys and format strings.
        # Use lowercase 'true'/'false' for JS boolean.
        # Use integer for port.
        setting_patterns = {
            # Regex for DEBUG: true/false (case-insensitive, optional comma/semicolon)
            re.compile(r"^\s*DEBUG\s*[:=]\s*(true|false)\s*[,;]?", re.IGNORECASE):
                ('client_debug', "    DEBUG: {value}, // Default to false for production\n"),
            # Regex for webSocketPort: 1234 or webSocketPort = 1234 (optional comma/semicolon)
            re.compile(r"^\s*webSocketPort\s*[:=]\s*(\d+)\s*[,;]?", re.IGNORECASE):
                ('wss_port', "    webSocketPort: {value}, // Updated by helix_manager\n"),
        }

        # Iterate through the existing lines.
        for line in lines:
            line_updated = False
            # Check if the current line matches any of the setting patterns.
            for pattern, (key, format_str) in setting_patterns.items():
                match = pattern.match(line)
                # If a pattern matches and this setting hasn't been updated yet...
                if match and not updated_flags[key]:
                    # Format the new value.
                    if key == 'client_debug':
                        value_to_write = str(settings[key]).lower() # 'true' or 'false'
                    elif key == 'wss_port':
                        value_to_write = int(settings[key]) # Ensure integer
                    else:
                        value_to_write = settings[key] # Fallback

                    # Try to preserve original indentation and comment if possible
                    leading_whitespace = line[:match.start(1) - len(key.replace('_', '') + ': ')] if key == 'client_debug' else line[:match.start(1) - len('webSocketPort: ')]
                    trailing_comment = ""
                    comment_match = re.search(r"//.*$", line)
                    if comment_match:
                        trailing_comment = comment_match.group(0)

                    # Construct the new line content (key: value,)
                    new_line_content = f"{key.replace('_', '')}: {value_to_write}," if key == 'client_debug' else f"webSocketPort: {value_to_write},"

                    # Construct the full new line with padding and comment
                    # Use a reasonable padding length based on typical line length
                    padding_length = max(len(match.group(0)), 25) # Adjust padding base length as needed
                    new_line = f"{leading_whitespace}{new_line_content:<{padding_length}} {trailing_comment}\n".rstrip() + "\n"

                    # Fallback format if padding/comment logic fails or looks wrong
                    if not new_line.strip().startswith(key.replace('_', '') + ':') and not new_line.strip().startswith('webSocketPort:'):
                         new_line = format_str.format(value=value_to_write)

                    new_lines.append(new_line)
                    updated_flags[key], line_updated = True, True # Mark as updated.
                    break
            # If the line didn't match any setting pattern, append it unchanged.
            if not line_updated: new_lines.append(line)

        # Check for any settings that were not found in the existing file.
        appended_header = False
        for pattern, (key, format_str) in setting_patterns.items():
            if not updated_flags[key]:
                # Add a header comment if this is the first setting being appended.
                if not appended_header:
                    # Ensure there's a newline before the header if needed.
                    if new_lines and not new_lines[-1].endswith('\n'): new_lines.append('\n')
                    new_lines.append("\n    // --- Settings added/updated by helix_manager ---\n")
                    appended_header = True
                # print(f"Warning: {key.upper()} line not found in {config_file_path}, appending.") # Silent write
                # Format the value.
                if key == 'client_debug':
                    value_to_write = str(settings[key]).lower()
                elif key == 'wss_port':
                    value_to_write = int(settings[key])
                else:
                    value_to_write = settings[key]
                # Append the new setting line using the standard format.
                new_lines.append(format_str.format(value=value_to_write))

        # Write the potentially modified lines back to the config file.
        with open(config_file_path, 'w', encoding='utf-8') as f: f.writelines(new_lines)
        # print(f"Client Configuration updated successfully in {config_file_path}.") # Silent write
        return True
    except Exception as e:
        # Handle any errors during file reading or writing.
        print(f"Error writing Client configuration to {config_file_path}: {e}")
        return False


def config_menu(settings):
    """
    Displays the main configuration menu. Allows modification of WSS, HTTPS,
    and Debug settings held in the 'settings' dictionary.
    WSS (HOST, PORT, DEBUG) and Client (DEBUG, WSS_PORT) settings are saved persistently
    when starting the server.

    Args:
        settings (dict): The current configuration values.

    Returns:
        bool: True if servers should start, False if exiting.
    """
    while True:
        print("\n--- HeliX Configuration & Management ---")
        print(f"1. WSS Host:         {settings['wss_host']}")
        # MODIFIED: Clarify WSS Port affects both server and client
        print(f"2. WSS Port:         {settings['wss_port']}")
        print(f"3. HTTPS Host:       {settings['https_host']}")
        print(f"4. HTTPS Port:       {settings['https_port']}")
        # Display Debug Modes
        server_debug_status = "ENABLED" if settings['server_debug'] else "DISABLED"
        client_debug_status = "ENABLED" if settings['client_debug'] else "DISABLED"
        print(f"5. Server Debug Log: {server_debug_status}")
        print(f"6. Client Debug Log: {client_debug_status}")
        print("------------------------------------")
        print("7. Manage TLS Certificates (Check/Generate/Install CA)")
        print("8. Start HTTPS/WSS Servers")
        print("9. Exit")
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
                    else:
                        settings['wss_port'] = port_int
                        print("Note: WSS Port change will update server/config.py and client/js/config.js.")
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
            # Toggle Server Debug Mode
            settings['server_debug'] = not settings['server_debug']
            print(f"Server Debug Mode {'ENABLED' if settings['server_debug'] else 'DISABLED'}.")
        elif choice == '6':
            # Toggle Client Debug Mode
            settings['client_debug'] = not settings['client_debug']
            print(f"Client Debug Mode {'ENABLED' if settings['client_debug'] else 'DISABLED'}.")
        elif choice == '7': # Manage Certificates
            if generate_certificates(): print("Certificate process completed successfully.")
            else: print("Certificate process failed or aborted.")
            input("Press Enter to return...")
            continue
        elif choice == '8': # Start Servers (Save Config First)
            if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
                print("\nError: Certificate files missing. Use option 7 first.")
                input("Press Enter to return...")
                continue
            # Attempt to write both server and client configs silently
            print("Saving configuration...") # Indicate saving is happening
            server_saved = write_config(settings)
            client_saved = write_client_config(settings) # Now writes WSS Port too
            if server_saved and client_saved:
                # print("All configurations saved successfully.") # Silent save
                return True # Signal to start servers
            else:
                input("Failed to save one or more configurations. Press Enter to return...")
            continue
        # Removed previous option 7 (Start without saving)
        elif choice == '9': # Exit
            return False # Signal to exit
        else: print("Invalid choice.")

# --- HTTPS Server Implementation ---
class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP handler logging to file via https_logger."""
    def __init__(self, *args, directory=None, **kwargs):
        # Ensure directory is set correctly before calling super().__init__
        if directory is None: directory = os.getcwd()
        # Use functools.partial to pass the directory to the handler
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
    # Use functools.partial to create a handler factory that includes the directory
    Handler = partial(QuietHTTPRequestHandler, directory=client_dir)
    try:
        https_server = ThreadingHTTPServer((host, port), Handler)
        print(f"[HTTPS Setup] Setting up SSL context...")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        https_server.socket = context.wrap_socket(https_server.socket, server_side=True)
        print(f"[HTTPS Setup] SSL context loaded and socket wrapped.")
        # Create the thread targeting the server's serve_forever method
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
    try:
        # Call serve_forever on the passed server instance
        server_instance.serve_forever()
    except Exception as e:
        # Log unexpected errors during the serve_forever loop
        https_logger.exception("Unexpected error in HTTPS serve_forever loop")
    finally:
        # Cleanup: Ensure server is closed and global reference is cleared
        if server_instance:
            try:
                server_instance.server_close()
            except Exception: pass # Ignore errors during close
        print("[HTTPS Thread] Server loop stopped.")
        https_logger.info("HTTPS Server loop stopped.")
        https_server = None # Clear the global reference

# --- WSS Server Logging ---
def log_wss_output(process):
    """Target function for the WSS logging thread."""
    print("[WSS Log Thread] Started.")
    try:
        # Read stdout line by line from the WSS process.
        # iter(process.stdout.readline, '') creates an iterator that stops when readline returns an empty string (EOF).
        for line in iter(process.stdout.readline, ''):
            # Check if the stop event is set (signaling shutdown).
            if stop_event.is_set(): break
            # Print the line received from the WSS server, prefixed.
            print(f"[WSS] {line.strip()}", flush=True) # flush=True ensures immediate output
        # Check if the loop ended because the process terminated unexpectedly.
        if not stop_event.is_set() and process.poll() is not None:
             print("[WSS Log Thread] WSS process stdout EOF or process terminated.", flush=True)
    except Exception as e:
        # Log errors during reading, but only if shutdown wasn't requested.
        if not stop_event.is_set(): print(f"[WSS Log Thread] Error reading WSS output: {e}", flush=True)
    finally: print("[WSS Log Thread] Exiting.", flush=True)

def _start_wss_server_process():
    """Internal helper to start the WSS server process."""
    global wss_process, wss_log_thread
    print("Starting WSS server subprocess...")
    wss_script_path = os.path.join(SCRIPT_DIR, 'server', 'main.py')
    try:
        # Start the server/main.py script using the same Python interpreter.
        wss_process = subprocess.Popen(
            [sys.executable, wss_script_path],
            stdout=subprocess.PIPE, # Capture standard output.
            stderr=subprocess.STDOUT, # Redirect standard error to standard output.
            text=True, # Decode output as text using default encoding.
            encoding='utf-8', # Specify UTF-8 encoding explicitly.
            bufsize=1, # Line-buffered output.
            cwd=SCRIPT_DIR # Set working directory to script's directory.
        )
        print(f"WSS server process started (PID: {wss_process.pid}). Output will follow:")
        # Start a separate thread to read and print the WSS server's output.
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
        settings (dict): The current configuration settings (includes WSS and HTTPS).
    """
    global wss_process, https_thread, wss_log_thread, https_server, stop_event

    # Reset global state before starting
    wss_process, https_thread, wss_log_thread, https_server = None, None, None, None
    stop_event.clear()

    servers_started_ok = False
    print("Starting local servers...")
    # Start the HTTPS server thread first, using settings from the dictionary.
    https_thread = _start_https_server_thread(
        settings['https_host'], settings['https_port'], HTTPS_CLIENT_DIR
    )
    time.sleep(1.0) # Allow HTTPS server time to bind to the port or fail.

    # Check if HTTPS server started successfully.
    if https_thread and https_thread.is_alive():
        # If HTTPS is okay, start the WSS server process.
        # WSS server reads its config (HOST/PORT/DEBUG) from server/config.py directly.
        wss_process = _start_wss_server_process()
        if wss_process:
            servers_started_ok = True # Both servers started successfully.
        else: print("Failed to start WSS server process. Shutting down HTTPS server.")
    else: print("Failed to start HTTPS server thread.")

    # Trigger immediate cleanup if any part of the startup failed.
    if not servers_started_ok:
         stop_event.set() # Signal threads to stop.
         # Call simplified shutdown logic directly.
         _shutdown_servers()
         print("Exiting due to server startup failure.")
         sys.exit(1) # Exit the manager script.

    # --- Manage Running Servers ---
    print("\nServers are running. Press Ctrl+C to stop.")
    try:
        # Main loop to monitor server status while running.
        while not stop_event.is_set():
            # Check if the WSS process has terminated unexpectedly.
            if wss_process and wss_process.poll() is not None:
                print(f"\nError: WSS server process terminated unexpectedly (Exit Code: {wss_process.returncode}).")
                stop_event.set(); break # Signal shutdown and exit loop.
            # Check if the HTTPS thread has terminated unexpectedly.
            if https_thread and not https_thread.is_alive():
                 # Differentiate between thread dying and server failing during startup.
                 if https_server is not None: print("\nError: HTTPS server thread terminated unexpectedly.")
                 else: print("\nError: HTTPS server failed during startup.")
                 stop_event.set(); break # Signal shutdown and exit loop.
            time.sleep(0.5) # Pause briefly to avoid busy-waiting.
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully.
        print("\nShutdown signal (Ctrl+C) received..."); stop_event.set()
    except Exception as e:
        # Handle any other unexpected errors in the monitoring loop.
        print(f"\nUnexpected error in main wait loop: {e}"); stop_event.set()
    finally:
        # --- Graceful Shutdown Sequence ---
        # Ensure shutdown logic runs regardless of how the loop exited.
        _shutdown_servers()

def _shutdown_servers():
    """Internal helper to perform the shutdown sequence."""
    global wss_process, https_thread, wss_log_thread, https_server

    print("Initiating server shutdown...")

    # Shutdown HTTPS Server
    # Check if the server instance exists.
    if https_server: print("Shutting down HTTPS server..."); https_server.shutdown()
    # Check if the thread exists and is alive.
    if https_thread and https_thread.is_alive():
        print("Waiting for HTTPS thread..."); https_thread.join(timeout=5)
        # Check again if the thread terminated gracefully.
        if https_thread.is_alive(): print("Warning: HTTPS thread did not exit gracefully.")
    https_thread = None # Clear the global reference.

    # Shutdown WSS Process
    # Check if the process exists and is still running.
    if wss_process and wss_process.poll() is None:
        print("Terminating WSS server process...")
        try:
            # Attempt graceful termination first.
            wss_process.terminate(); wss_process.wait(timeout=5)
            print("WSS server process terminated.")
        except subprocess.TimeoutExpired:
            # If terminate fails, forcefully kill the process.
            print("WSS process did not terminate gracefully, killing."); wss_process.kill()
            try: wss_process.wait(timeout=2) # Wait briefly after kill.
            except Exception: pass # Ignore errors during wait after kill.
        except Exception as e: print(f"Error terminating WSS process: {e}")
        finally: wss_process = None # Clear the global reference.

    # Shutdown WSS Logging Thread
    # Check if the thread exists and is alive.
    if wss_log_thread and wss_log_thread.is_alive():
        print("Waiting for WSS logging thread..."); wss_log_thread.join(timeout=2)
        # Check again if the thread terminated gracefully.
        if wss_log_thread.is_alive(): print("Warning: WSS logging thread did not exit.")
    wss_log_thread = None # Clear the global reference.

    print("Shutdown complete.")


# --- Main Execution ---
def main():
    """Main function: Check deps, read config, run menu, start/manage servers."""
    print("--- Starting HeliX Manager ---")
    # Call the updated dependency check function.
    check_dependencies()
    current_settings = read_config() # Load current configuration (WSS/ServerDebug from file, HTTPS/ClientDebug defaults/file).
    should_start = config_menu(current_settings) # Display menu and get user choice.

    if should_start:
        # Start servers using the potentially modified settings dictionary.
        start_servers(current_settings) # Enter monitoring loop.
    else:
        print("Exiting HeliX Manager.") # User chose to exit from the menu.

if __name__ == "__main__":
    # Run the main function only when the script is executed directly.
    main()