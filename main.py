import os
import json
import datetime
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk, simpledialog
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import warnings
import sys
import io
import tempfile
import re
import zipfile

# Suppress deprecation warnings because I am too lazy to fix them
warnings.filterwarnings("ignore", category=DeprecationWarning)

CACHE_FILE = 'skin_directory_cache.txt'
CONFIG_DRIVE_ID = '1DA6YNnnlcLL8tiqvvaaJJnDM2sxrxDTx'  # ID of the directory.json in Google Drive

# Default folder aliases to use if config can't be loaded, this will not work, just placeholder
DEFAULT_FOLDER_ALIASES = {
    "Default": "1234"
}

SERVICE_ACCOUNT_INFO = {
    "type": "service_account",
    "project_id": "th-429016",
    "private_key_id": "insert_private_key_id_here",
    "private_key": "insert_private_key_here"
    "client_id": "insert_client_id_here",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "cert_goes_here",
    "universe_domain": "googleapis.com"
}


class RedirectText:
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.buffer = ""

    def write(self, string):
        self.buffer += string
        self.text_widget.configure(state="normal")
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)
        self.text_widget.configure(state="disabled")

    def flush(self):
        pass


class SkinFileInfo:
    def __init__(self, id, name, mime_type, modified_time, path=None, status=None, parent_path=None, is_secured=False,
                 password=None):
        self.id = id
        self.name = name
        self.mime_type = mime_type
        self.modified_time = modified_time
        self.path = path  # Local path, if exists
        self.status = status  # "missing", "outdated", or "current"
        self.parent_path = parent_path  # Parent folder path for organizing files in tree
        self.is_secured = is_secured  # Whether this file requires password
        self.password = password  # Password for secured files
        self.local_name = None  # Local filename with password suffix if secured


class SkinSyncApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IL2 Squadron Livery Manager - Built by Jagged Fel")
        self.root.geometry("900x700")
        self.root.minsize(600, 400)

        # Initialize folder configs
        self.folder_config = {}
        self.secured_folder_config = {}
        self.secured_password_cache = {}  # Cache for entered passwords (memory only)
        self.secured_passwords_from_config = {}  # Individual passwords from config (memory only)

        self.skin_files = []
        self.current_folder_id = None
        self.current_is_secured = False
        self.current_password = None

        # Set up UI
        self.setup_ui()

        # Load cached directory if available (only the IL-2 directory path is cached)
        cached_dir = self.load_cached_directory()

        if cached_dir and os.path.exists(cached_dir):
            self.directory_var.set(cached_dir)
            print(f"Using cached IL-2 skins directory: {cached_dir}")
        else:
            # Start an async search for the skins directory
            # This prevents the UI from freezing on startup
            print("No valid cached directory found. Starting automatic detection...")
            self.directory_var.set("Searching for IL-2 directory...")
            self.root.after(100, self.search_async_for_skins_dir)

        # Load configurations from Google Drive (memory only, no file caching)
        self.load_configurations_from_drive()

    def load_configurations_from_drive(self):
        """Load configurations directly from Google Drive into memory"""
        # Start with default configuration
        self.folder_config = DEFAULT_FOLDER_ALIASES.copy()
        self.secured_folder_config = {}
        self.secured_passwords_from_config = {}

        # Update dropdown with defaults first
        self.update_folder_dropdown()

        # Then try to update from Google Drive in background
        self.status_var.set("Loading configuration from Google Drive...")
        threading.Thread(target=self.update_config_from_drive, daemon=True).start()

    def get_base_skin_name(self, filename):
        """
        Extract the base skin name, handling IL-2 special suffixes like &1#1 and &1
        Example: 'Mosquito_DUX-SQUAD_RABBID_&1#1.dds' -> 'Mosquito_DUX-SQUAD_RABBID'
        """
        # Remove extension first
        name_without_ext = os.path.splitext(filename)[0]

        # Remove password suffix if present (e.g., _1234)
        original_name, _ = self.extract_password_from_filename(filename)
        name_without_ext = os.path.splitext(original_name)[0]

        # Remove IL-2 special suffixes: &1#1, &1, etc.
        if name_without_ext.endswith('_&1#1'):
            return name_without_ext[:-5]  # Remove '_&1#1'
        elif name_without_ext.endswith('_&1'):
            return name_without_ext[:-3]  # Remove '_&1'
        else:
            return name_without_ext

    def get_il2_suffix(self, filename):
        """
        Extract the IL-2 special suffix (&1#1, &1, or empty)
        Example: 'Mosquito_DUX-SQUAD_RABBID_&1#1.dds' -> '_&1#1'
        """
        # Remove extension and password suffix first
        original_name, _ = self.extract_password_from_filename(filename)
        name_without_ext = os.path.splitext(original_name)[0]

        if name_without_ext.endswith('_&1#1'):
            return '_&1#1'
        elif name_without_ext.endswith('_&1'):
            return '_&1'
        else:
            return ''

    def get_local_filename_with_password(self, original_name, password):
        """Generate local filename with password suffix, handling IL-2 special naming"""
        if not password:
            return original_name

        # Get the base name, IL-2 suffix, and extension
        base_name = self.get_base_skin_name(original_name)
        il2_suffix = self.get_il2_suffix(original_name)
        ext = os.path.splitext(original_name)[1]

        # Construct: basename_password_il2suffix.ext
        # Example: Mosquito_DUX-SQUAD_RABBID_1234_&1#1.dds
        return f"{base_name}_{password}{il2_suffix}{ext}"

    def extract_password_from_filename(self, filename):
        """Extract password from filename, handling IL-2 special suffixes"""
        name, ext = os.path.splitext(filename)

        # Handle IL-2 suffixes first
        il2_suffix = ''
        if name.endswith('_&1#1'):
            il2_suffix = '_&1#1'
            name = name[:-5]
        elif name.endswith('_&1'):
            il2_suffix = '_&1'
            name = name[:-3]

        # Check for password pattern
        match = re.search(r'_(\d+)$', name)
        if match:
            password = match.group(1)
            original_base = name[:match.start()]
            original_name = f"{original_base}{il2_suffix}{ext}"
            return original_name, password

        # No password found, return original with IL-2 suffix
        return f"{name}{il2_suffix}{ext}", None

    def extract_and_process_zip(self, zip_path, target_directory, password=None):
        """
        Extract a zip file and apply password suffixes to the extracted files.
        Returns a list of successfully extracted files.
        """
        extracted_files = []

        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Get list of files in the zip
                zip_files = zip_ref.namelist()

                # Filter out directories and hidden files
                skin_files = [f for f in zip_files if f.endswith(('.dds', '.tga', '.png')) and not f.startswith('.')]

                if not skin_files:
                    print(f"No skin files found in {os.path.basename(zip_path)}")
                    return extracted_files

                print(f"Found {len(skin_files)} skin files in {os.path.basename(zip_path)}")

                for file_path in skin_files:
                    try:
                        # Extract the file to a temporary location first
                        file_data = zip_ref.read(file_path)

                        # Get just the filename (remove any directory structure from zip)
                        original_filename = os.path.basename(file_path)

                        # Generate the final filename with password suffix if this is a secured pack
                        if password:
                            final_filename = self.get_local_filename_with_password(original_filename, password)
                        else:
                            final_filename = original_filename

                        # Determine the final file path
                        final_path = os.path.join(target_directory, final_filename)

                        # Ensure the target directory exists
                        os.makedirs(os.path.dirname(final_path), exist_ok=True)

                        # Write the file to the final location
                        with open(final_path, 'wb') as output_file:
                            output_file.write(file_data)

                        print(f"  → Extracted: {original_filename} → {final_filename}")
                        extracted_files.append(final_path)

                    except Exception as e:
                        print(f"  → Failed to extract {file_path}: {e}")

        except zipfile.BadZipFile:
            print(f"Error: {os.path.basename(zip_path)} is not a valid zip file or is corrupted")
        except Exception as e:
            print(f"Error processing zip file {os.path.basename(zip_path)}: {e}")

        return extracted_files

    def get_expected_zip_contents(self, zip_file_info, base_directory):
        """
        Predict what files would be extracted from a zip file.
        Returns a list of (expected_path, original_name) tuples.
        """
        expected_files = []

        # Get the base name without extension
        base_name = os.path.splitext(zip_file_info.name)[0]

        # Common patterns for IL-2 skin zip files
        # Most zip files contain exactly these two variants
        common_patterns = [
            f"{base_name}_&1#1.dds",  # Standard pattern 1
            f"{base_name}_&1.dds",  # Standard pattern 2
        ]

        # Also check for other common extensions in case they exist
        additional_patterns = [
            f"{base_name}.dds",  # Base file without suffix
        ]

        # Add the common patterns first (most likely to exist)
        for pattern in common_patterns + additional_patterns:
            if zip_file_info.is_secured and zip_file_info.password:
                local_filename = self.get_local_filename_with_password(pattern, zip_file_info.password)
            else:
                local_filename = pattern

            if zip_file_info.parent_path:
                expected_path = os.path.join(base_directory, zip_file_info.parent_path, local_filename)
            else:
                expected_path = os.path.join(base_directory, local_filename)

            expected_files.append((expected_path, pattern))

        return expected_files

    def get_skin_pack_type(self, alias):
        """Determine if a skin pack is secured and get password if needed"""
        if alias in self.secured_folder_config:
            # Check if we already have the password cached
            if alias in self.secured_password_cache:
                return True, self.secured_password_cache[alias]

            return True, None

        return False, None

    def setup_ui(self):
        # I used Claud AI for this, I hate setting up GUIs
        main_frame = tk.Frame(self.root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Directory selection
        dir_frame = tk.Frame(main_frame)
        dir_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(dir_frame, text="IL2 Skins Directory:").pack(side=tk.LEFT, padx=(0, 5))

        self.directory_var = tk.StringVar()
        tk.Entry(dir_frame, textvariable=self.directory_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True,
                                                                            padx=(0, 5))

        browse_button = tk.Button(dir_frame, text="Browse...", command=self.browse_directory)
        browse_button.pack(side=tk.LEFT, padx=(0, 5))

        auto_detect_button = tk.Button(dir_frame, text="Auto-Detect", command=self.search_async_for_skins_dir)
        auto_detect_button.pack(side=tk.LEFT)

        # Example directory label
        example_frame = tk.Frame(main_frame)
        example_frame.pack(fill=tk.X, pady=(0, 10))
        example_label = tk.Label(example_frame,
                                 text="Example: C:\\SteamLibrary\\steamapps\\common\\IL-2 Sturmovik Battle of Stalingrad\\data\\graphics\\skins",
                                 fg="gray", anchor="w")
        example_label.pack(fill=tk.X, padx=5)

        # Create colored tab headers using Frame with Label
        tabs_container = tk.Frame(main_frame)
        tabs_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Tab headers frame
        self.headers_frame = tk.Frame(tabs_container)
        self.headers_frame.pack(fill=tk.X)

        # Create tab headers
        self.quick_sync_header = tk.Label(
            self.headers_frame,
            text="Quick Sync",
            bg="#4CAF50",  # Green
            fg="white",
            font=("Arial", 10, "bold"),
            padx=15,
            pady=5,
            relief=tk.RAISED,
            borderwidth=2
        )
        self.quick_sync_header.pack(side=tk.LEFT)
        self.quick_sync_header.bind("<Button-1>", lambda e: self.switch_tab(0))

        self.detailed_header = tk.Label(
            self.headers_frame,
            text="Detailed Skin Manager",
            bg="#2196F3",  # Blue
            fg="white",
            font=("Arial", 10),
            padx=15,
            pady=5,
            relief=tk.FLAT,
            borderwidth=2
        )
        self.detailed_header.pack(side=tk.LEFT, padx=(1, 0))
        self.detailed_header.bind("<Button-1>", lambda e: self.switch_tab(1))

        # Create frame for tab content with a neutral background
        self.tab_content = tk.Frame(tabs_container, borderwidth=2, relief=tk.RIDGE)
        self.tab_content.pack(fill=tk.BOTH, expand=True)

        # Create the tabs' content frames - using the system default background color
        self.sync_tab = tk.Frame(self.tab_content)  # No background color specified - uses system default
        self.advanced_tab = tk.Frame(self.tab_content)  # No background color specified - uses system default

        # Initially show the quick sync tab
        self.sync_tab.pack(fill=tk.BOTH, expand=True)
        self.current_tab = 0

        # Set up the Quick Sync tab
        self.setup_quick_sync_tab()

        # Set up the Detailed Skin Manager tab
        self.setup_detailed_tab()

        # Progress bar
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, mode="indeterminate")
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Flag to control sync operation
        self.sync_running = False

    def switch_tab(self, tab_index):
        """Switch between tabs with index 0 (Quick Sync) or 1 (Detailed)"""
        if tab_index == self.current_tab:
            return

        # Update tab header styles
        if tab_index == 0:
            self.quick_sync_header.config(relief=tk.RAISED, font=("Arial", 10, "bold"))
            self.detailed_header.config(relief=tk.FLAT, font=("Arial", 10))
            self.sync_tab.pack(fill=tk.BOTH, expand=True)
            self.advanced_tab.pack_forget()
        else:
            self.quick_sync_header.config(relief=tk.FLAT, font=("Arial", 10))
            self.detailed_header.config(relief=tk.RAISED, font=("Arial", 10, "bold"))
            self.advanced_tab.pack(fill=tk.BOTH, expand=True)
            self.sync_tab.pack_forget()

            # Ensure the detailed dropdown is properly synchronized with the main dropdown
            self.synchronize_detailed_dropdown()

        self.current_tab = tab_index

    def synchronize_detailed_dropdown(self):
        """Synchronize the detailed dropdown with the main folder dropdown"""
        if hasattr(self, 'folder_dropdown'):
            main_values = self.folder_dropdown['values']
            if main_values:
                self.detailed_dropdown['values'] = main_values
                # If nothing is selected or current selection is invalid, select the first item
                current_selection = self.detailed_alias.get()
                if not current_selection or current_selection not in main_values:
                    self.detailed_alias.set(main_values[0])
                print(f"Synchronized detailed dropdown with values: {main_values}")
                print(f"Current selection: {self.detailed_alias.get()}")

    def auto_detect_skins_directory(self):
        """
        Automatically detect the IL-2 skins directory by searching common installation paths
        across all available drives.

        Returns:
            str: The path to the skins directory if found, None otherwise
        """
        self.status_var.set("Searching for IL-2 skins directory...")
        print("Searching for IL-2 skins directory...")

        # Start progress bar
        self.progress_bar.start(10)

        # Common path patterns to check
        path_patterns = [
            # Steam installation patterns
            r"{drive}:\SteamLibrary\steamapps\common\IL-2 Sturmovik Battle of Stalingrad\data\graphics\skins",
            r"{drive}:\Steam\steamapps\common\IL-2 Sturmovik Battle of Stalingrad\data\graphics\skins",
            r"{drive}:\Program Files\Steam\steamapps\common\IL-2 Sturmovik Battle of Stalingrad\data\graphics\skins",
            r"{drive}:\Program Files (x86)\Steam\steamapps\common\IL-2 Sturmovik Battle of Stalingrad\data\graphics\skins",

            # Standalone installation patterns
            r"{drive}:\IL-2 Sturmovik Great Battles\data\graphics\skins",
            r"{drive}:\Program Files\IL-2 Sturmovik Great Battles\data\graphics\skins",
            r"{drive}:\Program Files (x86)\IL-2 Sturmovik Great Battles\data\graphics\skins",

            # Additional possible paths
            r"{drive}:\Games\IL-2 Sturmovik Great Battles\data\graphics\skins",
            r"{drive}:\Games\SteamLibrary\steamapps\common\IL-2 Sturmovik Battle of Stalingrad\data\graphics\skins"
        ]

        # Get all available drives
        available_drives = []

        if os.name == 'nt':  # Windows
            import string
            import ctypes

            # Get bitmask of available drives
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    available_drives.append(letter)
                bitmask >>= 1
        else:  # Non-Windows systems, just check common locations
            available_drives = ['C']  # Default to C: for testing

        print(f"Checking drives: {', '.join(available_drives)}")

        # Search for the skins directory
        found_path = None

        for drive in available_drives:
            for pattern in path_patterns:
                path = pattern.format(drive=drive)
                self.status_var.set(f"Checking: {path}")
                self.root.update_idletasks()  # Update the UI

                if os.path.exists(path) and os.path.isdir(path):
                    print(f"Found IL-2 skins directory at: {path}")
                    found_path = path
                    break

            if found_path:
                break

        # Stop progress bar
        self.progress_bar.stop()

        if found_path:
            self.status_var.set(f"Found IL-2 skins directory at {found_path}")
            # Verify that this is a skins directory by checking for certain folders
            # typically found in the IL-2 skins directory
            typical_skin_folders = ["Bf-109", "FW-190", "P-51", "Spitfire", "IL-2"]
            found_typical_folders = False

            for folder in typical_skin_folders:
                if os.path.exists(os.path.join(found_path, folder)):
                    found_typical_folders = True
                    break

            if not found_typical_folders:
                print(
                    "Warning: Found a directory that matches the expected path, but it may not be the correct skins directory.")
                print("Please verify that this is the correct directory.")

            return found_path
        else:
            print("IL-2 skins directory not found.")
            self.status_var.set("IL-2 skins directory not found.")
            return None

    def search_async_for_skins_dir(self):
        """
        Start an asynchronous search for the IL-2 skins directory.
        This prevents the UI from freezing during the search.
        """
        threading.Thread(target=self._async_search_task, daemon=True).start()

    def _async_search_task(self):
        """
        Background task to search for skins directory.
        """
        detected_dir = self.auto_detect_skins_directory()
        if detected_dir:
            self.root.after(0, lambda: self.directory_var.set(detected_dir))
            # Save the detected directory for future use
            self.save_directory_to_cache(detected_dir)

            # Show a notification to the user
            self.root.after(0, lambda: messagebox.showinfo(
                "Directory Found",
                f"IL-2 skins directory automatically detected at:\n{detected_dir}"
            ))
        else:
            self.root.after(0, lambda: messagebox.showinfo(
                "Directory Not Found",
                "Could not automatically detect IL-2 skins directory.\n"
                "Please use the Browse button to select it manually."
            ))

    def setup_quick_sync_tab(self):
        # Folder selection frame
        folder_frame = tk.LabelFrame(self.sync_tab, text="Select Squadron Pack to Sync")
        folder_frame.pack(fill=tk.X, pady=(0, 10))

        # Dropdown for folder selection
        self.selected_alias = tk.StringVar()
        self.folder_dropdown = ttk.Combobox(folder_frame, textvariable=self.selected_alias, state="readonly", width=40)
        self.folder_dropdown.pack(padx=5, pady=10, fill=tk.X)
        self.folder_dropdown.set("Loading folder list...")

        # Refresh button
        refresh_button = tk.Button(folder_frame, text="Refresh Folder List", command=self.refresh_folder_config)
        refresh_button.pack(padx=5, pady=(0, 10))

        # Save directory checkbox
        save_frame = tk.Frame(self.sync_tab)
        save_frame.pack(fill=tk.X, pady=(0, 10))

        self.save_var = tk.BooleanVar(value=True)
        tk.Checkbutton(save_frame, text="Save this directory for future use", variable=self.save_var).pack(anchor=tk.W)
        btn_frame = tk.Frame(self.sync_tab)
        btn_frame.pack(fill=tk.X, pady=(0, 10))

        self.sync_button = tk.Button(btn_frame, text="Start Synchronization", command=self.start_sync)
        self.sync_button.pack(side=tk.LEFT, padx=(0, 5))

        self.stop_button = tk.Button(btn_frame, text="Stop", command=self.stop_sync, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=(0, 5))

        # Console output
        output_frame = tk.LabelFrame(self.sync_tab, text="Console Output")
        output_frame.pack(fill=tk.BOTH, expand=True)

        self.console = scrolledtext.ScrolledText(output_frame, state="disabled", wrap=tk.WORD)
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Redirect stdout to the console
        self.text_redirect = RedirectText(self.console)
        sys.stdout = self.text_redirect

    def setup_detailed_tab(self):
        # Top frame for squadron selection
        top_frame = tk.Frame(self.advanced_tab)
        top_frame.pack(fill=tk.X, pady=(0, 10))

        # Dropdown for folder selection (reuse the same variable as in quick sync)
        tk.Label(top_frame, text="Select Squadron Pack:").pack(side=tk.LEFT, padx=(0, 5))
        self.detailed_alias = tk.StringVar()
        self.detailed_dropdown = ttk.Combobox(top_frame, textvariable=self.detailed_alias, state="readonly", width=40)
        self.detailed_dropdown.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.detailed_dropdown.set("Loading folder list...")

        # Bind the dropdown selection to an action
        self.detailed_dropdown.bind("<<ComboboxSelected>>", self.on_detailed_folder_selected)

        # Load button - make it green to stand out
        self.load_skins_button = tk.Button(
            top_frame,
            text="Load Skin List",
            command=self.load_skin_list,
            bg="#4CAF50",  # Green background
            fg="white",  # White text
            font=("Arial", 9, "bold"),  # Bold font
            relief=tk.RAISED,  # Give it a raised appearance
            padx=10  # Add some padding
        )
        self.load_skins_button.pack(side=tk.LEFT, padx=(0, 5))

        # Main content - split into two frames
        content_frame = tk.Frame(self.advanced_tab)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Left frame for tree view
        left_frame = tk.Frame(content_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        # Create a tree view for skin files with added date columns
        self.skin_tree = ttk.Treeview(left_frame,
                                      columns=("Status", "Cloud Modified", "Local Modified"),
                                      selectmode="extended")
        self.skin_tree.heading("#0", text="Skin Files")
        self.skin_tree.heading("Status", text="Status")
        self.skin_tree.heading("Cloud Modified", text="Cloud Modified")
        self.skin_tree.heading("Local Modified", text="Local Modified")

        # Set column widths
        self.skin_tree.column("#0", width=250)
        self.skin_tree.column("Status", width=80)
        self.skin_tree.column("Cloud Modified", width=150)
        self.skin_tree.column("Local Modified", width=150)

        # Add scrollbars
        tree_scroll_y = ttk.Scrollbar(left_frame, orient="vertical", command=self.skin_tree.yview)
        tree_scroll_x = ttk.Scrollbar(left_frame, orient="horizontal", command=self.skin_tree.xview)
        self.skin_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        # Layout the tree and scrollbars
        self.skin_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        # Right frame for buttons and details
        right_frame = tk.Frame(content_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))

        # Action buttons for selected items
        self.download_selected_button = tk.Button(right_frame, text="Download Selected",
                                                  command=self.download_selected_skins)
        self.download_selected_button.pack(fill=tk.X, pady=(0, 5))

        self.update_selected_button = tk.Button(right_frame, text="Update Selected",
                                                command=self.update_selected_skins)
        self.update_selected_button.pack(fill=tk.X, pady=(0, 5))

        self.delete_selected_button = tk.Button(right_frame, text="Delete Selected Local Files",
                                                command=self.delete_selected_local_skins)
        self.delete_selected_button.pack(fill=tk.X, pady=(0, 5))

        # Action buttons for all items
        tk.Label(right_frame, text="").pack(pady=10)  # Spacer

        self.download_all_button = tk.Button(right_frame, text="Download All Missing",
                                             command=self.download_all_missing_skins)
        self.download_all_button.pack(fill=tk.X, pady=(0, 5))

        self.update_all_button = tk.Button(right_frame, text="Update All Outdated",
                                           command=self.update_all_outdated_skins)
        self.update_all_button.pack(fill=tk.X, pady=(0, 5))

        # Cleanup button for secured skins
        tk.Label(right_frame, text="").pack(pady=5)  # Spacer
        self.cleanup_button = tk.Button(right_frame, text="Cleanup Old Secured Files",
                                        command=self.cleanup_old_secured_files,
                                        bg="#FF5722",  # Red/orange background
                                        fg="white",
                                        font=("Arial", 9, "bold"))
        self.cleanup_button.pack(fill=tk.X, pady=(0, 5))

        # Password sync button for secured skins
        self.password_sync_button = tk.Button(right_frame, text="Update Password Suffixes",
                                              command=self.update_password_suffixes,
                                              bg="#FF5722",
                                              fg="white",
                                              font=("Arial", 9, "bold"))
        self.password_sync_button.pack(fill=tk.X, pady=(0, 5))

        # Disable buttons initially
        self.disable_skin_action_buttons()

    def disable_skin_action_buttons(self):
        """Disable all skin action buttons until skins are loaded"""
        self.download_selected_button.config(state="disabled")
        self.update_selected_button.config(state="disabled")
        self.delete_selected_button.config(state="disabled")
        self.download_all_button.config(state="disabled")
        self.update_all_button.config(state="disabled")
        self.cleanup_button.config(state="disabled")
        if hasattr(self, 'password_sync_button'):
            self.password_sync_button.config(state="disabled")

    def enable_skin_action_buttons(self):
        """Enable skin action buttons once skins are loaded"""
        self.download_selected_button.config(state="normal")
        self.update_selected_button.config(state="normal")
        self.delete_selected_button.config(state="normal")
        self.download_all_button.config(state="normal")
        self.update_all_button.config(state="normal")
        self.cleanup_button.config(state="normal")
        if hasattr(self, 'password_sync_button'):
            self.password_sync_button.config(state="normal")

    def on_detailed_folder_selected(self, event):
        """Handle selection change in the detailed tab folder dropdown"""
        # When the user selects a folder in the detailed view, don't automatically load
        # skins yet - they need to click the Load Skin List button
        pass

    def prompt_for_password_with_retry(self, alias, max_attempts=3):
        """Prompt user for password with retry attempts for secured skin pack"""
        for attempt in range(max_attempts):
            password = simpledialog.askstring(
                "Password Required" + (f" (Attempt {attempt + 1}/{max_attempts})" if attempt > 0 else ""),
                f"Enter password for secured skin pack '{alias}':" +
                ("\n(Previous password was incorrect)" if attempt > 0 else ""),
                show='*'
            )

            # If user cancels, return None
            if password is None:
                return None

            # If user enters empty password, continue to next attempt
            if not password.strip():
                if attempt < max_attempts - 1:
                    messagebox.showwarning("Invalid Password", "Password cannot be empty. Please try again.")
                    continue
                else:
                    return None

            # Try to validate the password
            try:
                service = self.initialize_drive_api()
                if self.validate_password_for_secured_pack(service, self.secured_folder_config[alias], password, alias):
                    return password
                else:
                    # Invalid password
                    if attempt < max_attempts - 1:
                        messagebox.showerror("Invalid Password",
                                             f"The password for '{alias}' is incorrect.\n"
                                             f"Please try again. ({max_attempts - attempt - 1} attempts remaining)")
                    else:
                        messagebox.showerror("Invalid Password",
                                             f"The password for '{alias}' is incorrect.\n"
                                             f"Maximum attempts reached.")
                        return None
            except Exception as e:
                print(f"Error validating password: {e}")
                if attempt < max_attempts - 1:
                    messagebox.showerror("Validation Error",
                                         f"Error validating password: {e}\n"
                                         f"Please try again. ({max_attempts - attempt - 1} attempts remaining)")
                else:
                    messagebox.showerror("Validation Error",
                                         f"Error validating password: {e}\n"
                                         f"Maximum attempts reached.")
                    return None

        return None

    def validate_password_for_secured_pack(self, service, folder_id, password, alias):
        """
        Validate password by checking if it matches the password from the secured configuration.
        """
        try:
            # Compare with the individual password for this specific alias
            if alias in self.secured_passwords_from_config:
                stored_password = self.secured_passwords_from_config[alias]
                if password == stored_password:
                    print(f"Password validated successfully for {alias}")
                    return True
                else:
                    print(f"Password mismatch for {alias}: entered password does not match the configured password")
                    return False
            else:
                print(f"No configured password found for {alias}")
                return False

        except Exception as e:
            print(f"Error validating password for {alias}: {e}")
            return False

    def load_skin_list(self):
        """Load the skin list for the selected folder in the detailed tab"""
        selected_alias = self.detailed_alias.get()

        # Check if it's a secured pack first
        is_secured, password = self.get_skin_pack_type(selected_alias)

        if is_secured:
            # If password is not in config, prompt for it with retry
            if not password:
                password = self.prompt_for_password_with_retry(selected_alias)
                if not password:
                    messagebox.showwarning("Password Required", "Password is required for secured skin packs")
                    return
                # Cache the password
                self.secured_password_cache[selected_alias] = password

            folder_id = self.secured_folder_config[selected_alias]
        else:
            if selected_alias not in self.folder_config:
                messagebox.showerror("Error", "Please select a valid skin pack")
                return
            folder_id = self.folder_config[selected_alias]
            password = None

        directory = self.directory_var.get().strip()
        if not directory:
            messagebox.showerror("Error", "Please select a directory")
            return

        # Store current state
        self.current_folder_id = folder_id
        self.current_is_secured = is_secured
        self.current_password = password

        # Clear the tree view
        for item in self.skin_tree.get_children():
            self.skin_tree.delete(item)

        # Update status and disable buttons during loading
        self.status_var.set(f"Loading skin list for {selected_alias}...")
        self.disable_skin_action_buttons()
        self.load_skins_button.config(state="disabled")
        self.progress_bar.start(10)

        # Run in a separate thread to avoid freezing the UI
        threading.Thread(target=self.run_load_skin_list,
                         args=(directory, selected_alias, folder_id, is_secured, password),
                         daemon=True).start()

    def run_load_skin_list(self, directory, alias, folder_id, is_secured, password):
        """Thread function to load and compare skin files"""
        try:
            print(f"Loading skin list for {alias}...")
            if is_secured:
                print(f"  → This is a secured skin pack requiring password")

                # Password was already validated in load_skin_list, so we can proceed
                service = self.initialize_drive_api()
                print(f"  → Using validated password")
            else:
                service = self.initialize_drive_api()

            # Get the list of files from Google Drive
            drive_files = self.list_all_drive_files(service, folder_id, is_secured=is_secured, password=password)

            # Compare with local files
            self.skin_files = self.compare_with_local_files(drive_files, directory)

            # Update the tree view in the main thread
            self.root.after(0, self.update_skin_tree_view)

            self.root.after(0, lambda: self.status_var.set(f"Loaded {len(self.skin_files)} skin files"))
            self.root.after(0, self.enable_skin_action_buttons)
            self.root.after(0, lambda: self.load_skins_button.config(state="normal"))

        except Exception as e:
            print(f"An error occurred while loading skin list: {e}")
            # Fix lambda variable capture
            error_msg = str(e)
            self.root.after(0, lambda: self.status_var.set("Error loading skin list"))
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"An error occurred: {msg}"))
            self.root.after(0, lambda: self.load_skins_button.config(state="normal"))

        finally:
            self.root.after(0, self.progress_bar.stop)

    def list_all_drive_files(self, service, folder_id, parent_path="", is_secured=False, password=None):
        """Recursively list all files in a Google Drive folder"""
        result = []
        page_token = None

        while True:
            response = service.files().list(
                q=f"'{folder_id}' in parents and trashed=false",
                pageSize=1000,
                fields="nextPageToken, files(id, name, mimeType, modifiedTime)",
                pageToken=page_token
            ).execute()

            items = response.get('files', [])

            for item in items:
                file_id = item['id']
                file_name = item['name']
                mime_type = item.get('mimeType', '')
                modified_time = datetime.datetime.strptime(item['modifiedTime'], "%Y-%m-%dT%H:%M:%S.%fZ")

                # Create the current path
                current_path = os.path.join(parent_path, file_name) if parent_path else file_name

                if mime_type == 'application/vnd.google-apps.folder':
                    # Recursively get files from subfolder
                    subfolder_files = self.list_all_drive_files(service, file_id, current_path, is_secured, password)
                    result.extend(subfolder_files)
                else:
                    # Add file to the result with security info
                    file_info = SkinFileInfo(
                        id=file_id,
                        name=file_name,
                        mime_type=mime_type,
                        modified_time=modified_time,
                        parent_path=parent_path,
                        is_secured=is_secured,
                        password=password
                    )
                    result.append(file_info)

            page_token = response.get('nextPageToken', None)
            if not page_token:
                break

        return result

    def compare_with_local_files(self, drive_files, base_directory):
        """Compare Google Drive files with local files and determine status"""
        for file_info in drive_files:
            # Always set the cloud_modified_str first, regardless of file type
            file_info.cloud_modified_str = file_info.modified_time.strftime("%Y-%m-%d %H:%M:%S")

            # Check if this is a zip file
            is_zip_file = file_info.name.lower().endswith('.zip')

            if is_zip_file:
                # For zip files, we need to check the extracted contents
                if file_info.is_secured and file_info.password:
                    # For secured zip files, check if extracted files exist with correct password
                    expected_files = self.get_expected_zip_contents(file_info, base_directory)
                    file_info.extracted_files = expected_files

                    # Set the path for the zip file itself (though we don't use it for extraction)
                    if file_info.parent_path:
                        file_info.path = os.path.join(base_directory, file_info.parent_path, file_info.name)
                    else:
                        file_info.path = os.path.join(base_directory, file_info.name)

                    # Check if all expected files exist locally
                    all_exist = True
                    any_outdated = False
                    most_recent_local_time = None

                    for expected_path, original_name in expected_files:
                        if not os.path.exists(expected_path):
                            all_exist = False
                            break
                        else:
                            # Check if the extracted file is up to date
                            local_modified_time = datetime.datetime.utcfromtimestamp(os.path.getmtime(expected_path))

                            # Keep track of the most recent local file time
                            if most_recent_local_time is None or local_modified_time > most_recent_local_time:
                                most_recent_local_time = local_modified_time

                            drive_time = file_info.modified_time.replace(tzinfo=None)

                            if local_modified_time < drive_time:
                                any_outdated = True

                    if not all_exist:
                        file_info.status = "missing"
                        file_info.local_modified_str = "N/A"
                    elif any_outdated:
                        file_info.status = "outdated"
                        file_info.local_modified_str = "Outdated"
                    else:
                        file_info.status = "current"
                        if most_recent_local_time:
                            file_info.local_modified_str = most_recent_local_time.strftime("%Y-%m-%d %H:%M:%S")
                        else:
                            file_info.local_modified_str = "Current"
                else:
                    # For non-secured zip files, just check if the zip exists
                    if file_info.parent_path:
                        local_path = os.path.join(base_directory, file_info.parent_path, file_info.name)
                    else:
                        local_path = os.path.join(base_directory, file_info.name)
                    file_info.path = local_path

                    if not os.path.exists(local_path):
                        file_info.status = "missing"
                        file_info.local_modified_str = "N/A"
                    else:
                        local_modified_time = datetime.datetime.utcfromtimestamp(os.path.getmtime(local_path))
                        file_info.local_modified_str = local_modified_time.strftime("%Y-%m-%d %H:%M:%S")
                        drive_time = file_info.modified_time.replace(tzinfo=None)

                        if local_modified_time < drive_time:
                            file_info.status = "outdated"
                        else:
                            file_info.status = "current"
            else:
                # Handle regular files (existing logic)
                if file_info.is_secured and file_info.password:
                    local_filename = self.get_local_filename_with_password(file_info.name, file_info.password)
                    file_info.local_name = local_filename
                else:
                    local_filename = file_info.name
                    file_info.local_name = local_filename

                # Construct the expected local path
                if file_info.parent_path:
                    local_path = os.path.join(base_directory, file_info.parent_path, local_filename)
                else:
                    local_path = os.path.join(base_directory, local_filename)

                file_info.path = local_path

                # Check if file exists locally
                if not os.path.exists(local_path):
                    # For secured files, also check if there's an old version with different password
                    old_file_found = False
                    if file_info.is_secured:
                        # Look for files matching the pattern without the current password
                        dir_path = os.path.dirname(local_path)
                        if os.path.exists(dir_path):
                            base_name = self.get_base_skin_name(file_info.name)
                            ext = os.path.splitext(file_info.name)[1]
                            il2_suffix = self.get_il2_suffix(file_info.name)

                            import glob
                            pattern = f"{base_name}*{ext}"
                            matching_files = glob.glob(os.path.join(dir_path, pattern))

                            for match in matching_files:
                                match_filename = os.path.basename(match)
                                original_name, old_password = self.extract_password_from_filename(match_filename)
                                match_base = self.get_base_skin_name(original_name)
                                match_il2_suffix = self.get_il2_suffix(original_name)

                                if (match_base == base_name and match_il2_suffix == il2_suffix and
                                        old_password != file_info.password):
                                    # Found an old version with different password
                                    print(
                                        f"  → Found old version of {file_info.name} with different password, will update")
                                    file_info.status = "outdated"
                                    file_info.local_modified_str = "Old Password"
                                    old_file_found = True
                                    break

                    if not old_file_found:
                        file_info.status = "missing"
                        file_info.local_modified_str = "N/A"
                else:
                    # Get and format local modified time
                    local_modified_time = datetime.datetime.utcfromtimestamp(os.path.getmtime(local_path))
                    file_info.local_modified_str = local_modified_time.strftime("%Y-%m-%d %H:%M:%S")

                    # Make cloud timestamp timezone-naive for comparison
                    drive_time = file_info.modified_time.replace(tzinfo=None)

                    # Compare times to determine status
                    if local_modified_time < drive_time:
                        file_info.status = "outdated"
                    else:
                        file_info.status = "current"

        return drive_files

    def update_skin_tree_view(self):
        """Update the tree view with skin files"""
        # Clear tree
        for item in self.skin_tree.get_children():
            self.skin_tree.delete(item)

        # Dictionary to store folder IDs by path
        folders = {}

        # Create root entry if needed
        root_id = "root"
        folders[""] = root_id

        # First pass: create folders
        for file in self.skin_files:
            if file.parent_path and file.parent_path not in folders:
                # Create parent folders if they don't exist
                parts = file.parent_path.split(os.sep)
                current_path = ""

                for i, part in enumerate(parts):
                    if i == 0:
                        parent_id = root_id
                        current_path = part
                    else:
                        parent_id = folders[current_path]
                        current_path = os.path.join(current_path, part)

                    if current_path not in folders:
                        # Create this folder in the tree
                        folder_id = self.skin_tree.insert(
                            parent_id if i > 0 else "",
                            "end",
                            text=part,
                            values=("", "", ""),  # Empty values for status and dates
                            open=True
                        )
                        folders[current_path] = folder_id

        # Second pass: add files to their respective folders
        for file in self.skin_files:
            # Determine the parent ID for this file
            parent_id = folders[file.parent_path] if file.parent_path else root_id

            # Set tag and text based on status
            tag = file.status
            status_text = file.status.capitalize()

            # Show original name (no lock indicator needed in file view)
            display_name = file.name

            # Handle zip files display
            if file.name.lower().endswith('.zip'):
                if file.is_secured:
                    display_name += " (Secured Zip)"
                else:
                    display_name += " (Zip Archive)"

            # Ensure all required attributes exist before accessing them
            cloud_modified = getattr(file, 'cloud_modified_str', 'N/A')
            local_modified = getattr(file, 'local_modified_str', 'N/A')

            # Add the file to the tree with date information
            self.skin_tree.insert(
                parent_id,
                "end",
                text=display_name,
                values=(
                    status_text,
                    cloud_modified,
                    local_modified
                ),
                tags=(tag,)
            )

        # Configure tags with colors
        self.skin_tree.tag_configure("missing", foreground="red")
        self.skin_tree.tag_configure("outdated", foreground="orange")
        self.skin_tree.tag_configure("current", foreground="green")

    def get_files_from_selection(self, selected_items, status_filter=None):
        """Get file objects from tree view selection with optional status filtering"""
        result = []

        for item_id in selected_items:
            item_text = self.skin_tree.item(item_id, "text")
            item_values = self.skin_tree.item(item_id, "values")

            # Skip folders (no status value)
            if not item_values or not item_values[0]:
                continue

            # Get full path for this item
            path = self.get_full_path_for_tree_item(item_id)

            # Find matching file in our list
            for file in self.skin_files:
                file_path = os.path.join(file.parent_path, file.name) if file.parent_path else file.name
                if file_path == path:
                    # Apply status filter if provided
                    if status_filter:
                        if isinstance(status_filter, list):
                            if file.status not in status_filter:
                                continue
                        elif file.status != status_filter:
                            continue

                    result.append(file)
                    break

        return result

    def get_full_path_for_tree_item(self, item_id):
        """Get the full path for a tree item"""
        path_parts = []

        # Add the current item text
        item_text = self.skin_tree.item(item_id, "text")
        # Remove zip file indicators for path matching
        if item_text.endswith(" (Secured Zip)"):
            item_text = item_text[:-14]
        elif item_text.endswith(" (Zip Archive)"):
            item_text = item_text[:-13]
        path_parts.append(item_text)

        # Traverse up the tree to get parent names
        parent_id = self.skin_tree.parent(item_id)
        while parent_id:
            # Skip the root
            if parent_id == "root":
                break

            path_parts.append(self.skin_tree.item(parent_id, "text"))
            parent_id = self.skin_tree.parent(parent_id)

        # Reverse and join
        path_parts.reverse()
        return os.path.join(*path_parts) if len(path_parts) > 1 else path_parts[0]

    def download_selected_skins(self):
        """Download selected skins from the tree view"""
        selected_items = self.skin_tree.selection()
        if not selected_items:
            messagebox.showinfo("Info", "No skins selected")
            return

        # Get the full paths of selected items
        items_to_download = self.get_files_from_selection(selected_items)
        if not items_to_download:
            messagebox.showinfo("Info", "No files to download in the selection")
            return

        # Confirm with user
        if not messagebox.askyesno("Confirm Download",
                                   f"Download {len(items_to_download)} selected skin files?"):
            return

        # Start download process
        self.status_var.set(f"Downloading {len(items_to_download)} selected skins...")
        self.progress_bar.start(10)
        self.disable_skin_action_buttons()

        threading.Thread(target=self.run_download_files,
                         args=(items_to_download,),
                         daemon=True).start()

    def update_selected_skins(self):
        """Update selected outdated skins from the tree view"""
        selected_items = self.skin_tree.selection()
        if not selected_items:
            messagebox.showinfo("Info", "No skins selected")
            return

        # Get the full paths of selected items that are outdated
        items_to_update = self.get_files_from_selection(selected_items, status_filter="outdated")
        if not items_to_update:
            messagebox.showinfo("Info", "No outdated files in the selection")
            return

        # Confirm with user
        if not messagebox.askyesno("Confirm Update",
                                   f"Update {len(items_to_update)} outdated skin files?"):
            return

        # Start update process
        self.status_var.set(f"Updating {len(items_to_update)} selected skins...")
        self.progress_bar.start(10)
        self.disable_skin_action_buttons()

        threading.Thread(target=self.run_download_files,
                         args=(items_to_update,),
                         daemon=True).start()

    def delete_selected_local_skins(self):
        """Delete selected skins from local directory"""
        selected_items = self.skin_tree.selection()
        if not selected_items:
            messagebox.showinfo("Info", "No skins selected")
            return

        # Get the full paths of selected items that exist locally
        items_to_delete = self.get_files_from_selection(selected_items,
                                                        status_filter=["current", "outdated"])
        if not items_to_delete:
            messagebox.showinfo("Info", "No local files in the selection")
            return

        # Confirm with user - this is destructive so double-check
        if not messagebox.askyesno("Confirm Deletion",
                                   f"Delete {len(items_to_delete)} local skin files?\n\nThis cannot be undone!",
                                   icon="warning"):
            return

        # Start deletion process
        self.status_var.set(f"Deleting {len(items_to_delete)} local skins...")
        self.progress_bar.start(10)
        self.disable_skin_action_buttons()

        threading.Thread(target=self.run_delete_files,
                         args=(items_to_delete,),
                         daemon=True).start()

    def download_all_missing_skins(self):
        """Download all missing skins"""
        items_to_download = [f for f in self.skin_files if f.status == "missing"]
        if not items_to_download:
            messagebox.showinfo("Info", "No missing skins to download")
            return

        # Confirm with user
        if not messagebox.askyesno("Confirm Download",
                                   f"Download all {len(items_to_download)} missing skin files?"):
            return

        # Start download process
        self.status_var.set(f"Downloading {len(items_to_download)} missing skins...")
        self.progress_bar.start(10)
        self.disable_skin_action_buttons()

        threading.Thread(target=self.run_download_files,
                         args=(items_to_download,),
                         daemon=True).start()

    def update_all_outdated_skins(self):
        """Update all outdated skins"""
        items_to_update = [f for f in self.skin_files if f.status == "outdated"]
        if not items_to_update:
            messagebox.showinfo("Info", "No outdated skins to update")
            return

        # Confirm with user
        if not messagebox.askyesno("Confirm Update",
                                   f"Update all {len(items_to_update)} outdated skin files?"):
            return

        # Start update process
        self.status_var.set(f"Updating {len(items_to_update)} outdated skins...")
        self.progress_bar.start(10)
        self.disable_skin_action_buttons()

        threading.Thread(target=self.run_download_files,
                         args=(items_to_update,),
                         daemon=True).start()

    def cleanup_old_secured_files(self):
        """Find and delete old secured files with wrong passwords or missing password suffixes"""
        if not self.current_is_secured:
            messagebox.showinfo("Info", "Current pack is not secured. This cleanup is only for secured packs.")
            return

        directory = self.directory_var.get().strip()
        if not directory:
            messagebox.showerror("Error", "Please select a directory")
            return

        # Get current password for this secured pack
        current_password = self.current_password
        if not current_password:
            messagebox.showerror("Error", "No current password available for this secured pack")
            return

        # Find files that need cleanup
        files_to_cleanup = []

        # Check each secured file for old versions
        for file in self.skin_files:
            if not file.is_secured:
                continue

            # Look for files in the directory that match this skin but have wrong passwords
            if file.parent_path:
                search_dir = os.path.join(directory, file.parent_path)
            else:
                search_dir = directory

            if not os.path.exists(search_dir):
                continue

            # Get the base name and IL-2 suffix for this file
            base_name = self.get_base_skin_name(file.name)
            il2_suffix = self.get_il2_suffix(file.name)
            ext = os.path.splitext(file.name)[1]

            # Look for all files matching the pattern
            import glob
            pattern = f"{base_name}*{ext}"
            matching_files = glob.glob(os.path.join(search_dir, pattern))

            for match in matching_files:
                filename = os.path.basename(match)

                # Check if it's the current version with correct password
                expected_name = self.get_local_filename_with_password(file.name, current_password)
                if filename == expected_name:
                    continue  # This is the current version, don't delete

                # Check if it has a password suffix and IL-2 suffix
                original_name, old_password = self.extract_password_from_filename(filename)
                match_base = self.get_base_skin_name(original_name)
                match_il2_suffix = self.get_il2_suffix(original_name)

                # Delete if:
                # 1. It matches the base name and IL-2 suffix but has old/different password
                # 2. It's the exact original filename (no password suffix for secured files)
                if (match_base == base_name and match_il2_suffix == il2_suffix and
                        old_password != current_password):
                    files_to_cleanup.append(match)
                elif filename == file.name:  # No password suffix at all
                    files_to_cleanup.append(match)

        if not files_to_cleanup:
            messagebox.showinfo("Cleanup Complete", "No old secured files found to cleanup.")
            return

        # Confirm with user
        file_count = len(files_to_cleanup)
        if not messagebox.askyesno("Confirm Cleanup",
                                   f"Found {file_count} old secured files to delete.\n\n"
                                   "This will delete:\n"
                                   "• Files with old password suffixes\n"
                                   "• Secured files without password suffixes\n\n"
                                   "Continue?",
                                   icon="warning"):
            return

        # Start cleanup process
        self.status_var.set(f"Cleaning up {file_count} old secured files...")
        self.progress_bar.start(10)
        self.disable_skin_action_buttons()

        threading.Thread(target=self.run_cleanup_files,
                         args=(files_to_cleanup,),
                         daemon=True).start()

    def update_password_suffixes(self):
        """Update password suffixes for all secured files without re-downloading"""
        if not self.current_is_secured:
            messagebox.showinfo("Info", "Current pack is not secured. This feature is only for secured packs.")
            return

        directory = self.directory_var.get().strip()
        if not directory:
            messagebox.showerror("Error", "Please select a directory")
            return

        # Get current password for this secured pack
        current_password = self.current_password
        if not current_password:
            messagebox.showerror("Error", "No current password available for this secured pack")
            return

        # Check if there are any files that need password suffix updates
        files_to_update = []
        files_already_correct = []

        for file in self.skin_files:
            if not file.is_secured:
                continue

            # Check what exists locally
            if file.parent_path:
                search_dir = os.path.join(directory, file.parent_path)
            else:
                search_dir = directory

            if not os.path.exists(search_dir):
                continue

            # Look for any version of this file (with any password or no password)
            base_name = self.get_base_skin_name(file.name)
            ext = os.path.splitext(file.name)[1]

            import glob
            pattern = f"{base_name}*{ext}"
            matching_files = glob.glob(os.path.join(search_dir, pattern))

            # Check if we have the correct version already
            expected_filename = self.get_local_filename_with_password(file.name, current_password)
            expected_path = os.path.join(search_dir, expected_filename)

            has_correct_version = os.path.exists(expected_path)
            has_any_version = len(matching_files) > 0

            if has_any_version and not has_correct_version:
                # We have some version but not with the correct password
                files_to_update.append(file)
            elif has_correct_version:
                files_already_correct.append(file)

        if not files_to_update:
            if files_already_correct:
                messagebox.showinfo("Password Sync",
                                    f"All {len(files_already_correct)} secured files already have the correct password suffix.")
            else:
                messagebox.showinfo("Password Sync",
                                    "No secured files found to update.")
            return

        # Show confirmation with details
        update_count = len(files_to_update)
        correct_count = len(files_already_correct)
        total_count = update_count + correct_count

        message = f"Update password suffixes for {update_count} files?\n\n"
        message += f"• {update_count} files need password suffix updates\n"
        message += f"• {correct_count} files already have correct suffixes\n"
        message += f"• Total secured files: {total_count}\n\n"
        message += "This will rename files to use the current password suffix without re-downloading."

        if not messagebox.askyesno("Confirm Password Sync", message):
            return

        # Start the password sync process
        self.status_var.set(f"Updating password suffixes for {update_count} files...")
        self.progress_bar.start(10)
        self.disable_skin_action_buttons()

        threading.Thread(target=self.run_password_suffix_update,
                         args=(files_to_update, current_password, directory),
                         daemon=True).start()

    def run_password_suffix_update(self, files_to_update, new_password, directory):
        """Thread function to update password suffixes"""
        try:
            total_files = len(files_to_update)
            updated_count = 0

            for i, file in enumerate(files_to_update):
                # Update progress
                progress_text = f"Updating file {i + 1} of {total_files}: {file.name}"
                self.root.after(0, lambda t=progress_text: self.status_var.set(t))

                # Find existing files for this skin
                if file.parent_path:
                    search_dir = os.path.join(directory, file.parent_path)
                else:
                    search_dir = directory

                if not os.path.exists(search_dir):
                    continue

                # Get the base name and IL-2 suffix for this file
                base_name = self.get_base_skin_name(file.name)
                il2_suffix = self.get_il2_suffix(file.name)
                ext = os.path.splitext(file.name)[1]

                import glob
                # Look for files that match the base pattern
                pattern = f"{base_name}*{ext}"
                matching_files = glob.glob(os.path.join(search_dir, pattern))

                # Find the best candidate file to rename
                best_candidate = None
                for candidate_path in matching_files:
                    candidate_filename = os.path.basename(candidate_path)
                    original_name, old_password = self.extract_password_from_filename(candidate_filename)

                    # Check if this is the right base skin with the same IL-2 suffix
                    candidate_base = self.get_base_skin_name(original_name)
                    candidate_il2_suffix = self.get_il2_suffix(original_name)

                    if candidate_base == base_name and candidate_il2_suffix == il2_suffix:
                        # Skip if it already has the correct password
                        if old_password == new_password:
                            continue

                        # This is a candidate for renaming
                        best_candidate = candidate_path
                        break

                    # Also check for files without password suffix but with correct IL-2 suffix
                    if candidate_filename == file.name:
                        best_candidate = candidate_path
                        break

                if best_candidate:
                    # Generate new filename using the improved method
                    new_filename = self.get_local_filename_with_password(file.name, new_password)
                    new_path = os.path.join(search_dir, new_filename)

                    try:
                        # Rename the file
                        os.rename(best_candidate, new_path)
                        old_filename = os.path.basename(best_candidate)
                        print(f"Updated password suffix: {old_filename} → {new_filename}")
                        updated_count += 1

                        # Update the file info object
                        file.path = new_path
                        file.local_name = new_filename
                        file.status = "current"  # Assume it's current after password update

                    except Exception as e:
                        print(f"Failed to update {file.name}: {e}")

            # Refresh tree view to show the updated files
            self.root.after(0, self.update_skin_tree_view)
            self.root.after(0, lambda: self.status_var.set(f"Password sync complete: updated {updated_count} files"))

            # Show completion message
            if updated_count > 0:
                self.root.after(0, lambda count=updated_count: messagebox.showinfo("Password Sync Complete",
                                                                                   f"Successfully updated password suffixes for {count} files.\n\n"
                                                                                   f"Files now use the current password suffix."))
            else:
                self.root.after(0, lambda: messagebox.showinfo("Password Sync Complete",
                                                               "No files were updated. All files may already have the correct password suffixes."))

            self.root.after(0, self.enable_skin_action_buttons)

        except Exception as e:
            print(f"An error occurred during password sync: {e}")
            error_msg = str(e)
            self.root.after(0, lambda: self.status_var.set("Error during password sync"))
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"An error occurred: {msg}"))

        finally:
            self.root.after(0, self.progress_bar.stop)
            self.root.after(0, self.enable_skin_action_buttons)

    def run_cleanup_files(self, files_to_cleanup):
        """Thread function to cleanup old secured files"""
        try:
            total_files = len(files_to_cleanup)
            deleted_count = 0

            for i, file_path in enumerate(files_to_cleanup):
                # Update progress
                progress_text = f"Cleaning up file {i + 1} of {total_files}: {os.path.basename(file_path)}"
                self.root.after(0, lambda t=progress_text: self.status_var.set(t))

                # Delete file
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        print(f"Cleaned up: {os.path.basename(file_path)}")
                        deleted_count += 1
                except Exception as e:
                    print(f"Failed to delete {os.path.basename(file_path)}: {e}")

            # Refresh tree view to reflect the changes
            self.root.after(0, self.update_skin_tree_view)
            self.root.after(0, lambda: self.status_var.set(f"Cleanup complete: deleted {deleted_count} old files"))
            self.root.after(0, lambda count=deleted_count: messagebox.showinfo("Cleanup Complete",
                                                                               f"Successfully deleted {count} old secured files."))
            self.root.after(0, self.enable_skin_action_buttons)

        except Exception as e:
            print(f"An error occurred during cleanup: {e}")
            error_msg = str(e)
            self.root.after(0, lambda: self.status_var.set("Error during cleanup"))
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"An error occurred: {msg}"))

        finally:
            self.root.after(0, self.progress_bar.stop)
            self.root.after(0, self.enable_skin_action_buttons)

    def run_download_files(self, files_to_download):
        """Thread function to download files"""
        try:
            service = self.initialize_drive_api()
            total_files = len(files_to_download)

            for i, file in enumerate(files_to_download):
                # Update progress
                progress_text = f"Downloading file {i + 1} of {total_files}: {file.local_name or file.name}"
                self.root.after(0, lambda t=progress_text: self.status_var.set(t))

                # Ensure directory exists
                os.makedirs(os.path.dirname(file.path), exist_ok=True)

                # For secured files with old passwords, delete the old file first
                if file.is_secured and file.status == "outdated" and os.path.exists(file.path):
                    # Check if this is an old password file
                    dir_path = os.path.dirname(file.path)
                    base_name = self.get_base_skin_name(file.name)
                    ext = os.path.splitext(file.name)[1]
                    il2_suffix = self.get_il2_suffix(file.name)
                    pattern = f"{base_name}*{ext}"

                    import glob
                    matching_files = glob.glob(os.path.join(dir_path, pattern))

                    for match in matching_files:
                        match_filename = os.path.basename(match)
                        original_name, old_password = self.extract_password_from_filename(match_filename)
                        match_base = self.get_base_skin_name(original_name)
                        match_il2_suffix = self.get_il2_suffix(original_name)

                        if (match_base == base_name and match_il2_suffix == il2_suffix and
                                old_password != file.password):
                            # Delete old file with different password
                            os.remove(match)
                            print(f"Deleted old version: {match_filename}")

                # Download file
                try:
                    self.download_file(service, file.id, file.path)
                    print(f"Downloaded {file.local_name or file.name}")

                    # Update file status
                    file.status = "current"
                except Exception as e:
                    print(f"Failed to download {file.local_name or file.name}: {e}")

            # Refresh tree view
            self.root.after(0, self.update_skin_tree_view)
            self.root.after(0, lambda: self.status_var.set(f"Completed downloading {total_files} files"))
            self.root.after(0, self.enable_skin_action_buttons)

        except Exception as e:
            print(f"An error occurred during download: {e}")
            error_msg = str(e)
            self.root.after(0, lambda: self.status_var.set("Error during download"))
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"An error occurred: {msg}"))

        finally:
            self.root.after(0, self.progress_bar.stop)
            self.root.after(0, self.enable_skin_action_buttons)

    def run_delete_files(self, files_to_delete):
        """Thread function to delete local files"""
        try:
            total_files = len(files_to_delete)

            for i, file in enumerate(files_to_delete):
                # Update progress
                progress_text = f"Deleting file {i + 1} of {total_files}: {file.local_name or file.name}"
                self.root.after(0, lambda t=progress_text: self.status_var.set(t))

                # Delete file
                try:
                    if os.path.exists(file.path):
                        os.remove(file.path)
                        print(f"Deleted {file.local_name or file.name}")

                        # Update file status
                        file.status = "missing"
                except Exception as e:
                    print(f"Failed to delete {file.local_name or file.name}: {e}")

            # Refresh tree view
            self.root.after(0, self.update_skin_tree_view)
            self.root.after(0, lambda: self.status_var.set(f"Completed deleting {total_files} files"))
            self.root.after(0, self.enable_skin_action_buttons)

        except Exception as e:
            print(f"An error occurred during deletion: {e}")
            error_msg = str(e)
            self.root.after(0, lambda: self.status_var.set("Error during deletion"))
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"An error occurred: {msg}"))

        finally:
            self.root.after(0, self.progress_bar.stop)
            self.root.after(0, self.enable_skin_action_buttons)

    def browse_directory(self):
        directory = filedialog.askdirectory(
            title="Select IL2 Skins Directory",
            initialdir=self.directory_var.get() or os.path.expanduser("~")
        )
        if directory:
            self.directory_var.set(directory)

            # If we're on the detailed skin manager tab, clear the tree view
            if self.current_tab == 1:
                for item in self.skin_tree.get_children():
                    self.skin_tree.delete(item)

    def update_config_from_drive(self):
        """Get the config from Google Drive and store in memory only"""
        try:
            service = self.initialize_drive_api()
            print("Loading configuration from Google Drive...")

            # Get files in the config directory
            try:
                results = service.files().list(
                    q=f"'{CONFIG_DRIVE_ID}' in parents and trashed=false",
                    pageSize=10,
                    fields="files(id, name, mimeType)"
                ).execute()

                items = results.get('files', [])

                # Look for directory.json and directory_secured.json
                for item in items:
                    if item['name'] == 'directory.json':
                        # Found the regular JSON file, download it
                        json_file_id = item['id']
                        request = service.files().get_media(fileId=json_file_id)
                        content = request.execute()

                        if isinstance(content, bytes):
                            config_text = content.decode('utf-8')
                        else:
                            config_text = content

                        config_data = json.loads(config_text)
                        self.folder_config = config_data

                        print(f"Loaded regular configuration from Google Drive ({len(config_data)} folders)")

                    elif item['name'] == 'directory_secured.json':
                        # Found the secured JSON file, download it
                        json_file_id = item['id']
                        request = service.files().get_media(fileId=json_file_id)
                        content = request.execute()

                        if isinstance(content, bytes):
                            config_text = content.decode('utf-8')
                        else:
                            config_text = content

                        config_data = json.loads(config_text)

                        # New format: {"alias": ["folder_id", "password"], ...}
                        # Convert to separate configs for folder IDs and passwords (memory only)
                        self.secured_folder_config = {}
                        self.secured_passwords_from_config = {}

                        for alias, data in config_data.items():
                            if isinstance(data, list) and len(data) >= 2:
                                folder_id, password = data[0], data[1]
                                self.secured_folder_config[alias] = folder_id
                                self.secured_passwords_from_config[alias] = password
                            elif isinstance(data, str):
                                # Fallback for old format (just folder ID)
                                self.secured_folder_config[alias] = data

                        print(
                            f"Loaded secured configuration from Google Drive ({len(self.secured_folder_config)} secured folders)")

                self.root.after(0, self.update_folder_dropdown)
                self.root.after(0, lambda: self.status_var.set("Configuration loaded from Google Drive"))

            except Exception as e:
                print(f"Failed to load configuration from Google Drive: {e}")
                self.root.after(0, lambda: self.status_var.set("Using default configuration (Drive unavailable)"))

        except Exception as e:
            print(f"Error connecting to Google Drive for configuration: {e}")
            self.root.after(0, lambda: self.status_var.set("Using default configuration (Drive error)"))

    def refresh_folder_config(self):
        """Refresh folder configuration from Google Drive"""
        self.status_var.set("Refreshing configuration from Google Drive...")
        self.sync_button.config(state="disabled")
        self.folder_dropdown.set("Loading folder list...")
        self.folder_dropdown.config(values=[])

        # Also update the detailed dropdown
        self.detailed_dropdown.set("Loading folder list...")
        self.detailed_dropdown.config(values=[])

        # Clear password cache and stored config passwords
        self.secured_password_cache.clear()
        if hasattr(self, 'secured_passwords_from_config'):
            self.secured_passwords_from_config.clear()

        # Load fresh configurations from Google Drive
        threading.Thread(target=self.update_config_from_drive, daemon=True).start()

    def update_folder_dropdown(self):
        """Update the folder dropdown with aliases from both configurations"""
        all_aliases = []

        # Add regular folders
        if self.folder_config:
            regular_aliases = list(self.folder_config.keys())
            all_aliases.extend(regular_aliases)

        # Add secured folders without any indicator
        if self.secured_folder_config:
            # Filter out the 'Password' key if it exists
            secured_aliases = [alias for alias in self.secured_folder_config.keys() if alias != 'Password']
            all_aliases.extend(secured_aliases)

        if all_aliases:
            all_aliases.sort()  # Sort alphabetically

            # Update both dropdowns
            self.folder_dropdown.config(values=all_aliases)
            self.detailed_dropdown.config(values=all_aliases)

            if all_aliases:
                self.folder_dropdown.set(all_aliases[0])  # Select first one by default
                self.detailed_dropdown.set(all_aliases[0])
            else:
                self.folder_dropdown.set("No folders available")
                self.detailed_dropdown.set("No folders available")

            self.sync_button.config(state="normal")
            self.status_var.set("Ready")
        else:
            self.folder_dropdown.config(values=["No folders available"])
            self.folder_dropdown.set("No folders available")
            self.detailed_dropdown.config(values=["No folders available"])
            self.detailed_dropdown.set("No folders available")
            self.sync_button.config(state="disabled")

    def start_sync(self):
        directory = self.directory_var.get().strip()
        if not directory:
            messagebox.showerror("Error", "Please select a directory")
            return

        # Get selected alias - no need to clean since we removed lock symbols
        selected_alias = self.selected_alias.get()

        # Determine if this is a secured pack
        is_secured, password = self.get_skin_pack_type(selected_alias)

        if is_secured:
            # If password is not cached, prompt for it with retry
            if not password:
                password = self.prompt_for_password_with_retry(selected_alias)
                if not password:
                    messagebox.showwarning("Password Required", "Password is required for secured skin packs")
                    return
                # Cache the password
                self.secured_password_cache[selected_alias] = password

            folder_id = self.secured_folder_config[selected_alias]
        else:
            if selected_alias not in self.folder_config:
                messagebox.showerror("Error", "Please select a valid skin pack")
                return
            folder_id = self.folder_config[selected_alias]
            password = None

        # Ensure the directory exists and is writable
        if not os.path.exists(directory):
            messagebox.showerror("Error", f"The directory {directory} does not exist.")
            return
        elif not os.access(directory, os.W_OK):
            messagebox.showerror("Error", f"The directory {directory} is not writable.")
            return

        # Save the directory if requested
        if self.save_var.get():
            self.save_directory_to_cache(directory)

        # Set the sync running flag
        self.sync_running = True

        # Update button states
        self.sync_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress_bar.start(10)
        self.status_var.set(f"Synchronizing {selected_alias}...")

        # Run synchronization in a separate thread to avoid freezing the UI
        threading.Thread(target=self.run_sync, args=(directory, selected_alias, folder_id, is_secured, password),
                         daemon=True).start()

    def stop_sync(self):
        """Stop the synchronization process"""
        if self.sync_running:
            self.sync_running = False
            print("Stopping synchronization. Please wait for current operation to complete...")
            self.status_var.set("Stopping...")
            # Button states will be reset when run_sync completes

    def run_sync(self, directory, alias, folder_id, is_secured=False, password=None):
        try:
            print(f"Starting synchronization for {alias}...")
            if is_secured:
                print(f"  → This is a secured skin pack")
                # Password was already validated in start_sync, so we can proceed
                service = self.initialize_drive_api()
                print(f"  → Using validated password")
            else:
                service = self.initialize_drive_api()

            # Download directly to the specified directory - no alias subdirectory creation
            self.sync_google_drive_folder(service, folder_id, directory, is_secured=is_secured, password=password)

            # Check if operation was stopped
            if not self.sync_running:
                print("Synchronization was stopped by user.")
                self.root.after(0, lambda: self.status_var.set("Synchronization stopped"))
            else:
                self.root.after(0, lambda: self.status_var.set("Synchronization complete"))
                self.root.after(0, lambda: messagebox.showinfo("Complete",
                                                               f"Skin synchronization for {alias} has completed successfully!"))

        except Exception as e:
            print(f"An error occurred: {e}")
            self.root.after(0, lambda: self.status_var.set("Error occurred"))
            if self.sync_running:  # Only show error if not intentionally stopped
                error_msg = str(e)
                self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"An error occurred: {msg}"))

        finally:
            # Reset the sync running flag
            self.sync_running = False

            # Stop progress bar and update button states
            self.root.after(0, self.progress_bar.stop)
            self.root.after(0, lambda: self.sync_button.config(state="normal"))
            self.root.after(0, lambda: self.stop_button.config(state="disabled"))

    def initialize_drive_api(self):
        credentials = service_account.Credentials.from_service_account_info(
            SERVICE_ACCOUNT_INFO,
            scopes=['https://www.googleapis.com/auth/drive.readonly']
        )
        return build('drive', 'v3', credentials=credentials)

    def download_file(self, service, file_id, local_path):
        """Download a file and handle zip extraction if needed"""
        try:
            request = service.files().get_media(fileId=file_id)

            # Check if this is a zip file
            # Zipped files do not work with the new password system for duxford, do not store any files in zipped folders if you need them password protected
            is_zip = local_path.lower().endswith('.zip')

            if is_zip:
                # For zip files, download to a temporary location first
                with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
                    temp_zip_path = temp_file.name

                    # Download to temporary file
                    downloader = MediaIoBaseDownload(temp_file, request)
                    done = False
                    while not done:
                        status, done = downloader.next_chunk()
                        print(f'Download {int(status.progress() * 100)}%.')

                # Now extract the zip file
                target_directory = os.path.dirname(local_path)
                password = getattr(self, 'current_password', None) if hasattr(self,
                                                                              'current_is_secured') and self.current_is_secured else None

                print(f"Extracting zip file: {os.path.basename(local_path)}")
                extracted_files = self.extract_and_process_zip(temp_zip_path, target_directory, password)

                # Clean up temporary zip file
                os.unlink(temp_zip_path)

                if extracted_files:
                    print(f"Successfully extracted {len(extracted_files)} files from {os.path.basename(local_path)}")
                else:
                    raise Exception("No files were extracted from the zip archive")

            else:
                # Regular file download
                with open(local_path, 'wb') as fh:
                    downloader = MediaIoBaseDownload(fh, request)
                    done = False
                    while not done:
                        status, done = downloader.next_chunk()
                        print(f'Download {int(status.progress() * 100)}%.')

        except PermissionError as e:
            print(f'Failed to download {os.path.basename(local_path)}: Permission denied. {e}')
            raise
        except Exception as e:
            print(f'Failed to download {os.path.basename(local_path)}: {e}')
            raise

    def sync_google_drive_folder(self, service, folder_id, local_directory, is_secured=False, password=None):
        page_token = None
        selected_alias = self.selected_alias.get()

        # For secured directories, first do a password update pass
        if is_secured and password:
            print(f"  → Checking for files that can be updated with new password suffix...")
            self.update_passwords_during_sync(service, folder_id, local_directory, password)

        while True:
            # Check if sync has been stopped
            if not self.sync_running:
                print(f"Stopping synchronization for {selected_alias}...")
                return

            response = service.files().list(
                q=f"'{folder_id}' in parents and trashed=false",
                pageSize=1000,
                fields="nextPageToken, files(id, name, mimeType, modifiedTime)",
                pageToken=page_token
            ).execute()
            items = response.get('files', [])

            for item in items:
                # Check if sync has been stopped
                if not self.sync_running:
                    print(f"Stopping synchronization for {selected_alias}...")
                    return

                file_id = item['id']
                file_name = item['name']
                file_modified_time = datetime.datetime.strptime(item['modifiedTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
                mime_type = item.get('mimeType', '')

                if mime_type != 'application/vnd.google-apps.folder':
                    # Check if this is a zip file
                    is_zip = file_name.lower().endswith('.zip')

                    if is_zip:
                        # For zip files, handle extraction and password application
                        print(f'Processing zip file: {file_name}...')

                        # Download to temporary location
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
                            temp_zip_path = temp_file.name

                            # Download the zip file
                            request = service.files().get_media(fileId=file_id)
                            downloader = MediaIoBaseDownload(temp_file, request)
                            done = False
                            while not done:
                                status, done = downloader.next_chunk()

                        # Extract and process the zip contents
                        try:
                            extracted_files = self.extract_and_process_zip(temp_zip_path, local_directory, password)

                            if extracted_files:
                                print(
                                    f'Successfully processed zip file: {file_name} ({len(extracted_files)} files extracted)')
                            else:
                                print(f'Warning: No files extracted from {file_name}')

                        except Exception as e:
                            print(f'Error processing zip file {file_name}: {e}')
                        finally:
                            # Clean up temporary file
                            os.unlink(temp_zip_path)

                    else:
                        # Regular file handling
                        if is_secured and password:
                            local_filename = self.get_local_filename_with_password(file_name, password)
                        else:
                            local_filename = file_name

                        local_file_path = os.path.join(local_directory, local_filename)
                        download_needed = True
                        renamed_instead = False

                        # Check for existing file with correct password
                        if os.path.exists(local_file_path):
                            # Get the modification time of the local file in UTC
                            local_modified_time = datetime.datetime.utcfromtimestamp(os.path.getmtime(local_file_path))
                            drive_time = file_modified_time.replace(tzinfo=None)

                            if local_modified_time >= drive_time:
                                download_needed = False
                                print(f"  → {local_filename} is up to date")
                            else:
                                print(f"  → {local_filename} needs download (Drive version is newer)")

                        # For secured files, check if we already renamed a file during the password update pass
                        if is_secured and download_needed:
                            # Check if the file now exists after password updates
                            if os.path.exists(local_file_path):
                                local_modified_time = datetime.datetime.utcfromtimestamp(
                                    os.path.getmtime(local_file_path))
                                drive_time = file_modified_time.replace(tzinfo=None)

                                if local_modified_time >= drive_time:
                                    download_needed = False
                                    print(f"  → {local_filename} is now up to date after password update")

                        # For secured files, look for old password versions that might need renaming
                        if is_secured and download_needed:
                            # Look for files with old passwords that might just need renaming
                            dir_path = os.path.dirname(local_file_path)
                            if os.path.exists(dir_path):
                                base_name = self.get_base_skin_name(file_name)
                                ext = os.path.splitext(file_name)[1]
                                il2_suffix = self.get_il2_suffix(file_name)

                                import glob
                                pattern = f"{base_name}_*{ext}"
                                matching_files = glob.glob(os.path.join(dir_path, pattern))

                                for match in matching_files:
                                    match_filename = os.path.basename(match)
                                    original_name, old_password = self.extract_password_from_filename(match_filename)
                                    match_base = self.get_base_skin_name(original_name)
                                    match_il2_suffix = self.get_il2_suffix(original_name)

                                    # Check if this file is up to date content-wise but has wrong password
                                    if (match_base == base_name and match_il2_suffix == il2_suffix and
                                            old_password != password):
                                        match_modified_time = datetime.datetime.utcfromtimestamp(
                                            os.path.getmtime(match))

                                        # If the file content is up to date, just rename it
                                        if match_modified_time >= drive_time:
                                            try:
                                                os.rename(match, local_file_path)
                                                print(
                                                    f"  → Renamed {match_filename} to {local_filename} (content up to date, password updated)")
                                                download_needed = False
                                                renamed_instead = True
                                                break
                                            except Exception as e:
                                                print(f"  → Failed to rename {match_filename}: {e}")

                        # Download only if needed and we didn't rename instead
                        if download_needed and not renamed_instead:
                            print(f'Downloading {local_filename}...')
                            try:
                                # Delete any old versions with different passwords before downloading
                                if is_secured:
                                    dir_path = os.path.dirname(local_file_path)
                                    if os.path.exists(dir_path):
                                        base_name = self.get_base_skin_name(file_name)
                                        ext = os.path.splitext(file_name)[1]
                                        il2_suffix = self.get_il2_suffix(file_name)

                                        import glob
                                        pattern = f"{base_name}_*{ext}"
                                        matching_files = glob.glob(os.path.join(dir_path, pattern))

                                        for match in matching_files:
                                            match_filename = os.path.basename(match)
                                            original_name, old_password = self.extract_password_from_filename(
                                                match_filename)
                                            match_base = self.get_base_skin_name(original_name)
                                            match_il2_suffix = self.get_il2_suffix(original_name)

                                            if (match_base == base_name and match_il2_suffix == il2_suffix and
                                                    old_password != password):
                                                try:
                                                    os.remove(match)
                                                    print(f"  → Deleted old version: {match_filename}")
                                                except Exception as e:
                                                    print(f"  → Failed to delete old version {match_filename}: {e}")

                                self.download_file(service, file_id, local_file_path)
                            except Exception as e:
                                print(f'Failed to download {local_filename}: {e}')
                        elif not download_needed and not renamed_instead:
                            # Clean up old password versions even if current file is up to date
                            if is_secured:
                                dir_path = os.path.dirname(local_file_path)
                                if os.path.exists(dir_path):
                                    base_name = self.get_base_skin_name(file_name)
                                    ext = os.path.splitext(file_name)[1]
                                    il2_suffix = self.get_il2_suffix(file_name)

                                    import glob
                                    pattern = f"{base_name}_*{ext}"
                                    matching_files = glob.glob(os.path.join(dir_path, pattern))

                                    for match in matching_files:
                                        match_filename = os.path.basename(match)
                                        original_name, old_password = self.extract_password_from_filename(
                                            match_filename)
                                        match_base = self.get_base_skin_name(original_name)
                                        match_il2_suffix = self.get_il2_suffix(original_name)

                                        # Delete if it's the same skin but with wrong password
                                        if (match_base == base_name and match_il2_suffix == il2_suffix and
                                                old_password != password and match != local_file_path):
                                            try:
                                                os.remove(match)
                                                print(f"  → Cleaned up old version: {match_filename}")
                                            except Exception as e:
                                                print(f"  → Failed to clean up old version {match_filename}: {e}")
                else:
                    # It's a folder, recreate the same folder structure in the target directory
                    folder_path = os.path.join(local_directory, file_name)
                    if not os.path.exists(folder_path):
                        os.makedirs(folder_path)

                    # Recursively sync the folder's contents
                    self.sync_google_drive_folder(service, file_id, folder_path, is_secured, password)

            page_token = response.get('nextPageToken', None)
            if not page_token:
                break

    def update_passwords_during_sync(self, service, folder_id, local_directory, new_password, parent_path=""):
        """
        During sync, update password suffixes for secured files to avoid unnecessary downloads.
        This runs before the main sync to rename files with correct passwords.
        """
        try:
            # Get all files in this folder
            response = service.files().list(
                q=f"'{folder_id}' in parents and trashed=false",
                pageSize=1000,
                fields="files(id, name, mimeType, modifiedTime)"
            ).execute()

            items = response.get('files', [])
            updated_count = 0

            for item in items:
                # Check if sync has been stopped
                if not self.sync_running:
                    return updated_count

                file_name = item['name']
                mime_type = item.get('mimeType', '')

                if mime_type == 'application/vnd.google-apps.folder':
                    # Recursively handle subfolders
                    current_path = os.path.join(parent_path, file_name) if parent_path else file_name
                    folder_path = os.path.join(local_directory, file_name)

                    if os.path.exists(folder_path):
                        subfolder_updates = self.update_passwords_during_sync(
                            service, item['id'], folder_path, new_password, current_path
                        )
                        updated_count += subfolder_updates

                elif not file_name.lower().endswith('.zip'):  # Skip zip files for now, handle them normally
                    # Regular file - check if it needs password update
                    target_dir = os.path.join(local_directory, parent_path) if parent_path else local_directory

                    if not os.path.exists(target_dir):
                        continue

                    # Get the expected filename with current password
                    expected_filename = self.get_local_filename_with_password(file_name, new_password)
                    expected_path = os.path.join(target_dir, expected_filename)

                    # Skip if file already has correct password
                    if os.path.exists(expected_path):
                        continue

                    # Look for files that match this skin but have different passwords
                    base_name = self.get_base_skin_name(file_name)
                    il2_suffix = self.get_il2_suffix(file_name)
                    ext = os.path.splitext(file_name)[1]

                    import glob
                    pattern = f"{base_name}*{ext}"
                    matching_files = glob.glob(os.path.join(target_dir, pattern))

                    for match in matching_files:
                        match_filename = os.path.basename(match)
                        original_name, old_password = self.extract_password_from_filename(match_filename)
                        match_base = self.get_base_skin_name(original_name)
                        match_il2_suffix = self.get_il2_suffix(original_name)

                        # Check if this matches our target file but has wrong password
                        if (match_base == base_name and match_il2_suffix == il2_suffix and
                                old_password != new_password):

                            try:
                                # Rename to correct password
                                os.rename(match, expected_path)
                                print(f"  → Password updated: {match_filename} → {expected_filename}")
                                updated_count += 1
                                break  # Found and updated, move to next file

                            except Exception as e:
                                print(f"  → Failed to update password for {match_filename}: {e}")

                        # Also handle files without password suffix
                        elif match_filename == file_name:
                            try:
                                # Add password suffix
                                os.rename(match, expected_path)
                                print(f"  → Added password suffix: {match_filename} → {expected_filename}")
                                updated_count += 1
                                break

                            except Exception as e:
                                print(f"  → Failed to add password suffix to {match_filename}: {e}")

            if updated_count > 0:
                print(f"  → Updated {updated_count} files with correct password suffixes")

            return updated_count

        except Exception as e:
            print(f"Error during password update pass: {e}")
            return 0

    def load_cached_directory(self):
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                cached_directory = f.read().strip()
                if os.path.exists(cached_directory):
                    return cached_directory
        return None

    def save_directory_to_cache(self, directory):
        with open(CACHE_FILE, 'w') as f:
            f.write(directory)


def main():
    root = tk.Tk()
    app = SkinSyncApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
