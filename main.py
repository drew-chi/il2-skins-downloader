import os
import datetime
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import warnings

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

CACHE_FILE = 'skin_directory_cache.txt'
SERVICE_ACCOUNT_INFO = {} #Service account info goes here
# Function to initialize Google Drive API
def initialize_drive_api():
    credentials = service_account.Credentials.from_service_account_info(
        SERVICE_ACCOUNT_INFO,
        scopes=['https://www.googleapis.com/auth/drive.readonly']
    )
    return build('drive', 'v3', credentials=credentials)

# Function to download file from Google Drive
def download_file(service, file_id, local_path):
    try:
        request = service.files().get_media(fileId=file_id)
        with open(local_path, 'wb') as fh:
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
                print(f'Download {int(status.progress() * 100)}%.')
    except PermissionError as e:
        print(f'Failed to download {os.path.basename(local_path)}: Permission denied. {e}')
    except Exception as e:
        print(f'Failed to download {os.path.basename(local_path)}: {e}')


# Function to recursively sync Google Drive folder with local directory
def sync_google_drive_folder(service, folder_id, local_directory):
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
            file_modified_time = datetime.datetime.strptime(item['modifiedTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
            mime_type = item.get('mimeType', '')

            if mime_type != 'application/vnd.google-apps.folder':
                # It's a file, download it if it's out of date
                local_file_path = os.path.join(local_directory, file_name)
                download_needed = True

                if os.path.exists(local_file_path):
                    # Get the modification time of the local file in UTC
                    local_modified_time = datetime.datetime.utcfromtimestamp(os.path.getmtime(local_file_path))

                    # Compare the modification times
                    if local_modified_time >= file_modified_time.replace(tzinfo=None):
                        download_needed = False

                if download_needed:
                    print(f'Downloading {file_name}...')
                    try:
                        download_file(service, file_id, local_file_path)
                    except Exception as e:
                        print(f'Failed to download {file_name}: {e}')
                else:
                    print(f'{file_name} is up to date.')
            else:
                # It's a folder, recursively sync its contents
                folder_path = os.path.join(local_directory, file_name)
                if not os.path.exists(folder_path):
                    os.makedirs(folder_path)
                sync_google_drive_folder(service, file_id, folder_path)

        page_token = response.get('nextPageToken', None)
        if not page_token:
            break
# Main function
def load_cached_directory():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            cached_directory = f.read().strip()
            if os.path.exists(cached_directory):
                return cached_directory
    return None


# Function to save the directory to the cache file
def save_directory_to_cache(directory):
    with open(CACHE_FILE, 'w') as f:
        f.write(directory)


# Main function
def main():
    print("IL2 Skin Synchronization Program - Built by Jagged Fel")
    service = initialize_drive_api()
    google_drive_folder_id = '' #Update with folder id

    local_directory = load_cached_directory()
    if not local_directory:
        local_directory = input(
            'Please enter the directory containing IL2 skins (example: C:\\SteamLibrary\\steamapps\\common\\IL-2 Sturmovik Battle of Stalingrad\\data\\graphics\\skins): ').strip()

        # Ensure the directory exists
        if not os.path.exists(local_directory):
            print(f"The directory {local_directory} does not exist.")
            return
        elif not os.access(local_directory, os.W_OK):
            print(f"The directory {local_directory} is not writable.")
            return

        save_location = input('Do you want to save this directory for future use? (yes/no): ').strip().lower()
        if save_location == 'yes':
            save_directory_to_cache(local_directory)

    sync_google_drive_folder(service, google_drive_folder_id, local_directory)
    input('Press Enter to exit.')


if __name__ == '__main__':
    main()
