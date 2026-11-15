import os

def save_to_vault(file_path, data):
    """Save encrypted data to the given file path."""
    with open(file_path, "wb") as f:
        f.write(data)

def list_vault_files(user_folder):
    """List all files in the user's vault folder."""
    if not os.path.exists(user_folder):
        os.makedirs(user_folder, exist_ok=True)
    return os.listdir(user_folder)

def get_file_path(user_folder, filename):
    """Get the full path for a file inside the user's vault folder."""
    return os.path.join(user_folder, filename)
