import os
import shutil

# In a real-world scenario, this would be a URL to a remote git repository or file server.
# For this simulation, we use a local directory.
REMOTE_RULE_SOURCE = "remote_rules"
LOCAL_DATA_DIR = "data"


def _get_rule_files():
    """Returns a list of rule files from the source directory."""
    if not os.path.isdir(REMOTE_RULE_SOURCE):
        print(f"Warning: Remote rule source '{REMOTE_RULE_SOURCE}' not found.")
        return []
    return [f for f in os.listdir(REMOTE_RULE_SOURCE) if f.endswith('.txt')]


def update_rules():
    """
    Updates local rule files from the remote source.
    This function ensures the local data directory exists and copies the latest
    rule files into it.
    """
    print("Checking for rule updates...")
    # Ensure the local data directory exists.
    if not os.path.exists(LOCAL_DATA_DIR):
        os.makedirs(LOCAL_DATA_DIR)
        print(f"Created local data directory at '{LOCAL_DATA_DIR}'.")

    rule_files = _get_rule_files()
    if not rule_files:
        print("No rule files found to update.")
        return

    updated_count = 0
    for file_name in rule_files:
        remote_path = os.path.join(REMOTE_RULE_SOURCE, file_name)
        local_path = os.path.join(LOCAL_DATA_DIR, file_name)

        # A simple check: copy if the file doesn't exist or if remote is newer.
        # In a real app, you might check hashes (e.g., MD5, SHA256).
        should_update = True
        if os.path.exists(local_path):
            if os.path.getmtime(remote_path) <= os.path.getmtime(local_path):
                should_update = False

        if should_update:
            try:
                shutil.copy2(remote_path, local_path)
                print(f"  - Updated '{file_name}'")
                updated_count += 1
            except Exception as e:
                print(f"Error updating '{file_name}': {e}")

    if updated_count > 0:
        print(f"Update complete. {updated_count} file(s) updated.")
    else:
        print("All local rules are already up-to-date.")


if __name__ == '__main__':
    # This allows running the updater manually for testing.
    print("Running manual rule update...")
    update_rules()
    print("Manual update process finished.")