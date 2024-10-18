import os
import json
from datetime import datetime


class DirectoryScanner:
    def __init__(self, start_path="/"):
        self.start_path = start_path
        self.scan_data = {}
        self.error_data = {}

    def scan(self):
        """
        Recursively scans directories and files, records errors, and saves the data.
        """
        for root, dirs, files in os.walk(self.start_path):
            try:
                # Get last modified time for directories
                self.scan_data[root] = {
                    "last_modified": datetime.fromtimestamp(
                        os.path.getmtime(root)
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                    "directories": dirs,
                    "files": [],
                }
            except (FileNotFoundError, PermissionError) as e:
                self._log_error(root, None, str(e))
                continue

            # Process files
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    file_info = {
                        "name": file,
                        "last_modified": datetime.fromtimestamp(
                            os.path.getmtime(file_path)
                        ).strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    self.scan_data[root]["files"].append(file_info)
                except (FileNotFoundError, PermissionError, OSError) as e:
                    self._log_error(root, file, str(e))

    def _log_error(self, root, filename, error_type):
        """
        Logs errors encountered during the scanning process.
        """
        if error_type not in self.error_data:
            self.error_data[error_type] = []
        self.error_data[error_type].append(
            {
                "root": root,
                "filename": filename,
                "filepath": os.path.join(root, filename) if filename else root,
            }
        )

    def save_scan_data(self, output_file):
        """
        Saves the scan data to a JSON file.
        """
        with open(output_file, "w") as f:
            json.dump(self.scan_data, f, indent=4)

    def save_error_data(self, error_file):
        """
        Saves the error data to a JSON file.
        """
        with open(error_file, "w") as f:
            json.dump(self.error_data, f, indent=4)
