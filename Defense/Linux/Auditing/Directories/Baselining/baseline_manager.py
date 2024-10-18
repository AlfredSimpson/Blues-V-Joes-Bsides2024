import json
import shutil
import subprocess
import os
from datetime import datetime
import time as TIME


class BaselineManager:
    ### NOTE: Change user to reflect the correct user account on the Linux machine. This also requires having mail installed.
    def __init__(
        self,
        baseline_file="directories.json",
        new_entities_file="new_entities.json",
        modified_entities_file="modified_entities.json",
        error_file="scanning_errors.json",
        user="xxxxxxxxxxxxxxx",
    ):
        self.baseline_file = baseline_file
        self.new_entities_file = new_entities_file
        self.modified_entities_file = modified_entities_file
        self.error_file = error_file
        self.user = user

    def copy_baseline(self):
        """
        Copies the baseline JSON to a write-protected file.
        """
        if os.path.exists(self.baseline_file):
            protected_baseline = f"{self.baseline_file}.protected"
            shutil.copy(self.baseline_file, protected_baseline)
            os.chmod(protected_baseline, 0o444)  # Make the file read-only

    def compare_scans(self, current_scan_file):
        """
        Compares the current scan with the previous baseline to identify new and modified files.
        """
        with open(self.baseline_file, "r") as old_file, open(
            current_scan_file, "r"
        ) as new_file:
            old_scan = json.load(old_file)
            new_scan = json.load(new_file)

        new_entities = []
        modified_entities = []

        # Identify new files/directories and modified ones
        for directory, data in new_scan.items():
            if directory not in old_scan:
                new_entities.append(directory)
            else:
                # Compare files within the directory
                for file_info in data["files"]:
                    found = False
                    for old_file_info in old_scan[directory]["files"]:
                        if file_info["name"] == old_file_info["name"]:
                            found = True
                            if (
                                file_info["last_modified"]
                                != old_file_info["last_modified"]
                            ):
                                modified_entities.append(file_info)
                    if not found:
                        new_entities.append(file_info)

        # Save new and modified entities
        self._save_to_json(new_entities, self.new_entities_file)
        self._save_to_json(modified_entities, self.modified_entities_file, append=True)

    def _save_to_json(self, data, file, append=False):
        """
        Saves data to a JSON file, optionally appending if the file already exists.
        """
        mode = "a" if append else "w"
        with open(file, mode) as f:
            json.dump(data, f, indent=4)

    def alert_user(self):
        """
        Sends an email to alert the user using Ubuntu's mail functionality.
        """
        message = f"Scan completed at {datetime.now()}\n"
        message += f"New entities are listed in {self.new_entities_file}.\n"
        message += f"Modified entities are listed in {self.modified_entities_file}.\n"
        message += f"Errors encountered are listed in {self.error_file}.\n"

        subprocess.run(
            ["mail", "-s", "Directory Scan Alert", self.user],
            input=message.encode("utf-8"),
        )

    def run_periodically(self, interval=300):
        """
        Runs the scan and comparison periodically every `interval` seconds (default is 5 minutes).
        """
        while True:
            self.copy_baseline()
            self.compare_scans("directories.json")
            self.alert_user()
            TIME.sleep(interval)
