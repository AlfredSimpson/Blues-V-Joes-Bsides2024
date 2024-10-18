from directory_scanner import DirectoryScanner
from baseline_manager import BaselineManager
import argparse
import asyncio
import subprocess
import time as TIME

parser = argparse.ArgumentParser(
    prog="Directory Baseline and Scanner",
    description="Scan directories and alert user of changes.",
    epilog="Developed by Cyb0rgSw0rd",
)
parser.add_argument("-u", "--user", help="User to send email alerts to", required=True)
parser.add_argument(
    "-r",
    "--repeat",
    help="Repeatedly run the scan every few minutes in the background as a subprocess.",
    action="store_true",
)
parser.add_argument(
    "-o", "--once", help="Run the scan once. [DEFAULT]", action="store_true"
)
parser.add_argument("-r_bg", "--runinbackground", help=None, action="store_true")
# TODO: Add arguments to ignore files, directories, or extensions.
# TODO: Add argument and logic to specify path
# TODO: Add argument to specify interval
args = parser.parse_args()


async def run_on_interval(scanner, manager, interval=300):
    while True:
        # Perform the scan
        scanner.scan()

        # Save scan data and errors
        scanner.save_scan_data("directories.json")
        scanner.save_error_data("scanning_errors.json")

        manager.copy_baseline()
        manager.compare_scans("directories.json")
        manager.alert_user()
        TIME.sleep(interval)


def run_once(scanner, manager):
    # Perform the scan
    scanner.scan()

    # Save scan data and errors
    scanner.save_scan_data("directories.json")
    scanner.save_error_data("scanning_errors.json")

    # Manage baseline, compare, and alert user
    manager.copy_baseline()
    manager.compare_scans("directories.json")
    manager.alert_user()


def main():
    # Initialize scanner and manager, checking for args first
    args = parser.parse_args()
    scanner = DirectoryScanner(start_path="/")
    manager = BaselineManager(user=args.user)

    if args.repeat:
        # Run the scan and comparison periodically every 5 minutes
        # asyncio.run(run_on_interval(scanner, manager))
        subprocess.Popen(
            [
                "python3",
                "scan.py",
                "-u",
                args.user,
                "-r_bg",
            ]
        )
    else:
        # Perform the scan
        scanner.scan()

        # Save scan data and errors
        scanner.save_scan_data("directories.json")
        scanner.save_error_data("scanning_errors.json")

        # Manage baseline, compare, and alert user
        manager.copy_baseline()
        manager.compare_scans("directories.json")
        manager.alert_user()


if __name__ == "__main__":
    main()
