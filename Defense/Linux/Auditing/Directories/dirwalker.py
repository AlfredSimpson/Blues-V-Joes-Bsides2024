import os
import json
from datetime import datetime


def list_directories_and_files(start_path="/"):
    """
    Recursively list all directories and files, along with their last modified time,
    starting from the specified root directory. Handles errors gracefully for symbolic links,
    permissions, and inaccessible files.

    :param start_path: The root directory to start scanning from.
    :return: A dictionary with directories as keys and list of files as values, including metadata.
    """
    directory_structure = {}
    paths_with_errors = {}
    # Traverse the directory structure
    for root, dirs, files in os.walk(start_path):
        try:
            # Get last modified time for directories
            directory_structure[root] = {
                "last_modified": datetime.fromtimestamp(
                    os.path.getmtime(root)
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "directories": dirs,
                "files": [],
            }
        except (FileNotFoundError, PermissionError):
            paths_with_errors[root] = (
                "Directory not found or permission denied. Walking incomplete on this directory."
            )
            continue

        # Process files
        for file in files:
            file_path = os.path.join(root, file)
            try:
                # Gather file metadata (without file type)
                file_info = {
                    "name": file,
                    "last_modified": datetime.fromtimestamp(
                        os.path.getmtime(file_path)
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                }
                directory_structure[root]["files"].append(file_info)
            except FileNotFoundError:
                paths_with_errors[file_path] = f"File not found. See {root}"

            except PermissionError:
                paths_with_errors[file_path] = f"Permission denied. See {root}"

            except OSError as e:
                if e.errno in (
                    6,
                    40,
                ):  # Handle "No such device or address" and "Too many levels of symbolic links"
                    paths_with_errors[file_path] = (
                        f"Error processing file: {e}, OS Error."
                    )

                else:
                    paths_with_errors[file_path] = f"Error processing file: {e}"

    # Write all values in paths_with_errors to a json file called "dir_errors.json"
    with open("dir_errors.json", "w") as f:
        json.dump(paths_with_errors, f, indent=4)

    return directory_structure


def save_to_json(data, output_file):
    """
    Save the directory structure (directories and files with metadata) to a JSON file.

    :param data: Dictionary of directories and their files.
    :param output_file: Path to the output JSON file.
    """
    with open(output_file, "w") as f:
        json.dump(data, f, indent=4)


def write_summary_log(num_directories, output_file):
    """
    Write a summary log file with the number of directories scanned.

    :param num_directories: The number of directories scanned.
    :param output_file: Path to the log file.
    """
    with open(output_file, "w") as f:
        f.write(f"Total number of directories scanned: {num_directories}\n")


def main():
    # Define the start path and output files
    start_path = "/"  # Start from the root directory. Change this as needed.
    json_output_file = "directories.json"
    log_output_file = "dir.log"

    # Get the directory structure (directories and files with metadata)
    print(f"Scanning directories and files starting from {start_path}...")
    directory_structure = list_directories_and_files(start_path)

    # Save the directory structure to a JSON file
    save_to_json(directory_structure, json_output_file)
    print(f"Directory and file structure saved to {json_output_file}")

    # Write a summary log file
    num_directories = len(directory_structure)
    write_summary_log(num_directories, log_output_file)
    print(
        f"Summary log saved to {log_output_file} with {num_directories} directories scanned."
    )


if __name__ == "__main__":
    main()
