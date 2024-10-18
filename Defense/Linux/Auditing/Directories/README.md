# Directory Auditing

## Overview

Inside of this directory are scripts related to auditing directories and files on a Linux system. These scripts are designed to help you identify potential security issues with the permissions of directories and files on your system, monitoring changes over time.


## DIRWALKER.py

Dirwalker is a very basic script. All it does is walk through each directory and file on the system and logs them. It requires sudo or root access to run and is more manual than the successor, found in Baselining.

### Notes:

You *must* run this as root


## Baselining Directory

This subdirectory contains three scripts, which all must be copied exactly as they are to the same directory. The scripts are:
- `scan.py`
- `baseline_manager.py`
- `directory_scanner.py`

### Pre-requisites

- Python3
- mail running on the server
- sudo or root access

### Setup

- [ ] Fill in correct information in baseline_manager.py. 
  - [ ] Write the correct user account to notify
  - [ ] 

### Usage

1. Run `scan.py` as sudo/root to scan the entire system and create a baseline.