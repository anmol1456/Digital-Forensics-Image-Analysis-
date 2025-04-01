# Disk Image Analysis

This project provides a Python script for performing **disk image analysis**. The script utilizes the **pytsk3** library to analyze disk images in a forensic context, including:

- Recursively exploring directories within the disk image.
- Extracting file metadata (size, timestamps, etc.).
- Detecting deleted files and recovering them where possible.
- Hashing files (including deleted files) for integrity checks or cross-referencing.
- Flagging suspicious files based on file extensions.

## Features

- **Recursive Directory Exploration**: Lists files from the root directory and recursively explores subdirectories.
- **File Metadata Extraction**: Extracts essential metadata such as file size, timestamps (modified, accessed, created), and deletion status.
- **Suspicious File Detection**: Flags files with potentially dangerous extensions (e.g., `.exe`, `.bat`, `.dll`) as suspicious.
- **Deleted File Detection and Recovery**: Detects deleted files (if possible), extracts their contents, and computes hashes for file integrity.
- **File Hashing**: Computes the hash (SHA-256 by default) of files for integrity verification or comparison against threat databases.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/disk-image-analysis.git
   cd disk-image-analysis
