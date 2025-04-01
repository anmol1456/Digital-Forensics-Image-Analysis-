import pytsk3
import sys
import datetime
import os
import hashlib

# Function to open the disk image
def open_image(image_path):
    try:
        img = pytsk3.Img_Info(image_path)
        return img
    except IOError:
        print(f"Error: Unable to open disk image {image_path}")
        sys.exit(1)

# Function to list all files in a directory, recursively
def list_files(img, directory_path='/', parent_dir=''):
    fs = pytsk3.FS_Info(img)
    try:
        # Open the specified directory
        directory = fs.open_dir(directory_path)
    except IOError:
        print(f"Error: Unable to open directory {directory_path}")
        return

    for file in directory:
        file_name = file.info.name
        file_size = file.info.meta.size
        file_mtime = file.info.meta.mtime
        file_atime = file.info.meta.atime
        file_ctime = file.info.meta.ctime
        is_deleted = file.info.meta.flags == 0x02  # Check if the file is deleted
        
        # Handle file path
        file_path = os.path.join(parent_dir, file_name)

        # Print file information
        print_file_info(file_name, file_size, file_mtime, file_atime, file_ctime, is_deleted)
        
        # If the file is a directory, recursively explore it
        if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            list_files(img, directory_path + '/' + file_name, file_path)

        # Handle potential suspicious file types based on file extensions
        if is_suspicious_file(file_name):
            print(f"Suspicious file detected: {file_path}")

# Function to print file information
def print_file_info(file_name, file_size, file_mtime, file_atime, file_ctime, is_deleted):
    print(f"File: {file_name}")
    print(f"Size: {file_size} bytes")
    print(f"Last Modified: {convert_time(file_mtime)}")
    print(f"Last Accessed: {convert_time(file_atime)}")
    print(f"Creation Time: {convert_time(file_ctime)}")
    print(f"Deleted: {'Yes' if is_deleted else 'No'}")
    print("-" * 50)

# Function to convert Unix timestamp to readable date
def convert_time(timestamp):
    if timestamp == 0:
        return "N/A"
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

# Function to check if the file is suspicious (based on file extension)
def is_suspicious_file(file_name):
    suspicious_extensions = ['.exe', '.bat', '.vbs', '.dll', '.jar', '.msi', '.pif', '.cmd']
    return any(file_name.lower().endswith(ext) for ext in suspicious_extensions)

# Function to calculate the hash of a file (MD5, SHA-1, SHA-256)
def calculate_file_hash(file_object, hash_algorithm='sha256'):
    hash_func = hashlib.new(hash_algorithm)
    while True:
        data = file_object.read(65536)  # Read in chunks of 64KB
        if not data:
            break
        hash_func.update(data)
    return hash_func.hexdigest()

# Function to extract and hash the contents of deleted files (if possible)
def extract_deleted_files(img, directory_path='/', parent_dir=''):
    fs = pytsk3.FS_Info(img)
    try:
        directory = fs.open_dir(directory_path)
    except IOError:
        print(f"Error: Unable to open directory {directory_path}")
        return

    for file in directory:
        is_deleted = file.info.meta.flags == 0x02  # Check if file is deleted
        
        if is_deleted:
            file_path = os.path.join(parent_dir, file.info.name)
            print(f"Extracting deleted file: {file_path}")
            try:
                file_object = file.read_random(0, file.info.meta.size)
                file_hash = calculate_file_hash(file_object)
                print(f"File Hash (SHA-256): {file_hash}")
            except IOError:
                print(f"Error reading deleted file: {file_path}")
                
        # Recursively handle directories
        if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            extract_deleted_files(img, directory_path + '/' + file.info.name, file_path)

# Main function to run the analysis
def main():
    if len(sys.argv) != 2:
        print("Usage: python advanced_disk_image_analysis.py <path_to_disk_image>")
        sys.exit(1)

    image_path = sys.argv[1]
    print(f"Opening disk image: {image_path}")
    
    # Open the disk image
    img = open_image(image_path)
    
    # List files in the root directory
    print("\nListing files in root directory:\n")
    list_files(img, '/')

    # Extract deleted files and hash their contents
    print("\nExtracting and hashing deleted files:\n")
    extract_deleted_files(img, '/')

if __name__ == "__main__":
    main()
