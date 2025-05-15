#!/usr/bin/env python3

import os
import sys
import re
from pathlib import Path

def rename_pasted_images(directory="."):
    """
    Rename files matching 'Pasted image YYYYMMDDHHMMSS.png' to 'Pasted_image_YYYYMMDDHHMMSS.png'
    
    Args:
        directory (str): Directory to search for files to rename
    """
    # Ensure directory exists
    if not os.path.isdir(directory):
        print(f"Error: Directory '{directory}' not found.")
        print(f"Usage: {sys.argv[0]} [directory]")
        return False
    
    # Pattern to match "Pasted image" files
    pattern = re.compile(r"Pasted image \d+\.png$")
    
    # Counter for renamed files
    count = 0
    
    # Walk through the directory
    for root, _, files in os.walk(directory):
        for filename in files:
            # Check if the file matches our pattern
            if pattern.match(filename):
                old_path = os.path.join(root, filename)
                
                # Create new filename by replacing spaces with underscores
                new_filename = filename.replace("Pasted image", "Pasted_image").replace(" ", "_")
                new_path = os.path.join(root, new_filename)
                
                # Rename the file
                os.rename(old_path, new_path)
                print(f"Renamed: {filename} → {new_filename}")
                count += 1
    
    print(f"Completed: {count} files renamed.")
    return True

if __name__ == "__main__":
    # Get directory from command line arguments or use current directory
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    rename_pasted_images(directory)