#!/usr/bin/env python3
"""
Simple copy script to copy files from OWASP LLM Top 10 to llm_guardian directory.

This script copies all files from the OWASP LLM Top 10 project to a new directory,
respecting .gitignore patterns and excluding unnecessary files.
"""

import os
import sys
import shutil
import fnmatch
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Source and destination directories
SOURCE_DIR = "/Users/paulduvall/Code/owasp_llm_top10"
DEST_DIR = "/Users/paulduvall/Code/llm_guardian"


def parse_gitignore(gitignore_path):
    """Parse .gitignore file and return patterns."""
    patterns = []
    try:
        with open(gitignore_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                patterns.append(line)
        return patterns
    except Exception as e:
        logger.error(f"Error parsing .gitignore: {e}")
        return []


def should_exclude(path, exclude_patterns, source_dir):
    """Check if a path should be excluded based on patterns."""
    # Get relative path from source directory
    rel_path = os.path.relpath(path, source_dir)
    
    # Always include the root directory
    if rel_path == '.':
        return False
    
    # Check each pattern
    for pattern in exclude_patterns:
        # Handle directory patterns (ending with /)
        if pattern.endswith('/'):
            dir_pattern = pattern[:-1]
            if fnmatch.fnmatch(rel_path, dir_pattern) or \
               any(fnmatch.fnmatch(part, dir_pattern) for part in rel_path.split(os.sep)):
                return True
        # Handle file patterns
        elif fnmatch.fnmatch(os.path.basename(rel_path), pattern) or \
             fnmatch.fnmatch(rel_path, pattern):
            return True
    
    return False


def copy_files(source_dir, dest_dir, exclude_patterns):
    """Copy files from source to destination, respecting exclude patterns."""
    for root, dirs, files in os.walk(source_dir):
        # Skip directories that should be excluded
        dirs[:] = [d for d in dirs if not should_exclude(os.path.join(root, d), exclude_patterns, source_dir)]
        
        # Process files
        for file in files:
            src_path = os.path.join(root, file)
            
            # Skip files that should be excluded
            if should_exclude(src_path, exclude_patterns, source_dir):
                continue
            
            # Determine destination path
            rel_path = os.path.relpath(src_path, source_dir)
            dest_path = os.path.join(dest_dir, rel_path)
            
            # Create destination directory if it doesn't exist
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            
            # Copy the file
            try:
                shutil.copy2(src_path, dest_path)
                logger.info(f"Copied: {rel_path}")
            except Exception as e:
                logger.error(f"Error copying {rel_path}: {e}")


def main():
    """Main function to copy files."""
    logger.info(f"Starting copy from {SOURCE_DIR} to {DEST_DIR}")
    
    # Check if destination directory exists
    if not os.path.exists(DEST_DIR):
        os.makedirs(DEST_DIR)
        logger.info(f"Created destination directory: {DEST_DIR}")
    
    # Parse .gitignore
    gitignore_path = os.path.join(SOURCE_DIR, '.gitignore')
    gitignore_patterns = parse_gitignore(gitignore_path)
    logger.info(f"Loaded {len(gitignore_patterns)} exclude patterns from .gitignore")
    
    # Copy files
    copy_files(SOURCE_DIR, DEST_DIR, gitignore_patterns)
    logger.info("Copy completed successfully!")


if __name__ == "__main__":
    main()
