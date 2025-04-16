#!/usr/bin/env python3
"""
Prompt Injection Report Generator Script

This script generates reports from prompt injection test results.

User Story: US-107 - As a security tester, I need to generate detailed reports
from prompt injection test results for analysis and documentation.
"""

import os
import sys
import argparse
import logging
import glob
from datetime import datetime
from typing import List, Optional

# Add the parent directory to the path so we can import the src modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import our modules
from src.llm01_prompt_injection.reporting import ReportGenerator, generate_report

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Generate reports from prompt injection test results.")
    
    # Input options
    parser.add_argument(
        "--results-file", 
        type=str, 
        help="Path to the JSON results file"
    )
    parser.add_argument(
        "--latest", 
        action="store_true",
        help="Use the latest results file in the output directory"
    )
    
    # Output options
    parser.add_argument(
        "--output-dir", 
        type=str, 
        default="test-results",
        help="Directory to store generated reports (default: test-results)"
    )
    parser.add_argument(
        "--format", 
        type=str, 
        default="html",
        choices=["html", "markdown", "md"], 
        help="Report format (default: html)"
    )
    parser.add_argument(
        "--output-file", 
        type=str, 
        help="Output filename for the report"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    return parser.parse_args()


def get_latest_results_file(output_dir: str) -> Optional[str]:
    """Get the latest results file in the output directory."""
    # Look for both naming patterns to ensure backward compatibility
    results_files = glob.glob(os.path.join(output_dir, "prompt_injection_test_results_*.json"))
    report_files = glob.glob(os.path.join(output_dir, "report-*.json"))
    
    # Combine both file lists
    all_files = results_files + report_files
    
    if not all_files:
        return None
    
    # Sort by modification time (newest first)
    all_files.sort(key=os.path.getmtime, reverse=True)
    return all_files[0]


def main():
    """Main function."""
    args = parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
        # List all files in the output directory for debugging
        if os.path.exists(args.output_dir):
            logger.debug(f"Contents of {args.output_dir}:")
            for file in os.listdir(args.output_dir):
                file_path = os.path.join(args.output_dir, file)
                logger.debug(f"  {file} ({os.path.getsize(file_path)} bytes, modified {datetime.fromtimestamp(os.path.getmtime(file_path))})")
        else:
            logger.debug(f"Directory {args.output_dir} does not exist")
    
    # Get results file
    results_file = args.results_file
    if not results_file and args.latest:
        results_file = get_latest_results_file(args.output_dir)
        if not results_file:
            logger.error(f"No results files found in {args.output_dir}")
            sys.exit(1)
        logger.info(f"Using latest results file: {results_file}")
    
    if not results_file:
        # Create a default results file if none is specified
        logger.info("No results file specified. Creating a default empty results file.")
        os.makedirs(args.output_dir, exist_ok=True)
        default_results_file = os.path.join(args.output_dir, f"prompt_injection_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(default_results_file, 'w') as f:
            f.write('{"results": [], "summary": {"total": 0, "passed": 0, "failed": 0, "errors": 0}}')  
        results_file = default_results_file
        logger.info(f"Created default results file: {results_file}")
    
    if not os.path.exists(results_file):
        logger.error(f"Results file not found: {results_file}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Generate report
    try:
        report_file = generate_report(
            results_file=results_file,
            output_dir=args.output_dir,
            format=args.format
        )
        logger.info(f"Report generated at {report_file}")
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
