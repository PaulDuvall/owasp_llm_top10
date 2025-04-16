#!/usr/bin/env python3
"""
Prompt Injection Vulnerability Analysis Script

This script analyzes prompt injection test results to identify vulnerabilities
and set environment variables for GitHub Actions.

User Story: US-108 - As a security tester, I need to automatically analyze test
results to identify and report vulnerabilities.
"""

import os
import sys
import json
import logging
import glob
from datetime import datetime
from typing import Dict, List, Any, Optional
import argparse

# Add the parent directory to the path so we can import the src modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import our modules
from src.llm01_prompt_injection.detection import detect_prompt_injection, InjectionDetector, ContentAnalyzer
from src.llm01_prompt_injection.attack_vectors import get_attack_vectors, get_attack_vector_by_id

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Analyze prompt injection test results for vulnerabilities.")
    
    parser.add_argument(
        "--results-file", 
        type=str, 
        help="Path to the JSON results file"
    )
    parser.add_argument(
        "--output-dir", 
        type=str, 
        default="test-results",
        help="Directory containing test results (default: test-results)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    return parser.parse_args()


def get_latest_results_file(output_dir: str = "test-results") -> Optional[str]:
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
    logger.info(f"Found latest results file: {all_files[0]}")
    return all_files[0]


def analyze_vulnerabilities(results_file: str) -> Dict[str, Any]:
    """Analyze vulnerabilities in the test results."""
    try:
        with open(results_file, 'r') as f:
            results = json.load(f)
    except Exception as e:
        logger.error(f"Error loading results from {results_file}: {str(e)}")
        raise
    
    # Extract summary information
    summary = results.get("summary", {})
    total_tests = summary.get("total_tests", 0)
    vulnerabilities_detected = summary.get("vulnerabilities_detected", 0)
    
    # Count vulnerabilities by category and severity
    vulnerabilities_by_category = {}
    vulnerabilities_by_severity = {}
    critical_vulnerabilities = []
    high_vulnerabilities = []
    
    for result in results.get("results", []):
        attack_vector = result.get("attack_vector", {})
        category = attack_vector.get("category", "unknown")
        severity = attack_vector.get("severity", "unknown")
        is_vulnerable = result.get("detection", {}).get("injection_detected", False)
        
        # Initialize counters if needed
        if category not in vulnerabilities_by_category:
            vulnerabilities_by_category[category] = {"total": 0, "vulnerable": 0}
        if severity not in vulnerabilities_by_severity:
            vulnerabilities_by_severity[severity] = {"total": 0, "vulnerable": 0}
        
        # Update counters
        vulnerabilities_by_category[category]["total"] += 1
        vulnerabilities_by_severity[severity]["total"] += 1
        
        if is_vulnerable:
            vulnerabilities_by_category[category]["vulnerable"] += 1
            vulnerabilities_by_severity[severity]["vulnerable"] += 1
            
            # Add to critical/high vulnerabilities lists
            if severity == "critical":
                critical_vulnerabilities.append({
                    "id": attack_vector.get("id", ""),
                    "name": attack_vector.get("name", ""),
                    "category": category
                })
            elif severity == "high":
                high_vulnerabilities.append({
                    "id": attack_vector.get("id", ""),
                    "name": attack_vector.get("name", ""),
                    "category": category
                })
    
    # Calculate vulnerability percentages
    vulnerability_percentage = (vulnerabilities_detected / total_tests * 100) if total_tests > 0 else 0
    
    # Determine overall vulnerability level
    if vulnerabilities_by_severity.get("critical", {}).get("vulnerable", 0) > 0:
        vulnerability_level = "critical"
    elif vulnerabilities_by_severity.get("high", {}).get("vulnerable", 0) > 0:
        vulnerability_level = "high"
    elif vulnerabilities_by_severity.get("medium", {}).get("vulnerable", 0) > 0:
        vulnerability_level = "medium"
    elif vulnerabilities_by_severity.get("low", {}).get("vulnerable", 0) > 0:
        vulnerability_level = "low"
    else:
        vulnerability_level = "none"
    
    # Create the analysis results
    analysis = {
        "total_tests": total_tests,
        "vulnerabilities_detected": vulnerabilities_detected,
        "vulnerability_percentage": round(vulnerability_percentage, 2),
        "vulnerability_level": vulnerability_level,
        "by_category": vulnerabilities_by_category,
        "by_severity": vulnerabilities_by_severity,
        "critical_vulnerabilities": critical_vulnerabilities,
        "high_vulnerabilities": high_vulnerabilities,
        "timestamp": datetime.now().isoformat()
    }
    
    return analysis


def set_github_actions_output(analysis: Dict[str, Any]):
    """Set GitHub Actions output variables."""
    # Check if running in GitHub Actions
    if os.environ.get("GITHUB_ACTIONS") != "true":
        logger.info("Not running in GitHub Actions, skipping output variables")
        return
    
    # Set output variables
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"vulnerabilities_detected={analysis['vulnerabilities_detected']}\n")
        f.write(f"vulnerability_level={analysis['vulnerability_level']}\n")
        f.write(f"vulnerability_percentage={analysis['vulnerability_percentage']}\n")
    
    # Set environment variable for workflow to detect vulnerabilities
    if analysis["vulnerabilities_detected"] > 0:
        with open(os.environ["GITHUB_ENV"], "a") as f:
            f.write("VULNERABILITIES_DETECTED=true\n")


def main():
    """Main function."""
    # Parse command line arguments
    args = parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
        # List all files in the test-results directory for debugging
        if os.path.exists(args.output_dir):
            logger.debug(f"Contents of {args.output_dir}:")
            for file in os.listdir(args.output_dir):
                file_path = os.path.join(args.output_dir, file)
                logger.debug(f"  {file} ({os.path.getsize(file_path)} bytes, modified {datetime.fromtimestamp(os.path.getmtime(file_path))})")
        else:
            logger.debug(f"Directory {args.output_dir} does not exist")
    
    # Get results file
    results_file = args.results_file
    if not results_file:
        results_file = get_latest_results_file(args.output_dir)
        if not results_file:
            # Create an empty results file if none exists
            logger.warning("No results files found, creating an empty results file")
            os.makedirs(args.output_dir, exist_ok=True)
            empty_results_file = os.path.join(args.output_dir, f"report-{datetime.now().strftime('%Y%m%d%H%M%S')}.json")
            with open(empty_results_file, 'w') as f:
                f.write('{"results": [], "summary": {"total_tests": 0, "vulnerabilities_detected": 0}}')
            results_file = empty_results_file
            logger.info(f"Created empty results file: {results_file}")
    
    logger.info(f"Analyzing vulnerabilities in {results_file}")
    
    # Analyze vulnerabilities
    try:
        analysis = analyze_vulnerabilities(results_file)
    except Exception as e:
        logger.error(f"Error analyzing vulnerabilities: {str(e)}")
        sys.exit(1)
    
    # Print analysis summary
    logger.info(f"Vulnerability analysis complete:")
    logger.info(f"  Total tests: {analysis['total_tests']}")
    logger.info(f"  Vulnerabilities detected: {analysis['vulnerabilities_detected']} ({analysis['vulnerability_percentage']}%)")
    logger.info(f"  Vulnerability level: {analysis['vulnerability_level']}")
    
    if analysis["critical_vulnerabilities"]:
        logger.warning(f"Critical vulnerabilities detected:")
        for vuln in analysis["critical_vulnerabilities"]:
            logger.warning(f"  {vuln['id']}: {vuln['name']} ({vuln['category']})")
    
    if analysis["high_vulnerabilities"]:
        logger.warning(f"High vulnerabilities detected:")
        for vuln in analysis["high_vulnerabilities"]:
            logger.warning(f"  {vuln['id']}: {vuln['name']} ({vuln['category']})")
    
    # Set GitHub Actions output variables
    set_github_actions_output(analysis)
    
    # Exit with non-zero status if vulnerabilities detected
    if analysis["vulnerabilities_detected"] > 0:
        logger.warning("Vulnerabilities detected, exiting with status code 1")
        sys.exit(1)
    else:
        logger.info("No vulnerabilities detected")


if __name__ == "__main__":
    main()
