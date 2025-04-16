#!/usr/bin/env python3
"""
Prompt Injection Test Runner Script

This script runs prompt injection tests against LLM providers and generates reports.

User Story: US-106 - As a security tester, I need a command-line interface to run
prompt injection tests and generate reports.
"""

import os
import sys
import argparse
import logging
from datetime import datetime
from typing import List, Optional

# Add the parent directory to the path so we can import the src modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import our modules
from src.llm01_prompt_injection.llm_client import get_llm_client
from src.llm01_prompt_injection.attack_vectors import get_attack_vectors, get_attack_vector_by_id
from src.llm01_prompt_injection.test_runner import TestRunner
from src.llm01_prompt_injection.reporting import generate_report

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run prompt injection tests against LLM providers.")
    
    # LLM provider options
    parser.add_argument(
        "--provider", 
        type=str, 
        default="openai",
        choices=["openai"], 
        help="LLM provider to test (default: openai)"
    )
    parser.add_argument(
        "--model", 
        type=str, 
        help="Model to use (default: provider's default model)"
    )
    
    # Test selection options
    parser.add_argument(
        "--categories", 
        type=str, 
        nargs="+", 
        choices=["direct", "indirect", "goal_hijacking", "prompt_leaking", "jailbreaking"],
        help="Categories of attack vectors to test"
    )
    parser.add_argument(
        "--severities", 
        type=str, 
        nargs="+", 
        choices=["low", "medium", "high", "critical"],
        help="Severities of attack vectors to test"
    )
    parser.add_argument(
        "--vector-ids", 
        type=str, 
        nargs="+", 
        help="Specific attack vector IDs to test"
    )
    
    # Output options
    parser.add_argument(
        "--output-dir", 
        type=str, 
        default="test-results",
        help="Directory to store test results (default: test-results)"
    )
    parser.add_argument(
        "--report-format", 
        type=str, 
        default="html",
        choices=["html", "markdown", "md", "json"], 
        help="Report format (default: html)"
    )
    
    # System prompt
    parser.add_argument(
        "--system-prompt", 
        type=str, 
        help="System prompt to use for all tests"
    )
    parser.add_argument(
        "--system-prompt-file", 
        type=str, 
        help="File containing the system prompt to use for all tests"
    )
    
    return parser.parse_args()


def main():
    """Main function."""
    args = parse_args()
    
    # Get system prompt
    system_prompt = None
    if args.system_prompt:
        system_prompt = args.system_prompt
    elif args.system_prompt_file:
        try:
            with open(args.system_prompt_file, 'r') as f:
                system_prompt = f.read().strip()
        except Exception as e:
            logger.error(f"Error reading system prompt file: {str(e)}")
            sys.exit(1)
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Get attack vectors to test
    attack_vectors = []
    if args.vector_ids:
        for vector_id in args.vector_ids:
            vector = get_attack_vector_by_id(vector_id)
            if vector:
                attack_vectors.append(vector)
            else:
                logger.warning(f"Attack vector with ID {vector_id} not found")
    
    # Create LLM client
    try:
        llm_client = get_llm_client(provider=args.provider, model=args.model)
    except Exception as e:
        logger.error(f"Error creating LLM client: {str(e)}")
        sys.exit(1)
    
    # Create test runner
    runner = TestRunner(
        llm_client=llm_client,
        output_dir=args.output_dir,
        system_prompt=system_prompt
    )
    
    # Run tests
    try:
        logger.info("Running prompt injection tests...")
        runner.run_tests(
            attack_vectors=attack_vectors,
            categories=args.categories,
            severities=args.severities
        )
    except Exception as e:
        logger.error(f"Error running tests: {str(e)}")
        sys.exit(1)
    
    # Save results
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = runner.save_results(f"prompt_injection_test_results_{timestamp}.json")
        logger.info(f"Test results saved to {results_file}")
    except Exception as e:
        logger.error(f"Error saving test results: {str(e)}")
        sys.exit(1)
    
    # Generate report
    if args.report_format != "json":
        try:
            report_file = generate_report(
                results_file=results_file,
                output_dir=args.output_dir,
                format=args.report_format
            )
            logger.info(f"Report generated at {report_file}")
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            sys.exit(1)
    
    # Print summary
    summary = runner.results[0].to_dict()["detection"] if runner.results else {}
    vulnerabilities_detected = sum(1 for r in runner.results if r.detection_result.get("injection_detected", False))
    logger.info(f"Tests completed: {len(runner.results)} tests run, {vulnerabilities_detected} vulnerabilities detected")


if __name__ == "__main__":
    main()
