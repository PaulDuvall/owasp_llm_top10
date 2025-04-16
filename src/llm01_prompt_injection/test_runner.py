"""
Test Runner Module - Executes prompt injection tests against LLM providers.

This module provides functionality to run prompt injection tests against various
LLM providers and analyze the results to detect successful attacks.

User Story: US-104 - As a security tester, I need to run automated tests against
LLMs to identify prompt injection vulnerabilities.
"""

import os
import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path

# Local imports
from src.llm01_prompt_injection.llm_client import LLMClient, get_llm_client
from src.llm01_prompt_injection.attack_vectors import AttackVector, get_attack_vectors, get_attack_vector_by_id
from src.llm01_prompt_injection.detection import detect_prompt_injection, InjectionDetector, ContentAnalyzer

# Mark classes that should not be collected by pytest
__test__ = {"TestResult": False, "TestRunner": False}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TestResult:
    """Represents the result of a prompt injection test.
    
    Note: This is not a pytest test class, it's a data class for test results.
    """
    
    def __init__(self, 
                 attack_vector: AttackVector,
                 prompt: str,
                 response: Dict[str, Any],
                 detection_result: Dict[str, Any],
                 timestamp: Optional[datetime] = None):
        """
        Initialize a test result.
        
        Args:
            attack_vector: The attack vector used in the test
            prompt: The prompt sent to the LLM
            response: The LLM's response
            detection_result: The result of the injection detection
            timestamp: When the test was run (defaults to now)
        """
        self.attack_vector = attack_vector
        self.prompt = prompt
        self.response = response
        self.detection_result = detection_result
        self.timestamp = timestamp or datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the test result to a dictionary."""
        return {
            "attack_vector": {
                "id": self.attack_vector.id,
                "name": self.attack_vector.name,
                "category": self.attack_vector.category,
                "severity": self.attack_vector.severity
            },
            "prompt": self.prompt,
            "response": {
                "content": self.response.get("content", ""),
                "model": self.response.get("model", ""),
                "provider": self.response.get("provider", "")
            },
            "detection": {
                "injection_detected": self.detection_result.get("injection_detected", False),
                "risk_level": self.detection_result.get("overall_assessment", {}).get("risk_level", "low"),
                "matched_patterns": self.detection_result.get("detection_details", {}).get("matched_patterns", []),
                "detected_terms": self.detection_result.get("content_analysis", {}).get("detected_terms", [])
            },
            "timestamp": self.timestamp.isoformat()
        }


class TestRunner:
    """Runs prompt injection tests against LLM providers.
    
    Note: This is not a pytest test class, it's a runner for prompt injection tests.
    """
    
    def __init__(self, 
                 llm_client: Optional[LLMClient] = None,
                 output_dir: str = "test-results",
                 system_prompt: Optional[str] = None):
        """
        Initialize the test runner.
        
        Args:
            llm_client: Optional LLM client to use (will create default if None)
            output_dir: Directory to store test results
            system_prompt: Optional system prompt to use for all tests
        """
        self.llm_client = llm_client or get_llm_client()
        self.output_dir = output_dir
        self.system_prompt = system_prompt
        self.results: List[TestResult] = []
        
        # Create output directory if it doesn't exist
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized TestRunner with {self.llm_client.get_name()} and output directory {output_dir}")
    
    def run_test(self, attack_vector: AttackVector, prompt_index: int = 0) -> TestResult:
        """
        Run a single prompt injection test.
        
        Args:
            attack_vector: The attack vector to test
            prompt_index: Index of the prompt to use from the attack vector
            
        Returns:
            TestResult containing the test results
        """
        # Get the prompt to use
        if prompt_index >= len(attack_vector.prompts):
            prompt_index = 0
        
        prompt = attack_vector.prompts[prompt_index]
        
        # Log test information
        logger.info(f"Running test for attack vector {attack_vector.id}: {attack_vector.name}")
        logger.info(f"Using prompt: {prompt}")
        
        # Send the prompt to the LLM
        try:
            response = self.llm_client.send_prompt(
                prompt=prompt,
                system_prompt=self.system_prompt
            )
            
            # Detect if the prompt injection was successful
            detection_result = detect_prompt_injection(
                response_content=response.get("content", ""),
                attack_vector=attack_vector
            )
            
            # Create and store the test result
            result = TestResult(
                attack_vector=attack_vector,
                prompt=prompt,
                response=response,
                detection_result=detection_result
            )
            
            self.results.append(result)
            
            # Log detection result
            if detection_result.get("injection_detected", False):
                logger.warning(f"Prompt injection detected for {attack_vector.id}: {attack_vector.name}")
            else:
                logger.info(f"No prompt injection detected for {attack_vector.id}: {attack_vector.name}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error running test for {attack_vector.id}: {str(e)}")
            raise
    
    def run_tests(self, attack_vectors: Optional[List[AttackVector]] = None, 
                 categories: Optional[List[str]] = None,
                 severities: Optional[List[str]] = None) -> List[TestResult]:
        """
        Run multiple prompt injection tests.
        
        Args:
            attack_vectors: Optional list of attack vectors to test
            categories: Optional list of categories to filter attack vectors
            severities: Optional list of severities to filter attack vectors
            
        Returns:
            List of TestResult objects
        """
        # Get attack vectors to test
        vectors_to_test = attack_vectors or []
        
        if not vectors_to_test and (categories or severities):
            # Filter attack vectors by category and severity
            for category in categories or [None]:
                for severity in severities or [None]:
                    vectors_to_test.extend(get_attack_vectors(category=category, severity=severity))
        elif not vectors_to_test:
            # Use all attack vectors
            vectors_to_test = get_attack_vectors()
        
        # Remove duplicates while preserving order
        seen = set()
        vectors_to_test = [v for v in vectors_to_test if not (v.id in seen or seen.add(v.id))]
        
        logger.info(f"Running {len(vectors_to_test)} prompt injection tests")
        
        # Run tests for each attack vector
        results = []
        for vector in vectors_to_test:
            try:
                # Use a random prompt from the attack vector
                import random
                prompt_index = random.randint(0, len(vector.prompts) - 1)
                
                result = self.run_test(vector, prompt_index)
                results.append(result)
                
                # Add a small delay to avoid rate limiting
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error running test for {vector.id}: {str(e)}")
        
        return results
    
    def save_results(self, filename: Optional[str] = None) -> str:
        """
        Save test results to a JSON file.
        
        Args:
            filename: Optional filename to use
            
        Returns:
            Path to the saved results file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"prompt_injection_test_results_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Convert results to dictionaries
        results_dict = [result.to_dict() for result in self.results]
        
        # Add summary information
        summary = {
            "total_tests": len(results_dict),
            "vulnerabilities_detected": sum(1 for r in results_dict if r["detection"]["injection_detected"]),
            "risk_levels": {
                "high": sum(1 for r in results_dict if r["detection"]["risk_level"] == "high"),
                "medium": sum(1 for r in results_dict if r["detection"]["risk_level"] == "medium"),
                "low": sum(1 for r in results_dict if r["detection"]["risk_level"] == "low")
            },
            "llm_provider": self.llm_client.get_name(),
            "timestamp": datetime.now().isoformat()
        }
        
        # Create the full output
        output = {
            "summary": summary,
            "results": results_dict
        }
        
        # Write to file
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)
        
        logger.info(f"Saved test results to {filepath}")
        return filepath
    
    def generate_report(self, include_prompts: bool = True, 
                       include_responses: bool = True) -> Dict[str, Any]:
        """
        Generate a report of test results.
        
        Args:
            include_prompts: Whether to include the prompts in the report
            include_responses: Whether to include the responses in the report
            
        Returns:
            Dictionary containing the report data
        """
        # Count vulnerabilities by category and severity
        vulnerabilities_by_category = {}
        vulnerabilities_by_severity = {}
        
        for result in self.results:
            category = result.attack_vector.category
            severity = result.attack_vector.severity
            is_vulnerable = result.detection_result.get("injection_detected", False)
            
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
        
        # Create the report
        report = {
            "summary": {
                "total_tests": len(self.results),
                "vulnerabilities_detected": sum(1 for r in self.results if r.detection_result.get("injection_detected", False)),
                "llm_provider": self.llm_client.get_name(),
                "timestamp": datetime.now().isoformat()
            },
            "vulnerabilities_by_category": vulnerabilities_by_category,
            "vulnerabilities_by_severity": vulnerabilities_by_severity,
            "detailed_results": []
        }
        
        # Add detailed results if requested
        if include_prompts or include_responses:
            for result in self.results:
                detail = {
                    "attack_vector": {
                        "id": result.attack_vector.id,
                        "name": result.attack_vector.name,
                        "category": result.attack_vector.category,
                        "severity": result.attack_vector.severity
                    },
                    "injection_detected": result.detection_result.get("injection_detected", False),
                    "risk_level": result.detection_result.get("overall_assessment", {}).get("risk_level", "low")
                }
                
                if include_prompts:
                    detail["prompt"] = result.prompt
                
                if include_responses:
                    detail["response"] = result.response.get("content", "")
                    detail["matched_patterns"] = result.detection_result.get("detection_details", {}).get("matched_patterns", [])
                    detail["detected_terms"] = result.detection_result.get("content_analysis", {}).get("detected_terms", [])
                
                report["detailed_results"].append(detail)
        
        return report


def run_prompt_injection_tests(llm_provider: str = "openai", 
                              model: Optional[str] = None,
                              categories: Optional[List[str]] = None,
                              severities: Optional[List[str]] = None,
                              system_prompt: Optional[str] = None,
                              output_dir: str = "test-results") -> str:
    """
    Convenience function to run prompt injection tests.
    
    Args:
        llm_provider: LLM provider to test (openai)
        model: Optional model to use
        categories: Optional list of categories to filter attack vectors
        severities: Optional list of severities to filter attack vectors
        system_prompt: Optional system prompt to use for all tests
        output_dir: Directory to store test results
        
    Returns:
        Path to the saved results file
    """
    # Create LLM client
    llm_client = get_llm_client(provider=llm_provider, model=model)
    
    # Create test runner
    runner = TestRunner(
        llm_client=llm_client,
        output_dir=output_dir,
        system_prompt=system_prompt
    )
    
    # Run tests
    runner.run_tests(categories=categories, severities=severities)
    
    # Save results
    return runner.save_results()
