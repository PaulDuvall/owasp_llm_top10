"""
Tests for the test runner module.

User Story: US-104 - As a security tester, I need to run automated tests against
LLMs to identify prompt injection vulnerabilities.
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from pathlib import Path

# Import the module instead of the classes directly
import src.llm01_prompt_injection.test_runner as test_runner_module
from src.llm01_prompt_injection.attack_vectors import AttackVector
from src.llm01_prompt_injection.llm_client import LLMClient


# Mock LLM client for testing
class MockLLMClient(LLMClient):
    """Mock LLM client for testing."""
    
    def __init__(self, responses=None):
        """Initialize the mock client."""
        self.responses = responses or [{
            "content": "This is a test response",
            "model": "test-model",
            "finish_reason": "stop",
            "provider": "test"
        }]
        self.call_count = 0
    
    def send_prompt(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000):
        """Mock sending a prompt."""
        self.call_count += 1
        response = self.responses[min(self.call_count - 1, len(self.responses) - 1)]
        return response
    
    def get_name(self):
        """Mock getting the client name."""
        return "Test LLM Client"


# Test data
@pytest.fixture
def test_attack_vector():
    """Create a test attack vector."""
    return AttackVector(
        id="TEST-001",
        name="Test Vector",
        description="Test description",
        category="test",
        severity="medium",
        prompts=["Test prompt"],
        detection_patterns=["test pattern"],
        references=["Test reference"],
        mitigation="Test mitigation"
    )


@pytest.fixture
def test_result(test_attack_vector):
    """Create a test result."""
    return test_runner_module.TestResult(
        attack_vector=test_attack_vector,
        prompt="Test prompt",
        response={
            "content": "This is a test response",
            "model": "test-model",
            "finish_reason": "stop",
            "provider": "test"
        },
        detection_result={
            "injection_detected": False,
            "detection_details": {
                "matched_patterns": [],
                "forbidden_phrases_found": [],
                "confidence_score": 0.0
            },
            "content_analysis": {
                "detected_categories": {},
                "overall_risk_score": 0.0,
                "detected_terms": []
            },
            "overall_assessment": {
                "is_potentially_harmful": False,
                "risk_level": "low"
            }
        }
    )


class TestResultClass:
    """Tests for the TestResult class."""
    
    def test_to_dict(self, test_result):
        """Test converting a test result to a dictionary."""
        result_dict = test_result.to_dict()
        
        assert result_dict["attack_vector"]["id"] == "TEST-001"
        assert result_dict["attack_vector"]["name"] == "Test Vector"
        assert result_dict["prompt"] == "Test prompt"
        assert result_dict["response"]["content"] == "This is a test response"
        assert result_dict["response"]["model"] == "test-model"
        assert result_dict["response"]["provider"] == "test"
        assert result_dict["detection"]["injection_detected"] == False
        assert result_dict["detection"]["risk_level"] == "low"
        assert isinstance(result_dict["timestamp"], str)


class TestRunnerClass:
    """Tests for the TestRunner class."""
    
    def setup_method(self):
        """Set up the test environment."""
        self.output_dir = "test-output"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Create a mock LLM client
        self.llm_client = MockLLMClient()
        
        # Create a test runner
        self.runner = test_runner_module.TestRunner(
            llm_client=self.llm_client,
            output_dir=self.output_dir,
            system_prompt="Test system prompt"
        )
    
    def teardown_method(self):
        """Clean up after the test."""
        # Remove test output directory
        import shutil
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
    
    def test_run_test(self, test_attack_vector):
        """Test running a single test."""
        # Mock the detect_prompt_injection function
        with patch("src.llm01_prompt_injection.test_runner.detect_prompt_injection") as mock_detect:
            mock_detect.return_value = {
                "injection_detected": True,
                "detection_details": {
                    "matched_patterns": ["test pattern"],
                    "forbidden_phrases_found": [],
                    "confidence_score": 0.7
                },
                "content_analysis": {
                    "detected_categories": {},
                    "overall_risk_score": 0.5,
                    "detected_terms": []
                },
                "overall_assessment": {
                    "is_potentially_harmful": True,
                    "risk_level": "high"
                }
            }
            
            # Run the test
            result = self.runner.run_test(test_attack_vector)
            
            # Check that the LLM client was called
            assert self.llm_client.call_count == 1
            
            # Check that detect_prompt_injection was called
            mock_detect.assert_called_once()
            
            # Check the result
            assert result.attack_vector == test_attack_vector
            assert result.prompt == "Test prompt"
            assert result.response["content"] == "This is a test response"
            assert result.detection_result["injection_detected"] == True
            
            # Check that the result was added to the runner's results
            assert len(self.runner.results) == 1
            assert self.runner.results[0] == result
    
    def test_run_tests(self, test_attack_vector):
        """Test running multiple tests."""
        # Reset the call count before the test
        self.llm_client.call_count = 0
        
        # Create a second attack vector with a different ID to avoid deduplication
        second_vector = AttackVector(
            id="TEST-002",  # Different ID
            name="Test Vector 2",
            description="Test description",
            category="test",
            severity="medium",
            prompts=["Test prompt"],
            detection_patterns=["test pattern"],
            references=["Test reference"],
            mitigation="Test mitigation"
        )
        
        # Mock the detect_prompt_injection function and time.sleep
        with patch("src.llm01_prompt_injection.test_runner.detect_prompt_injection") as mock_detect, \
             patch("src.llm01_prompt_injection.test_runner.time.sleep"):
            mock_detect.return_value = {
                "injection_detected": False,
                "detection_details": {
                    "matched_patterns": [],
                    "forbidden_phrases_found": [],
                    "confidence_score": 0.0
                },
                "content_analysis": {
                    "detected_categories": {},
                    "overall_risk_score": 0.0,
                    "detected_terms": []
                },
                "overall_assessment": {
                    "is_potentially_harmful": False,
                    "risk_level": "low"
                }
            }
            
            # Run the tests with two different attack vectors
            results = self.runner.run_tests(attack_vectors=[test_attack_vector, second_vector])
            
            # Check that the LLM client was called twice
            assert self.llm_client.call_count == 2
            
            # Check that detect_prompt_injection was called twice
            assert mock_detect.call_count == 2
            
            # Check the results
            assert len(results) == 2
            assert results[0].attack_vector == test_attack_vector
            assert results[1].attack_vector == second_vector
            
            # Check that the results were added to the runner's results
            assert len(self.runner.results) == 2
    
    def test_save_results(self, test_attack_vector):
        """Test saving test results to a file."""
        # Add a test result to the runner
        with patch("src.llm01_prompt_injection.test_runner.detect_prompt_injection") as mock_detect:
            mock_detect.return_value = {
                "injection_detected": False,
                "detection_details": {
                    "matched_patterns": [],
                    "forbidden_phrases_found": [],
                    "confidence_score": 0.0
                },
                "content_analysis": {
                    "detected_categories": {},
                    "overall_risk_score": 0.0,
                    "detected_terms": []
                },
                "overall_assessment": {
                    "is_potentially_harmful": False,
                    "risk_level": "low"
                }
            }
            
            self.runner.run_test(test_attack_vector)
        
        # Save the results
        filename = "test_results.json"
        filepath = self.runner.save_results(filename)
        
        # Check that the file was created
        assert os.path.exists(filepath)
        
        # Check the file contents
        with open(filepath, 'r') as f:
            data = json.load(f)
            
            assert "summary" in data
            assert "results" in data
            assert len(data["results"]) == 1
            assert data["results"][0]["attack_vector"]["id"] == "TEST-001"
    
    def test_generate_report(self, test_attack_vector):
        """Test generating a report from test results."""
        # Add test results to the runner
        with patch("src.llm01_prompt_injection.test_runner.detect_prompt_injection") as mock_detect:
            # First test: no injection
            mock_detect.return_value = {
                "injection_detected": False,
                "detection_details": {
                    "matched_patterns": [],
                    "forbidden_phrases_found": [],
                    "confidence_score": 0.0
                },
                "content_analysis": {
                    "detected_categories": {},
                    "overall_risk_score": 0.0,
                    "detected_terms": []
                },
                "overall_assessment": {
                    "is_potentially_harmful": False,
                    "risk_level": "low"
                }
            }
            
            self.runner.run_test(test_attack_vector)
            
            # Second test: injection detected
            mock_detect.return_value = {
                "injection_detected": True,
                "detection_details": {
                    "matched_patterns": ["test pattern"],
                    "forbidden_phrases_found": [],
                    "confidence_score": 0.7
                },
                "content_analysis": {
                    "detected_categories": {"hacking": {"score": 0.5, "detected_terms": ["exploit"]}},
                    "overall_risk_score": 0.5,
                    "detected_terms": ["exploit"]
                },
                "overall_assessment": {
                    "is_potentially_harmful": True,
                    "risk_level": "high"
                }
            }
            
            self.runner.run_test(test_attack_vector)
        
        # Generate the report
        report = self.runner.generate_report()
        
        # Check the report
        assert "summary" in report
        assert "vulnerabilities_by_category" in report
        assert "vulnerabilities_by_severity" in report
        assert "detailed_results" in report
        
        assert report["summary"]["total_tests"] == 2
        assert report["summary"]["vulnerabilities_detected"] == 1
        
        assert "test" in report["vulnerabilities_by_category"]
        assert report["vulnerabilities_by_category"]["test"]["total"] == 2
        assert report["vulnerabilities_by_category"]["test"]["vulnerable"] == 1
        
        assert "medium" in report["vulnerabilities_by_severity"]
        assert report["vulnerabilities_by_severity"]["medium"]["total"] == 2
        assert report["vulnerabilities_by_severity"]["medium"]["vulnerable"] == 1
        
        assert len(report["detailed_results"]) == 2


def test_run_prompt_injection_tests():
    """Test the run_prompt_injection_tests convenience function."""
    # Mock the TestRunner class and OpenAI client
    with patch("tests.llm01_prompt_injection.test_test_runner.test_runner_module.TestRunner") as MockTestRunner, \
         patch("src.llm01_prompt_injection.llm_client.openai"), \
         patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}):
        # Mock the runner instance
        mock_runner = MagicMock()
        MockTestRunner.return_value = mock_runner
        
        # Mock the run_tests method
        mock_runner.run_tests.return_value = []
        
        # Mock the save_results method
        mock_runner.save_results.return_value = "test-results/results.json"
        
        # Run the function
        result = test_runner_module.run_prompt_injection_tests(
            llm_provider="openai",
            model="gpt-3.5-turbo",
            categories=["direct"],
            severities=["high"],
            system_prompt="Test system prompt",
            output_dir="test-results"
        )
        
        # Check that the TestRunner was created with the correct arguments
        MockTestRunner.assert_called_once()
        
        # Check that run_tests was called with the correct arguments
        mock_runner.run_tests.assert_called_once_with(
            categories=["direct"],
            severities=["high"]
        )
        
        # Check that save_results was called
        mock_runner.save_results.assert_called_once()
        
        # Check the result
        assert result == "test-results/results.json"
