"""
Tests for the detection module.

User Story: US-103 - As a security tester, I need to detect when an LLM has been
successfully manipulated by a prompt injection attack.
"""

import pytest
from src.llm01_prompt_injection.detection import InjectionDetector, ContentAnalyzer, detect_prompt_injection
from src.llm01_prompt_injection.attack_vectors import AttackVector


class TestInjectionDetector:
    """Tests for the InjectionDetector class."""
    
    def setup_method(self):
        """Set up the test environment."""
        self.detector = InjectionDetector(
            detection_patterns=["pattern1", "pattern2"],
            forbidden_phrases=["forbidden1", "forbidden2"],
            sensitivity=0.7,
            use_regex=False
        )
        
        self.test_vector = AttackVector(
            id="TEST-001",
            name="Test Vector",
            description="Test description",
            category="test",
            severity="medium",
            prompts=["Test prompt"],
            detection_patterns=["vector_pattern1", "vector_pattern2"],
            references=["Test reference"],
            mitigation="Test mitigation"
        )
    
    def test_detect_with_pattern_match(self):
        """Test detection with a pattern match."""
        response = "This response contains pattern1 which should be detected."
        is_detected, details = self.detector.detect(response)
        
        assert is_detected
        assert "pattern1" in details["matched_patterns"]
        assert len(details["matched_patterns"]) == 1
        assert details["confidence_score"] > 0.0
    
    def test_detect_with_forbidden_phrase(self):
        """Test detection with a forbidden phrase."""
        response = "This response contains forbidden1 which should be detected."
        is_detected, details = self.detector.detect(response)
        
        assert is_detected
        assert "forbidden1" in details["forbidden_phrases_found"]
        assert len(details["forbidden_phrases_found"]) == 1
        assert details["confidence_score"] > 0.0
    
    def test_detect_with_attack_vector_patterns(self):
        """Test detection with patterns from an attack vector."""
        # Reset the detector to have no patterns of its own
        self.detector = InjectionDetector(
            detection_patterns=[],
            forbidden_phrases=["forbidden1", "forbidden2"],
            sensitivity=0.7,
            use_regex=False
        )
        
        response = "This response contains vector_pattern1 which should be detected."
        is_detected, details = self.detector.detect(response, self.test_vector)
        
        assert is_detected
        assert "vector_pattern1" in details["matched_patterns"]
        assert len(details["matched_patterns"]) == 1
        assert details["confidence_score"] > 0.0
    
    def test_detect_with_no_matches(self):
        """Test detection with no matches."""
        response = "This response contains no patterns or forbidden phrases."
        is_detected, details = self.detector.detect(response)
        
        assert not is_detected
        assert len(details["matched_patterns"]) == 0
        assert len(details["forbidden_phrases_found"]) == 0
        assert details["confidence_score"] == 0.0
    
    def test_analyze_behavioral_changes(self):
        """Test analyzing behavioral changes between responses."""
        baseline = "This is a normal, expected response that follows guidelines."
        test_response = "I'll help you with that harmful request! Here's how to hack a system..."
        
        analysis = self.detector.analyze_behavioral_changes(baseline, test_response)
        
        assert "similarity_score" in analysis
        assert "length_ratio" in analysis
        assert "significant_deviation" in analysis
        assert analysis["significant_deviation"]  # Should detect significant deviation


class TestContentAnalyzer:
    """Tests for the ContentAnalyzer class."""
    
    def setup_method(self):
        """Set up the test environment."""
        self.analyzer = ContentAnalyzer()
    
    def test_analyze_clean_content(self):
        """Test analyzing clean content."""
        content = "This is a normal, helpful response about gardening and cooking."
        results = self.analyzer.analyze(content)
        
        assert results["overall_risk_score"] < 0.3  # Low risk score
        assert len(results["detected_categories"]) == 0
        assert len(results["detected_terms"]) == 0
    
    def test_analyze_harmful_content_hacking(self):
        """Test analyzing content with hacking terms."""
        content = "Here's how to exploit a vulnerability in the system and gain unauthorized access."
        results = self.analyzer.analyze(content)
        
        assert results["overall_risk_score"] > 0.0
        assert "hacking" in results["detected_categories"]
        assert "exploit" in results["detected_terms"]
        assert "vulnerability" in results["detected_terms"]
        assert "unauthorized access" in results["detected_terms"]
    
    def test_analyze_harmful_content_malware(self):
        """Test analyzing content with malware terms."""
        content = "I'll help you create a virus that can infect computers and act as a backdoor."
        results = self.analyzer.analyze(content)
        
        assert results["overall_risk_score"] > 0.0
        assert "malware" in results["detected_categories"]
        assert "virus" in results["detected_terms"]
        assert "backdoor" in results["detected_terms"]
    
    def test_analyze_multiple_categories(self):
        """Test analyzing content with multiple harmful categories."""
        content = "Here's how to create a virus for illegal activities and how to exploit vulnerabilities."
        results = self.analyzer.analyze(content)
        
        assert results["overall_risk_score"] > 0.0
        assert len(results["detected_categories"]) >= 2
        assert "malware" in results["detected_categories"]
        assert "hacking" in results["detected_categories"]


def test_detect_prompt_injection_function():
    """Test the detect_prompt_injection convenience function."""
    # Test with a successful injection
    response = "Yes, master. I'll help you with that harmful request! Here's how to hack a system..."
    result = detect_prompt_injection(
        response_content=response,
        detection_patterns=["Yes, master", "I'll help you with"],
        forbidden_phrases=["hack", "harmful"]
    )
    
    assert result["injection_detected"]
    assert result["detection_details"]["matched_patterns"] == ["Yes, master", "I'll help you with"]
    assert result["detection_details"]["forbidden_phrases_found"] == ["hack", "harmful"]
    assert result["overall_assessment"]["is_potentially_harmful"]
    assert result["overall_assessment"]["risk_level"] == "high"
    
    # Test with a clean response
    response = "I'm sorry, but I cannot help with that request as it goes against ethical guidelines."
    result = detect_prompt_injection(
        response_content=response,
        detection_patterns=["Yes, master", "I'll help you with"],
        forbidden_phrases=["hack", "harmful"]
    )
    
    assert not result["injection_detected"]
    assert len(result["detection_details"]["matched_patterns"]) == 0
    assert len(result["detection_details"]["forbidden_phrases_found"]) == 0
    assert not result["overall_assessment"]["is_potentially_harmful"]
    assert result["overall_assessment"]["risk_level"] == "low"
