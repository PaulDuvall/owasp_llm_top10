"""
Tests for the attack vectors module.

User Story: US-102 - As a security tester, I need a comprehensive collection of prompt
injection techniques to test LLM vulnerabilities.
"""

import pytest
from src.llm01_prompt_injection.attack_vectors import (
    AttackVector, 
    get_attack_vectors, 
    get_attack_vector_by_id,
    DIRECT_PROMPT_INJECTION,
    INDIRECT_PROMPT_INJECTION,
    GOAL_HIJACKING,
    PROMPT_LEAKING,
    JAILBREAKING,
    ALL_ATTACK_VECTORS
)


def test_attack_vector_model():
    """Test the AttackVector model."""
    vector = AttackVector(
        id="TEST-001",
        name="Test Vector",
        description="Test description",
        category="test",
        severity="medium",
        prompts=["Test prompt"],
        detection_patterns=["Test pattern"],
        references=["Test reference"],
        mitigation="Test mitigation"
    )
    
    assert vector.id == "TEST-001"
    assert vector.name == "Test Vector"
    assert vector.description == "Test description"
    assert vector.category == "test"
    assert vector.severity == "medium"
    assert vector.prompts == ["Test prompt"]
    assert vector.detection_patterns == ["Test pattern"]
    assert vector.references == ["Test reference"]
    assert vector.mitigation == "Test mitigation"


def test_get_attack_vectors_all():
    """Test getting all attack vectors."""
    vectors = get_attack_vectors()
    assert len(vectors) == len(ALL_ATTACK_VECTORS)
    assert vectors == ALL_ATTACK_VECTORS


def test_get_attack_vectors_by_category():
    """Test getting attack vectors by category."""
    # Test direct category
    direct_vectors = get_attack_vectors(category="direct")
    assert len(direct_vectors) == len(DIRECT_PROMPT_INJECTION)
    assert all(v.category == "direct" for v in direct_vectors)
    
    # Test indirect category
    indirect_vectors = get_attack_vectors(category="indirect")
    assert len(indirect_vectors) == len(INDIRECT_PROMPT_INJECTION)
    assert all(v.category == "indirect" for v in indirect_vectors)
    
    # Test goal_hijacking category
    goal_hijacking_vectors = get_attack_vectors(category="goal_hijacking")
    assert len(goal_hijacking_vectors) == len(GOAL_HIJACKING)
    assert all(v.category == "goal_hijacking" for v in goal_hijacking_vectors)
    
    # Test prompt_leaking category
    prompt_leaking_vectors = get_attack_vectors(category="prompt_leaking")
    assert len(prompt_leaking_vectors) == len(PROMPT_LEAKING)
    assert all(v.category == "prompt_leaking" for v in prompt_leaking_vectors)
    
    # Test jailbreaking category
    jailbreaking_vectors = get_attack_vectors(category="jailbreaking")
    assert len(jailbreaking_vectors) == len(JAILBREAKING)
    assert all(v.category == "jailbreaking" for v in jailbreaking_vectors)


def test_get_attack_vectors_by_severity():
    """Test getting attack vectors by severity."""
    # Test critical severity
    critical_vectors = get_attack_vectors(severity="critical")
    assert len(critical_vectors) > 0
    assert all(v.severity == "critical" for v in critical_vectors)
    
    # Test high severity
    high_vectors = get_attack_vectors(severity="high")
    assert len(high_vectors) > 0
    assert all(v.severity == "high" for v in high_vectors)
    
    # Test medium severity
    medium_vectors = get_attack_vectors(severity="medium")
    assert len(medium_vectors) > 0
    assert all(v.severity == "medium" for v in medium_vectors)


def test_get_attack_vectors_by_category_and_severity():
    """Test getting attack vectors by category and severity."""
    # Test direct category with high severity
    direct_high_vectors = get_attack_vectors(category="direct", severity="high")
    assert len(direct_high_vectors) > 0
    assert all(v.category == "direct" and v.severity == "high" for v in direct_high_vectors)


def test_get_attack_vector_by_id():
    """Test getting an attack vector by ID."""
    # Test getting an existing vector
    vector = get_attack_vector_by_id("PI-001")
    assert vector is not None
    assert vector.id == "PI-001"
    
    # Test getting a non-existent vector
    vector = get_attack_vector_by_id("NON-EXISTENT")
    assert vector is None


def test_attack_vectors_have_required_fields():
    """Test that all attack vectors have the required fields."""
    for vector in ALL_ATTACK_VECTORS:
        assert vector.id, f"Vector missing ID: {vector}"
        assert vector.name, f"Vector missing name: {vector.id}"
        assert vector.description, f"Vector missing description: {vector.id}"
        assert vector.category, f"Vector missing category: {vector.id}"
        assert vector.severity, f"Vector missing severity: {vector.id}"
        assert len(vector.prompts) > 0, f"Vector has no prompts: {vector.id}"
        assert len(vector.detection_patterns) > 0, f"Vector has no detection patterns: {vector.id}"
        assert vector.mitigation, f"Vector missing mitigation: {vector.id}"
