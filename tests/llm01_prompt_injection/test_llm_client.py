"""
Tests for the LLM client module.

User Story: US-101 - As a security tester, I need to interact with various LLM providers
to test for prompt injection vulnerabilities.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from src.llm01_prompt_injection.llm_client import LLMClient, OpenAIClient, get_llm_client


# Test the factory function
def test_get_llm_client_openai():
    """Test getting an OpenAI client."""
    with patch("src.llm01_prompt_injection.llm_client.openai") as mock_openai, \
         patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}):
        client = get_llm_client(provider="openai")
        assert isinstance(client, OpenAIClient)
        assert client.model == "gpt-3.5-turbo"


def test_get_llm_client_invalid():
    """Test getting an invalid client."""
    with pytest.raises(ValueError):
        get_llm_client(provider="invalid")


# Test the OpenAI client
class TestOpenAIClient:
    """Tests for the OpenAI client."""
    
    def setup_method(self):
        """Set up the test environment."""
        # Mock the OpenAI client
        self.openai_patcher = patch("src.llm01_prompt_injection.llm_client.openai")
        self.mock_openai = self.openai_patcher.start()
        
        # Mock the OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Test response"
        mock_response.choices[0].finish_reason = "stop"
        mock_response.model = "gpt-3.5-turbo"
        
        # Set up the mock client to return the mock response
        self.mock_openai.OpenAI.return_value.chat.completions.create.return_value = mock_response
        
        # Create the client
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}):
            self.client = OpenAIClient()
    
    def teardown_method(self):
        """Clean up after the test."""
        self.openai_patcher.stop()
    
    def test_send_prompt(self):
        """Test sending a prompt to OpenAI."""
        response = self.client.send_prompt("Test prompt")
        
        # Check that the client was called correctly
        self.mock_openai.OpenAI.return_value.chat.completions.create.assert_called_once()
        
        # Check the response - the client now returns a string directly
        assert response == "Test response"
    
    def test_send_prompt_with_system(self):
        """Test sending a prompt with a system prompt to OpenAI."""
        response = self.client.send_prompt("Test prompt", system_prompt="System prompt")
        
        # Check that the client was called correctly
        call_args = self.mock_openai.OpenAI.return_value.chat.completions.create.call_args[1]
        assert len(call_args["messages"]) == 2
        assert call_args["messages"][0]["role"] == "system"
        assert call_args["messages"][0]["content"] == "System prompt"
        assert call_args["messages"][1]["role"] == "user"
        assert call_args["messages"][1]["content"] == "Test prompt"
        
        # Check the response is a string
        assert response == "Test response"
    
    def test_get_name(self):
        """Test getting the client name."""
        assert self.client.get_name() == "OpenAI (gpt-3.5-turbo)"
