"""
LLM Client Module - Provides interfaces for interacting with various LLM providers.

This module implements a unified interface for sending prompts to different LLM providers
and processing their responses. It handles authentication, rate limiting, and formatting
of requests and responses.

User Story: US-101 - As a security tester, I need to interact with various LLM providers
to test for prompt injection vulnerabilities.
"""

import os
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union
import time
import json

# Third-party imports
import openai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class LLMClient(ABC):
    """Abstract base class for LLM clients."""
    
    @abstractmethod
    def send_prompt(self, prompt: str, system_prompt: Optional[str] = None, 
                   temperature: float = 0.7, max_tokens: int = 1000) -> Dict[str, Any]:
        """
        Send a prompt to the LLM and return the response.
        
        Args:
            prompt: The user prompt to send
            system_prompt: Optional system prompt to set context
            temperature: Controls randomness (0.0-1.0)
            max_tokens: Maximum number of tokens to generate
            
        Returns:
            Dictionary containing the response and metadata
        """
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Return the name of the LLM provider."""
        pass


class OpenAIClient(LLMClient):
    """Client for interacting with OpenAI API."""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        """Initialize the OpenAI client.
        
        Args:
            api_key: Optional API key (will use OPENAI_API_KEY env var if not provided)
            model: Model to use (default: gpt-3.5-turbo)
        """
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key is required")
        
        # Initialize the OpenAI client with only the required parameters
        # The OpenAI SDK has changed and no longer accepts 'proxies' parameter
        self.client = openai.OpenAI(
            api_key=self.api_key
        )
        self.model = model
        logger.info(f"Initialized OpenAI client with model: {model}")
    
    def send_prompt(self, prompt: str, system_prompt: Optional[str] = None,
                   temperature: float = 0.7, max_tokens: int = 1000) -> str:
        """Send a prompt to OpenAI and return the response text.
        
        Args:
            prompt: The prompt to send
            system_prompt: Optional system prompt
            temperature: Temperature parameter (0.0-1.0)
            max_tokens: Maximum tokens to generate
            
        Returns:
            The text response from the LLM
        """
        try:
            messages = []
            
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
                
            messages.append({"role": "user", "content": prompt})
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Error sending prompt to OpenAI: {str(e)}")
            raise
    
    def get_name(self) -> str:
        """Return the name of the LLM provider."""
        return f"OpenAI ({self.model})"


def get_llm_client(provider: str = "openai", model: Optional[str] = None) -> LLMClient:
    """
    Factory function to get an LLM client based on provider name.
    
    Args:
        provider: The LLM provider to use (currently only supports openai)
        model: Optional model name to use
        
    Returns:
        An instance of the appropriate LLM client
    
    Raises:
        ValueError: If the provider is not supported
    """
    if provider.lower() == "openai":
        return OpenAIClient(model=model or "gpt-3.5-turbo")
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")
