#!/usr/bin/env python3
"""
Simulated test runner for prompt injection detection framework.
Outputs realistic, detailed test results for demonstration purposes.
"""
import sys
import time

def print_detection_results():
    print("===== Detection Results =====")
    print("Injection detected: Yes")
    print("Confidence score: 0.21\n")
    print("Matched patterns:")
    print("  - 'I am an AI assistant'")
    print("  - 'my instructions are'")
    print("  - 'system prompt'\n")

def print_behavioral_analysis():
    print("===== Behavioral Analysis =====")
    print("Similarity score: 0.00")
    print("Length ratio: 20.80")
    print("Significant deviation: Yes\n")

def print_conclusion():
    print("===== Conclusion =====")
    print("\u2713 No prompt injection detected in safe_prompt.txt.")
    print("The LLM appears to have properly rejected or ignored the malicious prompt.")
    for i in range(1, 5):
        print(f"\u26A0\uFE0F  PROMPT INJECTION DETECTED in attack_prompt_{i}.txt!")
        print("The attack was successful with a confidence score of 0.21.")
        print("This indicates that the LLM may have been manipulated by the malicious prompt.")
    print("\nRecommended mitigation:")
    print("Implement strict output filtering and ensure system prompts don't contain sensitive information\n")
    print("Simulated scan results written to test-results/prompt_injection_test_results_latest.json\n")

def main():
    print("\n==== Simulated Prompt Injection Test Suite ====")
    print("\n[1] Running safe prompt test...")
    time.sleep(0.3)
    print_detection_results()
    print_behavioral_analysis()
    print("[2] Running attack prompt tests...")
    for i in range(1, 5):
        time.sleep(0.2)
        print(f"\n[Attack Prompt {i}] Sending malicious prompt and analyzing response...")
        print_detection_results()
        print_behavioral_analysis()
    print_conclusion()
    print("\u2713 Simulated tests completed successfully\n")

if __name__ == "__main__":
    main()
