# OWASP LLM Top 10 Testing Framework

[![GitHub Actions Workflow Status](https://github.com/PaulDuvall/owasp_llm_top10/actions/workflows/llm01_prompt_injection_tests.yml/badge.svg)](https://github.com/PaulDuvall/owasp_llm_top10/actions/workflows/llm01_prompt_injection_tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/PaulDuvall/owasp_llm_top10)
![Page Views](https://komarev.com/ghpvc/?username=PaulDuvall&repo=owasp_llm_top10&label=Page%20Views)

This repository provides an automated testing framework inspired by the [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/). The goal is to help developers and security professionals proactively identify and mitigate the most critical risks facing LLM-powered systems.

**Currently, prompt injection (OWASP LLM01) is the first and primary implementation.** The framework is designed to expand and support testing for additional OWASP LLM Top 10 risks in future releases.

## Overview

Prompt injection attacks occur when malicious users craft inputs that manipulate an LLM into performing unintended actions or bypassing security controls. This framework helps test LLM implementations against various prompt injection techniques and detect vulnerabilities automatically using GitHub Actions.

## Features

- **Automated Testing**: GitHub Actions workflows that run prompt injection tests on schedule or when code changes
- **Comprehensive Test Scenarios**: Tests covering various prompt injection techniques from simple to advanced
- **Detection Mechanisms**: Tools to analyze LLM outputs and detect successful prompt injections
- **Detailed Logging**: Clear reporting of test results with specific indicators of potential vulnerabilities
- **Extensible Framework**: Easy-to-extend architecture for adding new test cases as attack techniques evolve
- **Secure API Key Management**: Integration with AWS Parameter Store for secure credential management
- **Direct API Demo**: Interactive demonstration of prompt injection detection using direct API calls

## Getting Started

### Prerequisites

- Python 3.11 or higher
- (Optional for simulation) AWS CLI and OpenAI API key are **not required** if you use simulated mode (see below)
- For full functionality: AWS CLI configured with appropriate permissions, and access to an OpenAI API key (stored in AWS Parameter Store)
- GitHub account (for running GitHub Actions)

### Simulated Mode (No Cloud Required)

You can run both the demo and tests in simulated mode—**no AWS account or OpenAI API key required**. This allows you to explore all detection and reporting features with zero cloud dependencies, perfect for demos, evaluation, or learning.

**To use simulated mode:**
```bash
./run.sh demo --simulate-vulnerable     # Demo, no AWS/OpenAI needed
./run.sh test --simulate-vulnerable     # Tests, no AWS/OpenAI needed
```

### Full Setup (Cloud-Backed)

If you want to test against a real LLM and use secure credential management, follow these steps:

1. Clone this repository:
   ```bash
   git clone https://github.com/PaulDuvall/owasp_llm_top10.git
   cd owasp_llm_top10
   ```
2. Run the setup script to create a virtual environment and install dependencies:
   ```bash
   ./run.sh setup
   ```
3. Configure your LLM API credentials in AWS Parameter Store:
   ```bash
   ./run.sh params check
   ./run.sh params set
   ```
4. Run the demo to see prompt injection detection in action:
   ```bash
   ./run.sh demo
   ```
5. Run tests locally:
   ```bash
   ./run.sh test
   ```

> **Note:**
> - For full functionality with a real LLM, an AWS account is required to securely store your API keys and credentials via Parameter Store. For setup instructions, see Appendix or the docs.
> - **However, you can run both the demo and tests in simulated mode without AWS or an OpenAI key** by using the `--simulate-vulnerable` flag.

## Interactive Demo

The framework includes an interactive demo that demonstrates prompt injection detection:

```bash
./run.sh demo             # Real LLM (requires AWS/OpenAI)
./run.sh demo --simulate-vulnerable  # Simulated mode (no AWS/OpenAI)
```

This demo:
1. Sends a safe baseline prompt to the LLM (or simulates response)
2. Sends malicious prompts attempting to extract system instructions
3. Analyzes the response using pattern matching and behavioral analysis
4. Provides a detailed report with confidence scores and mitigation recommendations

## Running Tests

You can run the full test suite:

```bash
./run.sh test             # Real LLM (requires AWS/OpenAI)
./run.sh test --simulate-vulnerable  # Simulated mode (no AWS/OpenAI)
```

Simulated mode produces realistic, detailed output for demos and evaluation with no cloud dependencies.

## GitHub Actions Setup

1. Fork this repository to your GitHub account
2. Add your AWS credentials as GitHub Secrets:
   - Go to your repository settings
   - Navigate to Secrets and Variables > Actions
   - Add `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` with appropriate permissions
3. Ensure your AWS Parameter Store contains the required API keys (e.g., `/owasp-llm-top10/OPENAI_API_KEY`)
4. The GitHub Actions workflow will run automatically based on the configured triggers

## GitHub Actions OIDC Authentication

This project includes a script to set up OpenID Connect (OIDC) authentication for GitHub Actions workflows, allowing secure access to AWS resources without storing long-lived credentials.

### Setting Up OIDC Authentication

1. Run the setup script:
   ```bash
   ./scripts/setup_oidc.sh --github-token YOUR_GITHUB_TOKEN
   ```

2. The script will:
   - Auto-detect your GitHub organization and repository name
   - Create a CloudFormation stack with the necessary IAM resources
   - Set up an OIDC provider for GitHub Actions
   - Create an IAM role with appropriate permissions
   - Add the role ARN as a GitHub repository variable

3. Once set up, your GitHub Actions workflows can authenticate with AWS using the role assumption pattern in `.github/workflows/llm01_prompt_injection_tests.yml`:
   ```yaml
   - name: Configure AWS credentials
     uses: aws-actions/configure-aws-credentials@v2
     with:
       role-to-assume: ${{ vars.AWS_ROLE_TO_ASSUME }}
       aws-region: us-east-1
   ```

### Troubleshooting OIDC Authentication

If your GitHub Actions workflow fails with authentication errors, you may need to check the trust policy of the IAM role:

1. View the current trust policy using AWS CLI:
   ```bash
   aws iam get-role --role-name ROLE_NAME --query 'Role.AssumeRolePolicyDocument' --output json
   ```
   Replace `ROLE_NAME` with your actual role name (e.g., `github-oidc-role-PaulDuvall-owasp_llm_top10`)

2. Verify that the trust policy includes the correct repository patterns:
   ```json
   "StringLike": {
     "token.actions.githubusercontent.com:sub": [
       "repo:ORG_NAME/REPO_NAME:*",
       "repo:ORG_NAME/REPO_NAME:ref:*",
       "repo:ORG_NAME/REPO_NAME:environment:*",
       "repo:ORG_NAME/REPO_NAME:pull_request",
       "repo:ORG_NAME/REPO_NAME:workflow:*",
       "repo:ORG_NAME/REPO_NAME:branch:*"
     ]
   }
   ```

3. If the trust policy is incorrect, you can update it by running the setup script again or manually update it:
   ```bash
   # Create a trust-policy.json file with the correct values
   aws iam update-assume-role-policy --role-name ROLE_NAME --policy-document file://trust-policy.json
   ```

This approach eliminates the need to store AWS access keys in GitHub Secrets, following security best practices for CI/CD pipelines.

## Test Scenarios

This framework includes test scenarios for various prompt injection techniques:

1. **Direct Prompt Injection**: Attempts to override system instructions
2. **Indirect Prompt Injection**: Exploits flaws in how user inputs are processed
3. **Goal Hijacking**: Redirects the LLM to perform unintended tasks
4. **Prompt Leaking**: Extracts system prompts or sensitive information
5. **Jailbreaking Techniques**: Advanced methods to bypass restrictions

Each test scenario includes:
- Description of the attack vector
- Sample malicious prompts
- Expected behavior if the LLM is vulnerable
- Detection criteria

## Detection Mechanisms

The framework uses several methods to detect successful prompt injections:

1. **Pattern Matching**: Searches for specific patterns in LLM responses that indicate successful exploitation
2. **Behavioral Analysis**: Compares LLM behavior against expected responses
3. **Confidence Scoring**: Calculates a confidence score based on multiple detection factors
4. **Similarity Analysis**: Measures how much an attack response differs from a baseline response

## Extending the Framework

To add new test scenarios:

1. Create a new test file in the `tests/` directory
2. Implement your test case following the existing patterns
3. Update the documentation to include your new test scenario

## Interpreting Results

Test results are available in the GitHub Actions logs and as artifacts. Each test run produces:

- Summary report of passed/failed tests
- Detailed logs of LLM responses
- Analysis of detected vulnerabilities
- Recommendations for mitigation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [OWASP Top 10 for Large Language Model Applications](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- Contributors to the OWASP community
