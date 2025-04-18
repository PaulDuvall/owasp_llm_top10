# Project Requirements Document (PRD)

## 1. Overview
The OWASP LLM Top 10 Testing Framework automates detection of prompt injection and related vulnerabilities in LLM-powered systems, supporting security testing and reporting.

## 2. Scope & Context
- Focus: Automated security testing for LLM applications, initially targeting prompt injection (OWASP LLM01).
- Context: Used by developers and security professionals to assess LLM deployments via API, CLI, and CI/CD pipelines.

## 3. Functional Requirements
| ID       | Description                                                                                          | Priority | Code Reference                                 |
|----------|------------------------------------------------------------------------------------------------------|----------|------------------------------------------------|
| FR-001   | Execute prompt injection tests against LLM providers.                                                | Must     | src/llm01_prompt_injection/test_runner.py:342  |
| FR-002   | Provide a unified interface for sending prompts to LLMs.                                             | Must     | src/llm01_prompt_injection/llm_client.py:33     |
| FR-003   | Detect successful prompt injections using pattern and behavioral analysis.                           | Must     | src/llm01_prompt_injection/detection.py:24      |
| FR-004   | Generate reports (Markdown, HTML) from test results.                                                 | Must     | src/llm01_prompt_injection/reporting.py:28      |
| FR-005   | Store and retrieve attack vectors and detection patterns.                                             | Must     | src/llm01_prompt_injection/attack_vectors.py:15 |
| FR-006   | Analyze vulnerabilities and set CI/CD output variables.                                              | Should   | scripts/analyze_vulnerabilities.py:77           |
| FR-007   | Securely manage API credentials using AWS Parameter Store.                                           | Must     | run.sh:1, README.md:14                         |
| FR-008   | Support extension with new attack vectors and test scenarios.                                        | Could    | README.md:193, src/llm01_prompt_injection/      |
| FR-009   | Provide detailed logging of test execution and results.                                              | Should   | src/llm01_prompt_injection/test_runner.py:33    |
| FR-010   | Integrate with GitHub Actions for automated scheduled/security test runs.                            | Must     | .github/workflows/llm01_prompt_injection_tests.yml:1 |

## 4. Non-Functional Requirements
1. Performance: Test execution completes in < 10 minutes for 20 attack vectors (src/llm01_prompt_injection/test_runner.py:342).
2. Security: API keys stored as AWS Parameter Store SecureString (run.sh:1, README.md:14).
3. Scalability: Supports adding new attack vectors without codebase refactor (src/llm01_prompt_injection/attack_vectors.py:359).
4. Reliability: All test results and errors are logged (src/llm01_prompt_injection/test_runner.py:33).
5. Usability: CLI and CI/CD integration documented in README.md (README.md:14).
6. Maintainability: Modular code structure, PEP8 compliance (src/llm01_prompt_injection/).

## 5. Data Models & Schemas
- Entity: AttackVector (id, name, description, category, severity, prompts, detection_patterns, references, mitigation) (src/llm01_prompt_injection/attack_vectors.py:15)
- Entity: TestResult (attack_vector, prompt, response, detection_result, timestamp) (src/llm01_prompt_injection/test_runner.py:34)
- Relationship: One TestResult references one AttackVector.

## 6. External Dependencies & Integrations
- OpenAI API (src/llm01_prompt_injection/llm_client.py:59)
- AWS Parameter Store (run.sh:1, README.md:14)
- GitHub Actions (README.md:124, .github/workflows/)
- Libraries: openai, pydantic, jinja2, pytest-json-report, dotenv (requirements.txt:1-8)

## 7. Assumptions & Constraints
1. Python 3.11+ required (README.md:14).
2. AWS CLI configured with permissions (README.md:14).
3. OpenAI API key in AWS Parameter Store (README.md:14).
4. CI/CD runs on GitHub Actions (README.md:124).
5. Compliance: Follows OWASP Top 10 for LLM Applications (README.md:1).
