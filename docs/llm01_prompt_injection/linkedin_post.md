# Detecting Prompt Injection in AI Apps: My Approach

According to OWASP, prompt injection is one of the top vulnerabilities affecting LLMs—models can be tricked into leaking info or doing things you didn’t intend. This isn’t just theory: I’ve run hands-on tests and seen real vulnerabilities.

A few takeaways:
- Prompt injection is real and testable. LLMs can be probed with crafted prompts to expose weaknesses.
- While I'm still experimenting, I tried open source tools, but hit practical issues—so I built my own tool. (Your mileage may vary.)
- The OWASP LLM Top 10 keeps me focused on real-world risks.

**Why this is accessible:**
- You can run all tests and demos in a fully simulated mode—**no AWS account or OpenAI key required**.
- This makes it easy for anyone to explore detection and reporting features, even in restricted environments or for quick demos.
- When you want to test against a real LLM, secure AWS-based secret management is supported via AWS Parameter Store.

The tool automates detection, generates reports (Markdown, HTML, JSON), and makes it easy to review findings. Right now, the focus is prompt injection, but I plan to cover more LLM risks soon.

If you’re building with LLMs, try testing for prompt injection early. Security works best when you automatically build it into the AI lifecycle.

**Try it out:**
- Simulated mode (no setup):
  ```
  ./run.sh demo --simulate-vulnerable
  ./run.sh test --simulate-vulnerable
  ```
- Or connect to a real LLM for full coverage.

Details and code here:
[https://github.com/PaulDuvall/owasp_llm_top10](https://github.com/PaulDuvall/owasp_llm_top10)

#AI #Security #OWASP #PromptInjection #DevSecOps #LLM #MachineLearning #CloudSecurity
