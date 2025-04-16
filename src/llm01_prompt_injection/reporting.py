"""
Reporting Module - Generates reports from prompt injection test results.

This module provides functionality to generate detailed reports from prompt
injection test results, including summary statistics, visualizations, and
recommendations for mitigation.

User Story: US-105 - As a security tester, I need detailed reports of prompt
injection test results to understand vulnerabilities and prioritize fixes.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
import markdown
from jinja2 import Template

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates reports from prompt injection test results."""
    
    def __init__(self, results_file: str, output_dir: str = "test-results"):
        """
        Initialize the report generator.
        
        Args:
            results_file: Path to the JSON results file
            output_dir: Directory to store generated reports
        """
        self.results_file = results_file
        self.output_dir = output_dir
        self.results = self._load_results()
        
        # Create output directory if it doesn't exist
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized ReportGenerator with results from {results_file}")
    
    def _load_results(self) -> Dict[str, Any]:
        """Load test results from the JSON file."""
        try:
            with open(self.results_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading results from {self.results_file}: {str(e)}")
            raise
    
    def generate_markdown_report(self, filename: Optional[str] = None) -> str:
        """
        Generate a markdown report from the test results.
        
        Args:
            filename: Optional filename for the report
            
        Returns:
            Path to the generated report file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"prompt_injection_report_{timestamp}.md"
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Extract summary information
        summary = self.results.get("summary", {})
        total_tests = summary.get("total_tests", 0)
        vulnerabilities_detected = summary.get("vulnerabilities_detected", 0)
        llm_provider = summary.get("llm_provider", "Unknown")
        timestamp = summary.get("timestamp", datetime.now().isoformat())
        
        # Calculate vulnerability percentage
        vulnerability_percentage = (vulnerabilities_detected / total_tests * 100) if total_tests > 0 else 0
        
        # Count vulnerabilities by category and severity
        vulnerabilities_by_category = {}
        vulnerabilities_by_severity = {}
        
        for result in self.results.get("results", []):
            category = result.get("attack_vector", {}).get("category", "unknown")
            severity = result.get("attack_vector", {}).get("severity", "unknown")
            is_vulnerable = result.get("detection", {}).get("injection_detected", False)
            
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
        
        # Create the markdown report
        report_template = """
# Prompt Injection Test Report

## Summary

- **Date**: {{ timestamp }}
- **LLM Provider**: {{ llm_provider }}
- **Total Tests**: {{ total_tests }}
- **Vulnerabilities Detected**: {{ vulnerabilities_detected }} ({{ vulnerability_percentage }}%)

## Vulnerability Analysis

### By Category

| Category | Vulnerable | Total | Percentage |
|----------|------------|-------|------------|
{% for category, counts in vulnerabilities_by_category.items() %}
| {{ category }} | {{ counts.vulnerable }} | {{ counts.total }} | {{ (counts.vulnerable / counts.total * 100) | round(2) }}% |
{% endfor %}

### By Severity

| Severity | Vulnerable | Total | Percentage |
|----------|------------|-------|------------|
{% for severity, counts in vulnerabilities_by_severity.items() %}
| {{ severity }} | {{ counts.vulnerable }} | {{ counts.total }} | {{ (counts.vulnerable / counts.total * 100) | round(2) }}% |
{% endfor %}

## Detailed Results

{% for result in detailed_results %}
### {{ result.attack_vector.id }}: {{ result.attack_vector.name }}

- **Category**: {{ result.attack_vector.category }}
- **Severity**: {{ result.attack_vector.severity }}
- **Injection Detected**: {{ result.detection.injection_detected }}
- **Risk Level**: {{ result.detection.risk_level }}

#### Prompt

```
{{ result.prompt }}
```

#### Response

```
{{ result.response.content }}
```

{% if result.detection.matched_patterns %}
#### Matched Patterns

{% for pattern in result.detection.matched_patterns %}
- `{{ pattern }}`
{% endfor %}
{% endif %}

{% if result.detection.detected_terms %}
#### Detected Terms

{% for term in result.detection.detected_terms %}
- `{{ term }}`
{% endfor %}
{% endif %}

---
{% endfor %}

## Recommendations

Based on the test results, consider implementing the following mitigations:

1. **Input Validation**: Implement strict validation of user inputs to detect and reject potential prompt injection attempts.
2. **Output Filtering**: Add filters to detect and block responses that may indicate a successful prompt injection.
3. **Prompt Engineering**: Design system prompts that are resistant to injection attacks.
4. **Sandboxing**: Isolate LLM interactions in a secure environment to limit the impact of successful injections.
5. **Monitoring**: Implement continuous monitoring to detect and respond to prompt injection attempts in production.

## References

- [OWASP Top 10 for Large Language Model Applications](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [Prompt Engineering Guide - Security](https://www.promptingguide.ai/risks/prompt-injection)
- [LLM Security Best Practices](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications)
"""
        
        # Prepare template data
        template_data = {
            "timestamp": datetime.fromisoformat(timestamp).strftime("%Y-%m-%d %H:%M:%S") if isinstance(timestamp, str) else timestamp,
            "llm_provider": llm_provider,
            "total_tests": total_tests,
            "vulnerabilities_detected": vulnerabilities_detected,
            "vulnerability_percentage": round(vulnerability_percentage, 2),
            "vulnerabilities_by_category": vulnerabilities_by_category,
            "vulnerabilities_by_severity": vulnerabilities_by_severity,
            "detailed_results": self.results.get("results", [])
        }
        
        # Render the template
        template = Template(report_template)
        report_content = template.render(**template_data)
        
        # Write to file
        with open(filepath, 'w') as f:
            f.write(report_content)
        
        logger.info(f"Generated markdown report at {filepath}")
        return filepath
    
    def generate_html_report(self, filename: Optional[str] = None) -> str:
        """
        Generate an HTML report from the test results.
        
        Args:
            filename: Optional filename for the report
            
        Returns:
            Path to the generated report file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"prompt_injection_report_{timestamp}.html"
        
        # First generate the markdown report
        md_filepath = self.generate_markdown_report(filename.replace(".html", ".md"))
        
        # Convert markdown to HTML
        with open(md_filepath, 'r') as f:
            md_content = f.read()
        
        html_content = markdown.markdown(md_content, extensions=['tables'])
        
        # Add HTML wrapper with styling
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prompt Injection Test Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3, h4 {
            color: #2c3e50;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px 12px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        code {
            background-color: #f8f8f8;
            padding: 2px 4px;
            border-radius: 4px;
            font-family: Consolas, Monaco, 'Andale Mono', monospace;
        }
        pre {
            background-color: #f8f8f8;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: Consolas, Monaco, 'Andale Mono', monospace;
        }
        .vulnerable-true {
            color: #e74c3c;
            font-weight: bold;
        }
        .vulnerable-false {
            color: #27ae60;
        }
        .risk-high {
            color: #e74c3c;
            font-weight: bold;
        }
        .risk-medium {
            color: #f39c12;
            font-weight: bold;
        }
        .risk-low {
            color: #27ae60;
        }
        hr {
            border: none;
            border-top: 1px solid #eee;
            margin: 30px 0;
        }
    </style>
</head>
<body>
    {{ content }}
</body>
</html>
"""
        
        # Add classes for styling
        html_content = html_content.replace(">True<", " class=\"vulnerable-true\">Yes<")
        html_content = html_content.replace(">False<", " class=\"vulnerable-false\">No<")
        html_content = html_content.replace(">high<", " class=\"risk-high\">High<")
        html_content = html_content.replace(">medium<", " class=\"risk-medium\">Medium<")
        html_content = html_content.replace(">low<", " class=\"risk-low\">Low<")
        
        # Render the HTML template
        template = Template(html_template)
        full_html = template.render(content=html_content)
        
        # Write to file
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            f.write(full_html)
        
        logger.info(f"Generated HTML report at {filepath}")
        return filepath
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """
        Generate a summary report with key statistics.
        
        Returns:
            Dictionary containing summary statistics
        """
        # Extract summary information
        summary = self.results.get("summary", {})
        total_tests = summary.get("total_tests", 0)
        vulnerabilities_detected = summary.get("vulnerabilities_detected", 0)
        
        # Count vulnerabilities by category and severity
        vulnerabilities_by_category = {}
        vulnerabilities_by_severity = {}
        most_vulnerable_attacks = []
        
        for result in self.results.get("results", []):
            attack_vector = result.get("attack_vector", {})
            category = attack_vector.get("category", "unknown")
            severity = attack_vector.get("severity", "unknown")
            is_vulnerable = result.get("detection", {}).get("injection_detected", False)
            
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
                
                # Add to most vulnerable attacks
                most_vulnerable_attacks.append({
                    "id": attack_vector.get("id", ""),
                    "name": attack_vector.get("name", ""),
                    "category": category,
                    "severity": severity
                })
        
        # Sort most vulnerable attacks by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        most_vulnerable_attacks.sort(key=lambda x: severity_order.get(x["severity"], 5))
        
        # Limit to top 5
        most_vulnerable_attacks = most_vulnerable_attacks[:5]
        
        # Calculate vulnerability percentages
        vulnerability_percentage = (vulnerabilities_detected / total_tests * 100) if total_tests > 0 else 0
        
        category_percentages = {}
        for category, counts in vulnerabilities_by_category.items():
            category_percentages[category] = (counts["vulnerable"] / counts["total"] * 100) if counts["total"] > 0 else 0
        
        severity_percentages = {}
        for severity, counts in vulnerabilities_by_severity.items():
            severity_percentages[severity] = (counts["vulnerable"] / counts["total"] * 100) if counts["total"] > 0 else 0
        
        # Create the summary report
        summary_report = {
            "total_tests": total_tests,
            "vulnerabilities_detected": vulnerabilities_detected,
            "vulnerability_percentage": round(vulnerability_percentage, 2),
            "by_category": {
                category: {
                    "total": counts["total"],
                    "vulnerable": counts["vulnerable"],
                    "percentage": round(category_percentages[category], 2)
                } for category, counts in vulnerabilities_by_category.items()
            },
            "by_severity": {
                severity: {
                    "total": counts["total"],
                    "vulnerable": counts["vulnerable"],
                    "percentage": round(severity_percentages[severity], 2)
                } for severity, counts in vulnerabilities_by_severity.items()
            },
            "most_vulnerable_attacks": most_vulnerable_attacks,
            "timestamp": datetime.now().isoformat()
        }
        
        return summary_report


def generate_report(results_file: str, output_dir: str = "test-results", 
                   format: str = "html") -> str:
    """
    Convenience function to generate a report from test results.
    
    Args:
        results_file: Path to the JSON results file
        output_dir: Directory to store generated reports
        format: Report format (html, markdown)
        
    Returns:
        Path to the generated report file
    """
    generator = ReportGenerator(results_file=results_file, output_dir=output_dir)
    
    if format.lower() == "html":
        return generator.generate_html_report()
    elif format.lower() in ["markdown", "md"]:
        return generator.generate_markdown_report()
    else:
        raise ValueError(f"Unsupported report format: {format}")
