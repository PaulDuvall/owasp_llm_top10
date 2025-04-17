#!/usr/bin/env python3
"""
Generate Prompt Injection Scan Report (HTML, Markdown, JSON)

Usage:
    python scripts/generate_prompt_injection_report.py scan_results.json

Input JSON format:
{
    "scanned_files": ["prompts/file1.txt", ...],
    "results": {
        "prompts/file1.txt": {
            "injection_detected": true,
            "detections": [
                {"line": 1, "phrase": "requires login"}
            ]
        },
        ...
    }
}
"""
import os
import sys
import json
from datetime import datetime

REPORT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../report/reports'))
os.makedirs(REPORT_DIR, exist_ok=True)

def render_html(scan_data):
    html = []
    html.append('<!DOCTYPE html>')
    html.append('<html lang="en"><head>')
    html.append('<meta charset="UTF-8">')
    html.append('<title>Prompt Injection Scan Results</title>')
    html.append('<style>')
    html.append('body { font-family: Arial, sans-serif; margin: 2em; }')
    html.append('h1 { font-size: 2.2em; }')
    html.append('h2 { margin-top: 2em; }')
    html.append('.file-list { margin-bottom: 2em; }')
    html.append('.result { margin-bottom: 1.5em; }')
    html.append('.warn { color: #b30000; font-weight: bold; }')
    html.append('.ok { color: #1b7e2e; font-weight: bold; }')
    html.append('.icon { font-size: 1.3em; vertical-align: middle; margin-right: 0.2em; }')
    html.append('.phrase { background: #eee; padding: 0.15em 0.3em; border-radius: 4px; font-family: monospace; }')
    html.append('</style></head><body>')
    html.append('<h1>Prompt Injection Scan Results</h1>')
    html.append('<h2>Scanned files:</h2>')
    html.append('<ul class="file-list">')
    for f in scan_data['scanned_files']:
        html.append(f'<li>{f}</li>')
    html.append('</ul>')
    html.append('<h2>Results</h2>')
    clean_count = 0
    inj_count = 0
    for fname in scan_data['scanned_files']:
        result = scan_data['results'].get(fname, {})
        if result.get('injection_detected'):
            inj_count += 1
            html.append(f'<div class="result warn"><span class="icon">&#9888;&#65039;</span><span style="color:#b30000;font-weight:bold">{fname}</span>')
            for det in result['detections']:
                html.append(f'<div>Line {det["line"]}:<br>Detected phrase: <span class="phrase">{det["phrase"]}</span><br><i>Potential prompt injection phrase detected.</i></div>')
            html.append('</div>')
        else:
            clean_count += 1
            html.append(f'<div class="result ok"><span class="icon">&#9989;</span><span style="color:#1b7e2e;font-weight:bold">{fname}</span><br>No prompt injection phrases detected.</div>')
    html.append('<h2>Summary:</h2>')
    html.append('<ul>')
    html.append(f'<li>Files scanned: {len(scan_data["scanned_files"])}')
    html.append(f'<li>Injections detected: {inj_count}')
    html.append(f'<li>Clean files: {clean_count}')
    html.append('</ul>')
    html.append(f'<div style="margin-top:2em;font-size:0.9em;color:#888;">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>')
    html.append('</body></html>')
    return '\n'.join(html)

def render_markdown(scan_data):
    md = []
    md.append('# Prompt Injection Scan Results\n')
    md.append('## Scanned files:')
    for f in scan_data['scanned_files']:
        md.append(f'- {f}')
    md.append('\n## Results')
    clean_count = 0
    inj_count = 0
    for fname in scan_data['scanned_files']:
        result = scan_data['results'].get(fname, {})
        if result.get('injection_detected'):
            inj_count += 1
            md.append(f'**:warning: {fname}**')
            for det in result['detections']:
                md.append(f'  - Line {det["line"]}: Detected phrase: `{det["phrase"]}` (Potential prompt injection phrase detected)')
        else:
            clean_count += 1
            md.append(f'**:white_check_mark: {fname}**')
            md.append('  - No prompt injection phrases detected.')
    md.append('\n## Summary')
    md.append(f'- Files scanned: {len(scan_data["scanned_files"])}')
    md.append(f'- Injections detected: {inj_count}')
    md.append(f'- Clean files: {clean_count}')
    return '\n'.join(md)

def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/generate_prompt_injection_report.py scan_results.json")
        sys.exit(1)
    scan_json = sys.argv[1]
    with open(scan_json, 'r', encoding='utf-8') as f:
        scan_data = json.load(f)

    # HTML
    html_report = render_html(scan_data)
    html_path = os.path.join(REPORT_DIR, 'prompt_injection_report.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_report)
    print(f"HTML report written to {html_path}")

    # Markdown
    md_report = render_markdown(scan_data)
    md_path = os.path.join(REPORT_DIR, 'prompt_injection_report.md')
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md_report)
    print(f"Markdown report written to {md_path}")

    # JSON (copy input)
    json_path = os.path.join(REPORT_DIR, 'prompt_injection_report.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(scan_data, f, indent=2)
    print(f"JSON report written to {json_path}")

if __name__ == "__main__":
    main()
