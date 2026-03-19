"""
Report Generator

Produces structured vulnerability reports in JSON and HTML formats.
Combines findings from source scanner, binary analyzer, and dependency checker
into a unified report with severity scoring, CVE cross-references, and remediation.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Environment


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SSID Vulnerability Scan Report</title>
<style>
body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; padding: 20px; background: #0d1117; color: #c9d1d9; }
h1, h2, h3 { color: #58a6ff; }
.header { border-bottom: 2px solid #30363d; padding-bottom: 16px; margin-bottom: 24px; }
.header .tool-name { font-size: 0.5em; color: #8b949e; font-weight: normal; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 20px 0; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
.card .number { font-size: 2em; font-weight: bold; }
.card .label { font-size: 0.85em; color: #8b949e; margin-top: 4px; }
.critical { color: #f85149; }
.high { color: #db6d28; }
.medium { color: #d29922; }
.low { color: #3fb950; }
.confirmed { color: #f85149; }
table { width: 100%; border-collapse: collapse; margin: 16px 0; }
th { background: #161b22; color: #58a6ff; text-align: left; padding: 10px 12px; border: 1px solid #30363d; }
td { padding: 8px 12px; border: 1px solid #30363d; vertical-align: top; word-break: break-word; max-width: 300px; }
tr:hover { background: #161b22; }
.severity-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; display: inline-block; }
.severity-critical { background: #f8514922; color: #f85149; }
.severity-high { background: #db6d2822; color: #db6d28; }
.severity-medium { background: #d2992222; color: #d29922; }
.severity-low { background: #3fb95022; color: #3fb950; }
.confidence-badge { padding: 2px 6px; border-radius: 3px; font-size: 0.8em; margin-left: 4px; }
.confidence-confirmed { background: #f8514933; color: #f85149; }
.confidence-high { background: #db6d2833; color: #db6d28; }
.confidence-medium { background: #d2992233; color: #d29922; }
.confidence-low { background: #3fb95033; color: #8b949e; }
code { background: #161b22; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
.section { margin: 32px 0; }
.type-summary { display: flex; gap: 24px; margin: 16px 0; flex-wrap: wrap; }
.type-pill { background: #161b22; border: 1px solid #30363d; border-radius: 20px; padding: 6px 16px; font-size: 0.9em; }
.type-pill strong { color: #58a6ff; }
.footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #30363d; color: #8b949e; font-size: 0.85em; }
</style>
</head>
<body>
<div class="header">
<h1>SSID Vulnerability Scan Report</h1>
<p>Target: <code>{{ target }}</code></p>
<p>Generated: {{ timestamp }}</p>
<p>Scanner: {{ tool_name }} v{{ tool_version }}</p>
</div>

<div class="summary">
<div class="card">
<div class="number">{{ total_findings }}</div>
<div class="label">Total Findings</div>
</div>
<div class="card">
<div class="number">{{ unique_findings }}</div>
<div class="label">Unique Findings</div>
</div>
<div class="card">
<div class="number critical">{{ severity.critical or 0 }}</div>
<div class="label">Critical</div>
</div>
<div class="card">
<div class="number high">{{ severity.high or 0 }}</div>
<div class="label">High</div>
</div>
<div class="card">
<div class="number medium">{{ severity.medium or 0 }}</div>
<div class="label">Medium</div>
</div>
<div class="card">
<div class="number low">{{ severity.low or 0 }}</div>
<div class="label">Low</div>
</div>
<div class="card">
<div class="number">{{ files_scanned }}</div>
<div class="label">Files Scanned</div>
</div>
</div>

<div class="type-summary">
<div class="type-pill"><strong>{{ source_count }}</strong> Source Code</div>
<div class="type-pill"><strong>{{ binary_count }}</strong> Binary Analysis</div>
<div class="type-pill"><strong>{{ dependency_count }}</strong> Dependencies</div>
</div>

{% if confidence_counts %}
<div class="type-summary">
{% for conf, cnt in confidence_counts.items() %}
<div class="type-pill"><span class="confidence-badge confidence-{{ conf }}">{{ conf|upper }}</span> {{ cnt }}</div>
{% endfor %}
</div>
{% endif %}

{% if source_findings %}
<div class="section">
<h2>Source Code Findings ({{ source_count }})</h2>
<table>
<tr>
<th>Severity</th><th>Confidence</th><th>Class</th><th>File</th><th>Line</th><th>Pattern</th><th>CVEs</th>
</tr>
{% for f in source_findings %}
<tr>
<td><span class="severity-badge severity-{{ f.severity }}">{{ f.severity|upper }}</span></td>
<td>{% if f.confidence %}<span class="confidence-badge confidence-{{ f.confidence }}">{{ f.confidence }}</span>{% else %}—{% endif %}</td>
<td><code>{{ f.class }}</code></td>
<td><code>{{ f.file|truncate_path }}</code></td>
<td>{{ f.line }}</td>
<td><code>{{ f.content|truncate(80, True) }}</code></td>
<td>{{ f.cves|join(', ') if f.cves else '—' }}</td>
</tr>
{% endfor %}
</table>
</div>
{% endif %}

{% if binary_findings %}
<div class="section">
<h2>Binary Analysis Findings ({{ binary_count }})</h2>
<table>
<tr>
<th>Severity</th><th>Confidence</th><th>Class</th><th>Binary</th><th>Function</th><th>Details</th><th>CVEs</th>
</tr>
{% for f in binary_findings %}
<tr>
<td><span class="severity-badge severity-{{ f.severity }}">{{ f.severity|upper }}</span></td>
<td>{% if f.confidence %}<span class="confidence-badge confidence-{{ f.confidence }}">{{ f.confidence }}</span>{% else %}—{% endif %}</td>
<td><code>{{ f.class }}</code></td>
<td><code>{{ f.file|truncate_path }}</code></td>
<td><code>{{ f.function }}</code></td>
<td>{{ f.details|truncate(100, True) }}</td>
<td>{{ f.cves|join(', ') if f.cves else '—' }}</td>
</tr>
{% endfor %}
</table>
</div>
{% endif %}

{% if dependency_findings %}
<div class="section">
<h2>Vulnerable Dependencies ({{ dependency_count }})</h2>
<table>
<tr>
<th>Severity</th><th>Library</th><th>Version</th><th>CVE</th><th>Fixed In</th><th>Details</th>
</tr>
{% for f in dependency_findings %}
<tr>
<td><span class="severity-badge severity-{{ f.severity }}">{{ f.severity|upper }}</span></td>
<td><code>{{ f.library }}</code></td>
<td>{{ f.version }}</td>
<td>{{ f.cve }}</td>
<td>{{ f.fixed_version }}</td>
<td>{{ f.details|truncate(100, True) }}</td>
</tr>
{% endfor %}
</table>
</div>
{% endif %}

<div class="section">
<h2>Vulnerability Classes Detected</h2>
<table>
<tr><th>Class</th><th>Count</th><th>Description</th></tr>
{% for cls, count in class_counts.items() %}
<tr>
<td><code>{{ cls }}</code></td>
<td>{{ count }}</td>
<td>{{ class_descriptions.get(cls, '') }}</td>
</tr>
{% endfor %}
</table>
</div>

<div class="footer">
<p>Generated by {{ tool_name }} v{{ tool_version }} | Based on CommandInWiFi-Zeroclick research</p>
<p>14 vulnerability classes | 17 CVEs cross-referenced</p>
</div>
</body>
</html>"""


CLASS_DESCRIPTIONS = {
    "wifi_cmd": "Shell command injection via SSID in system()/popen()/exec()",
    "wifi_overflow": "Buffer overflow from SSID copy without length validation",
    "wifi_fmt": "Format string: SSID used as format argument in printf/syslog",
    "wifi_xss": "Cross-site scripting via unescaped SSID in web interfaces",
    "wifi_serial": "Serialization/config injection: SSID in JSON/XML/SQL/YAML",
    "wifi_crlf": "CRLF injection via SSID reflected in HTTP headers",
    "wifi_jndi": "JNDI/expression language injection via SSID in Log4j",
    "wifi_path": "Path traversal via SSID used in filesystem path construction",
    "wifi_nosql": "NoSQL/LDAP injection via SSID in database queries",
    "wifi_esc": "Terminal escape injection via SSID in serial/log output",
    "wifi_enc": "Encoding normalization bypass: validation before normalization",
    "wifi_heap": "Heap metadata corruption via SSID overflow into allocator structures",
    "wifi_chain": "Multi-SSID chain: split payloads across concatenated scan results",
    "wifi_probe": "Malformed SSID probes targeting WiFi stack parsing logic",
}

TOOL_NAME = "SiDEWiNDER"
TOOL_VERSION = "1.0.0"


def _truncate_path(path: str, max_parts: int = 4) -> str:
    """Truncate a long file path keeping last N parts."""
    parts = Path(path).parts
    if len(parts) <= max_parts:
        return path
    return ".../" + "/".join(parts[-max_parts:])


def _truncate(text: str, length: int = 80, ellipsis: bool = True) -> str:
    """Truncate text to max length."""
    if not text:
        return ""
    text = str(text)
    if len(text) <= length:
        return text
    return text[:length] + ("..." if ellipsis else "")


class ReportGenerator:
    """Generates structured vulnerability reports."""

    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(
        self,
        target: str,
        source_summary: dict = None,
        binary_summary: dict = None,
        dependency_summary: dict = None,
    ) -> dict:
        """Generate a complete scan report from all scanner outputs."""
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Merge all findings
        source_findings = (source_summary or {}).get("findings", [])
        binary_findings = (binary_summary or {}).get("findings", [])
        dependency_findings = (dependency_summary or {}).get("findings", [])

        all_findings = source_findings + binary_findings + dependency_findings
        total = len(all_findings)

        # Deduplicate by dedup_key if available
        seen_keys = set()
        unique_count = 0
        for f in all_findings:
            key = f.get("dedup_key", f"{f.get('file', '')}:{f.get('line', '')}:{f.get('class', '')}")
            if key not in seen_keys:
                seen_keys.add(key)
                unique_count += 1

        # Count severities
        severity = {}
        class_counts = {}
        confidence_counts = {}
        for f in all_findings:
            sev = f.get("severity", "unknown")
            severity[sev] = severity.get(sev, 0) + 1
            cls = f.get("class", f.get("vuln_class", "unknown"))
            class_counts[cls] = class_counts.get(cls, 0) + 1
            conf = f.get("confidence", "")
            if conf:
                confidence_counts[conf] = confidence_counts.get(conf, 0) + 1

        # Count files
        files_scanned = (
            (source_summary or {}).get("files_scanned", 0)
            + (binary_summary or {}).get("binaries_analyzed", 0)
            + (dependency_summary or {}).get("files_checked", 0)
        )

        report = {
            "meta": {
                "tool": TOOL_NAME,
                "version": TOOL_VERSION,
                "target": target,
                "timestamp": timestamp,
                "timestamp_iso": now.isoformat(),
            },
            "summary": {
                "total_findings": total,
                "unique_findings": unique_count,
                "files_scanned": files_scanned,
                "severity": severity,
                "confidence": confidence_counts,
                "class_counts": class_counts,
                "by_type": {
                    "source": len(source_findings),
                    "binary": len(binary_findings),
                    "dependency": len(dependency_findings),
                },
            },
            "source_findings": source_findings,
            "binary_findings": binary_findings,
            "dependency_findings": dependency_findings,
        }

        return report

    def save_json(self, report: dict, filename: str = None) -> str:
        """Save report as JSON file."""
        if filename is None:
            filename = f"sidewinder_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        return filepath

    def save_html(self, report: dict, filename: str = None) -> str:
        """Save report as HTML file."""
        if filename is None:
            filename = f"sidewinder_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.output_dir, filename)

        env = Environment()
        env.filters["truncate_path"] = _truncate_path
        template = env.from_string(HTML_TEMPLATE)

        html = template.render(
            target=report["meta"]["target"],
            timestamp=report["meta"]["timestamp"],
            tool_name=report["meta"]["tool"],
            tool_version=report["meta"]["version"],
            total_findings=report["summary"]["total_findings"],
            unique_findings=report["summary"]["unique_findings"],
            severity=report["summary"]["severity"],
            confidence_counts=report["summary"].get("confidence", {}),
            files_scanned=report["summary"]["files_scanned"],
            source_findings=report["source_findings"],
            binary_findings=report["binary_findings"],
            dependency_findings=report["dependency_findings"],
            source_count=report["summary"]["by_type"]["source"],
            binary_count=report["summary"]["by_type"]["binary"],
            dependency_count=report["summary"]["by_type"]["dependency"],
            class_counts=report["summary"]["class_counts"],
            class_descriptions=CLASS_DESCRIPTIONS,
        )

        with open(filepath, "w") as f:
            f.write(html)
        return filepath
