"""
Source Code Scanner for SSID Injection Vulnerabilities

Scans source code files (C, Python, Java, JavaScript, PHP, Lua, HTML, Go,
Ruby, Perl, Shell) for vulnerable code patterns that process WiFi SSIDs
without sanitization. Includes confidence scoring, deduplication, multi-line
support, and SSID context validation.
"""

import json
import os
import re
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class Finding:
    """A single vulnerability finding in source code."""
    file_path: str
    line_number: int
    line_content: str
    vuln_class: str
    vuln_name: str
    severity: str
    cwe: str
    pattern_matched: str
    language: str
    zero_click: bool
    confidence: str = "medium"  # low, medium, high, confirmed
    ssid_context: bool = False  # whether SSID context was validated nearby
    matching_cves: list = field(default_factory=list)
    test_payloads: list = field(default_factory=list)

    @property
    def dedup_key(self) -> str:
        """Unique key for deduplication: same file + line + vuln class."""
        return f"{self.file_path}:{self.line_number}:{self.vuln_class}"

    def to_dict(self):
        return {
            "file": self.file_path,
            "line": self.line_number,
            "content": self.line_content.strip(),
            "class": self.vuln_class,
            "name": self.vuln_name,
            "severity": self.severity,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "ssid_context": self.ssid_context,
            "pattern": self.pattern_matched,
            "language": self.language,
            "zero_click": self.zero_click,
            "cves": self.matching_cves,
            "payloads": self.test_payloads,
        }


# Map file extensions to language identifiers used in rule files
EXTENSION_TO_LANG = {
    ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".cxx": "c", ".ino": "c",
    ".py": "python",
    ".java": "java",
    ".js": "javascript", ".ts": "javascript", ".mjs": "javascript",
    ".php": "php",
    ".lua": "lua",
    ".html": "html", ".htm": "html", ".asp": "html", ".jsp": "html", ".tpl": "html",
    ".go": "go",
    ".rb": "ruby",
    ".pl": "perl", ".pm": "perl",
    ".sh": "shell", ".bash": "shell",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".svn", "venv", ".venv",
    "env", ".eggs", "dist", "build", ".tox", ".cache",
}

SKIP_FILES = {
    ".pyc", ".pyo", ".so", ".o", ".a", ".dll", ".exe", ".bin",
    ".png", ".jpg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz",
    ".woff", ".woff2", ".ttf", ".eot", ".ico", ".svg",
}

# SSID-related variable/function names for context validation
SSID_CONTEXT_WORDS = re.compile(
    r'\b(ssid|essid|network_name|network\.name|ap_name|wifi_name|'
    r'bss_info|scan_result|wifi_scan|wlan_scan|beacon|ie_data|ie_len|'
    r'ssid_len|ssid_ie|iwconfig|iwpriv|iwlist|nmcli|wpa_cli|'
    r'wpa_supplicant|hostapd|softAP|WiFi\.|wifi_config|'
    r'WLAN_EID_SSID|IEEE80211|site.survey|wireless.scan)\b',
    re.IGNORECASE,
)

# Comment patterns per language
COMMENT_PATTERNS = {
    "c": (re.compile(r'^\s*//'), re.compile(r'^\s*/?\*')),
    "python": (re.compile(r'^\s*#'),),
    "java": (re.compile(r'^\s*//'), re.compile(r'^\s*/?\*')),
    "javascript": (re.compile(r'^\s*//'), re.compile(r'^\s*/?\*')),
    "php": (re.compile(r'^\s*//'), re.compile(r'^\s*#'), re.compile(r'^\s*/?\*')),
    "lua": (re.compile(r'^\s*--'),),
    "html": (re.compile(r'^\s*<!--'),),
    "go": (re.compile(r'^\s*//'), re.compile(r'^\s*/?\*')),
    "ruby": (re.compile(r'^\s*#'),),
    "perl": (re.compile(r'^\s*#'),),
    "shell": (re.compile(r'^\s*#'),),
}


class SourceScanner:
    """Scans source code for SSID injection vulnerability patterns."""

    def __init__(self, rules_dir: str, cve_db_path: str):
        self.rules = self._load_rules(rules_dir)
        self.cve_db = self._load_cve_db(cve_db_path)
        self.findings: list[Finding] = []
        self._seen_keys: set[str] = set()  # dedup tracking
        self.files_scanned = 0
        self.lines_scanned = 0
        self.warnings: list[str] = []

    def _load_rules(self, rules_dir: str) -> list[dict]:
        """Load all vulnerability class rule files from the rules directory."""
        rules = []
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

        for rule_file in sorted(rules_path.glob("wifi_*.json")):
            with open(rule_file) as f:
                rule = json.load(f)
                compiled = {}
                for lang, patterns in rule.get("source_patterns", {}).items():
                    compiled[lang] = [
                        (p, re.compile(p, re.IGNORECASE))
                        for p in patterns
                    ]
                rule["_compiled"] = compiled

                safe_compiled = []
                for p in rule.get("safe_patterns", []):
                    safe_compiled.append(re.compile(p, re.IGNORECASE))
                rule["_safe_compiled"] = safe_compiled

                rules.append(rule)

        return rules

    def _load_cve_db(self, cve_db_path: str) -> list[dict]:
        try:
            with open(cve_db_path) as f:
                return json.load(f).get("cves", [])
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _get_matching_cves(self, vuln_class: str) -> list[str]:
        return [c["id"] for c in self.cve_db if c.get("vuln_class") == vuln_class]

    def _detect_language(self, file_path: str) -> str | None:
        ext = Path(file_path).suffix.lower()
        return EXTENSION_TO_LANG.get(ext)

    def _should_skip(self, path: Path) -> bool:
        if path.is_dir():
            return path.name in SKIP_DIRS
        return path.suffix in SKIP_FILES

    def _is_comment(self, line: str, lang: str) -> bool:
        """Check if a line is a comment. Always skip comments."""
        patterns = COMMENT_PATTERNS.get(lang, ())
        for p in patterns:
            if p.match(line):
                return True
        return False

    def _is_safe_line(self, line: str, rule: dict) -> bool:
        for safe_re in rule["_safe_compiled"]:
            if safe_re.search(line):
                return True
        return False

    def _check_ssid_context(self, lines: list[str], target_line: int,
                             window: int = 10) -> bool:
        """Check if SSID-related context exists within a window around the target line.

        This reduces false positives by confirming the flagged code actually
        deals with SSID/WiFi data, not just happens to use a variable named 'ssid'.
        """
        start = max(0, target_line - window)
        end = min(len(lines), target_line + window)
        context_text = " ".join(lines[start:end])
        return bool(SSID_CONTEXT_WORDS.search(context_text))

    def _compute_confidence(self, line: str, has_ssid_context: bool,
                             vuln_class: str, lang: str) -> str:
        """Compute confidence level for a finding.

        Factors:
        - SSID context nearby (strongest signal)
        - Direct SSID variable in the vulnerable call
        - Vulnerability class severity
        - Language-specific risk (C is riskier than Python for overflows)
        """
        score = 0

        # Direct SSID reference in the line itself
        if re.search(r'\bssid\b', line, re.IGNORECASE):
            score += 3

        # SSID context within surrounding code
        if has_ssid_context:
            score += 2

        # WiFi-related function names in the line
        if re.search(r'\b(iwconfig|iwpriv|nmcli|wpa_cli|softAP|wifi)\b', line, re.IGNORECASE):
            score += 2

        # C/C++ with memory operations = higher risk
        if lang == "c" and vuln_class in ("wifi_overflow", "wifi_heap", "wifi_fmt"):
            score += 1

        # Map score to confidence level
        if score >= 6:
            return "confirmed"
        elif score >= 4:
            return "high"
        elif score >= 2:
            return "medium"
        return "low"

    def _build_multiline_view(self, lines: list[str]) -> str:
        """Join lines with spaces to catch patterns spanning line breaks.

        Returns a single string where line boundaries are replaced with spaces,
        preserving the ability to match patterns like:
            strcpy(buffer,
                   ssid);
        """
        return " ".join(l.rstrip() for l in lines)

    # Limits to prevent hanging on firmware blobs
    MAX_FILE_SIZE = 2 * 1024 * 1024   # 2 MB - skip huge auto-generated/minified files
    MAX_LINES_MULTILINE = 10000       # Multi-line phase only on files < 10K lines

    def scan_file(self, file_path: str) -> list[Finding]:
        """Scan a single source file for SSID vulnerability patterns."""
        lang = self._detect_language(file_path)
        if lang is None:
            return []

        # Skip files larger than MAX_FILE_SIZE (firmware blobs, minified JS, etc.)
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.MAX_FILE_SIZE:
                self.warnings.append(
                    f"Skipped {file_path} ({file_size // 1024}KB > {self.MAX_FILE_SIZE // 1024}KB limit)"
                )
                self.files_scanned += 1
                return []
        except OSError:
            pass

        try:
            with open(file_path, "r", errors="replace") as f:
                lines = f.readlines()
        except (OSError, PermissionError) as e:
            self.warnings.append(f"Cannot read {file_path}: {e}")
            return []

        file_findings = []
        self.files_scanned += 1
        self.lines_scanned += len(lines)

        # Phase 1: Single-line scanning
        for rule in self.rules:
            compiled_patterns = rule["_compiled"].get(lang, [])
            if not compiled_patterns:
                continue

            for line_num, line in enumerate(lines, start=1):
                # Skip comment lines entirely
                if self._is_comment(line, lang):
                    continue

                for pattern_str, pattern_re in compiled_patterns:
                    if pattern_re.search(line):
                        if self._is_safe_line(line, rule):
                            continue

                        # Check SSID context and compute confidence
                        has_context = self._check_ssid_context(lines, line_num - 1)
                        confidence = self._compute_confidence(
                            line, has_context, rule["class"], lang,
                        )

                        finding = Finding(
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line,
                            vuln_class=rule["class"],
                            vuln_name=rule["name"],
                            severity=rule["severity"],
                            cwe=rule.get("cwe", "N/A"),
                            pattern_matched=pattern_str,
                            language=lang,
                            zero_click=rule.get("zero_click", False),
                            confidence=confidence,
                            ssid_context=has_context,
                            matching_cves=self._get_matching_cves(rule["class"]),
                            test_payloads=rule.get("test_payloads", []),
                        )

                        # Deduplicate: same file + line + vuln class
                        if finding.dedup_key not in self._seen_keys:
                            self._seen_keys.add(finding.dedup_key)
                            file_findings.append(finding)

        # Phase 2: Multi-line scanning (sliding window of 3 lines)
        # Only run on reasonably-sized files to avoid O(n*p) explosion
        if 2 <= len(lines) <= self.MAX_LINES_MULTILINE:
            for rule in self.rules:
                compiled_patterns = rule["_compiled"].get(lang, [])
                if not compiled_patterns:
                    continue

                for i in range(len(lines) - 1):
                    # Join 2-3 consecutive lines
                    window_size = min(3, len(lines) - i)
                    joined = self._build_multiline_view(lines[i:i + window_size])

                    for pattern_str, pattern_re in compiled_patterns:
                        if pattern_re.search(joined):
                            # Only report if NOT already found in single-line pass
                            dedup = f"{file_path}:{i + 1}:{rule['class']}"
                            if dedup in self._seen_keys:
                                continue
                            # Verify the pattern doesn't match any single line alone
                            single_match = any(
                                pattern_re.search(lines[i + j])
                                for j in range(window_size)
                            )
                            if single_match:
                                continue  # Already caught in phase 1

                            has_context = self._check_ssid_context(lines, i)
                            confidence = self._compute_confidence(
                                joined, has_context, rule["class"], lang,
                            )

                            finding = Finding(
                                file_path=file_path,
                                line_number=i + 1,
                                line_content=joined[:200],
                                vuln_class=rule["class"],
                                vuln_name=rule["name"],
                                severity=rule["severity"],
                                cwe=rule.get("cwe", "N/A"),
                                pattern_matched=f"[multi-line] {pattern_str}",
                                language=lang,
                                zero_click=rule.get("zero_click", False),
                                confidence=confidence,
                                ssid_context=has_context,
                                matching_cves=self._get_matching_cves(rule["class"]),
                                test_payloads=rule.get("test_payloads", []),
                            )
                            self._seen_keys.add(dedup)
                            file_findings.append(finding)

        self.findings.extend(file_findings)
        return file_findings

    def collect_files(self, target_dir: str, recursive: bool = True) -> list[str]:
        """Collect all scannable source files from a directory tree."""
        target = Path(target_dir)
        if not target.exists():
            raise FileNotFoundError(f"Target directory not found: {target_dir}")

        if target.is_file():
            return [str(target)]

        files_to_scan = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            if not recursive and root != str(target):
                break
            for fname in sorted(files):
                fpath = Path(root) / fname
                if not self._should_skip(fpath) and self._detect_language(str(fpath)):
                    files_to_scan.append(str(fpath))

        return files_to_scan

    def scan_directory(self, target_dir: str, recursive: bool = True,
                       progress_callback=None) -> list[Finding]:
        """Scan all source files in a directory tree.

        Args:
            target_dir: Path to scan
            recursive: Scan subdirectories
            progress_callback: Optional callable(file_path, files_done, total_files)
                               called after each file is scanned
        """
        files_to_scan = self.collect_files(target_dir, recursive)
        total = len(files_to_scan)

        for i, fpath in enumerate(files_to_scan):
            self.scan_file(fpath)
            if progress_callback:
                progress_callback(fpath, i + 1, total)

        return self.findings

    def get_summary(self) -> dict:
        severity_counts = {}
        class_counts = {}
        confidence_counts = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            class_counts[f.vuln_class] = class_counts.get(f.vuln_class, 0) + 1
            confidence_counts[f.confidence] = confidence_counts.get(f.confidence, 0) + 1

        return {
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "by_class": class_counts,
            "by_confidence": confidence_counts,
            "unique_findings": len(self._seen_keys),
            "warnings": self.warnings,
            "findings": [f.to_dict() for f in self.findings],
        }

    def reset(self):
        self.findings.clear()
        self._seen_keys.clear()
        self.warnings.clear()
        self.files_scanned = 0
        self.lines_scanned = 0
