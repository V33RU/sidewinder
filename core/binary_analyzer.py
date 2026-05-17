"""
Binary Analyzer for SSID Injection Vulnerabilities

Analyzes compiled ELF binaries (ARM, MIPS, x86) from IoT firmware
for dangerous function imports and SSID-related string references.
No source code required.
"""

import json
import os
import re
import subprocess
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class BinaryFinding:
    """A vulnerability indicator found in a binary."""
    file_path: str
    finding_type: str  # "dangerous_import", "ssid_string", "cross_reference", "buffer_pattern"
    function_name: str
    context: str
    vuln_class: str
    severity: str
    details: str
    offset: int = 0
    matching_cves: list = field(default_factory=list)

    confidence: str = "medium"  # low, medium, high, confirmed

    def to_dict(self):
        return {
            "file": self.file_path,
            "type": self.finding_type,
            "function": self.function_name,
            "context": self.context,
            "class": self.vuln_class,
            "severity": self.severity,
            "confidence": self.confidence,
            "details": self.details,
            "offset": hex(self.offset) if self.offset else "N/A",
            "cves": self.matching_cves,
        }


# Dangerous functions grouped by vulnerability class
DANGEROUS_FUNCTIONS = {
    "wifi_cmd": {
        "functions": ["system", "popen", "execl", "execlp", "execle", "execv",
                      "execvp", "execvpe", "dlopen"],
        "severity": "critical",
    },
    "wifi_overflow": {
        "functions": ["sprintf", "strcpy", "strcat", "gets", "scanf", "vsprintf",
                      "memcpy", "memmove", "strncpy", "strncat"],
        "severity": "critical",
    },
    "wifi_fmt": {
        "functions": ["printf", "fprintf", "sprintf", "snprintf", "syslog",
                      "vsprintf", "vsnprintf", "vfprintf", "vprintf"],
        "severity": "critical",
    },
    "wifi_heap": {
        "functions": ["malloc", "calloc", "realloc", "free",
                      "pvPortMalloc", "vPortFree", "heap_caps_malloc"],
        "severity": "critical",
    },
    "wifi_serial": {
        "functions": ["sqlite3_exec", "sqlite3_prepare", "sqlite3_prepare_v2",
                      "mysql_query", "mysql_real_query",
                      "xmlParseMemory", "xmlParseDoc", "xmlReadMemory"],
        "severity": "high",
    },
    "wifi_path": {
        "functions": ["fopen", "open", "creat", "access", "stat",
                      "unlink", "remove", "rename", "mkdir"],
        "severity": "high",
    },
    "wifi_nosql": {
        "functions": ["ldap_search_s", "ldap_search_ext_s", "ldap_modify_s"],
        "severity": "high",
    },
}

# Strings that indicate SSID processing context
# These must be specific enough to avoid matching unrelated binaries
SSID_CONTEXT_STRINGS = [
    b"ssid", b"SSID", b"essid", b"ESSID",
    b"network_name", b"ap_name", b"bss_info",
    b"wifi_scan", b"wlan_scan",
    b"probe_req", b"probe_resp",
    b"ie_data", b"ie_len", b"ssid_len", b"ssid_ie",
    b"iwconfig", b"iwpriv", b"iwlist",
    b"nmcli", b"wpa_cli", b"wpa_supplicant",
    b"hostapd", b"uci set wireless",
    b"WiFi.softAP", b"wifi_set_opmode",
    b"esp_wifi", b"wifi_config_t",
    b"IEEE80211", b"WLAN_EID_SSID",
    b"wifi_history",
]
# Note: removed overly generic strings that cause false positives:
# - "INSERT INTO" - matches any SQL-using binary
# - "beacon" - matches timer/debug/UI beacons, not just WiFi beacons
# - "scan_result" - matches any scan operation, not just WiFi
# - "Site Survey", "Wireless Networks" - too broad for binary matching

# Shell command strings that may consume SSIDs
SHELL_CONTEXT_STRINGS = [
    b"iwconfig %s essid", b"iwpriv %s set SSID",
    b"nmcli dev wifi connect", b"wpa_cli set_network",
    b"uci set wireless", b"iwlist %s scan",
]


class BinaryAnalyzer:
    """Analyzes ELF binaries for SSID injection vulnerability indicators."""

    def __init__(self, rules_dir: str, cve_db_path: str):
        self.rules = self._load_binary_rules(rules_dir)
        self.cve_db = self._load_cve_db(cve_db_path)
        self.findings: list[BinaryFinding] = []
        self.files_analyzed = 0

        # Effective function->class map: starts from the hardcoded fallback
        # and is extended by anything declared in rule JSONs'
        # ``binary_signatures.dangerous_imports``. Rule JSONs are authoritative
        # when they list a class that also lives in DANGEROUS_FUNCTIONS.
        self._effective_dangerous = self._build_effective_dangerous()
        # Per-class additional context strings drawn from rule JSONs
        # (``binary_signatures.context_strings``). Empty when no rule
        # contributes any.
        self._rule_context_strings = self._build_rule_context_strings()

    def _load_binary_rules(self, rules_dir: str) -> dict:
        """Load binary-specific signatures from rule files."""
        rules = {}
        rules_path = Path(rules_dir)
        for rule_file in rules_path.glob("wifi_*.json"):
            with open(rule_file) as f:
                rule = json.load(f)
                if "binary_signatures" in rule:
                    rules[rule["class"]] = rule
        return rules

    def _build_effective_dangerous(self) -> dict:
        """Merge rule-JSON ``dangerous_imports`` with the hardcoded fallback.

        Rule JSONs are authoritative when present; the hardcoded
        ``DANGEROUS_FUNCTIONS`` dict supplies (a) a default severity for any
        class only mentioned in a rule and (b) coverage for classes with no
        rule entry at all (backward compatibility).
        """
        effective = {
            cls: {"functions": list(info["functions"]), "severity": info["severity"]}
            for cls, info in DANGEROUS_FUNCTIONS.items()
        }
        for cls, rule in self.rules.items():
            sig = rule.get("binary_signatures", {})
            funcs = sig.get("dangerous_imports", [])
            if not funcs:
                continue
            severity = rule.get("severity") or effective.get(cls, {}).get("severity", "medium")
            existing = effective.setdefault(cls, {"functions": [], "severity": severity})
            existing["severity"] = severity
            # Union the function lists, preserving order
            merged = list(existing["functions"])
            for f in funcs:
                if f not in merged:
                    merged.append(f)
            existing["functions"] = merged
        return effective

    def _build_rule_context_strings(self) -> dict:
        """Pull additional per-class context strings from rule JSONs."""
        out = {}
        for cls, rule in self.rules.items():
            ctx = rule.get("binary_signatures", {}).get("context_strings", [])
            if ctx:
                out[cls] = [c.encode("utf-8", errors="ignore") for c in ctx]
        return out

    def _load_cve_db(self, cve_db_path: str) -> list[dict]:
        try:
            with open(cve_db_path) as f:
                return json.load(f).get("cves", [])
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _get_matching_cves(self, vuln_class: str) -> list[str]:
        return [c["id"] for c in self.cve_db if c.get("vuln_class") == vuln_class]

    def _is_elf(self, file_path: str) -> bool:
        """Check if file is an ELF binary."""
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                return magic == b"\x7fELF"
        except (OSError, PermissionError):
            return False

    def _get_elf_info(self, file_path: str) -> dict:
        """Get basic ELF metadata using readelf or file command."""
        info = {"arch": "unknown", "bits": 0, "endian": "unknown"}
        try:
            result = subprocess.run(
                ["file", file_path],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout
            if "ARM" in output:
                info["arch"] = "ARM"
            elif "MIPS" in output:
                info["arch"] = "MIPS"
            elif "x86-64" in output:
                info["arch"] = "x86_64"
            elif "80386" in output:
                info["arch"] = "x86"
            elif "Xtensa" in output:
                info["arch"] = "Xtensa"

            if "32-bit" in output:
                info["bits"] = 32
            elif "64-bit" in output:
                info["bits"] = 64

            if "LSB" in output:
                info["endian"] = "little"
            elif "MSB" in output:
                info["endian"] = "big"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return info

    MAX_BINARY_SIZE = 20 * 1024 * 1024  # 20 MB - skip huge binaries for string extraction

    def _extract_strings(self, file_path: str, min_length: int = 4) -> list[tuple[int, bytes]]:
        """Extract printable strings from binary with their offsets.

        Handles both ASCII (0x20-0x7E) and valid UTF-8 sequences.
        Also attempts UTF-16LE extraction for Windows/UEFI binaries.

        For performance, uses the system `strings` command when available,
        falling back to manual extraction for smaller files.
        """
        strings = []

        # Check file size first
        try:
            file_size = os.path.getsize(file_path)
        except OSError:
            return strings

        # Use system `strings` for large files (much faster than Python byte-by-byte)
        if file_size > 512 * 1024:  # > 512KB, use system strings
            return self._extract_strings_fast(file_path, min_length)

        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except (OSError, PermissionError):
            return strings

        # ASCII / UTF-8 strings
        current = bytearray()
        start_offset = 0
        for i, byte in enumerate(data):
            if 0x20 <= byte <= 0x7e or byte in (0x09, 0x0a, 0x0d):
                if not current:
                    start_offset = i
                current.append(byte)
            elif byte >= 0xc0 and current:
                current.append(byte)
            elif 0x80 <= byte <= 0xbf and current and current[-1] >= 0x80:
                current.append(byte)
            else:
                if len(current) >= min_length:
                    strings.append((start_offset, bytes(current)))
                current = bytearray()

        if len(current) >= min_length:
            strings.append((start_offset, bytes(current)))

        # UTF-16LE strings (common in Windows binaries)
        i = 0
        while i < len(data) - 3:
            if 0x20 <= data[i] <= 0x7e and data[i + 1] == 0x00:
                start = i
                chars = []
                while i < len(data) - 1 and 0x20 <= data[i] <= 0x7e and data[i + 1] == 0x00:
                    chars.append(data[i])
                    i += 2
                if len(chars) >= min_length:
                    strings.append((start, bytes(chars)))
            else:
                i += 1

        return strings

    def _extract_strings_fast(self, file_path: str, min_length: int = 4) -> list[tuple[int, bytes]]:
        """Use system `strings` command for fast extraction on large binaries."""
        strings = []
        try:
            # -t d gives decimal offsets, -n sets min length
            result = subprocess.run(
                ["strings", f"-n{min_length}", "-t", "d", file_path],
                capture_output=True, timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.split(b"\n"):
                    line = line.strip()
                    if not line:
                        continue
                    # Format: "   offset string_content"
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        try:
                            offset = int(parts[0])
                            strings.append((offset, parts[1]))
                        except ValueError:
                            strings.append((0, line))
                    else:
                        strings.append((0, line))

            # Also try UTF-16LE extraction
            result_le = subprocess.run(
                ["strings", f"-n{min_length}", "-t", "d", "-e", "l", file_path],
                capture_output=True, timeout=30,
            )
            if result_le.returncode == 0:
                for line in result_le.stdout.split(b"\n"):
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        try:
                            offset = int(parts[0])
                            strings.append((offset, parts[1]))
                        except ValueError:
                            strings.append((0, line))

        except (subprocess.TimeoutExpired, FileNotFoundError):
            # If system strings not available, skip large files rather than hang
            pass

        return strings

    @staticmethod
    def _normalize_symbol(name: str) -> str:
        """Drop GLIBC/ld versioning suffixes so ``system@GLIBC_2.2.5`` matches
        a plain ``system`` lookup. Modern Linux toolchains emit versioned
        symbols by default; without this step the entire analyzer reports no
        dangerous imports on any glibc-linked binary."""
        if "@" in name:
            name = name.split("@", 1)[0]
        return name.lstrip("_")  # also tolerate leading-underscore mangling

    def _get_imported_functions(self, file_path: str) -> list[str]:
        """Extract imported function names from ELF binary."""
        imports = []
        try:
            # Try nm first
            result = subprocess.run(
                ["nm", "-D", "--undefined-only", file_path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.strip().split()
                    if parts:
                        imports.append(self._normalize_symbol(parts[-1]))
                return imports

            # Fallback to objdump
            result = subprocess.run(
                ["objdump", "-T", file_path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "*UND*" in line:
                        parts = line.strip().split()
                        if parts:
                            imports.append(self._normalize_symbol(parts[-1]))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return imports

    def analyze_file(self, file_path: str) -> list[BinaryFinding]:
        """Analyze a single ELF binary for SSID vulnerability indicators."""
        if not self._is_elf(file_path):
            return []

        self.files_analyzed += 1
        file_findings = []
        elf_info = self._get_elf_info(file_path)

        # Step 1: Check imported functions (rule-driven, with hardcoded fallback)
        imports = self._get_imported_functions(file_path)
        imports_set = set(imports)
        found_dangerous = {}

        for vuln_class, info in self._effective_dangerous.items():
            for func in info["functions"]:
                if func in imports_set:
                    found_dangerous.setdefault(vuln_class, []).append(func)

        # Step 2: Extract and analyze strings
        strings = self._extract_strings(file_path)
        has_ssid_context = False
        ssid_string_offsets = []
        shell_command_offsets = []

        # Only the hardcoded SSID_CONTEXT_STRINGS list is used as the global
        # "this binary processes SSIDs" signal. Rule-JSON context strings are
        # intentionally NOT pooled here: a wifi_serial rule lists SQL keywords
        # like SELECT/VALUES as class-specific corroboration signals, not as
        # SSID identifiers. Pooling them caused ~10x false-positive inflation
        # against real firmware (any binary with the word "select" got tagged
        # as SSID-processing).
        for offset, s in strings:
            for ctx in SSID_CONTEXT_STRINGS:
                if ctx.lower() in s.lower():
                    has_ssid_context = True
                    ssid_string_offsets.append((offset, s))
                    break
            for cmd in SHELL_CONTEXT_STRINGS:
                if cmd.lower() in s.lower():
                    shell_command_offsets.append((offset, s))
                    break

        # Step 3: Cross-reference dangerous imports with SSID context.
        # Require at least 2 distinct SSID-context string hits before emitting
        # critical/high cross-reference findings. A single accidental
        # substring match (e.g. "processid" containing "ssid", "mmap_name"
        # containing "ap_name") is far more likely to be coincidence than a
        # genuine SSID-processing binary. Real WiFi-handling binaries observed
        # in production firmware have dozens of context hits, while
        # non-WiFi binaries with accidental matches almost always have just 1.
        # Binaries with 0 or 1 hits fall through to Step 4 (low severity).
        if has_ssid_context and len(ssid_string_offsets) >= 2:
            for vuln_class, funcs in found_dangerous.items():
                severity = self._effective_dangerous[vuln_class]["severity"]
                for func in funcs:
                    # Confidence based on number of SSID context hits
                    n_ctx = len(ssid_string_offsets)
                    if n_ctx >= 5:
                        confidence = "high"
                    elif n_ctx >= 2:
                        confidence = "medium"
                    else:
                        confidence = "low"

                    finding = BinaryFinding(
                        file_path=file_path,
                        finding_type="cross_reference",
                        function_name=func,
                        context=f"Binary imports {func}() and contains SSID-related strings",
                        vuln_class=vuln_class,
                        severity=severity,
                        confidence=confidence,
                        details=(
                            f"Architecture: {elf_info['arch']} {elf_info['bits']}-bit "
                            f"{elf_info['endian']}-endian. "
                            f"Function {func}() is imported and SSID context strings "
                            f"found at {n_ctx} locations. "
                            f"Manual analysis needed to confirm SSID flows to {func}()."
                        ),
                        matching_cves=self._get_matching_cves(vuln_class),
                    )
                    file_findings.append(finding)

            # Shell command patterns are strong indicators of wifi_cmd
            for offset, cmd_str in shell_command_offsets:
                if "system" in imports or "popen" in imports:
                    finding = BinaryFinding(
                        file_path=file_path,
                        finding_type="cross_reference",
                        function_name="system/popen",
                        context=f"Shell command pattern with SSID: {cmd_str.decode('ascii', errors='replace')}",
                        vuln_class="wifi_cmd",
                        severity="critical",
                        confidence="confirmed",
                        details=(
                            f"Found shell command pattern at offset {hex(offset)} "
                            f"combined with system()/popen() import. Confirmed high-risk "
                            f"command injection vector via SSID."
                        ),
                        offset=offset,
                        matching_cves=self._get_matching_cves("wifi_cmd"),
                    )
                    file_findings.append(finding)

        # Step 4: Report dangerous imports even without confirmed SSID context.
        # Reached when the binary has 0 or 1 SSID-context hits (insufficient
        # corroboration for a high-severity finding) but still imports
        # dangerous functions worth manual review.
        elif found_dangerous:
            for vuln_class, funcs in found_dangerous.items():
                for func in funcs:
                    finding = BinaryFinding(
                        file_path=file_path,
                        finding_type="dangerous_import",
                        function_name=func,
                        context=f"Binary imports {func}() but no SSID context confirmed",
                        vuln_class=vuln_class,
                        severity="low",
                        details=(
                            f"Architecture: {elf_info['arch']}. "
                            f"Function {func}() is imported. No SSID-related strings "
                            f"found, but binary may process SSIDs through renamed or "
                            f"obfuscated variables. Consider manual review."
                        ),
                        matching_cves=self._get_matching_cves(vuln_class),
                    )
                    file_findings.append(finding)

        # Step 5: Check for fixed buffer sizes near SSID context
        for offset, s in strings:
            # Look for format strings with fixed buffers
            decoded = s.decode("ascii", errors="replace")
            if re.search(r"char\s+\w+\[(?:32|33|64|128)\]", decoded):
                if any(ctx.lower() in s.lower() for ctx in SSID_CONTEXT_STRINGS):
                    finding = BinaryFinding(
                        file_path=file_path,
                        finding_type="buffer_pattern",
                        function_name="fixed_buffer",
                        context=f"Fixed-size buffer declaration near SSID context: {decoded[:80]}",
                        vuln_class="wifi_overflow",
                        severity="high",
                        details=f"Fixed buffer at offset {hex(offset)} may receive unsanitized SSID",
                        offset=offset,
                        matching_cves=self._get_matching_cves("wifi_overflow"),
                    )
                    file_findings.append(finding)

        self.findings.extend(file_findings)
        return file_findings

    def collect_elf_files(self, target_dir: str) -> list[str]:
        """Collect all ELF binaries from a directory tree.

        Skips binaries larger than MAX_BINARY_SIZE to prevent hangs
        on massive firmware blobs.
        """
        target = Path(target_dir)
        if target.is_file():
            return [str(target)]

        elf_files = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
            for fname in files:
                fpath = str(Path(root) / fname)
                try:
                    # Skip files larger than limit
                    if os.path.getsize(fpath) > self.MAX_BINARY_SIZE:
                        continue
                    with open(fpath, "rb") as f:
                        if f.read(4) == b"\x7fELF":
                            elf_files.append(fpath)
                except (OSError, PermissionError):
                    continue
        return elf_files

    def analyze_directory(self, target_dir: str,
                          progress_callback=None) -> list[BinaryFinding]:
        """Recursively analyze all ELF binaries in a directory.

        Args:
            target_dir: Path to scan
            progress_callback: Optional callable(file_path, files_done, total_files)
        """
        elf_files = self.collect_elf_files(target_dir)
        total = len(elf_files)

        for i, fpath in enumerate(elf_files):
            self.analyze_file(fpath)
            if progress_callback:
                progress_callback(fpath, i + 1, total)

        return self.findings

    def get_summary(self) -> dict:
        severity_counts = {}
        class_counts = {}
        type_counts = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            class_counts[f.vuln_class] = class_counts.get(f.vuln_class, 0) + 1
            type_counts[f.finding_type] = type_counts.get(f.finding_type, 0) + 1

        return {
            "binaries_analyzed": self.files_analyzed,
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "by_class": class_counts,
            "by_type": type_counts,
            "findings": [f.to_dict() for f in self.findings],
        }

    def reset(self):
        self.findings.clear()
        self.files_analyzed = 0
