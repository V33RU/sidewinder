"""
Dependency Checker for Known Vulnerable Libraries

Checks firmware and source code for libraries with known SSID-related
vulnerabilities. Matches library versions against CVE database.
"""

import json
import os
import re
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class DependencyFinding:
    """A vulnerable dependency detected in the target."""
    file_path: str
    library: str
    version_found: str
    vuln_class: str
    severity: str
    cve_id: str
    fixed_version: str
    details: str
    detection_method: str  # "version_string", "binary_symbol", "package_manifest", "config_file"

    def to_dict(self):
        return {
            "file": self.file_path,
            "library": self.library,
            "version": self.version_found,
            "class": self.vuln_class,
            "severity": self.severity,
            "cve": self.cve_id,
            "fixed_version": self.fixed_version,
            "details": self.details,
            "method": self.detection_method,
        }


# Known vulnerable libraries and their version ranges
VULNERABLE_LIBRARIES = [
    {
        "name": "wpa_supplicant",
        "vuln_class": "wifi_overflow",
        "cve": "CVE-2015-1863",
        "severity": "critical",
        "vulnerable_below": "2.5",
        "fixed": "2.5",
        "details": "Heap overflow via SSID IE length during P2P discovery",
        "binary_names": ["wpa_supplicant", "wpa_cli"],
        "version_patterns": [
            r"wpa_supplicant\s+v?([\d.]+)",
            r"WPA_SUPPLICANT_VERSION\s*=?\s*\"?([\d.]+)",
        ],
    },
    {
        "name": "Log4j (log4j-core)",
        "vuln_class": "wifi_jndi",
        "cve": "CVE-2021-44228",
        "severity": "critical",
        "vulnerable_range": ">=2.0-beta9,<=2.14.1",
        "fixed": "2.15.0",
        "details": "JNDI lookup RCE via logged SSID containing ${jndi:...}",
        "file_patterns": ["**/log4j-core-*.jar", "**/log4j*.properties", "**/log4j*.xml"],
        "version_patterns": [
            r"log4j-core-([\d.]+(?:-\w+)?)",
            r"log4j\.version\s*=?\s*([\d.]+)",
        ],
    },
    {
        "name": "systeminformation (npm)",
        "vuln_class": "wifi_cmd",
        "cve": "CVE-2023-42810",
        "severity": "critical",
        "vulnerable_below": "5.21.7",
        "fixed": "5.21.7",
        "details": "Command injection via exec() in wifiConnections()",
        "file_patterns": ["**/node_modules/systeminformation/**", "**/package.json", "**/package-lock.json"],
        "manifest_only": True,  # Only check in package manifests, NOT in binary strings
        "version_patterns": [
            r"\"systeminformation\":\s*\"[~^]?([\d.]+)\"",
        ],
    },
    {
        "name": "MediaTek wappd",
        "vuln_class": "wifi_overflow",
        "cve": "CVE-2024-20017",
        "severity": "critical",
        "vulnerable_below": "7.4.0.2",
        "fixed": "7.4.0.2",
        "details": "Zero-click OOB write in MediaTek WiFi daemon (CVSS 9.8)",
        "binary_names": ["wappd", "wapid"],
        "version_patterns": [
            r"wappd\s+v?([\d.]+)",
            r"MT76\w+\s+SDK\s+([\d.]+)",
        ],
    },
    {
        "name": "Broadcom BCM43xx WiFi firmware",
        "vuln_class": "wifi_overflow",
        "cve": "CVE-2017-9417",
        "severity": "critical",
        "details": "Broadpwn: heap overflow in WiFi chip firmware beacon parsing",
        "binary_names": ["bcmdhd", "brcmfmac", "wl"],
        "file_patterns": ["**/*bcm43*", "**/*brcm*"],
        "version_patterns": [
            r"BCM43\w+\s+firmware\s+v?([\d.]+)",
        ],
    },
    {
        "name": "Realtek RTL8195A",
        "vuln_class": "wifi_overflow",
        "cve": "CVE-2020-9395",
        "severity": "critical",
        "details": "Stack overflow in WiFi module, exploitable without password",
        "binary_names": ["rtl8195a", "rtl87xx"],
        "file_patterns": ["**/*rtl819*", "**/*rtl87*"],
        "version_patterns": [
            r"RTL8195A?\s+v?([\d.]+)",
        ],
    },
    {
        "name": "FreeBSD net80211",
        "vuln_class": "wifi_overflow",
        "cve": "CVE-2022-23088",
        "severity": "critical",
        "details": "Heap overflow via Mesh ID IE in kernel WiFi stack",
        "binary_names": ["if_iwm", "if_rtwn", "if_ath"],
        "version_patterns": [
            r"FreeBSD\s+([\d.]+)",
        ],
    },
]


class DependencyChecker:
    """Checks for known vulnerable libraries in firmware and source code."""

    def __init__(self):
        self.findings: list[DependencyFinding] = []
        self.files_checked = 0

    def _version_compare(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        def normalize(v):
            parts = []
            for p in re.split(r'[.\-]', v):
                if p.isdigit():
                    parts.append(int(p))
                else:
                    parts.append(0)
            return parts

        p1, p2 = normalize(v1), normalize(v2)
        # Pad shorter list
        max_len = max(len(p1), len(p2))
        p1.extend([0] * (max_len - len(p1)))
        p2.extend([0] * (max_len - len(p2)))

        for a, b in zip(p1, p2):
            if a < b:
                return -1
            if a > b:
                return 1
        return 0

    def _is_vulnerable_version(self, version: str, lib: dict) -> bool:
        """Check if a detected version falls within the vulnerable range.

        Supports:
        - vulnerable_below: version < threshold
        - vulnerable_range: ">=lower,<=upper" (e.g. Log4j 2.0-beta9 to 2.14.1)
        """
        if "vulnerable_below" in lib:
            return self._version_compare(version, lib["vulnerable_below"]) < 0

        if "vulnerable_range" in lib:
            range_str = lib["vulnerable_range"]
            for constraint in range_str.split(","):
                constraint = constraint.strip()
                if constraint.startswith(">="):
                    bound = constraint[2:]
                    if self._version_compare(version, bound) < 0:
                        return False
                elif constraint.startswith(">"):
                    bound = constraint[1:]
                    if self._version_compare(version, bound) <= 0:
                        return False
                elif constraint.startswith("<="):
                    bound = constraint[2:]
                    if self._version_compare(version, bound) > 0:
                        return False
                elif constraint.startswith("<"):
                    bound = constraint[1:]
                    if self._version_compare(version, bound) >= 0:
                        return False
            return True

        return True  # If no version range specified, flag for manual review

    def check_binary_strings(self, file_path: str) -> list[DependencyFinding]:
        """Check binary file for version strings of vulnerable libraries."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except (OSError, PermissionError):
            return []

        self.files_checked += 1
        file_findings = []

        # Extract ASCII strings
        text = data.decode("ascii", errors="ignore")

        fname = Path(file_path).name.lower()
        stem = Path(file_path).stem.lower()

        for lib in VULNERABLE_LIBRARIES:
            # Skip libraries marked as manifest-only (e.g. npm packages)
            # These should only be checked in package.json, not in ELF binaries
            if lib.get("manifest_only", False):
                continue

            # Skip libraries that only have file_patterns for non-binary types
            # (e.g. .jar, .json, .xml, .properties) — these aren't relevant to ELF
            if "file_patterns" in lib and "binary_names" not in lib:
                continue

            # Check binary name match (exact or with extension/suffix only)
            binary_match = any(
                stem == bname.lower()
                or re.match(rf"^{re.escape(bname.lower())}[\d._-]*$", stem)
                for bname in lib.get("binary_names", [])
            )

            # Search for version patterns — but ONLY if binary name matches
            # or the library is known to have binary-detectable patterns.
            # This prevents generic patterns from matching unrelated binaries.
            if binary_match or lib.get("binary_names"):
                for pattern in lib.get("version_patterns", []):
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    for version in matches:
                        if self._is_vulnerable_version(version, lib):
                            finding = DependencyFinding(
                                file_path=file_path,
                                library=lib["name"],
                                version_found=version,
                                vuln_class=lib["vuln_class"],
                                severity=lib["severity"],
                                cve_id=lib["cve"],
                                fixed_version=lib.get("fixed", "Unknown"),
                                details=lib["details"],
                                detection_method="version_string",
                            )
                            file_findings.append(finding)

            # If binary name matches but no version found, flag for review
            if binary_match and not any(
                re.search(p, text, re.IGNORECASE)
                for p in lib.get("version_patterns", [])
            ):
                finding = DependencyFinding(
                    file_path=file_path,
                    library=lib["name"],
                    version_found="unknown",
                    vuln_class=lib["vuln_class"],
                    severity="medium",
                    cve_id=lib["cve"],
                    fixed_version=lib.get("fixed", "Unknown"),
                    details=f"{lib['details']} (binary name match, version unknown)",
                    detection_method="binary_symbol",
                )
                file_findings.append(finding)

        self.findings.extend(file_findings)
        return file_findings

    def check_package_manifest(self, file_path: str) -> list[DependencyFinding]:
        """Check package manifest files (package.json, requirements.txt, pom.xml)."""
        try:
            with open(file_path, "r", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError):
            return []

        self.files_checked += 1
        file_findings = []
        fname = Path(file_path).name.lower()

        for lib in VULNERABLE_LIBRARIES:
            for pattern in lib.get("version_patterns", []):
                matches = re.findall(pattern, content, re.IGNORECASE)
                for version in matches:
                    if self._is_vulnerable_version(version, lib):
                        finding = DependencyFinding(
                            file_path=file_path,
                            library=lib["name"],
                            version_found=version,
                            vuln_class=lib["vuln_class"],
                            severity=lib["severity"],
                            cve_id=lib["cve"],
                            fixed_version=lib.get("fixed", "Unknown"),
                            details=lib["details"],
                            detection_method="package_manifest",
                        )
                        file_findings.append(finding)

        self.findings.extend(file_findings)
        return file_findings

    def check_directory(self, target_dir: str,
                        progress_callback=None) -> list[DependencyFinding]:
        """Scan a directory tree for vulnerable dependencies.

        Args:
            target_dir: Path to scan
            progress_callback: Optional callable(file_path, files_done, total_files)
        """
        manifest_names = {
            "package.json", "package-lock.json", "yarn.lock",
            "requirements.txt", "Pipfile.lock", "setup.py", "setup.cfg",
            "pom.xml", "build.gradle", "build.gradle.kts",
            "Makefile", "CMakeLists.txt", "configure.ac",
        }

        # First pass: collect all files to check
        all_files = []
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in {".git", "__pycache__"}]
            for fname in files:
                all_files.append(os.path.join(root, fname))

        total = len(all_files)
        for idx, fpath in enumerate(all_files):
            fname = os.path.basename(fpath)

            # Check package manifests
            if fname.lower() in manifest_names:
                self.check_package_manifest(fpath)

            # Check binaries
            try:
                with open(fpath, "rb") as f:
                    if f.read(4) == b"\x7fELF":
                        self.check_binary_strings(fpath)
            except (OSError, PermissionError):
                if progress_callback:
                    progress_callback(fpath, idx + 1, total)
                continue

            # Check JAR files (for Log4j and similar)
            if fname.endswith(".jar"):
                from fnmatch import fnmatch
                for lib in VULNERABLE_LIBRARIES:
                    jar_patterns = [
                        p for p in lib.get("file_patterns", [])
                        if p.endswith(".jar") or "*.jar" in p
                    ]
                    if not jar_patterns:
                        continue
                    if not any(fnmatch(fname, Path(p).name) for p in jar_patterns):
                        continue
                    for pattern in lib.get("version_patterns", []):
                        match = re.search(pattern, fname)
                        if match:
                            version = match.group(1)
                            if self._is_vulnerable_version(version, lib):
                                finding = DependencyFinding(
                                    file_path=fpath,
                                    library=lib["name"],
                                    version_found=version,
                                    vuln_class=lib["vuln_class"],
                                    severity=lib["severity"],
                                    cve_id=lib["cve"],
                                    fixed_version=lib.get("fixed", "Unknown"),
                                    details=lib["details"],
                                    detection_method="package_manifest",
                                )
                                self.findings.append(finding)

            if progress_callback:
                progress_callback(fpath, idx + 1, total)

        return self.findings

    def get_summary(self) -> dict:
        lib_counts = {}
        severity_counts = {}
        for f in self.findings:
            lib_counts[f.library] = lib_counts.get(f.library, 0) + 1
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "files_checked": self.files_checked,
            "total_findings": len(self.findings),
            "by_library": lib_counts,
            "by_severity": severity_counts,
            "findings": [f.to_dict() for f in self.findings],
        }

    def reset(self):
        self.findings.clear()
        self.files_checked = 0
