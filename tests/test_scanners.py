"""Snapshot tests for the three scanners.

These lock in current detection behavior so detection-changing refactors
(Phase 2+) cannot silently regress. When intentionally changing detection,
re-run the scanner against the fixtures and update the expected counts here.
"""
from __future__ import annotations

import json
from collections import Counter

import pytest

from core.binary_analyzer import BinaryAnalyzer
from core.dependency_checker import DependencyChecker
from core.source_scanner import SourceScanner


# ---------------------------------------------------------------------------
# Source scanner snapshot
# ---------------------------------------------------------------------------

# Expected (vuln_class, severity) -> count, captured from a clean run against
# tests/test_source on the Phase 1 baseline. Changing detection logic in a way
# that moves these numbers requires deliberately updating this dict.
EXPECTED_SOURCE_COUNTS: dict[tuple[str, str], int] = {
    ("wifi_cmd", "critical"): 10,
    ("wifi_enc", "medium"): 3,
    ("wifi_esc", "medium"): 2,
    ("wifi_fmt", "critical"): 2,
    ("wifi_jndi", "critical"): 3,
    ("wifi_nosql", "high"): 2,
    ("wifi_overflow", "critical"): 27,
    ("wifi_path", "high"): 5,
    ("wifi_probe", "high"): 2,
    ("wifi_serial", "high"): 7,
    ("wifi_xss", "high"): 2,
}


def test_source_scanner_finds_expected_classes(rules_dir, cve_db_path, fixture_dir):
    scanner = SourceScanner(rules_dir, cve_db_path)
    scanner.scan_directory(str(fixture_dir))

    actual = Counter((f.vuln_class, f.severity) for f in scanner.findings)
    assert dict(actual) == EXPECTED_SOURCE_COUNTS, (
        "Source scanner findings shifted. If intentional, update "
        "EXPECTED_SOURCE_COUNTS in this test."
    )


def test_source_scanner_dedup_keys_unique(rules_dir, cve_db_path, fixture_dir):
    scanner = SourceScanner(rules_dir, cve_db_path)
    scanner.scan_directory(str(fixture_dir))

    keys = [f.dedup_key for f in scanner.findings]
    assert len(keys) == len(set(keys)), "Duplicate findings escaped dedup"


def test_source_scanner_summary_shape(rules_dir, cve_db_path, fixture_dir):
    scanner = SourceScanner(rules_dir, cve_db_path)
    scanner.scan_directory(str(fixture_dir))
    summary = scanner.get_summary()

    for key in ("files_scanned", "total_findings", "by_severity",
                "by_class", "by_confidence", "findings"):
        assert key in summary, f"summary missing key {key}"

    assert summary["total_findings"] == sum(EXPECTED_SOURCE_COUNTS.values())


# ---------------------------------------------------------------------------
# Dependency checker - regression tests for the Phase 1 bug fixes
# ---------------------------------------------------------------------------

def test_dep_checker_flag_any_version_required(tmp_path):
    """Libraries with neither vulnerable_below nor vulnerable_range now require
    explicit flag_any_version=True. Without it, the checker MUST NOT flag.
    """
    checker = DependencyChecker()

    # Spoof a fake library entry with no version constraints.
    lib = {
        "name": "fake-lib",
        "vuln_class": "wifi_overflow",
        "cve": "CVE-XXXX-XXXX",
        "severity": "critical",
        "details": "test",
        "version_patterns": [],
    }
    assert checker._is_vulnerable_version("1.2.3", lib) is False, (
        "Library without explicit flag_any_version must not match"
    )

    lib_flagged = {**lib, "flag_any_version": True}
    assert checker._is_vulnerable_version("1.2.3", lib_flagged) is True


def test_dep_checker_version_ordering_with_packaging():
    """packaging.Version must order ``2.0-beta9`` < ``2.0`` correctly."""
    checker = DependencyChecker()
    assert checker._version_compare("2.0-beta9", "2.0") == -1
    assert checker._version_compare("2.14.1", "2.15.0") == -1
    assert checker._version_compare("2.5", "2.5") == 0
    assert checker._version_compare("2.5", "2.4.99") == 1


def test_dep_checker_vulnerable_below():
    checker = DependencyChecker()
    lib = {"vulnerable_below": "2.5"}
    assert checker._is_vulnerable_version("2.4", lib) is True
    assert checker._is_vulnerable_version("2.5", lib) is False
    assert checker._is_vulnerable_version("2.6", lib) is False


def test_dep_checker_vulnerable_range_log4j():
    checker = DependencyChecker()
    lib = {"vulnerable_range": ">=2.0-beta9,<=2.14.1"}
    assert checker._is_vulnerable_version("2.10.0", lib) is True
    assert checker._is_vulnerable_version("2.14.1", lib) is True
    assert checker._is_vulnerable_version("2.15.0", lib) is False
    assert checker._is_vulnerable_version("1.2.17", lib) is False


def test_dep_checker_detects_log4shell_jar(tmp_path):
    """A log4j-core-2.14.1.jar in the tree should be reported as vulnerable."""
    (tmp_path / "lib").mkdir()
    fake_jar = tmp_path / "lib" / "log4j-core-2.14.1.jar"
    fake_jar.write_bytes(b"PK\x03\x04fake jar content")

    checker = DependencyChecker()
    checker.check_directory(str(tmp_path))

    log4j = [f for f in checker.findings if "Log4j" in f.library]
    assert log4j, "Vulnerable log4j-core jar not detected"
    assert any(f.cve_id == "CVE-2021-44228" for f in log4j)


def test_dep_checker_detects_systeminformation_manifest(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "demo",
        "dependencies": {"systeminformation": "^5.10.0"},
    }))
    checker = DependencyChecker()
    checker.check_directory(str(tmp_path))

    siem = [f for f in checker.findings if "systeminformation" in f.library.lower()]
    assert siem, "Vulnerable systeminformation not detected from package.json"
    assert siem[0].cve_id == "CVE-2023-42810"


# ---------------------------------------------------------------------------
# Binary analyzer - smoke tests
# ---------------------------------------------------------------------------

def _have_cc() -> bool:
    import shutil
    return shutil.which("cc") is not None or shutil.which("gcc") is not None


@pytest.mark.skipif(not _have_cc(), reason="no C compiler available")
def test_binary_analyzer_detects_dangerous_imports(tmp_path, rules_dir, cve_db_path):
    """Compile a tiny C program that imports system() and references an SSID
    string, then verify the analyzer cross-references them.
    """
    import subprocess

    src = tmp_path / "vuln.c"
    src.write_text(
        '#include <stdio.h>\n'
        '#include <stdlib.h>\n'
        '#include <string.h>\n'
        'int main(int argc, char **argv) {\n'
        '    const char *ssid = argv[1];\n'
        '    char buf[128];\n'
        '    snprintf(buf, sizeof buf, "iwconfig wlan0 essid %s", ssid);\n'
        '    return system(buf);\n'
        '}\n'
    )
    binary = tmp_path / "vuln"
    cc = "gcc"
    import shutil
    if shutil.which("gcc") is None:
        cc = "cc"
    res = subprocess.run([cc, "-O0", "-o", str(binary), str(src)],
                         capture_output=True)
    if res.returncode != 0:
        pytest.skip(f"compile failed: {res.stderr.decode()[:200]}")

    analyzer = BinaryAnalyzer(rules_dir, cve_db_path)
    analyzer.analyze_file(str(binary))

    classes = {f.vuln_class for f in analyzer.findings}
    assert "wifi_cmd" in classes, "system() with SSID context should produce wifi_cmd"


def test_binary_analyzer_skips_non_elf(tmp_path, rules_dir, cve_db_path):
    not_elf = tmp_path / "not_elf.txt"
    not_elf.write_text("hello world")
    analyzer = BinaryAnalyzer(rules_dir, cve_db_path)
    findings = analyzer.analyze_file(str(not_elf))
    assert findings == []


def test_binary_rules_are_loaded(rules_dir, cve_db_path):
    """The rule JSONs declare binary_signatures; they must populate
    self._effective_dangerous (regression for the dead-code bug)."""
    analyzer = BinaryAnalyzer(rules_dir, cve_db_path)
    # At minimum, wifi_cmd should be in the merged dangerous set with system().
    assert "wifi_cmd" in analyzer._effective_dangerous
    assert "system" in analyzer._effective_dangerous["wifi_cmd"]["functions"]


def test_binary_analyzer_does_not_flag_unrelated_select(tmp_path, rules_dir, cve_db_path):
    """Regression: rule JSONs list class-specific context strings like
    'SELECT' / 'VALUES' (wifi_serial SQL signals). Pooling them into the
    global SSID detector caused every binary that contains the word
    'select' to be tagged as SSID-processing, flooding scans with false
    positives (observed: ~26k findings on a 3.8k-ELF Crestron firmware,
    including /bin/busybox).

    A binary whose only "context-ish" strings are SQL keywords must NOT
    register as SSID context.
    """
    import shutil
    import subprocess

    if shutil.which("gcc") is None and shutil.which("cc") is None:
        pytest.skip("no C compiler available")
    cc = "gcc" if shutil.which("gcc") else "cc"

    src = tmp_path / "sql_like.c"
    src.write_text(
        '#include <stdio.h>\n'
        '#include <string.h>\n'
        '#include <stdlib.h>\n'
        'int main(int argc, char **argv) {\n'
        '    char buf[64];\n'
        '    strcpy(buf, "SELECT * FROM table");\n'
        '    printf("VALUES (%s)\\n", buf);\n'
        '    return system(buf);\n'
        '}\n'
    )
    binary = tmp_path / "sql_like"
    res = subprocess.run([cc, "-O0", "-o", str(binary), str(src)],
                         capture_output=True)
    if res.returncode != 0:
        pytest.skip(f"compile failed: {res.stderr.decode()[:200]}")

    analyzer = BinaryAnalyzer(rules_dir, cve_db_path)
    analyzer.analyze_file(str(binary))

    # No ssid/essid/wpa/iwconfig strings present, so Step 3 (cross-reference)
    # must NOT fire. Step 4 may emit low-severity dangerous-import findings.
    high_or_critical = [f for f in analyzer.findings
                        if f.severity in ("critical", "high")]
    assert not high_or_critical, (
        f"Got {len(high_or_critical)} high/critical findings on a non-WiFi "
        f"binary. Classes: {[f.vuln_class for f in high_or_critical]}"
    )
