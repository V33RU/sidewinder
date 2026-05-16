"""
Firmware Extractor

Extracts filesystem contents from IoT firmware images using unblob.
Supports SquashFS, JFFS2, CramFS, UBIFS, ext4, and compressed formats.
Prepares extracted files for source and binary analysis.

unblob is preferred over binwalk for its accuracy, recursive extraction,
and active maintenance. Install: pip install unblob
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ExtractionResult:
    """Result of firmware extraction."""
    firmware_path: str
    output_dir: str
    success: bool
    file_count: int
    elf_binaries: list
    source_files: list
    web_files: list
    config_files: list
    error: str = ""

    def to_dict(self):
        return {
            "firmware": self.firmware_path,
            "output": self.output_dir,
            "success": self.success,
            "files": self.file_count,
            "elf_count": len(self.elf_binaries),
            "source_count": len(self.source_files),
            "web_count": len(self.web_files),
            "config_count": len(self.config_files),
            "error": self.error,
        }


# File extensions of interest for SSID vulnerability scanning
SOURCE_EXTENSIONS = {
    ".c", ".h", ".cpp", ".cc", ".cxx", ".ino",
    ".py", ".java", ".js", ".ts", ".mjs",
    ".php", ".lua", ".sh", ".bash",
}

WEB_EXTENSIONS = {
    ".html", ".htm", ".asp", ".aspx", ".jsp",
    ".php", ".cgi", ".tpl", ".lua",
}

CONFIG_EXTENSIONS = {
    ".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml",
    ".properties", ".env", ".toml",
}

# WiFi-related binary names to prioritize
WIFI_BINARIES = {
    "wpa_supplicant", "hostapd", "wpa_cli", "hostapd_cli",
    "iwconfig", "iwlist", "iwpriv", "iw",
    "nmcli", "NetworkManager",
    "wifid", "wappd", "wlmngr", "wlan",
    "httpd", "lighttpd", "nginx", "uhttpd", "mini_httpd",
    "rc", "nvram", "cfg_manager",
}


class FirmwareExtractor:
    """Extracts and catalogs contents of IoT firmware images using unblob."""

    def __init__(self, output_base: str = None):
        self.output_base = output_base or tempfile.mkdtemp(prefix="ssid_fw_")
        self._check_dependencies()

    def _check_dependencies(self) -> dict:
        """Check which extraction tools are available."""
        tools = {}
        for tool in ["unblob", "unsquashfs", "jefferson", "cpio", "tar", "gzip", "xz"]:
            tools[tool] = shutil.which(tool) is not None
        self.available_tools = tools
        return tools

    def extract(self, firmware_path: str, output_dir: str = None, depth: int = 10) -> ExtractionResult:
        """Extract filesystem from firmware image using unblob.

        Args:
            firmware_path: Path to firmware image file.
            output_dir: Where to extract. Auto-generated if None.
            depth: Maximum recursion depth for nested containers (default 10).
        """
        firmware_path = os.path.abspath(firmware_path)

        if not os.path.isfile(firmware_path):
            return ExtractionResult(
                firmware_path=firmware_path, output_dir="",
                success=False, file_count=0,
                elf_binaries=[], source_files=[],
                web_files=[], config_files=[],
                error=f"File not found: {firmware_path}",
            )

        if output_dir is None:
            fw_name = Path(firmware_path).stem
            output_dir = os.path.join(self.output_base, fw_name)
        os.makedirs(output_dir, exist_ok=True)

        if not self.available_tools.get("unblob"):
            return ExtractionResult(
                firmware_path=firmware_path, output_dir=output_dir,
                success=False, file_count=0,
                elf_binaries=[], source_files=[],
                web_files=[], config_files=[],
                error="unblob not installed. Install with: pip install unblob",
            )

        # Run unblob extraction
        try:
            result = subprocess.run(
                [
                    "unblob",
                    "--extract-dir", output_dir,
                    "--depth", str(depth),
                    firmware_path,
                ],
                capture_output=True, text=True, timeout=600,
            )
        except subprocess.TimeoutExpired:
            return ExtractionResult(
                firmware_path=firmware_path, output_dir=output_dir,
                success=False, file_count=0,
                elf_binaries=[], source_files=[],
                web_files=[], config_files=[],
                error="Extraction timed out after 600 seconds",
            )

        # Catalog extracted files
        elf_binaries = []
        source_files = []
        web_files = []
        config_files = []
        file_count = 0

        for root, dirs, files in os.walk(output_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                file_count += 1
                ext = Path(fname).suffix.lower()

                # Classify files
                if ext in SOURCE_EXTENSIONS:
                    source_files.append(fpath)
                if ext in WEB_EXTENSIONS:
                    web_files.append(fpath)
                if ext in CONFIG_EXTENSIONS:
                    config_files.append(fpath)

                # Check for ELF binaries
                try:
                    with open(fpath, "rb") as f:
                        if f.read(4) == b"\x7fELF":
                            elf_binaries.append(fpath)
                            continue
                except (OSError, PermissionError):
                    continue

        # Prioritize WiFi-related binaries
        wifi_bins = [b for b in elf_binaries
                     if Path(b).name in WIFI_BINARIES]
        other_bins = [b for b in elf_binaries
                      if Path(b).name not in WIFI_BINARIES]
        elf_binaries = wifi_bins + other_bins

        return ExtractionResult(
            firmware_path=firmware_path,
            output_dir=output_dir,
            success=file_count > 0,
            file_count=file_count,
            elf_binaries=elf_binaries,
            source_files=source_files,
            web_files=web_files,
            config_files=config_files,
        )

    def identify(self, firmware_path: str) -> dict:
        """Identify firmware contents without full extraction.

        Uses unblob's ``--skip-extraction`` to carve chunks and produce a
        metadata report without performing the (potentially slow) recursive
        extraction.
        """
        if not self.available_tools.get("unblob"):
            return {"error": "unblob not installed"}

        try:
            result = subprocess.run(
                ["unblob", "--skip-extraction", firmware_path],
                capture_output=True, text=True, timeout=60,
            )
            return {
                "firmware": firmware_path,
                "size": os.path.getsize(firmware_path),
                "scan_output": result.stdout,
                "scan_errors": result.stderr,
                "returncode": result.returncode,
            }
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return {"error": str(e)}

    def cleanup(self, output_dir: str):
        """Remove extracted firmware files."""
        if os.path.isdir(output_dir):
            shutil.rmtree(output_dir)
