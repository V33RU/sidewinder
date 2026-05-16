"""Shared pytest fixtures for SiDEWiNDER tests."""
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "config" / "rules"
CVE_DB = REPO_ROOT / "config" / "cve_database.json"
FIXTURE_DIR = REPO_ROOT / "tests" / "test_source"


@pytest.fixture(scope="session")
def rules_dir() -> str:
    return str(RULES_DIR)


@pytest.fixture(scope="session")
def cve_db_path() -> str:
    return str(CVE_DB)


@pytest.fixture(scope="session")
def fixture_dir() -> Path:
    return FIXTURE_DIR
