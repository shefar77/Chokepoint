"""Scanner adapter tests: version comparison, redaction, parsing, honest metadata."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.scanner_orchestrator import (
    REACH_NOT_ESTABLISHED,
    SECRET_REDACTION,
    ScannerOrchestrator,
    is_vulnerable,
)


# --------------------------------------------------------------- versions ----
@pytest.mark.parametrize(
    "installed,fixed,expected",
    [
        ("4.17.11", "4.17.21", True),
        ("4.17.21", "4.17.21", False),
        ("4.18.0", "4.17.21", False),
        ("5.1", "5.4", True),
        ("6.0.1", "5.4", False),
        ("^4.16.0", "4.20.0", True),
        ("~4.21.2", "4.20.0", False),
        ("1.1.2", "2.3.2", True),
        ("3.0.0", "2.3.2", False),
    ],
)
def test_version_comparison(installed: str, fixed: str, expected: bool) -> None:
    vulnerable, reason = is_vulnerable(installed, fixed)
    assert vulnerable is expected, reason
    assert reason


def test_uncomparable_version_is_kept_not_assumed_safe() -> None:
    """An unparseable version must not be silently treated as patched."""
    vulnerable, reason = is_vulnerable("github:org/repo#branch", "4.17.21")
    assert vulnerable is True
    assert "not possible" in reason


# ------------------------------------------------------- manifest findings ---
def test_outdated_dependencies_are_reported(vulnerable_repo: Path) -> None:
    findings, status = ScannerOrchestrator.run_manifest_scanner(vulnerable_repo, "scan-t")
    assert status == "completed"
    cves = {f["cve"] for f in findings}
    assert "CVE-2021-23337" in cves  # lodash 4.17.11 < 4.17.21
    assert "CVE-2020-14343" in cves  # pyyaml 5.1 < 5.4


def test_patched_dependencies_produce_no_dependency_findings(patched_repo: Path) -> None:
    """The regression that mattered most: every declared package is already fixed."""
    findings, _ = ScannerOrchestrator.run_manifest_scanner(patched_repo, "scan-t")
    dependency_findings = [f for f in findings if f["category"] == "vulnerability"]
    assert dependency_findings == [], [
        (f["cve"], f["package_name"], f["installed_version"]) for f in dependency_findings
    ]


def test_declared_version_is_recorded_not_a_placeholder(vulnerable_repo: Path) -> None:
    findings, _ = ScannerOrchestrator.run_manifest_scanner(vulnerable_repo, "scan-t")
    lodash = next(f for f in findings if f["package_name"] == "lodash")
    assert lodash["installed_version"] == "4.17.11"
    assert lodash["installed_version"] != "declared"


def test_dev_dependencies_are_not_scanned(vulnerable_repo: Path) -> None:
    findings, _ = ScannerOrchestrator.run_manifest_scanner(vulnerable_repo, "scan-t")
    assert not [f for f in findings if f["package_name"] == "mocha"]


# ---------------------------------------------------------------- secrets ----
def test_secret_value_is_redacted(vulnerable_repo: Path) -> None:
    findings = ScannerOrchestrator.run_pattern_sast(vulnerable_repo, "scan-t")
    secrets = [f for f in findings if f["category"] == "secret"]
    assert secrets, "the hardcoded API key should be detected"
    blob = json.dumps(secrets)
    assert "sk_live_AbCdEf0123456789XyZqWeRtY" not in blob
    assert SECRET_REDACTION in blob


def test_every_match_in_a_file_is_reported(vulnerable_repo: Path) -> None:
    """A secret on line 2 must not hide the interpolated SQL on line 6."""
    findings = ScannerOrchestrator.run_pattern_sast(vulnerable_repo, "scan-t")
    rules = {f["rule_id"] for f in findings}
    assert "CWE-798-HARDCODED-SECRET" in rules
    assert "CWE-89-SQL-INJECTION" in rules


# ------------------------------------------------------ honest metadata ------
def test_findings_do_not_assert_reachability(vulnerable_repo: Path) -> None:
    findings, _ = ScannerOrchestrator.run_manifest_scanner(vulnerable_repo, "scan-t")
    assert findings
    for f in findings:
        assert f["reachable_code"] is False
        assert f["reachability"] == REACH_NOT_ESTABLISHED


def test_advisory_metadata_declares_its_source(vulnerable_repo: Path) -> None:
    findings, _ = ScannerOrchestrator.run_manifest_scanner(vulnerable_repo, "scan-t")
    dep = next(f for f in findings if f["category"] == "vulnerability")
    evidence = json.loads(dep["evidence_json"])
    assert "epss_source" in evidence and "not a live EPSS feed" in evidence["epss_source"]
    assert "kev_source" in evidence
    assert evidence["declared_version"]


def test_pattern_findings_carry_no_invented_cvss_or_kev(vulnerable_repo: Path) -> None:
    """A regex rule has no CVSS vector and no KEV listing; it must claim neither."""
    findings = ScannerOrchestrator.run_pattern_sast(vulnerable_repo, "scan-t")
    assert findings
    for f in findings:
        assert f["cvss"] == 0.0
        assert f["epss"] == 0.0
        assert f["kev"] is False


# ----------------------------------------------------------- trivy parsing ---
def test_trivy_cvss_is_read_from_the_vendor_map() -> None:
    """Trivy nests scores per vendor; the old code looked for a top-level Score."""
    score, source = ScannerOrchestrator._trivy_cvss(
        {"CVSS": {"nvd": {"V3Score": 9.8, "V3Vector": "..."}, "redhat": {"V3Score": 7.5}}}
    )
    assert score == 9.8
    assert source == "nvd:V3Score"


def test_trivy_cvss_absent_is_none_not_a_default() -> None:
    assert ScannerOrchestrator._trivy_cvss({}) == (None, "")
    assert ScannerOrchestrator._trivy_cvss({"CVSS": {}}) == (None, "")


def test_trivy_cvss_falls_back_to_any_vendor() -> None:
    score, source = ScannerOrchestrator._trivy_cvss({"CVSS": {"vendorx": {"V2Score": 5.0}}})
    assert score == 5.0
    assert "vendorx" in source


def test_missing_scanner_is_skipped_not_failed() -> None:
    findings, status = ScannerOrchestrator.run_trivy(Path("."), "scan-t")
    # On a machine without Trivy the status must be "skipped", never "completed".
    if status != "completed":
        assert status == "skipped" or status.startswith("failed")
        assert findings == []
