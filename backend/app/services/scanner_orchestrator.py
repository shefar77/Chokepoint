"""Scanner orchestration: Trivy, Semgrep, and manifest dependency security analyzer."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import settings
from app.repositories.findings import FindingRepository

log = logging.getLogger("chokepoint.service.scanners")

SECRET_REDACTION = "[REDACTED]"

# Reachability vocabulary (PRD FR-04). "not_established" is NOT "unreachable":
# it records that nothing in the evidence either supports or contradicts the
# vulnerable code being reached.
REACH_NOT_ESTABLISHED = "not_established"


def redact(line: str, pattern: "re.Pattern[str]") -> str:
    """Replace the secret literal in a matched line with a placeholder.

    Scanner evidence is shown in the UI and fed to the model, so the value must
    never survive. Only the shape of the assignment is kept.
    """
    def _sub(match: "re.Match[str]") -> str:
        return f"{match.group(1)} = \"{SECRET_REDACTION}\""

    redacted = pattern.sub(_sub, line)
    if SECRET_REDACTION not in redacted:
        # Pattern matched but the substitution did not; drop the line entirely.
        return SECRET_REDACTION
    return redacted.strip()[:120]


def _version_tuple(raw: str) -> tuple[int, ...] | None:
    """Parse a dotted numeric version. None when it is not comparable."""
    cleaned = re.sub(r"^[^0-9]*", "", str(raw or "").strip())
    cleaned = re.split(r"[^0-9.]", cleaned)[0].strip(".")
    if not cleaned:
        return None
    try:
        return tuple(int(part) for part in cleaned.split(".") if part != "")
    except ValueError:
        return None


def is_vulnerable(installed: str, fixed_in: str) -> tuple[bool, str]:
    """Compare a declared version against a fixed-in version.

    Returns (vulnerable, reason). When either version cannot be parsed the
    finding is kept and the reason says the comparison was not possible, so an
    unknown version is never silently treated as safe.
    """
    inst = _version_tuple(installed)
    fix = _version_tuple(fixed_in)
    if inst is None or fix is None:
        return True, f"version comparison not possible (declared {installed!r}, fixed in {fixed_in!r})"
    length = max(len(inst), len(fix))
    inst_p = inst + (0,) * (length - len(inst))
    fix_p = fix + (0,) * (length - len(fix))
    if inst_p < fix_p:
        return True, f"declared {installed} is below the fixed version {fixed_in}"
    return False, f"declared {installed} is at or above the fixed version {fixed_in}"


# Known vulnerabilities for common dependencies when scanning real repositories
KNOWN_ADVISORIES: dict[str, list[dict[str, Any]]] = {
    "jsonwebtoken": [
        {
            "cve": "CVE-2022-23529",
            "cvss": 9.8,
            "epss": 0.45,
            "kev": False,
            "severity": "CRITICAL",
            "summary": "Remote Code Execution via insecure secretOrPublicKey parameter",
            "fixed_in": "9.0.0",
        },
        {
            "cve": "CVE-2022-23540",
            "cvss": 9.1,
            "epss": 0.32,
            "kev": False,
            "severity": "CRITICAL",
            "summary": "Insecure key verification bypass in verify function",
            "fixed_in": "9.0.0",
        },
    ],
    "express": [
        {
            "cve": "CVE-2024-43796",
            "cvss": 7.5,
            "epss": 0.12,
            "kev": False,
            "severity": "HIGH",
            "summary": "Open redirect vulnerability in express router",
            "fixed_in": "4.20.0",
        }
    ],
    "sqlite3": [
        {
            "cve": "CVE-2022-35737",
            "cvss": 7.5,
            "epss": 0.08,
            "kev": False,
            "severity": "HIGH",
            "summary": "Memory corruption in sqlite3_str_vappendf",
            "fixed_in": "3.39.2",
        }
    ],
    "lodash": [
        {
            "cve": "CVE-2021-23337",
            "cvss": 7.2,
            "epss": 0.28,
            "kev": False,
            "severity": "HIGH",
            "summary": "Command injection vulnerability in lodash template function",
            "fixed_in": "4.17.21",
        }
    ],
    "pyyaml": [
        {
            "cve": "CVE-2020-14343",
            "cvss": 9.8,
            "epss": 0.65,
            "kev": True,
            "severity": "CRITICAL",
            "summary": "Arbitrary code execution through yaml.load() deserialization",
            "fixed_in": "5.4",
        }
    ],
    "requests": [
        {
            "cve": "CVE-2023-32681",
            "cvss": 6.5,
            "epss": 0.05,
            "kev": False,
            "severity": "MEDIUM",
            "summary": "Proxy-Authorization header leak on redirect to HTTPS",
            "fixed_in": "2.31.0",
        }
    ],
    "flask": [
        {
            "cve": "CVE-2023-30861",
            "cvss": 7.5,
            "epss": 0.15,
            "kev": False,
            "severity": "HIGH",
            "summary": "Session cookie disclosure with custom SECRET_KEY",
            "fixed_in": "2.3.2",
        }
    ],
    "urllib3": [
        {
            "cve": "CVE-2023-45803",
            "cvss": 7.1,
            "epss": 0.08,
            "kev": False,
            "severity": "HIGH",
            "summary": "Cookie disclosure on redirect with custom authorization header",
            "fixed_in": "2.0.7",
        }
    ],
    "axios": [
        {
            "cve": "CVE-2023-45857",
            "cvss": 7.5,
            "epss": 0.18,
            "kev": False,
            "severity": "HIGH",
            "summary": "Cross-Site Request Forgery (CSRF) in axios HTTP requests",
            "fixed_in": "1.6.0",
        }
    ],
}


class ScannerOrchestrator:
    """Runs configured scanners on a workspace and normalizes their output."""

    @staticmethod
    def check_available(scanner: str) -> bool:
        """True when the scanner binary runs and reports a version."""
        try:
            res = subprocess.run(
                [scanner, "--version"], capture_output=True, timeout=10
            )
            return res.returncode == 0
        except Exception:  # noqa: BLE001 - not installed or not executable
            return False

    @staticmethod
    def scanner_version(scanner: str) -> str:
        """The scanner's own version string, or '' when it cannot be read."""
        try:
            res = subprocess.run(
                [scanner, "--version"], capture_output=True, text=True, timeout=10
            )
            if res.returncode == 0:
                return (res.stdout or res.stderr).strip().splitlines()[0][:120]
        except Exception:  # noqa: BLE001
            pass
        return ""

    @staticmethod
    def _trivy_cvss(vuln: dict[str, Any]) -> tuple[float | None, str]:
        """Pull a CVSS base score out of Trivy's per-vendor CVSS map.

        Trivy reports `CVSS: {"nvd": {"V3Score": 9.8, ...}, "redhat": {...}}`.
        The previous code looked for a top-level "Score" key that Trivy never
        emits, so every CVSS came out as 0.0 or a hardcoded 7.5.
        """
        cvss = vuln.get("CVSS")
        if not isinstance(cvss, dict):
            return None, ""
        for vendor in ("nvd", "redhat", "ghsa", "bitnami"):
            entry = cvss.get(vendor)
            if isinstance(entry, dict):
                for key in ("V4Score", "V3Score", "V2Score"):
                    score = entry.get(key)
                    if isinstance(score, (int, float)):
                        return float(score), f"{vendor}:{key}"
        for vendor, entry in cvss.items():
            if isinstance(entry, dict):
                for key in ("V4Score", "V3Score", "V2Score"):
                    score = entry.get(key)
                    if isinstance(score, (int, float)):
                        return float(score), f"{vendor}:{key}"
        return None, ""

    @staticmethod
    def _base_finding(scan_id: str, scanner: str, prefix: str) -> dict[str, Any]:
        """Shared defaults. Nothing here asserts exploitability or reachability."""
        return {
            "finding_id": f"{prefix}-{uuid.uuid4().hex[:8]}",
            "scan_id": scan_id,
            "scanner": scanner,
            "cvss": 0.0,
            "epss": 0.0,
            "kev": False,
            "requires_auth": False,
            "package_name": "",
            "installed_version": "",
            "fixed_version": "",
            "fixed_in": "",
            "symbol": "",
            "mapping_status": "unmatched",
            "status": "open",
            # Reachability is a conclusion of the graph analysis, never an
            # assumption of the scanner adapter (PRD FR-04).
            "reachable_code": False,
            "reachability": REACH_NOT_ESTABLISHED,
        }

    @staticmethod
    def run_trivy(workspace: Path, scan_id: str) -> tuple[list[dict[str, Any]], str]:
        """Run a Trivy filesystem scan: vulnerabilities, misconfigurations, secrets."""
        if not ScannerOrchestrator.check_available(settings.trivy_path):
            return [], "skipped"

        version = ScannerOrchestrator.scanner_version(settings.trivy_path)
        try:
            result = subprocess.run(
                [
                    settings.trivy_path,
                    "fs",
                    "--format",
                    "json",
                    "--scanners",
                    "vuln,misconfig,secret",
                    "--severity",
                    "CRITICAL,HIGH,MEDIUM,LOW",
                    str(workspace),
                ],
                capture_output=True,
                text=True,
                timeout=settings.scanner_timeout_s,
            )
        except subprocess.TimeoutExpired:
            return [], f"failed: timed out after {settings.scanner_timeout_s}s"
        except Exception as exc:  # noqa: BLE001
            log.error("Trivy error: %s", exc)
            return [], f"failed: {exc}"

        if result.returncode not in (0, 1):
            log.warning("Trivy exited %d: %s", result.returncode, result.stderr[:200])
            return [], f"failed: {result.stderr.strip()[:300]}"

        try:
            output = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            return [], f"failed: could not parse Trivy JSON ({exc})"

        findings: list[dict[str, Any]] = []
        for target in output.get("Results", []) or []:
            target_name = target.get("Target", "unknown")
            target_class = str(target.get("Class", "")).lower()

            for vuln in target.get("Vulnerabilities", []) or []:
                score, score_src = ScannerOrchestrator._trivy_cvss(vuln)
                f = ScannerOrchestrator._base_finding(scan_id, "trivy", "trivy")
                f.update({
                    "rule_id": vuln.get("VulnerabilityID", ""),
                    "category": "vulnerability",
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "cve": vuln.get("VulnerabilityID", ""),
                    "cvss": float(score) if score is not None else 0.0,
                    "attack_vector": "network",
                    "ecosystem": str(vuln.get("PkgIdentifier", {}).get("PURL", "") or target_class),
                    "package_name": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "package_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "fixed_in": vuln.get("FixedVersion", ""),
                    "file_path": vuln.get("PkgPath") or target_name,
                    "line_start": None,
                    "line_end": None,
                    "summary": vuln.get("Title", "") or str(vuln.get("Description", ""))[:200],
                    "evidence_json": json.dumps({
                        "target": target_name,
                        "description": str(vuln.get("Description", ""))[:2000],
                        "cvss_source": score_src or "not supplied by Trivy",
                        "epss_source": "not supplied by Trivy",
                        "kev_source": "not supplied by Trivy",
                        "scanner_version": version,
                    }),
                    "references_json": json.dumps(vuln.get("References", []) or []),
                    "provenance": "trivy_fs_vuln",
                })
                findings.append(f)

            for mis in target.get("Misconfigurations", []) or []:
                cause = mis.get("CauseMetadata") or {}
                f = ScannerOrchestrator._base_finding(scan_id, "trivy", "trivy")
                f.update({
                    "rule_id": mis.get("ID", ""),
                    "category": "misconfiguration",
                    "severity": mis.get("Severity", "UNKNOWN"),
                    "cve": mis.get("ID", ""),
                    "attack_vector": "local",
                    "ecosystem": target_class or "config",
                    "file_path": target_name,
                    "line_start": cause.get("StartLine"),
                    "line_end": cause.get("EndLine"),
                    "summary": mis.get("Title", "") or str(mis.get("Message", ""))[:200],
                    "evidence_json": json.dumps({
                        "target": target_name,
                        "message": str(mis.get("Message", ""))[:2000],
                        "resolution": str(mis.get("Resolution", ""))[:500],
                        "scanner_version": version,
                    }),
                    "references_json": json.dumps(mis.get("References", []) or []),
                    "provenance": "trivy_fs_misconfig",
                })
                findings.append(f)

            for sec in target.get("Secrets", []) or []:
                f = ScannerOrchestrator._base_finding(scan_id, "trivy", "trivy")
                f.update({
                    "rule_id": sec.get("RuleID", ""),
                    "category": "secret",
                    "severity": sec.get("Severity", "UNKNOWN"),
                    "cve": sec.get("RuleID", ""),
                    "attack_vector": "local",
                    "ecosystem": "code",
                    "file_path": target_name,
                    "line_start": sec.get("StartLine"),
                    "line_end": sec.get("EndLine"),
                    "summary": sec.get("Title", "") or "Secret detected by Trivy",
                    # Trivy's Match/Code fields carry the secret itself; never store them.
                    "evidence_json": json.dumps({
                        "target": target_name,
                        "rule": sec.get("RuleID", ""),
                        "category": sec.get("Category", ""),
                        "snippet": SECRET_REDACTION,
                        "redacted": True,
                        "scanner_version": version,
                    }),
                    "references_json": json.dumps([]),
                    "provenance": "trivy_fs_secret",
                })
                findings.append(f)

        return findings, "completed"

    @staticmethod
    def run_semgrep(workspace: Path, scan_id: str) -> tuple[list[dict[str, Any]], str]:
        """Run Semgrep and normalise its JSON results."""
        if not ScannerOrchestrator.check_available(settings.semgrep_path):
            return [], "skipped"

        version = ScannerOrchestrator.scanner_version(settings.semgrep_path)
        try:
            result = subprocess.run(
                [
                    settings.semgrep_path,
                    "scan",
                    "--config=auto",
                    "--json",
                    "--timeout=60",
                    str(workspace),
                ],
                capture_output=True,
                text=True,
                timeout=settings.scanner_timeout_s,
            )
        except subprocess.TimeoutExpired:
            return [], f"failed: timed out after {settings.scanner_timeout_s}s"
        except Exception as exc:  # noqa: BLE001
            return [], f"failed: {exc}"

        if result.returncode not in (0, 1):
            return [], f"failed: {result.stderr.strip()[:300]}"

        try:
            output = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            return [], f"failed: could not parse Semgrep JSON ({exc})"

        findings: list[dict[str, Any]] = []
        for item in output.get("results", []) or []:
            extra = item.get("extra", {}) or {}
            metadata = extra.get("metadata", {}) or {}
            cwe = metadata.get("cwe")
            if isinstance(cwe, list):
                cwe = cwe[0] if cwe else ""
            severity = str(extra.get("severity") or metadata.get("impact") or "UNKNOWN").upper()
            category = "secret" if "secret" in str(item.get("check_id", "")).lower() else "sast"
            snippet = str(extra.get("lines", ""))
            f = ScannerOrchestrator._base_finding(scan_id, "semgrep", "semgrep")
            f.update({
                "rule_id": item.get("check_id", ""),
                "category": category,
                "severity": {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(
                    severity, severity
                ),
                "cve": str(cwe or item.get("check_id", "")),
                "cwe": str(cwe or ""),
                "attack_vector": "network",
                "ecosystem": "code",
                "file_path": item.get("path", ""),
                "line_start": (item.get("start") or {}).get("line"),
                "line_end": (item.get("end") or {}).get("line"),
                "summary": str(extra.get("message", ""))[:400],
                "evidence_json": json.dumps({
                    "code": SECRET_REDACTION if category == "secret" else snippet[:500],
                    "redacted": category == "secret",
                    "cwe": str(cwe or ""),
                    "owasp": metadata.get("owasp", ""),
                    "confidence": metadata.get("confidence", ""),
                    "cvss_source": "not supplied by Semgrep",
                    "scanner_version": version,
                }),
                "references_json": json.dumps(metadata.get("references", []) or []),
                "provenance": "semgrep",
            })
            findings.append(f)

        return findings, "completed"

    @staticmethod
    def _declared_packages(workspace: Path) -> list[dict[str, str]]:
        """Read declared runtime dependencies with their actual version strings."""
        out: list[dict[str, str]] = []
        skip = {"node_modules", ".venv", "venv", ".git"}

        for mf in workspace.rglob("package.json"):
            if any(part in skip for part in mf.parts):
                continue
            try:
                data = json.loads(mf.read_text(encoding="utf-8", errors="ignore"))
            except Exception:  # noqa: BLE001 - a malformed manifest is not fatal
                continue
            if not isinstance(data, dict):
                continue
            for name, spec in (data.get("dependencies") or {}).items():
                out.append({
                    "name": str(name),
                    "version": str(spec),
                    "ecosystem": "npm",
                    "manifest": str(mf.relative_to(workspace)),
                })

        for rf in workspace.rglob("requirements*.txt"):
            if any(part in skip for part in rf.parts) or "dev" in rf.name:
                continue
            try:
                lines = rf.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:  # noqa: BLE001
                continue
            for line in lines:
                line = line.split("#")[0].strip()
                if not line or line.startswith("-"):
                    continue
                parts = re.split(r"[=><~!]+", line, maxsplit=1)
                name = parts[0].strip()
                if not name:
                    continue
                out.append({
                    "name": name,
                    "version": parts[1].strip() if len(parts) > 1 else "",
                    "ecosystem": "pypi",
                    "manifest": str(rf.relative_to(workspace)),
                })
        return out

    @staticmethod
    def run_manifest_scanner(workspace: Path, scan_id: str) -> tuple[list[dict[str, Any]], str]:
        """Match declared dependencies against a small local advisory table.

        This is a deliberately narrow local check, not a vulnerability database.
        A finding is raised only when the declared version is actually below the
        advisory's fixed version, or when the two cannot be compared.
        """
        findings = []

        for pkg in ScannerOrchestrator._declared_packages(workspace):
            advisories = KNOWN_ADVISORIES.get(pkg["name"].lower())
            if not advisories:
                continue
            for adv in advisories:
                vulnerable, reason = is_vulnerable(pkg["version"], adv["fixed_in"])
                if not vulnerable:
                    continue
                fid = f"cve-{uuid.uuid4().hex[:8]}"
                findings.append({
                    "finding_id": fid,
                    "scan_id": scan_id,
                    "scanner": "local-advisory-table",
                    "rule_id": adv["cve"],
                    "category": "vulnerability",
                    "severity": adv["severity"],
                    "cve": adv["cve"],
                    "cvss": float(adv["cvss"]),
                    "epss": float(adv["epss"]),
                    "kev": bool(adv["kev"]),
                    "attack_vector": "network",
                    "requires_auth": False,
                    "ecosystem": pkg["ecosystem"],
                    "package_name": pkg["name"],
                    "installed_version": pkg["version"],
                    "package_version": pkg["version"],
                    "fixed_version": adv["fixed_in"],
                    "fixed_in": adv["fixed_in"],
                    "file_path": pkg["manifest"],
                    "line_start": None,
                    "line_end": None,
                    "symbol": pkg["name"],
                    "summary": adv["summary"],
                    "evidence_json": json.dumps({
                        "manifest": pkg["manifest"],
                        "package": pkg["name"],
                        "declared_version": pkg["version"],
                        "version_comparison": reason,
                        "severity_source": "local advisory table bundled with CHOKEPOINT",
                        "epss_source": "local advisory table estimate, not a live EPSS feed",
                        "kev_source": "local advisory table flag, not a live CISA KEV feed",
                    }),
                    "references_json": json.dumps(
                        [f"https://nvd.nist.gov/vuln/detail/{adv['cve']}"]
                    ),
                    "mapping_status": "unmatched",
                    "provenance": "local_advisory_table",
                    "status": "open",
                    "reachable_code": False,
                    "reachability": REACH_NOT_ESTABLISHED,
                })

        findings.extend(ScannerOrchestrator.run_pattern_sast(workspace, scan_id))
        return findings, "completed"

    @staticmethod
    def run_pattern_sast(workspace: Path, scan_id: str) -> list[dict[str, Any]]:
        """Regex source checks for hardcoded secrets and string-built SQL.

        Every match is reported: the scan no longer stops at the first hit in a
        file, and secret values are redacted before the evidence is stored.
        """
        findings: list[dict[str, Any]] = []
        secret_pattern = re.compile(
            r"""(?i)\b(api[_-]?key|secret|password|access[_-]?token)\b\s*[:=]\s*['"][^'"\s]{16,}['"]"""
        )
        sqli_pattern = re.compile(
            r"""(?i)(execute|executemany|query|raw)\s*\(\s*f?['"][^'"]*"""
            r"""(SELECT|INSERT|UPDATE|DELETE)[^'"]*(\{|\$\{)"""
        )
        skip = {"node_modules", ".venv", "venv", ".git", "dist", "build"}

        candidates = (
            list(workspace.rglob("*.py"))
            + list(workspace.rglob("*.js"))
            + list(workspace.rglob("*.ts"))
        )
        for code_file in candidates:
            if any(part in skip for part in code_file.parts):
                continue
            try:
                rel = str(code_file.relative_to(workspace))
                lines = code_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:  # noqa: BLE001 - unreadable file, keep scanning
                continue

            for idx, line in enumerate(lines, 1):
                if secret_pattern.search(line):
                    findings.append({
                        "finding_id": f"sast-{uuid.uuid4().hex[:8]}",
                        "scan_id": scan_id,
                        "scanner": "sast-pattern",
                        "rule_id": "CWE-798-HARDCODED-SECRET",
                        "category": "secret",
                        "severity": "HIGH",
                        "cve": "CWE-798",
                        "cvss": 0.0,
                        "epss": 0.0,
                        "kev": False,
                        "attack_vector": "local",
                        "requires_auth": False,
                        "ecosystem": "code",
                        "package_name": "",
                        "installed_version": "",
                        "fixed_version": "",
                        "fixed_in": "",
                        "file_path": rel,
                        "line_start": idx,
                        "line_end": idx,
                        "symbol": "",
                        "summary": "Hardcoded credential or API token literal in source code",
                        "evidence_json": json.dumps({
                            "line": idx,
                            "snippet": redact(line, secret_pattern),
                            "redacted": True,
                            "severity_source": "fixed rating for this pattern rule; no CVSS vector",
                        }),
                        "references_json": json.dumps(
                            ["https://cwe.mitre.org/data/definitions/798.html"]
                        ),
                        "mapping_status": "unmatched",
                        "provenance": "sast_pattern",
                        "status": "open",
                        "reachable_code": False,
                        "reachability": REACH_NOT_ESTABLISHED,
                    })
                if sqli_pattern.search(line):
                    findings.append({
                        "finding_id": f"sast-{uuid.uuid4().hex[:8]}",
                        "scan_id": scan_id,
                        "scanner": "sast-pattern",
                        "rule_id": "CWE-89-SQL-INJECTION",
                        "category": "sast",
                        "severity": "HIGH",
                        "cve": "CWE-89",
                        "cvss": 0.0,
                        "epss": 0.0,
                        "kev": False,
                        "attack_vector": "network",
                        "requires_auth": False,
                        "ecosystem": "code",
                        "package_name": "",
                        "installed_version": "",
                        "fixed_version": "",
                        "fixed_in": "",
                        "file_path": rel,
                        "line_start": idx,
                        "line_end": idx,
                        "symbol": "",
                        "summary": "Possible SQL injection: query string built by interpolation",
                        "evidence_json": json.dumps({
                            "line": idx,
                            "snippet": line.strip()[:120],
                            "severity_source": "fixed rating for this pattern rule; no CVSS vector",
                            "note": "pattern match only; taint from external input is not proven",
                        }),
                        "references_json": json.dumps(
                            ["https://cwe.mitre.org/data/definitions/89.html"]
                        ),
                        "mapping_status": "unmatched",
                        "provenance": "sast_pattern",
                        "status": "open",
                        "reachable_code": False,
                        "reachability": REACH_NOT_ESTABLISHED,
                    })
        return findings

    @staticmethod
    def run_all(workspace: Path, scan_id: str) -> dict[str, Any]:
        """Run all available scanners and return combined results."""
        all_findings = []
        statuses = {}

        trivy_findings, trivy_status = ScannerOrchestrator.run_trivy(workspace, scan_id)
        all_findings.extend(trivy_findings)
        statuses["trivy"] = trivy_status

        semgrep_findings, semgrep_status = ScannerOrchestrator.run_semgrep(workspace, scan_id)
        all_findings.extend(semgrep_findings)
        statuses["semgrep"] = semgrep_status

        # The bundled local checks always run: they are the only coverage when
        # neither external scanner is installed, and they are reported under
        # their own scanner name so nothing is passed off as Trivy or Semgrep.
        local_findings, local_status = ScannerOrchestrator.run_manifest_scanner(workspace, scan_id)
        all_findings.extend(local_findings)
        statuses["local_checks"] = local_status

        # Persist findings
        if all_findings:
            FindingRepository.bulk_insert(all_findings)

        coverage = {
            "trivy": trivy_status,
            "semgrep": semgrep_status,
            "local_checks": local_status,
            "external_scanners_available": [
                name
                for name, status in (("trivy", trivy_status), ("semgrep", semgrep_status))
                if status == "completed"
            ],
            "note": (
                "Coverage is limited to the scanners that actually ran. "
                "CHOKEPOINT does not claim to find every vulnerability in a repository."
            ),
        }
        return {
            "scan_id": scan_id,
            "findings_count": len(all_findings),
            "statuses": statuses,
            "coverage": coverage,
            "finding_ids": [f["finding_id"] for f in all_findings],
        }
