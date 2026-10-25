"""Deterministic estate generator with SQLite persistence.

Planted facts come from :mod:`app.seed.scenarios`; filler is generated from a
fixed RNG seed so ids are stable between runs. Filler never creates an attack
path: filler services have no public ingress, only mTLS call edges and no
crown-jewel access, and filler findings on planted services always have
`reachable_code` false.
"""

from __future__ import annotations

import json
import logging
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.config import settings
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.repositories.findings import FindingRepository
from app.repositories.graph import GraphRepository
from app.repositories.mappings import MappingRepository
from app.seed import scenarios

log = logging.getLogger("chokepoint.seed.generate")

RNG_SEED = 1337
TARGET_FINDINGS = 320
TARGET_FILLER_VULNS = 24
WEAKNESS_CLASSES = (
    "deserialisation of untrusted input",
    "path traversal in archive extraction",
    "improper certificate validation",
    "uncontrolled resource consumption",
    "server-side request forgery in the URL handler",
    "improper neutralisation of template expressions",
    "integer overflow in the length prefix parser",
    "incorrect authorisation on a batch endpoint",
)


def package_id(name: str, version: str) -> str:
    return f"pkg-{name}@{version}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _repo(service_id: str) -> str:
    return f"acme/{service_id}"


class Generator:
    """Builds the whole estate layer in a deterministic order."""

    def __init__(self, scale: int = 1, graph: str | None = None) -> None:
        self.scale = max(1, int(scale))
        self.graph = graph or settings.graph_name
        self.rng = random.Random(RNG_SEED)
        self.created_at = _now()
        self.services: dict[str, dict[str, Any]] = {}
        self.packages: dict[str, dict[str, Any]] = {}
        self.vulnerabilities: dict[str, dict[str, Any]] = {}
        self.findings: dict[str, dict[str, Any]] = {}
        self.dependencies: set[tuple[str, str, bool]] = set()
        self.affected_by: set[tuple[str, str, str]] = set()
        self.people: list[dict[str, Any]] = []
        self.on_call: list[tuple[str, str]] = []
        self.calls: list[tuple[str, str, str, str, int]] = []
        self.store_access: list[tuple[str, str, str]] = []
        self.filler_vuln_ids: list[str] = []

    # --- model building ----------------------------------------------------

    def build(self) -> None:
        self._build_services()
        self._build_packages_and_vulns()
        self._build_people()
        self._build_calls()
        self._build_store_access()
        self._build_planted_findings()
        self._build_filler_findings()

    def _build_services(self) -> None:
        public_services = {ing["service"] for ing in scenarios.INGRESS if ing["public"]}
        for spec in scenarios.PLANTED_SERVICES:
            sid = str(spec["id"])
            self.services[sid] = {
                "id": sid,
                "name": spec.get("name", sid),
                "repo": _repo(sid),
                "language": spec["language"],
                "tier": int(spec["tier"]),
                "status": spec.get("status", "active"),
                "internet_facing": sid in public_services,
                "env": spec.get("env", "prod"),
                "cluster": spec["cluster"],
                "team": spec["team"],
                "planted": True,
                "created_at": self.created_at,
            }
        for copy_index in range(self.scale):
            suffix = "" if copy_index == 0 else f"-{copy_index + 1}"
            for spec in scenarios.FILLER_SERVICES:
                sid = f"{spec['id']}{suffix}"
                self.services[sid] = {
                    "id": sid,
                    "name": sid,
                    "repo": _repo(sid),
                    "language": spec["language"],
                    "tier": int(spec["tier"]),
                    "status": "deprecated" if spec["id"] == "chat-relay" else "active",
                    "internet_facing": False,
                    "env": spec.get("env", "prod"),
                    "cluster": spec["cluster"],
                    "team": spec["team"],
                    "planted": False,
                    "created_at": self.created_at,
                }

    def _add_package(self, name: str, version: str, ecosystem: str, internal: bool) -> str:
        pid = f"pkg-{name}@{version}"
        if pid not in self.packages:
            self.packages[pid] = {
                "id": pid,
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
                "internal": internal,
                "created_at": self.created_at,
            }
        return pid

    def _build_packages_and_vulns(self) -> None:
        for spec in scenarios.PLANTED_PACKAGES:
            self._add_package(spec["name"], spec["version"], spec["ecosystem"], bool(spec["internal"]))
        for vuln in scenarios.PLANTED_VULNERABILITIES:
            self.vulnerabilities[str(vuln["id"])] = {**vuln, "created_at": self.created_at}

        pool = [*scenarios.FILLER_PACKAGE_NAMES, *scenarios.INTERNAL_FILLER_PACKAGE_NAMES]
        counter = 0
        for copy_index in range(self.scale):
            for name, version, ecosystem in pool:
                internal = name.startswith("acme-")
                pkg_name = name if copy_index == 0 else f"{name}-v{copy_index + 1}"
                pid = self._add_package(pkg_name, version, ecosystem, internal)
                counter += 1
                # Roughly a quarter of packages carry no advisory, and the
                # advisory count is capped so the vulnerability table stays
                # near the target size however many packages exist.
                if counter % 4 == 3 or len(self.filler_vuln_ids) >= TARGET_FILLER_VULNS * self.scale:
                    continue
                vuln_id = f"SYN-2026-{counter:04d}"
                cvss = [9.8, 9.1, 8.8, 8.1, 7.5, 6.5, 5.9, 5.3, 4.3][counter % 9]
                self.vulnerabilities[vuln_id] = {
                    "id": vuln_id,
                    "cve": vuln_id,
                    "cvss": cvss,
                    "epss": round(0.002 + (counter % 23) * 0.013, 4),
                    "kev": counter % 11 == 0,
                    "attack_vector": ("network", "network", "adjacent", "local")[counter % 4],
                    "requires_auth": counter % 3 == 0,
                    "fixed_in": f"{version.split('.')[0]}.99.0",
                    "summary": (
                        f"Synthetic advisory for {pkg_name}: "
                        f"{WEAKNESS_CLASSES[counter % len(WEAKNESS_CLASSES)]}."
                    ),
                    "created_at": self.created_at,
                }
                self.filler_vuln_ids.append(vuln_id)
                self.affected_by.add((pid, vuln_id, str(self.vulnerabilities[vuln_id]["fixed_in"])))

        for name, version, service_ids, direct in scenarios.PLANTED_DEPENDENCIES:
            pid = package_id(name, version)
            for sid in service_ids:
                self.dependencies.add((sid, pid, bool(direct)))

        for finding in (*scenarios.PLANTED_FINDINGS, *scenarios.DELTA_FINDINGS):
            pkg_spec = next(p for p in scenarios.PLANTED_PACKAGES if p["name"] == finding["package"])
            pid = package_id(spec["name"], spec["version"])
            vuln = self.vulnerabilities[str(finding["cve"])]
            self.affected_by.add((pid, str(finding["cve"]), str(vuln["fixed_in"])))

    def _build_people(self) -> None:
        team_ids = [t["id"] for t in scenarios.TEAMS]
        for index, (name, role) in enumerate(scenarios.PERSON_NAMES):
            team = team_ids[index % len(team_ids)]
            handle = name.lower().replace(" ", ".")
            self.people.append(
                {
                    "id": f"per-{index + 1:03d}",
                    "name": name,
                    "email": f"{handle}@acme.example",
                    "role": role,
                    "team": team,
                    "created_at": self.created_at,
                }
            )
        by_team: dict[str, list[str]] = {}
        for person in self.people:
            by_team.setdefault(str(person["team"]), []).append(str(person["id"]))
        for sid, service in sorted(self.services.items()):
            members = by_team.get(str(service["team"])) or [p["id"] for p in self.people[:2]]
            count = 2 if service["tier"] == 1 else 1
            # A stable digest keeps on-call assignment identical between runs;
            # the builtin hash() of a str is salted per process.
            digest = sum(ord(ch) * (i + 1) for i, ch in enumerate(sid))
            picks = [members[(digest + i) % len(members)] for i in range(count)]
            for person_id in dict.fromkeys(picks):
                self.on_call.append((person_id, sid))

    def _build_calls(self) -> None:
        self.calls = list(scenarios.PLANTED_CALLS)
        for copy_index in range(self.scale):
            suffix = "" if copy_index == 0 else f"-{copy_index + 1}"
            for src, dst, authz, protocol, rps in scenarios.FILLER_CALLS:
                src_id = f"{src}{suffix}" if src in {s["id"] for s in scenarios.FILLER_SERVICES} else src
                dst_id = f"{dst}{suffix}" if dst in {s["id"] for s in scenarios.FILLER_SERVICES} else dst
                if src_id in self.services and dst_id in self.services:
                    # Filler edges are always mTLS so filler can never carry a path.
                    self.calls.append((src_id, dst_id, "mtls", protocol, rps))

    def _build_store_access(self) -> None:
        self.store_access = list(scenarios.STORE_ACCESS)
        for copy_index in range(self.scale):
            suffix = "" if copy_index == 0 else f"-{copy_index + 1}"
            for service, rel, store in scenarios.FILLER_STORE_ACCESS:
                sid = f"{service}{suffix}"
                if sid in self.services:
                    self.store_access.append((sid, rel, store))

    def _build_planted_findings(self) -> None:
        for spec in scenarios.PLANTED_FINDINGS:
            pkg_spec = next(p for p in scenarios.PLANTED_PACKAGES if p["name"] == spec["package"])
            pid = package_id(pkg_spec["name"], pkg_spec["version"])
            vuln = self.vulnerabilities[str(spec["cve"])]
            self.findings[str(spec["id"])] = {
                "id": str(spec["id"]),
                "service": str(spec["service"]),
                "package": pid,
                "cve": str(spec["cve"]),
                "cvss": float(vuln["cvss"]),
                "status": str(spec["status"]),
                "reachable_code": bool(spec["reachable_code"]),
                "scan_id": scenarios.SCAN_DAY1,
                "first_seen": _iso_days_ago(21),
                "last_seen": _iso_days_ago(1),
                "planted": True,
                "created_at": self.created_at,
            }

    def _build_filler_findings(self) -> None:
        """Fill up to the target count from (service, vulnerable package) pairs."""
        target = TARGET_FINDINGS * self.scale
        vulnerable: list[tuple[str, str, str]] = sorted(self.affected_by)
        filler_pairs = [
            (pid, vid, fixed)
            for pid, vid, fixed in vulnerable
            if vid in set(self.filler_vuln_ids)
        ]
        if not filler_pairs:
            return
        service_ids = sorted(self.services)
        planted_ids = {s for s, v in self.services.items() if v["planted"]}
        pairs = [
            (service_id, pid, vid)
            for service_id in service_ids
            for pid, vid, _fixed in filler_pairs
        ]
        self.rng.shuffle(pairs)
        counter = 0
        for service_id, pid, vid in pairs:
            if len(self.findings) >= target:
                break
            if (service_id, pid, True) in self.dependencies or (service_id, pid, False) in self.dependencies:
                continue
            counter += 1
            finding_id = f"F-{1000 + counter}"
            self.dependencies.add((service_id, pid, counter % 3 != 0))
            status = ("open", "open", "open", "suppressed", "fixed")[counter % 5]
            # A filler finding on a planted service is never reachable code, so
            # it can never become a live exploit and disturb the planted story.
            reachable = False if service_id in planted_ids else counter % 3 == 0
            self.findings[finding_id] = {
                "id": finding_id,
                "service": service_id,
                "package": pid,
                "cve": vid,
                "cvss": float(self.vulnerabilities[vid]["cvss"]),
                "status": status,
                "reachable_code": reachable,
                "scan_id": scenarios.SCAN_DAY1,
                "first_seen": _iso_days_ago(10 + counter % 40),
                "last_seen": _iso_days_ago(1),
                "planted": False,
                "created_at": self.created_at,
            }

    # --- writing -----------------------------------------------------------

    def write(self) -> dict[str, Any]:
        started = time.perf_counter()
        # Drop and regenerate using repositories
        ProjectRepository.delete_all()
        ScanRepository.delete_all()
        FindingRepository.delete_all()
        GraphRepository.delete_all()

        # Write projects
        for sid, svc in self.services.items():
            ProjectRepository.create(sid, svc.get("name", sid), svc.get("repo", ""))

        # Write scan
        scan_id = scenarios.SCAN_DAY1
        ScanRepository.create(
            scan_id=scan_id,
            project_id=list(self.services.keys())[0] if self.services else "initial",
            kind="repository",
            source_type="generated",
            source_ref=self.graph,
            workspace_path="",
            status="completed",
        )

        # Write packages
        for pid, pkg in self.packages.items():
            FindingRepository._add_package(pid, pkg["name"], pkg["version"], pkg["ecosystem"], pkg["internal"])

        # Write findings
        findings_to_insert = []
        for fid, f in self.findings.items():
            vid = f["cve"]
            pid = f["package"]
            vuln = self.vulnerabilities.get(vid, {})
            findings_to_insert.append({
                "finding_id": fid,
                "scan_id": scan_id,
                "scanner": "synthetic",
                "rule_id": vid,
                "category": "vulnerability",
                "severity": "CRITICAL",
                "cve": vid,
                "epss": float(vuln.get("epss") or 0.0),
                "kev": bool(vuln.get("kev")),
                "attack_vector": vuln.get("attack_vector", "network"),
                "requires_auth": bool(vuln.get("requires_auth")),
                "ecosystem": pid.split("@")[0] if "@" in pid else "",
                "package_name": pid.split("@")[0] if "@" in pid else pid,
                "package_version": pid.split("@")[1] if "@" in pid else "",
                "fixed_in": vuln.get("fixed_in", ""),
                "summary": vuln.get("summary", ""),
                "status": f.get("status", "open"),
                "reachable_code": bool(f.get("reachable_code")),
            })
        FindingRepository.bulk_insert(findings_to_insert)

        # Write graph nodes and edges
        GraphRepository.bulk_insert_nodes([
            {"id": sid, "scan_id": scan_id, "label": "Service", "properties": svc}
            for sid, svc in self.services.items()
        ])
        GraphRepository.bulk_insert_nodes([
            {"id": pid, "scan_id": scan_id, "label": "Package", "properties": pkg}
            for pid, pkg in self.packages.items()
        ])
        GraphRepository.bulk_insert_nodes([
            {"id": store["id"], "scan_id": scan_id, "label": "DataStore", "properties": store}
            for store in scenarios.DATA_STORES
        ])
        GraphRepository.bulk_insert_edges([
            {"source_id": src, "target_id": dst, "relation": "CALLS", "scan_id": scan_id, "properties": {"authz": authz, "protocol": protocol, "rps": rps}}
            for src, dst, authz, protocol, rps in self.calls
            if src in self.services and dst in self.services
        ])
        GraphRepository.bulk_insert_edges([
            {"source_id": sid, "target_id": pid, "relation": "DEPENDS_ON", "scan_id": scan_id, "properties": {"direct": direct}}
            for sid, pid, direct in self.dependencies
        ])
        GraphRepository.bulk_insert_edges([
            {"source_id": sid, "target_id": did, "relation": rel, "scan_id": scan_id, "properties": {}}
            for sid, rel, did in self.store_access
        ])

        # Write finding mappings
        mappings = [
            {
                "finding_id": fid,
                "node_id": f["service"],
                "match_kind": "direct",
                "confidence": 1.0,
                "evidence": f"Synthetic finding on {f['service']} via {f['package']}",
            }
            for fid, f in self.findings.items()
        ]
        MappingRepository.bulk_insert(mappings)

        # Store affected_by relationships
        for pid, vid, fixed in sorted(self.affected_by):
            if pid in self.packages:
                FindingRepository._mark_affected(pid, vid, fixed)

        stats = self._stats()
        stats["seconds"] = round(time.perf_counter() - started, 2)
        stats["ground_truth_path"] = str(settings.ground_truth_file)
        return stats

    def _stats(self) -> dict[str, Any]:
        return {
            "graph": self.graph,
            "scale": self.scale,
            "services": len(self.services),
            "packages": len(self.packages),
            "vulnerabilities": len(self.vulnerabilities),
            "findings": len(self.findings),
            "scan_id": scenarios.SCAN_DAY1,
        }


def generate(scale: int | None = None, graph: str | None = None) -> dict[str, Any]:
    """Drop and rebuild the estate layer. Returns write statistics."""
    generator = Generator(scale=scale or settings.seed_scale, graph=graph)
    generator.build()
    stats = generator.write()
    log.info(
        "seeded graph '%s' scale %s: %d services, %d packages, %d vulns, %d findings in %.2fs",
        stats["graph"],
        stats["scale"],
        stats["services"],
        stats["packages"],
        stats["vulnerabilities"],
        stats["findings"],
        stats["seconds"],
    )
    return stats