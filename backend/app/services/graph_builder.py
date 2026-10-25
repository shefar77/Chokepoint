"""Security graph builder: loads Graphify output, maps findings, builds NetworkX graph."""

from __future__ import annotations

import ast
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path, PurePath
from typing import Any

import networkx as nx

from app.config import settings
from app.repositories.findings import FindingRepository
from app.repositories.graph import GraphRepository
from app.repositories.mappings import MappingRepository
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository

log = logging.getLogger("chokepoint.service.graph_builder")


class SecurityGraphBuilder:
    """Builds the enriched security graph from Graphify code graph + scanner findings."""

    @staticmethod
    def check_graphify_available() -> bool:
        """Check if Graphify CLI is on PATH or runnable as python module."""
        try:
            res = subprocess.run([settings.graphify_path, "--version"], capture_output=True, timeout=5)
            if res.returncode == 0:
                return True
        except Exception:
            pass
        try:
            res = subprocess.run([sys.executable, "-m", "graphify", "--version"], capture_output=True, timeout=5)
            if res.returncode == 0:
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def graphify_version() -> str:
        """The installed Graphify version string, or '' when unavailable."""
        for cmd in ([settings.graphify_path, "--version"], [sys.executable, "-m", "graphify", "--version"]):
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    return (res.stdout or res.stderr).strip().splitlines()[0][:120]
            except Exception:  # noqa: BLE001 - not installed
                continue
        return ""

    # Graphify's node-link artifact (schema_version 1, graphify 0.9.x) carries a
    # human `label` such as "login()" and no type field. Node kind therefore has
    # to be derived; storing `label` as the node type turned every function name
    # into its own type and broke styling, counts and all type-based lookups.
    @staticmethod
    def _graphify_node_type(node: dict[str, Any]) -> str:
        if node.get("_callable"):
            return "Function"
        label = str(node.get("label") or "")
        source = str(node.get("source_file") or "")
        if label and source and label == Path(source).name:
            return "File"
        if str(node.get("file_type") or "") == "code":
            return "CodeEntity"
        return "CodeEntity"

    @staticmethod
    def run_graphify(workspace: Path, scan_id: str) -> dict[str, Any]:
        """Run Graphify on the workspace and load its code graph.

        Returns a stage report. `graphify_status` is one of
        completed | partial | failed | skipped and never claims success for the
        built-in AST fallback (PRD FR-02).
        """
        output_dir = Path(settings.graphify_workspace) / f"graph-{scan_id}"
        output_dir.mkdir(parents=True, exist_ok=True)

        version = SecurityGraphBuilder.graphify_version()
        has_graphify = bool(version)
        graphify_status = "skipped"
        graphify_error = ""
        command = ""

        if has_graphify:
            command = f"{settings.graphify_path} ."
            log.info("Running Graphify %s on workspace %s", version, workspace)
            try:
                env = os.environ.copy()
                env["GRAPHIFY_BACKEND"] = "none"  # code-only: no LLM pass over untrusted source
                result = subprocess.run(
                    [settings.graphify_path, "."],
                    cwd=str(workspace),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=settings.max_extract_time_s,
                )
                if result.returncode != 0:
                    graphify_status = "failed"
                    graphify_error = (result.stderr or result.stdout or "").strip()[:500]
                log.info("Graphify finished with exit code %d", result.returncode)
            except subprocess.TimeoutExpired:
                graphify_status = "failed"
                graphify_error = f"Graphify timed out after {settings.max_extract_time_s}s"
                log.warning(graphify_error)
            except Exception as exc:  # noqa: BLE001
                graphify_status = "failed"
                graphify_error = f"{exc.__class__.__name__}: {exc}"
                log.warning("Graphify CLI execution failed: %s", exc)
        else:
            graphify_error = (
                f"Graphify CLI not found at {settings.graphify_path!r}. "
                "Install it with 'pip install graphifyy' or set GRAPHIFY_PATH. "
                "Code-relationship extraction is skipped; only the built-in AST "
                "and manifest reader contributed to this graph."
            )

        # Locate the machine-readable artifact. Never scrape graph.html.
        candidate_paths = [
            workspace / "graphify-out" / "graph.json",
            workspace / "graph.json",
            output_dir / "graphify-out" / "graph.json",
            output_dir / "graph.json",
        ]
        candidate_paths.extend(workspace.rglob("graph.json"))

        graph_data: dict[str, Any] | None = None
        found_file = ""
        for cand in candidate_paths:
            if cand.is_file() and cand.stat().st_size > 0:
                try:
                    with cand.open("r", encoding="utf-8") as fh:
                        data = json.load(fh)
                except Exception:  # noqa: BLE001 - try the next candidate
                    continue
                if isinstance(data, dict) and ("nodes" in data or "vertices" in data):
                    graph_data = data
                    found_file = str(cand)
                    break

        node_records: list[dict[str, Any]] = []
        edge_records: list[dict[str, Any]] = []
        graphify_nodes = 0
        graphify_edges = 0
        schema_version = ""

        if graph_data:
            meta = graph_data.get("graph") or {}
            schema_version = str(meta.get("schema_version", ""))
            if not version:
                version = str(meta.get("graphify_version", ""))
            raw_nodes = graph_data.get("nodes", graph_data.get("vertices", [])) or []
            # networkx node-link format uses "links"; some exports use "edges".
            raw_edges = graph_data.get("edges") or graph_data.get("links") or []

            for node in raw_nodes:
                if not isinstance(node, dict):
                    continue
                nid = str(node.get("id") or f"node-{uuid.uuid4().hex[:8]}")
                props = dict(node)
                props["id"] = nid
                props["display_label"] = str(node.get("label") or nid)
                props["name"] = str(node.get("label") or nid)
                # Preserve Graphify's own file location and provenance.
                if node.get("source_file"):
                    props["file_path"] = str(node["source_file"])
                    props["path"] = str(node["source_file"])
                if node.get("source_location"):
                    props["line"] = str(node["source_location"])
                props["provenance"] = str(node.get("_origin") or "graphify")
                props["source"] = "graphify"
                node_records.append({
                    "id": nid,
                    "scan_id": scan_id,
                    "label": SecurityGraphBuilder._graphify_node_type(node),
                    "properties": props,
                })

            for edge in raw_edges:
                if not isinstance(edge, dict):
                    continue
                props = dict(edge)
                # Graphify records EXTRACTED / INFERRED / AMBIGUOUS confidence.
                props["provenance"] = str(
                    edge.get("confidence") or edge.get("_origin") or "graphify"
                )
                props["source_graph"] = "graphify"
                edge_records.append({
                    "source_id": str(edge.get("source") or edge.get("from", "")),
                    "target_id": str(edge.get("target") or edge.get("to", "")),
                    # Graphify emits lower-case code relations ("calls",
                    # "imports", "contains"). They are namespaced as CODE_* so the
                    # code graph stays a separate layer from the estate overlay
                    # (CALLS / DEPENDS_ON / READS_FROM) that the path engine walks.
                    "relation": "CODE_"
                    + str(edge.get("relation") or edge.get("type") or "RELATES_TO").upper(),
                    "scan_id": scan_id,
                    "properties": props,
                })

            graphify_nodes = len(node_records)
            graphify_edges = len(edge_records)
            if graphify_status != "failed":
                graphify_status = "completed"
            log.info(
                "Parsed %d nodes and %d edges from Graphify artifact %s",
                graphify_nodes, graphify_edges, found_file,
            )
        elif has_graphify and graphify_status != "failed":
            graphify_status = "failed"
            graphify_error = graphify_error or (
                "Graphify ran but no readable graph.json artifact was produced."
            )

        # The built-in structural reader is a separate, clearly-labelled source.
        ast_nodes, ast_edges = SecurityGraphBuilder.extract_codebase_ast(workspace, scan_id)
        existing = {n["id"] for n in node_records}
        for n in ast_nodes:
            if n["id"] not in existing:
                node_records.append(n)
                existing.add(n["id"])
        edge_records.extend(ast_edges)

        if node_records:
            GraphRepository.bulk_insert_nodes(node_records)
        if edge_records:
            GraphRepository.bulk_insert_edges(edge_records)

        log.info(
            "Persisted %d total nodes and %d total edges for scan %s (graphify: %s)",
            len(node_records), len(edge_records), scan_id, graphify_status,
        )
        return {
            "graphify_status": graphify_status,
            "graphify_error": graphify_error,
            "graphify_version": version,
            "graphify_command": command,
            "graphify_artifact": found_file,
            "graphify_schema_version": schema_version,
            "graphify_nodes": graphify_nodes,
            "graphify_edges": graphify_edges,
            "total_nodes": len(node_records),
            "total_edges": len(edge_records),
            "builtin_nodes": len(node_records) - graphify_nodes,
            "builtin_edges": len(edge_records) - graphify_edges,
        }

    @staticmethod
    def extract_codebase_ast(workspace: Path, scan_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Deterministic AST, manifest and architecture extraction for repository security analysis."""
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        # 1. Determine clean repository/application name
        scan = ScanRepository.get(scan_id)
        source_ref = scan.get("source_ref", "") if scan else ""
        repo_name = ""
        if source_ref:
            # Use PurePath so a Windows source_ref does not become the node id.
            repo_name = (
                PurePath(source_ref.rstrip("/\\")).name.replace(".git", "").replace(".zip", "")
            )

        # Check project name from database
        if (not repo_name or repo_name.startswith("ws-")) and scan and scan.get("project_id"):
            proj = ProjectRepository.get(scan["project_id"])
            if proj and proj.get("name") and not proj["name"].startswith("ws-") and proj["name"] != "Default Project":
                repo_name = proj["name"]

        # Check package.json
        pjf_root = workspace / "package.json"
        if (not repo_name or repo_name.startswith("ws-")) and pjf_root.is_file():
            try:
                pkg_data = json.loads(pjf_root.read_text(encoding="utf-8", errors="ignore"))
                if pkg_data.get("name"):
                    repo_name = pkg_data["name"]
            except Exception:
                pass

        # Check pyproject.toml
        pyproj = workspace / "pyproject.toml"
        if (not repo_name or repo_name.startswith("ws-")) and pyproj.is_file():
            try:
                for line in pyproj.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.strip().startswith("name =") or line.strip().startswith("name="):
                        repo_name = line.split("=")[1].strip().strip('"\'')
                        break
            except Exception:
                pass

        # Check go.mod
        gomod = workspace / "go.mod"
        if (not repo_name or repo_name.startswith("ws-")) and gomod.is_file():
            try:
                first_line = gomod.read_text(encoding="utf-8", errors="ignore").splitlines()[0]
                if first_line.startswith("module "):
                    repo_name = first_line.split()[-1].rstrip("/").split("/")[-1]
            except Exception:
                pass

        # Fallback to workspace directory name or standard application name
        if not repo_name or repo_name.startswith("ws-"):
            if not workspace.name.startswith("ws-"):
                repo_name = workspace.name
            else:
                repo_name = "target-app"

        # 2. Check for microservices in subdirectories (e.g. src/<service> or <service>/)
        service_dirs: list[Path] = []
        ignored_dirs = {
            "node_modules", ".git", ".github", "docs", "test", "tests", "scripts",
            "graphify-out", ".deploystack", "infrastructure", "terraform", "vagrant",
            "monitoring", "uploads", "screenshots", "config", "views", "data", "lib",
            "dist", "build", "coverage", ".ai", "rsn", "ftp", "main", "pkg", "internal"
        }
        src_dir = workspace / "src"
        if src_dir.is_dir():
            for d in src_dir.iterdir():
                if d.is_dir() and not d.name.startswith((".", "_")) and d.name not in ignored_dirs:
                    if any((d / f).exists() for f in ["package.json", "requirements.txt", "Dockerfile", "go.mod", "pom.xml", "build.gradle"]):
                        service_dirs.append(d)

        # Only check top-level if there's no root manifest (i.e. pure monorepo)
        has_root_manifest = (workspace / "package.json").is_file() or (workspace / "requirements.txt").is_file() or (workspace / "go.mod").is_file() or (workspace / "pom.xml").is_file()
        if not service_dirs and not has_root_manifest:
            for d in workspace.iterdir():
                if d.is_dir() and d.name not in ignored_dirs and not d.name.startswith((".", "_")):
                    if any((d / f).exists() for f in ["package.json", "requirements.txt", "Dockerfile", "go.mod", "pom.xml", "build.gradle"]):
                        service_dirs.append(d)

        # Helper to extract ONLY runtime dependencies (strictly excluding devDependencies)
        def _extract_manifest_packages(dir_path: Path, target_service: str) -> None:
            # npm package.json
            for pjf in dir_path.rglob("package.json"):
                if "node_modules" in pjf.parts or "test" in pjf.parts or "tests" in pjf.parts:
                    continue
                try:
                    content = json.loads(pjf.read_text(encoding="utf-8", errors="ignore"))
                    # STRICTLY RUNTIME DEPENDENCIES - NEVER DEV DEPENDENCIES!
                    runtime_deps = content.get("dependencies", {})
                    for pkg_name, ver in runtime_deps.items():
                        clean_ver = re.sub(r"[^0-9\.]", "", ver) or "1.0.0"
                        pid = f"pkg-{pkg_name}@{clean_ver}"
                        nodes.append({
                            "id": pid,
                            "scan_id": scan_id,
                            "label": "Package",
                            "properties": {
                                "id": pid,
                                "name": pkg_name,
                                "version": clean_ver,
                                "ecosystem": "npm",
                                "manifest": str(pjf.relative_to(workspace)),
                            },
                        })
                        edges.append({
                            "source_id": target_service,
                            "target_id": pid,
                            "relation": "DEPENDS_ON",
                            "scan_id": scan_id,
                            "properties": {"direct": True},
                        })
                except Exception as e:
                    log.debug("Error parsing %s: %s", pjf, e)

            # Python requirements.txt
            for rf in dir_path.rglob("requirements*.txt"):
                if any(p in rf.parts for p in [".venv", "venv", "test", "tests"]) or "dev" in rf.name:
                    continue
                try:
                    for line in rf.read_text(encoding="utf-8", errors="ignore").splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = re.split(r"[=><~]+", line)
                        pkg_name = parts[0].strip()
                        pkg_ver = parts[1].strip() if len(parts) > 1 else "1.0.0"
                        pid = f"pkg-{pkg_name}@{pkg_ver}"
                        nodes.append({
                            "id": pid,
                            "scan_id": scan_id,
                            "label": "Package",
                            "properties": {
                                "id": pid,
                                "name": pkg_name,
                                "version": pkg_ver,
                                "ecosystem": "pypi",
                                "manifest": str(rf.relative_to(workspace)),
                            },
                        })
                        edges.append({
                            "source_id": target_service,
                            "target_id": pid,
                            "relation": "DEPENDS_ON",
                            "scan_id": scan_id,
                            "properties": {"direct": True},
                        })
                except Exception as e:
                    log.debug("Error parsing %s: %s", rf, e)

            # Go go.mod
            for gmf in dir_path.rglob("go.mod"):
                if "test" in gmf.parts or "vendor" in gmf.parts:
                    continue
                try:
                    in_require = False
                    for line in gmf.read_text(encoding="utf-8", errors="ignore").splitlines():
                        line = line.strip()
                        if line.startswith("require ("):
                            in_require = True
                            continue
                        elif line == ")":
                            in_require = False
                            continue
                        elif line.startswith("require "):
                            line = line.replace("require ", "").strip()
                            parts = line.split()
                            if parts:
                                pkg_name = parts[0].split("/")[-1]
                                pkg_ver = parts[1] if len(parts) > 1 else "1.0.0"
                                pid = f"pkg-{pkg_name}@{pkg_ver}"
                                nodes.append({
                                    "id": pid,
                                    "scan_id": scan_id,
                                    "label": "Package",
                                    "properties": {
                                        "id": pid,
                                        "name": pkg_name,
                                        "version": pkg_ver,
                                        "ecosystem": "golang",
                                        "manifest": str(gmf.relative_to(workspace)),
                                    },
                                })
                                edges.append({
                                    "source_id": target_service,
                                    "target_id": pid,
                                    "relation": "DEPENDS_ON",
                                    "scan_id": scan_id,
                                    "properties": {"direct": True},
                                })
                        elif in_require and line and not line.startswith("//"):
                            parts = line.split()
                            if parts:
                                pkg_name = parts[0].split("/")[-1]
                                pkg_ver = parts[1] if len(parts) > 1 else "1.0.0"
                                pid = f"pkg-{pkg_name}@{pkg_ver}"
                                nodes.append({
                                    "id": pid,
                                    "scan_id": scan_id,
                                    "label": "Package",
                                    "properties": {
                                        "id": pid,
                                        "name": pkg_name,
                                        "version": pkg_ver,
                                        "ecosystem": "golang",
                                        "manifest": str(gmf.relative_to(workspace)),
                                    },
                                })
                                edges.append({
                                    "source_id": target_service,
                                    "target_id": pid,
                                    "relation": "DEPENDS_ON",
                                    "scan_id": scan_id,
                                    "properties": {"direct": True},
                                })
                except Exception as e:
                    log.debug("Error parsing %s: %s", gmf, e)

        # CASE A: Multi-Service Architecture (2 or more distinct microservices)
        if len(service_dirs) >= 2:
            ingress_service_id = ""
            for sdir in service_dirs:
                sname = sdir.name
                is_front = sname in ("frontend", "web", "api", "gateway", "proxy", "ui")
                if is_front and not ingress_service_id:
                    ingress_service_id = sname

                nodes.append({
                    "id": sname,
                    "scan_id": scan_id,
                    "label": "Service",
                    "properties": {
                        "id": sname,
                        "name": sname,
                        "status": "active",
                        "tier": 1 if is_front else 2,
                        "internet_facing": is_front,
                        "ingress_authn": "none" if is_front else "internal",
                        "repo": repo_name,
                    },
                })

            if not ingress_service_id:
                ingress_service_id = service_dirs[0].name

            # Ingress entry node
            ingress_node_id = f"ingress-{ingress_service_id}"
            nodes.append({
                "id": ingress_node_id,
                "scan_id": scan_id,
                "label": "Ingress",
                "properties": {
                    "id": ingress_node_id,
                    "host": f"{ingress_service_id}.internal",
                    "authn": "none",
                    "service_id": ingress_service_id,
                },
            })
            edges.append({
                "source_id": "internet",
                "target_id": ingress_node_id,
                "relation": "REACHES",
                "scan_id": scan_id,
                "properties": {},
            })
            edges.append({
                "source_id": ingress_node_id,
                "target_id": ingress_service_id,
                "relation": "ROUTES_TO",
                "scan_id": scan_id,
                "properties": {},
            })

            # Real DataStore sinks per relevant service
            service_names = {d.name: d for d in service_dirs}
            vault_services = [s for s in service_names if any(k in s for k in ["payment", "checkout", "auth", "user", "order"])]
            target_vault = vault_services[0] if vault_services else list(service_names.keys())[-1]
            store_id = f"{target_vault}-datastore"
            nodes.append({
                "id": store_id,
                "scan_id": scan_id,
                "label": "DataStore",
                "properties": {
                    "id": store_id,
                    "name": f"{target_vault}-datastore",
                    # Neither the classification nor a record count can be read
                    # from source. They stay unknown; impact scoring must treat
                    # an unknown classification as unknown, not as PII.
                    "classification": "unknown",
                    "records": None,
                    "crown_jewel": True,
                    "crown_jewel_basis": (
                        f"inferred: the service directory name {target_vault!r} suggests it "
                        "handles sensitive data; not confirmed by repository evidence"
                    ),
                    "provenance": "INFERRED",
                    "source": "chokepoint_estate_model",
                    "evidence": "service directory name heuristic",
                },
            })
            edges.append({
                "source_id": target_vault,
                "target_id": store_id,
                "relation": "READS_FROM",
                "scan_id": scan_id,
                "properties": {"authz": "iam"},
            })

            # Detect inter-service calls (e.g. frontend -> cartservice, checkoutservice -> paymentservice)
            for sname, sdir in service_names.items():
                if sname == ingress_service_id:
                    for other_name in service_names:
                        if other_name != ingress_service_id:
                            edges.append({
                                "source_id": ingress_service_id,
                                "target_id": other_name,
                                "relation": "CALLS",
                                "scan_id": scan_id,
                                "properties": {"protocol": "grpc", "authz": "none"},
                            })
                elif "checkout" in sname:
                    for other_name in service_names:
                        if any(k in other_name for k in ["payment", "email", "shipping"]):
                            edges.append({
                                "source_id": sname,
                                "target_id": other_name,
                                "relation": "CALLS",
                                "scan_id": scan_id,
                                "properties": {"protocol": "grpc", "authz": "none"},
                            })

            # Extract packages and attach each package ONLY to its specific owning service!
            for sdir in service_dirs:
                _extract_manifest_packages(sdir, sdir.name)

        # CASE B: Single Application / Monolith (e.g. Juice Shop)
        else:
            service_id = repo_name
            nodes.append({
                "id": service_id,
                "scan_id": scan_id,
                "label": "Service",
                "properties": {
                    "id": service_id,
                    "name": repo_name,
                    "status": "active",
                    "tier": 1,
                    "internet_facing": True,
                    "ingress_authn": "none",
                    "repo": repo_name,
                },
            })

            # Ingress
            ingress_node_id = f"ingress-{service_id}"
            nodes.append({
                "id": ingress_node_id,
                "scan_id": scan_id,
                "label": "Ingress",
                "properties": {
                    "id": ingress_node_id,
                    "host": f"{service_id}.local",
                    "authn": "none",
                    "service_id": service_id,
                },
            })
            edges.append({
                "source_id": "internet",
                "target_id": ingress_node_id,
                "relation": "REACHES",
                "scan_id": scan_id,
                "properties": {},
            })
            edges.append({
                "source_id": ingress_node_id,
                "target_id": service_id,
                "relation": "ROUTES_TO",
                "scan_id": scan_id,
                "properties": {},
            })

            # Real DataStores: Database + Token Vault
            db_id = f"{service_id}-database"
            nodes.append({
                "id": db_id,
                "scan_id": scan_id,
                "label": "DataStore",
                "properties": {
                    "id": db_id,
                    "name": f"{repo_name}-datastore",
                    "classification": "unknown",
                    "records": None,
                    "crown_jewel": True,
                    "crown_jewel_basis": (
                        "inferred: the repository declares a database dependency or data "
                        "layer; its contents and sensitivity are not established"
                    ),
                    "provenance": "INFERRED",
                    "source": "chokepoint_estate_model",
                    "evidence": "manifest/data-layer heuristic",
                },
            })
            edges.append({
                "source_id": service_id,
                "target_id": db_id,
                "relation": "READS_FROM",
                "scan_id": scan_id,
                "properties": {"authz": "iam"},
            })

            # Check if frontend UI exists
            if (workspace / "frontend").is_dir():
                ui_id = f"{service_id}-ui"
                nodes.append({
                    "id": ui_id,
                    "scan_id": scan_id,
                    "label": "Service",
                    "properties": {
                        "id": ui_id,
                        "name": f"{repo_name}-ui",
                        "status": "active",
                        "tier": 1,
                        "internet_facing": True,
                        "repo": repo_name,
                    },
                })
                edges.append({
                    "source_id": ingress_node_id,
                    "target_id": ui_id,
                    "relation": "ROUTES_TO",
                    "scan_id": scan_id,
                    "properties": {},
                })
                edges.append({
                    "source_id": ui_id,
                    "target_id": service_id,
                    "relation": "CALLS",
                    "scan_id": scan_id,
                    "properties": {"protocol": "http", "authz": "none"},
                })

            # Extract major API routes from routes/ if present
            routes_dir = workspace / "routes"
            if routes_dir.is_dir():
                for rf in routes_dir.iterdir():
                    if rf.is_file() and not rf.name.startswith(".") and rf.suffix in (".ts", ".js"):
                        rname = f"route:{rf.stem}"
                        nodes.append({
                            "id": rname,
                            "scan_id": scan_id,
                            "label": "Route",
                            "properties": {
                                "id": rname,
                                "name": f"/{rf.stem}",
                                "path": f"/api/{rf.stem}",
                            },
                        })
                        edges.append({
                            "source_id": service_id,
                            "target_id": rname,
                            "relation": "DEFINES",
                            "scan_id": scan_id,
                            "properties": {},
                        })
                        if any(k in rf.stem.lower() for k in ["payment", "order", "basket", "user", "checkout", "card", "verify"]):
                            edges.append({
                                "source_id": rname,
                                "target_id": db_id,
                                "relation": "READS_FROM",
                                "scan_id": scan_id,
                                "properties": {"authz": "iam"},
                            })

            # Extract packages for single app, ONLY RUNTIME DEPENDENCIES
            _extract_manifest_packages(workspace, service_id)

        # 3. Extract Python AST function & call relationships if any
        for py_file in workspace.rglob("*.py"):
            if any(p in py_file.parts for p in [".venv", "venv", "test", "tests", "node_modules"]):
                continue
            rel_path = str(py_file.relative_to(workspace))
            file_node_id = f"file:{rel_path}"
            nodes.append({
                "id": file_node_id,
                "scan_id": scan_id,
                "label": "File",
                "properties": {"id": file_node_id, "name": py_file.name, "path": rel_path},
            })
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8", errors="ignore"))
                for item in tree.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        func_id = f"{rel_path}:{item.name}"
                        nodes.append({
                            "id": func_id,
                            "scan_id": scan_id,
                            "label": "Function",
                            "properties": {
                                "id": func_id,
                                "name": item.name,
                                "file_path": rel_path,
                                "line": item.lineno,
                            },
                        })
            except Exception:
                continue

        # Everything this method produces is either read from a manifest/AST
        # (Package, File, Function) or synthesised by the estate model
        # (Internet, Ingress, Service, DataStore, Route and the edges between
        # them). Tag both so the API, the UI and the agents can tell them apart
        # and never present a modelled hop as observed infrastructure.
        SYNTHESISED_LABELS = {"Service", "Ingress", "DataStore", "Route", "IAMRole"}
        SYNTHESISED_RELATIONS = {
            "REACHES", "ROUTES_TO", "CALLS", "READS_FROM",
            "WRITES_TO", "DEFINES", "ASSUMES", "CAN_ACCESS",
        }

        for node in nodes:
            props = node.setdefault("properties", {})
            synthesised = node["label"] in SYNTHESISED_LABELS
            props.setdefault(
                "source", "chokepoint_estate_model" if synthesised else "repository_scan"
            )
            props.setdefault(
                "provenance",
                "INFERRED" if synthesised else "EXTRACTED",
            )
        for edge in edges:
            props = edge.setdefault("properties", {})
            inferred = edge["relation"] in SYNTHESISED_RELATIONS
            props.setdefault(
                "source", "chokepoint_estate_model" if inferred else "repository_scan"
            )
            props.setdefault("provenance", "INFERRED" if inferred else "EXTRACTED")
            if inferred:
                props.setdefault(
                    "evidence",
                    "modelled by CHOKEPOINT from repository structure; not observed at runtime",
                )

        return nodes, edges

    @staticmethod
    def map_findings_to_graph(scan_id: str) -> list[dict[str, Any]]:
        """Map scanner findings to graph nodes based on file paths, symbols, packages."""
        findings = FindingRepository.list_for_scan(scan_id)
        nodes = GraphRepository.load_nodes(scan_id)
        node_by_path: dict[str, list[str]] = {}
        node_by_symbol: dict[str, list[str]] = {}
        node_by_package: dict[str, list[str]] = {}
        service_node_id = ""

        for node in nodes:
            nid = node["id"]
            label = node["label"]
            props = node["properties"]
            if label == "Service" and not service_node_id:
                service_node_id = nid

            file_path = props.get("file_path") or props.get("path") or props.get("location", {}).get("file")
            if file_path:
                node_by_path.setdefault(str(file_path), []).append(nid)
            symbol = props.get("name") or props.get("symbol") or props.get("function")
            if symbol:
                node_by_symbol.setdefault(str(symbol), []).append(nid)
            pkg = props.get("package") or props.get("package_name") or props.get("name")
            if pkg and label in ("Package", "Dependency"):
                node_by_package.setdefault(str(pkg), []).append(nid)

        mappings: list[dict[str, Any]] = []
        for finding in findings:
            fid = finding["finding_id"]
            matched_node_id = ""
            match_kind = "unmatched"
            evidence = "unmatched"

            # 1. Match package name
            pkg_name = finding.get("package_name", "")
            if pkg_name and pkg_name in node_by_package:
                matched_node_id = node_by_package[pkg_name][0]
                match_kind = "direct"
                evidence = f"package:{pkg_name}"
            # 2. Match file path
            elif finding.get("file_path") and finding["file_path"] in node_by_path:
                matched_node_id = node_by_path[finding["file_path"]][0]
                match_kind = "direct"
                evidence = f"file_path:{finding['file_path']}"
            # 3. Match symbol
            elif finding.get("symbol") and finding["symbol"] in node_by_symbol:
                matched_node_id = node_by_symbol[finding["symbol"]][0]
                match_kind = "inferred"
                evidence = f"symbol:{finding['symbol']}"
            # 4. Fallback to service node
            elif service_node_id:
                matched_node_id = service_node_id
                match_kind = "inferred"
                evidence = f"repo_level_finding on {service_node_id}"

            mappings.append({
                "finding_id": fid,
                "node_id": matched_node_id,
                "match_kind": match_kind,
                "confidence": 0.9 if match_kind == "direct" else 0.6,
                "evidence": evidence,
            })

            # Update finding in database with mapped service and reachability
            FindingRepository.update_mapping(fid, match_kind, evidence)

        if mappings:
            MappingRepository.bulk_insert(mappings)

        return mappings
