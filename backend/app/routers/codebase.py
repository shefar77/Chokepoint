"""Codebase ingestion, Graphify code-graph generation, and scanner orchestration router."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.config import settings
from app.db import execute, transaction
from app.models import CodebaseScanResponse, ScanDirectoryRequest, ScanManualRequest, ScanUrlRequest
from app.repositories.findings import FindingRepository
from app.repositories.graph import GraphRepository
from app.repositories.mappings import MappingRepository
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.services.graph_builder import SecurityGraphBuilder
from app.services.repository_intake import MANUAL_CODEBASES_DIR, RepositoryIntakeService
from app.services.scanner_orchestrator import ScannerOrchestrator

router = APIRouter(prefix="/codebases", tags=["codebases"])
log = logging.getLogger("chokepoint.router.codebases")

SUGGESTED_TESTBEDS = [
    {
        "name": "OWASP Juice Shop",
        "url": "https://github.com/juice-shop/juice-shop",
        "description": "Premier modern web application security testbed (TypeScript/Node.js/Express). Contains real CVEs across dependencies (JWT, lodash, sqlite), SQL injection, and insecure auth flows.",
        "architecture": "Single-repo multi-tier (Frontend -> REST/WS API -> Models -> SQLite)",
        "stars": "12k+",
    },
    {
        "name": "Google Cloud Online Boutique",
        "url": "https://github.com/GoogleCloudPlatform/microservices-demo",
        "description": "11-tier microservices application (Go, Python, Node.js, Java, C#) designed to showcase cloud security, lateral movement from Frontend to Payment/Email services, and Redis datastores.",
        "architecture": "Distributed Microservices (Frontend -> Checkout -> Payment/Currency -> Redis)",
        "stars": "17k+",
    },
    {
        "name": "OWASP NodeGoat",
        "url": "https://github.com/OWASP/NodeGoat",
        "description": "OWASP Top 10 security testbed in Node.js/MongoDB demonstrating broken access control, session fixation, and vulnerable dependencies.",
        "architecture": "MVC Web Application (Router -> Controller -> Mongo)",
        "stars": "3k+",
    },
    {
        "name": "Vulnerable Flask App",
        "url": "https://github.com/we45/Vulnerable-Flask-App",
        "description": "Lightweight Python/Flask vulnerable application with Python dependencies, PyYAML deserialization, SQL injection, and secret leakage.",
        "architecture": "Python Web Service (Flask routes -> SQLAlchemy -> SQLite)",
        "stars": "500+",
    },
]


def _execute_codebase_pipeline(
    workspace: Path,
    source_type: str,
    source_ref: str,
    project_name: str,
) -> CodebaseScanResponse:
    """End-to-end pipeline: workspace -> Graphify -> Scanners -> Mapping -> NetworkX/SQLite."""
    project_id = f"proj-{uuid.uuid4().hex[:12]}"
    ProjectRepository.create(project_id, project_name, source_ref)

    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    ScanRepository.create(
        scan_id=scan_id,
        project_id=project_id,
        source_type=source_type,
        source_ref=source_ref,
        workspace_path=str(workspace),
        status="running",
    )

    # 1. Graphify code-graph extraction. The report distinguishes what Graphify
    #    produced from what the built-in AST/manifest reader contributed, so the
    #    stage is never shown as completed when Graphify did not run.
    report = SecurityGraphBuilder.run_graphify(workspace, scan_id)
    graphify_status = report["graphify_status"]
    node_count = report["total_nodes"]
    edge_count = report["total_edges"]

    # 2. Run the scanner adapters.
    scan_results = ScannerOrchestrator.run_all(workspace, scan_id)
    findings_count = scan_results["findings_count"]

    # 3. Map findings onto graph entities.
    mappings = SecurityGraphBuilder.map_findings_to_graph(scan_id)
    mapped = sum(1 for m in mappings if m.get("match_kind") != "unmatched")

    # 4. Record the scan with per-stage statuses.
    stages = {
        "intake": "completed",
        "graphify_extraction": graphify_status,
        "trivy": scan_results["statuses"].get("trivy", "skipped"),
        "semgrep": scan_results["statuses"].get("semgrep", "skipped"),
        "local_checks": scan_results["statuses"].get("local_checks", "skipped"),
        "finding_normalisation": "completed" if findings_count else "completed",
        "graph_construction": "completed" if node_count else "failed",
        "finding_mapping": "completed",
        "agent_investigation": "pending",
        "remediation_simulation": "pending",
    }
    ScanRepository.update(
        scan_id,
        status="completed",
        graphify_status=graphify_status,
        trivy_status=stages["trivy"],
        semgrep_status=stages["semgrep"],
        graphify_node_count=report["graphify_nodes"],
        graphify_edge_count=report["graphify_edges"],
        metadata_json=json.dumps({
            "stages": stages,
            "graphify": {
                k: report[k]
                for k in (
                    "graphify_version",
                    "graphify_command",
                    "graphify_artifact",
                    "graphify_schema_version",
                    "graphify_nodes",
                    "graphify_edges",
                    "graphify_error",
                )
            },
            "builtin_nodes": report["builtin_nodes"],
            "builtin_edges": report["builtin_edges"],
            "scanner_coverage": scan_results.get("coverage", {}),
        }),
    )
    # mark_completed stamps completed_at and owns error_message, so the
    # Graphify note is written through it rather than being overwritten by it.
    ScanRepository.mark_completed(
        scan_id, status="completed", error=report.get("graphify_error", "") or ""
    )

    if graphify_status == "completed":
        graph_note = (
            f"{report['graphify_nodes']} Graphify code nodes and "
            f"{report['graphify_edges']} code relationships"
        )
    else:
        graph_note = (
            f"Graphify {graphify_status} ({report.get('graphify_error', '')[:120]}); "
            f"{report['builtin_nodes']} nodes came from the built-in AST/manifest reader only"
        )

    external = scan_results.get("coverage", {}).get("external_scanners_available") or [
        "local checks only"
    ]
    summary = (
        f"Analysed {project_name}: {graph_note}; {findings_count} findings from "
        f"{', '.join(external)}; "
        f"{mapped} of {len(mappings)} findings mapped to a graph entity. "
        "Coverage is limited to the scanners that ran; this is not a claim of complete detection."
    )
    log.info(summary)

    return CodebaseScanResponse(
        ok=True,
        scan_id=scan_id,
        project_id=project_id,
        project_name=project_name,
        source_type=source_type,
        source_ref=source_ref,
        node_count=node_count,
        edge_count=edge_count,
        findings_count=findings_count,
        graphify_status=graphify_status,
        scanner_statuses=scan_results["statuses"],
        summary=summary,
    )


@router.post("/scan-url", response_model=CodebaseScanResponse)
async def scan_git_url(req: ScanUrlRequest) -> CodebaseScanResponse:
    """Clone a public HTTPS Git repository and run Graphify + security analysis."""
    valid, err = RepositoryIntakeService.validate_url(req.url)
    if not valid:
        raise HTTPException(status_code=400, detail=err)

    workspace = RepositoryIntakeService.create_workspace()
    repo_name = req.name or req.url.rstrip("/").split("/")[-1].replace(".git", "")

    # Run clone in thread
    clone_ok, clone_err = await asyncio.to_thread(
        RepositoryIntakeService.clone_repo, req.url, workspace
    )
    if not clone_ok:
        RepositoryIntakeService.cleanup_workspace(workspace)
        raise HTTPException(status_code=400, detail=clone_err)

    actual_root = RepositoryIntakeService.find_repo_root(workspace)
    return await asyncio.to_thread(
        _execute_codebase_pipeline, actual_root, "git_clone", req.url, repo_name
    )


@router.post("/scan-directory", response_model=CodebaseScanResponse)
async def scan_directory(req: ScanDirectoryRequest) -> CodebaseScanResponse:
    """Scan an existing directory on the host or in /data/codebases."""
    # PRD 8.1: a public endpoint must not accept arbitrary filesystem paths.
    # The request is resolved strictly inside the configured codebase root, so
    # it cannot be pointed at /etc or at another scan's workspace.
    root = MANUAL_CODEBASES_DIR.resolve()
    relative = req.path.strip().lstrip("/\\")
    if not relative:
        raise HTTPException(
            status_code=400,
            detail=f"path must name a repository directory inside {root}",
        )
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=(
                f"path must be relative to the codebase directory ({root}); "
                "absolute or traversing paths are not accepted"
            ),
        ) from None
    if not candidate.is_dir():
        raise HTTPException(
            status_code=404,
            detail=f"No directory {req.path!r} under {root}. Place the repository there first.",
        )
    target_path = candidate

    repo_name = req.name or target_path.name
    return await asyncio.to_thread(
        _execute_codebase_pipeline, target_path, "local_directory", str(target_path), repo_name
    )


@router.post("/scan-upload", response_model=CodebaseScanResponse)
async def scan_zip_upload(file: UploadFile = File(...)) -> CodebaseScanResponse:
    """Upload a repository ZIP archive and run Graphify + security analysis."""
    workspace = RepositoryIntakeService.create_workspace()
    # file.filename is client-controlled: "../../x.zip" would escape the
    # workspace. Only the basename is used, and only for the display name.
    safe_name = Path(file.filename or "upload.zip").name or "upload.zip"
    zip_dest = workspace / "upload.zip"

    with zip_dest.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    valid, why = RepositoryIntakeService.validate_zip(zip_dest)
    if not valid:
        RepositoryIntakeService.cleanup_workspace(workspace)
        raise HTTPException(status_code=400, detail=why)

    extract_ok, extract_err = RepositoryIntakeService.extract_zip(zip_dest, workspace)
    if not extract_ok:
        RepositoryIntakeService.cleanup_workspace(workspace)
        raise HTTPException(status_code=400, detail=extract_err)

    try:
        zip_dest.unlink()
    except Exception:
        pass

    repo_name = Path(safe_name).stem or "uploaded-repository"
    actual_root = RepositoryIntakeService.find_repo_root(workspace)
    return await asyncio.to_thread(
        _execute_codebase_pipeline, actual_root, "zip_upload", safe_name, repo_name
    )


@router.get("/manual")
async def list_manual_codebases() -> list[dict[str, Any]]:
    """List all manual repository ZIP files found in data/codebases/."""
    return RepositoryIntakeService.get_manual_codebases()


@router.post("/scan-manual", response_model=CodebaseScanResponse)
async def scan_manual_zip(req: ScanManualRequest) -> CodebaseScanResponse:
    """Scan a ZIP archive manually placed in data/codebases/."""
    codebases = RepositoryIntakeService.get_manual_codebases()
    target_item = next((c for c in codebases if c["filename"] == req.filename or c["codebase_id"] == req.filename), None)
    if not target_item:
        raise HTTPException(
            status_code=404,
            detail=f"Archive '{req.filename}' not found in data/codebases/. Place your .zip there first.",
        )

    zip_path = Path(target_item["path"])
    workspace = RepositoryIntakeService.create_workspace()
    extract_ok, extract_err = RepositoryIntakeService.extract_zip(zip_path, workspace)
    if not extract_ok:
        RepositoryIntakeService.cleanup_workspace(workspace)
        raise HTTPException(status_code=400, detail=extract_err)

    repo_name = req.name or target_item["codebase_id"]
    actual_root = RepositoryIntakeService.find_repo_root(workspace)
    return await asyncio.to_thread(
        _execute_codebase_pipeline, actual_root, "manual_zip", target_item["filename"], repo_name
    )



@router.get("/suggested")
async def suggested_codebases() -> list[dict[str, Any]]:
    """Return recommended real-world vulnerable test repositories."""
    return SUGGESTED_TESTBEDS


@router.get("/scans")
async def list_scans() -> list[dict[str, Any]]:
    """List all real codebase scans in the database."""
    from app.db import query
    rows = query("SELECT s.*, p.name as project_name FROM scans s LEFT JOIN projects p ON s.project_id = p.id ORDER BY s.started_at DESC")
    return rows


@router.post("/clear")
async def clear_database() -> dict[str, Any]:
    """Wipe all seed data, scans, findings, graph nodes, and investigations."""
    with transaction() as conn:
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM finding_mappings")
        conn.execute("DELETE FROM graph_edges")
        conn.execute("DELETE FROM graph_nodes")
        conn.execute("DELETE FROM investigations")
        conn.execute("DELETE FROM blackboard")
        conn.execute("DELETE FROM verdicts")
        conn.execute("DELETE FROM actions")
        conn.execute("DELETE FROM feedback")
        conn.execute("DELETE FROM scans")
        conn.execute("DELETE FROM projects")
    log.info("Cleared all scans, findings, and graph entities")
    return {"ok": True, "message": "Database cleared; ready for fresh real codebase scan"}

