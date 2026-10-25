"""Test fixtures. Every test runs against a throwaway SQLite file and local fixtures.

No test requires network access, Graphify, Trivy, Semgrep or a model provider
(PRD 15: "Tests must not require network access by default").
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

# These must be set before any test module imports app.config, which builds a
# cached Settings at import time. A fixture runs too late: test modules are
# imported during collection, so the settings would still point at the real
# /data/chokepoint.db and tests would share state with a live install.
_TMP_ROOT = Path(tempfile.mkdtemp(prefix="chokepoint-tests-"))
(_TMP_ROOT / "ws").mkdir(parents=True, exist_ok=True)
(_TMP_ROOT / "outbox").mkdir(parents=True, exist_ok=True)
(_TMP_ROOT / "codebases").mkdir(parents=True, exist_ok=True)
os.environ["SQLITE_PATH"] = str(_TMP_ROOT / "test.db")
os.environ["GRAPHIFY_WORKSPACE"] = str(_TMP_ROOT / "ws")
os.environ["OUTBOX_DIR"] = str(_TMP_ROOT / "outbox")
os.environ["CODEBASES_DIR"] = str(_TMP_ROOT / "codebases")
# Point the MCP client at a port nothing listens on: these tests exercise the
# in-process tool functions, and a real server would make them non-hermetic.
os.environ["MCP_URL"] = ""
os.environ["EMBEDDINGS"] = "none"
os.environ["AGENT_MODE"] = "scripted"
os.environ["GEMINI_API_KEY"] = ""

import pytest  # noqa: E402 - must follow the environment setup above


@pytest.fixture(scope="session", autouse=True)
def _isolated_env() -> None:
    """Settings already point at the temporary workspace; clean it up at the end."""
    yield
    shutil.rmtree(_TMP_ROOT, ignore_errors=True)


@pytest.fixture()
def db(_isolated_env: None):
    """A clean database for one test."""
    from app import db as dbmod

    dbmod.close_all()
    dbmod._initialized = False
    path = Path(os.environ["SQLITE_PATH"])
    if path.exists():
        path.unlink()
    for suffix in ("-wal", "-shm"):
        side = Path(str(path) + suffix)
        if side.exists():
            side.unlink()
    dbmod._get_conn()
    yield dbmod
    dbmod.close_all()


@pytest.fixture()
def vulnerable_repo(tmp_path: Path) -> Path:
    """A small fixture repository: outdated deps, a secret and interpolated SQL."""
    repo = tmp_path / "vulnshop"
    (repo / "routes").mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "vulnshop",
                "dependencies": {"lodash": "4.17.11", "express": "4.16.0"},
                "devDependencies": {"mocha": "8.0.0"},
            }
        ),
        encoding="utf-8",
    )
    (repo / "requirements.txt").write_text("pyyaml==5.1\nflask==1.1.2\n", encoding="utf-8")
    (repo / "app.py").write_text(
        'import sqlite3\n'
        'API_KEY = "sk_live_AbCdEf0123456789XyZqWeRtY"\n'
        '\n'
        'def get_user(uid):\n'
        '    cur = sqlite3.connect("shop.db").cursor()\n'
        '    cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
        '    return cur.fetchone()\n',
        encoding="utf-8",
    )
    (repo / "routes" / "payment.js").write_text("module.exports = {};\n", encoding="utf-8")
    return repo


@pytest.fixture()
def patched_repo(tmp_path: Path) -> Path:
    """The same shape, but every dependency already at or above its fixed version."""
    repo = tmp_path / "patched"
    repo.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "patched", "dependencies": {"lodash": "4.17.21", "express": "4.21.2"}}),
        encoding="utf-8",
    )
    (repo / "requirements.txt").write_text("pyyaml==6.0.1\nflask==3.0.0\n", encoding="utf-8")
    return repo


@pytest.fixture()
def graphify_artifact(tmp_path: Path) -> Path:
    """A graph.json in the real Graphify 0.9.x node-link schema."""
    repo = tmp_path / "graphed"
    out = repo / "graphify-out"
    out.mkdir(parents=True)
    (repo / "auth.py").write_text("def login():\n    return check()\n\ndef check():\n    return True\n", encoding="utf-8")
    (out / "graph.json").write_text(
        json.dumps(
            {
                "directed": True,
                "multigraph": False,
                "graph": {"schema_version": 1, "graphify_version": "0.9.95"},
                "nodes": [
                    {
                        "id": "auth_login",
                        "label": "login()",
                        "_callable": True,
                        "_origin": "ast",
                        "file_type": "code",
                        "source_file": "auth.py",
                        "source_location": "L1",
                    },
                    {
                        "id": "auth_check",
                        "label": "check()",
                        "_callable": True,
                        "_origin": "ast",
                        "file_type": "code",
                        "source_file": "auth.py",
                        "source_location": "L4",
                    },
                    {
                        "id": "auth",
                        "label": "auth.py",
                        "_origin": "ast",
                        "file_type": "code",
                        "source_file": "auth.py",
                        "source_location": "L1",
                    },
                ],
                "links": [
                    {
                        "source": "auth_login",
                        "target": "auth_check",
                        "relation": "calls",
                        "_origin": "ast",
                        "confidence": "EXTRACTED",
                        "source_file": "auth.py",
                        "source_location": "L2",
                    },
                    {
                        "source": "auth",
                        "target": "auth_login",
                        "relation": "contains",
                        "_origin": "ast",
                        "confidence": "EXTRACTED",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return repo


@pytest.fixture()
def seeded_scan(db, vulnerable_repo: Path):
    """A persisted project + scan with graph nodes, findings and mappings."""
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository
    from app.services.graph_builder import SecurityGraphBuilder
    from app.services.scanner_orchestrator import ScannerOrchestrator

    project_id = f"proj-{uuid.uuid4().hex[:8]}"
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    ProjectRepository.create(project_id, "vulnshop", str(vulnerable_repo))
    ScanRepository.create(
        scan_id,
        project_id,
        source_type="local_directory",
        source_ref=str(vulnerable_repo),
        workspace_path=str(vulnerable_repo),
        status="running",
    )
    nodes, edges = SecurityGraphBuilder.extract_codebase_ast(vulnerable_repo, scan_id)
    from app.repositories.graph import GraphRepository

    GraphRepository.bulk_insert_nodes(nodes)
    GraphRepository.bulk_insert_edges(edges)
    findings, status = ScannerOrchestrator.run_manifest_scanner(vulnerable_repo, scan_id)
    from app.repositories.findings import FindingRepository

    FindingRepository.bulk_insert(findings)
    SecurityGraphBuilder.map_findings_to_graph(scan_id)
    ScanRepository.mark_completed(scan_id)
    return {"project_id": project_id, "scan_id": scan_id, "findings": findings, "status": status}
