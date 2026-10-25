"""Repository intake: upload, clone, workspace management."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from app.config import settings
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository

log = logging.getLogger("chokepoint.service.intake")

def _find_codebases_dir() -> Path:
    """The directory manual scans are confined to (CODEBASES_DIR, then fallbacks)."""
    candidates = [Path(settings.codebases_dir), Path("./data/codebases"), Path("data/codebases")]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate.resolve()
        except OSError:
            continue
    return Path("./data/codebases").resolve()

MANUAL_CODEBASES_DIR = _find_codebases_dir()


class RepositoryIntakeService:
    """Handles repository ZIP uploads and Git URL clones into isolated workspaces."""

    # Exact host allow-list. A substring test let "github.com.evil.example" and
    # "gitea.attacker.example" through, which is an SSRF vector (PRD 13.3).
    ALLOWED_GIT_HOSTS = frozenset(
        {"github.com", "www.github.com", "gitlab.com", "www.gitlab.com", "bitbucket.org", "www.bitbucket.org"}
    )

    @staticmethod
    def validate_url(url: str) -> tuple[bool, str]:
        """Validate that a URL is a supported, credential-free HTTPS Git remote."""
        try:
            parsed = urlparse(url.strip())
        except Exception:  # noqa: BLE001
            return False, "Invalid URL"
        if parsed.scheme != "https":
            return False, "Only HTTPS URLs are supported"
        if not parsed.netloc:
            return False, "Invalid URL"
        if parsed.username or parsed.password or "@" in parsed.netloc:
            return False, "URLs with embedded credentials are not accepted"
        host = (parsed.hostname or "").lower()
        if parsed.port not in (None, 443):
            return False, f"Unsupported port {parsed.port}; only 443 is accepted"
        if host not in RepositoryIntakeService.ALLOWED_GIT_HOSTS:
            return False, (
                f"Unsupported host {host!r}. Allowed hosts: "
                + ", ".join(sorted(RepositoryIntakeService.ALLOWED_GIT_HOSTS))
            )
        if not parsed.path.strip("/"):
            return False, "URL does not name a repository"
        return True, ""

    @staticmethod
    def validate_zip(path: Path) -> tuple[bool, str]:
        """Basic ZIP validation - check size and magic bytes."""
        if not path.exists():
            return False, "File does not exist"
        if path.stat().st_size > settings.max_repo_size_mb * 1024 * 1024:
            return False, f"Archive exceeds {settings.max_repo_size_mb}MB limit"
        # Check ZIP magic bytes
        with path.open("rb") as f:
            magic = f.read(4)
        if magic[:2] != b"PK":
            return False, "Not a valid ZIP archive (expected a PK header)"
        return True, ""

    @staticmethod
    def create_workspace() -> Path:
        """Create a unique, isolated workspace directory."""
        ws = Path(settings.graphify_workspace) / f"ws-{uuid.uuid4().hex[:12]}"
        ws.mkdir(parents=True, exist_ok=True)
        return ws

    MAX_ARCHIVE_MEMBERS = 20000
    MAX_COMPRESSION_RATIO = 200

    @staticmethod
    def extract_zip(zip_path: Path, dest: Path) -> tuple[bool, str]:
        """Extract a ZIP archive safely.

        Guards against path traversal (checked by containment, not by string
        prefix, which let a sibling directory such as /ws/abc pass for /ws/a),
        absolute member paths, symlink members, excessive member counts and
        zip bombs (uncompressed size and compression ratio).
        """
        import zipfile

        dest_resolved = dest.resolve()
        size_limit = settings.max_repo_size_mb * 1024 * 1024
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                members = zf.infolist()
                if len(members) > RepositoryIntakeService.MAX_ARCHIVE_MEMBERS:
                    return False, (
                        f"Archive holds {len(members)} entries, over the "
                        f"{RepositoryIntakeService.MAX_ARCHIVE_MEMBERS} limit"
                    )

                total_uncompressed = 0
                for member in members:
                    name = member.filename
                    if name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
                        return False, f"Absolute paths not allowed in archive: {name}"
                    member_path = (dest / name).resolve()
                    if member_path != dest_resolved and dest_resolved not in member_path.parents:
                        return False, f"Path traversal attempt in archive: {name}"
                    # Unix mode is in the top 16 bits; 0xA000 marks a symlink.
                    if (member.external_attr >> 16) & 0o170000 == 0o120000:
                        return False, f"Symlink members are not extracted: {name}"
                    total_uncompressed += member.file_size
                    if total_uncompressed > size_limit:
                        return False, (
                            f"Archive expands to more than {settings.max_repo_size_mb}MB"
                        )
                    if member.compress_size > 0:
                        ratio = member.file_size / member.compress_size
                        if ratio > RepositoryIntakeService.MAX_COMPRESSION_RATIO:
                            return False, (
                                f"Archive member {name} has a compression ratio of "
                                f"{ratio:.0f}:1, which looks like a zip bomb"
                            )

                zf.extractall(dest)
            return True, ""
        except zipfile.BadZipFile as e:
            return False, f"Bad ZIP file: {e}"
        except Exception as e:  # noqa: BLE001
            return False, f"Extraction failed: {e}"

    @staticmethod
    def clone_repo(url: str, dest: Path, timeout_s: int = 120) -> tuple[bool, str]:
        """Clone a Git repository with size/time limits. No submodules, no LFS."""
        import subprocess

        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--no-recurse-submodules", url, str(dest)],
                capture_output=True,
                text=True,
                timeout=timeout_s,
                cwd=dest.parent,
            )
            if result.returncode != 0:
                return False, f"Git clone failed: {result.stderr.strip()}"
            # Check size
            total_size = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())
            if total_size > settings.max_repo_size_mb * 1024 * 1024:
                shutil.rmtree(dest, ignore_errors=True)
                return False, f"Cloned repo exceeds {settings.max_repo_size_mb}MB limit"
            return True, ""
        except subprocess.TimeoutExpired:
            shutil.rmtree(dest, ignore_errors=True)
            return False, f"Clone timed out after {timeout_s}s"
        except Exception as e:  # noqa: BLE001
            shutil.rmtree(dest, ignore_errors=True)
            return False, f"Clone error: {e}"

    @staticmethod
    def cleanup_workspace(ws: Path) -> None:
        """Remove a workspace directory."""
        if ws and ws.exists():
            try:
                shutil.rmtree(ws)
            except Exception as e:  # noqa: BLE001
                log.warning("failed to cleanup workspace %s: %s", ws, e)

    @staticmethod
    def create_project_from_repo(name: str, source_url: str = "") -> dict[str, Any]:
        """Create a project record and return its ID."""
        project_id = f"proj-{uuid.uuid4().hex[:12]}"
        ProjectRepository.create(project_id, name, source_url)
        return {"project_id": project_id, "name": name, "source_url": source_url}

    @staticmethod
    def create_scan(project_id: str, source_type: str, source_ref: str, workspace: Path) -> dict[str, Any]:
        """Create a scan record for a project."""
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        ScanRepository.create(
            scan_id,
            project_id,
            source_type=source_type,
            source_ref=source_ref,
            workspace_path=str(workspace),
            status="running",
        )
        return {"scan_id": scan_id, "project_id": project_id}

    @staticmethod
    def find_repo_root(workspace: Path) -> Path:
        """Find the repository root (handle nested directories from ZIPs)."""
        # Look for common repo markers
        markers = [".git", "pyproject.toml", "package.json", "go.mod", "Cargo.toml", "pom.xml", "requirements.txt"]
        for marker in markers:
            found = list(workspace.rglob(marker))
            if found:
                return found[0].parent
        return workspace

    @staticmethod
    def get_manual_codebases() -> list[dict[str, Any]]:
        """Find all ZIP files in the manual codebase directory.

        Returns list of dicts with:
        - filename: ZIP filename
        - path: full path to ZIP
        - codebase_id: derived ID
        - modified: last modified time
        """
        codebase_dir = MANUAL_CODEBASES_DIR
        codebases = []

        if not codebase_dir.exists():
            codebase_dir.mkdir(parents=True, exist_ok=True)
            return codebases

        for zip_path in codebase_dir.glob("*.zip"):
            stat = zip_path.stat()
            # Derive codebase ID from filename (remove .zip extension)
            codebase_id = zip_path.stem.replace("-codebase", "").replace("_codebase", "")
            codebases.append({
                "filename": zip_path.name,
                "path": str(zip_path),
                "codebase_id": codebase_id,
                "modified": stat.st_mtime,
                "size": stat.st_size,
            })

        # Sort by modification time, newest first
        codebases.sort(key=lambda x: x["modified"], reverse=True)
        return codebases

    @staticmethod
    def get_latest_manual_codebase() -> Optional[dict[str, Any]]:
        """Get the most recent manual codebase, or None if none exist."""
        codebases = RepositoryIntakeService.get_manual_codebases()
        return codebases[0] if codebases else None

    @staticmethod
    def get_all_manual_codebases() -> list[dict[str, Any]]:
        """Get all manual codebases."""
        return RepositoryIntakeService.get_manual_codebases()