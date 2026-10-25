"""SQLite persistence layer for CHOKEPOINT.

SQLite is the source of truth for persistent application records:
projects, scans, normalized findings, graph node/edge records for
reconstruction, investigation state, hypotheses, verdicts, feedback,
lessons, and remediation simulations.

NetworkX holds the operational in-memory security graph reconstructed
from these persisted graph records and findings. We never pickle a
NetworkX graph into SQLite as the only durable representation.

All mutations go through :func:`execute` / :func:`query` so transactions
and parameter binding are uniform.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterator

from .config import settings

log = logging.getLogger("chokepoint.db")

_lock = threading.RLock()
_pool: dict[int, sqlite3.Connection] = {}
_initialized = False
CURRENT_SCHEMA_VERSION = 5


def _thread_id() -> int:
    return threading.get_ident()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(
        settings.sqlite_path,
        check_same_thread=False,
        isolation_level=None,  # autocommit; tx() manages transactions
        timeout=30.0,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _get_conn() -> sqlite3.Connection:
    global _initialized
    tid = _thread_id()
    with _lock:
        if tid not in _pool:
            _pool[tid] = _connect()
        conn = _pool[tid]
        if not _initialized:
            _init_schema(conn)
            _initialized = True
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA_SQL)
    # Run pending migrations
    version = _schema_version(conn)
    if version < CURRENT_SCHEMA_VERSION:
        _migrate(conn, version)
    log.info("SQLite schema at version %s", _schema_version(conn))


def _schema_version(conn: sqlite3.Connection) -> int:
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
        if row:
            return int(row["value"])
    except sqlite3.OperationalError:
        pass
    return 0


def _migrate(conn: sqlite3.Connection, from_version: int) -> None:
    log.info("migrating SQLite schema from %s to %s", from_version, CURRENT_SCHEMA_VERSION)
    if from_version < 2:
        conn.executescript(_MIGRATION_1_TO_2)
    if from_version < 3:
        conn.executescript(_MIGRATION_2_TO_3)
    if from_version < 4:
        _migrate_3_to_4(conn)
    if from_version < 5:
        _migrate_4_to_5(conn)
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
        (str(CURRENT_SCHEMA_VERSION),),
    )


def close_all() -> None:
    with _lock:
        for conn in _pool.values():
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
        _pool.clear()


@contextmanager
def tx() -> Iterator[sqlite3.Connection]:
    """Transaction context: commit on exit, rollback on exception."""
    conn = _get_conn()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def execute(sql: str, params: tuple | dict | None = None) -> sqlite3.Cursor:
    conn = _get_conn()
    return conn.execute(sql, params or ())


def query(sql: str, params: tuple | dict | None = None) -> list[dict[str, Any]]:
    conn = _get_conn()
    rows = conn.execute(sql, params or ()).fetchall()
    return [dict(r) for r in rows]


def query_one(sql: str, params: tuple | dict | None = None, many: bool = False) -> Any:
    conn = _get_conn()
    if many:
        rows = conn.execute(sql, params or ()).fetchall()
        return [dict(r) for r in rows]
    row = conn.execute(sql, params or ()).fetchone()
    return dict(row) if row is not None else None


def query_scalar(sql: str, params: tuple | dict | None = None) -> Any:
    row = query_one(sql, params)
    if row is None:
        return None
    return list(row.values())[0] if isinstance(row, dict) else row[0]


def ping() -> bool:
    """True when the SQLite database is reachable."""
    try:
        query_scalar("SELECT 1")
        return True
    except Exception:  # noqa: BLE001
        return False


def node_count() -> int:
    """Count of graph nodes in the active graph."""
    try:
        return query_scalar("SELECT COUNT(*) FROM graph_nodes") or 0
    except Exception:  # noqa: BLE001
        return 0


def ro_query(statement: str, params: tuple | dict | None = None, **kwargs: Any) -> list[dict[str, Any]]:
    """Read-only query helper for backwards compatibility."""
    return query(statement, params)


def try_query(statement: str, params: tuple | dict | None = None, **kwargs: Any) -> str:
    """Execute a statement safely, returning status string."""
    try:
        execute(statement, params)
        return "ok"
    except Exception as exc:
        return f"skip: {exc}"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '1');

-- Projects: repositories under analysis
CREATE TABLE IF NOT EXISTS projects (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    repo_url      TEXT,
    kind          TEXT NOT NULL DEFAULT 'repository',
    source_url    TEXT,
    status        TEXT NOT NULL DEFAULT 'active',
    visibility    TEXT NOT NULL DEFAULT 'private',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- Scans: one per repository analysis run
CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL DEFAULT 'repository',
    status        TEXT NOT NULL DEFAULT 'running',
    started_at    TEXT,
    completed_at  TEXT,
    finished_at   TEXT,
    source_type   TEXT NOT NULL DEFAULT 'zip_upload',
    source_ref    TEXT,
    workspace_path TEXT,
    graphify_status TEXT NOT NULL DEFAULT 'pending',
    trivy_status  TEXT NOT NULL DEFAULT 'pending',
    semgrep_status TEXT NOT NULL DEFAULT 'pending',
    error_message TEXT,
    error         TEXT,
    graphify_node_count INTEGER,
    graphify_edge_count INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL DEFAULT ''
);

-- Normalized scanner findings
CREATE TABLE IF NOT EXISTS findings (
    finding_id    TEXT PRIMARY KEY,
    scan_id       TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner       TEXT NOT NULL DEFAULT '',
    rule_id       TEXT,
    cve           TEXT,
    severity      TEXT,
    cvss          REAL,
    epss          REAL,
    kev           INTEGER DEFAULT 0,
    cwe           TEXT,
    category      TEXT,
    attack_vector TEXT,
    requires_auth INTEGER DEFAULT 0,
    ecosystem     TEXT,
    package_name  TEXT,
    installed_version TEXT,
    package_version TEXT,
    fixed_version TEXT,
    fixed_in      TEXT,
    file_path     TEXT,
    source_file   TEXT,
    line_start    INTEGER,
    source_line   INTEGER,
    line_end      INTEGER,
    symbol        TEXT,
    source_symbol TEXT,
    summary       TEXT,
    description   TEXT,
    recommendation TEXT,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    references_json TEXT NOT NULL DEFAULT '[]',
    mapping_status TEXT NOT NULL DEFAULT 'unmatched',
    provenance    TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'open',
    reachable_code BOOLEAN DEFAULT 0,
    reachability  TEXT NOT NULL DEFAULT 'not_established',
    raw           TEXT,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve);

-- Graph nodes persisted for reconstruction
CREATE TABLE IF NOT EXISTS graph_nodes (
    id              TEXT NOT NULL,
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    label           TEXT NOT NULL,
    kind            TEXT,
    name            TEXT,
    properties_json TEXT NOT NULL DEFAULT '{}',
    props           TEXT,
    created_at      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, id)
);

CREATE INDEX IF NOT EXISTS idx_nodes_scan ON graph_nodes(scan_id);
CREATE INDEX IF NOT EXISTS idx_nodes_label ON graph_nodes(label);

-- Graph edges persisted for reconstruction
CREATE TABLE IF NOT EXISTS graph_edges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id       TEXT NOT NULL,
    target_id       TEXT NOT NULL,
    relation        TEXT NOT NULL,
    rel_type        TEXT,
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    properties_json TEXT NOT NULL DEFAULT '{}',
    props           TEXT,
    created_at      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_edges_scan ON graph_edges(scan_id);
CREATE INDEX IF NOT EXISTS idx_edges_src ON graph_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON graph_edges(target_id);

-- Mapping: findings -> graph nodes/packages (evidence-backed)
CREATE TABLE IF NOT EXISTS finding_mappings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       TEXT,
    finding_id    TEXT NOT NULL,
    node_id       TEXT,
    package_id    TEXT,
    match_kind    TEXT NOT NULL DEFAULT 'direct',
    confidence    REAL DEFAULT 1.0,
    evidence      TEXT,
    created_at    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_mappings_finding ON finding_mappings(finding_id);
CREATE INDEX IF NOT EXISTS idx_mappings_node ON finding_mappings(node_id);

-- Investigations
CREATE TABLE IF NOT EXISTS investigations (
    id               TEXT PRIMARY KEY,
    project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scan_id          TEXT NOT NULL,
    goal             TEXT NOT NULL,
    mode             TEXT NOT NULL,
    preset           TEXT,
    status           TEXT NOT NULL DEFAULT 'running',
    model            TEXT,
    started_at       TEXT NOT NULL,
    ended_at         TEXT,
    duration_ms      REAL,
    snapshot_json    TEXT,
    chokepoints_json TEXT,
    simulation_json  TEXT,
    memory_json      TEXT,
    error            TEXT,
    created_at       TEXT NOT NULL
);

-- Agent steps within investigations
CREATE TABLE IF NOT EXISTS steps (
    id            TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    n             INTEGER NOT NULL,
    agent         TEXT NOT NULL,
    tool          TEXT NOT NULL,
    args          TEXT NOT NULL,
    result        TEXT,
    rows          INTEGER,
    latency_ms    REAL,
    summary       TEXT,
    touched_ids   TEXT,
    engine        TEXT,
    ok            INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_steps_inv ON steps(investigation_id);

-- Blackboard: hypotheses, challenges
CREATE TABLE IF NOT EXISTS blackboard (
    id            TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    agent         TEXT NOT NULL,
    claim         TEXT NOT NULL,
    status        TEXT,
    confidence    REAL,
    about_ids     TEXT,
    based_on_step_ids TEXT,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blackboard_inv ON blackboard(investigation_id);

-- Verdicts
CREATE TABLE IF NOT EXISTS verdicts (
    id            TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    finding_ids   TEXT NOT NULL,
    services      TEXT NOT NULL,
    kind          TEXT NOT NULL,
    requested_kind TEXT,
    confidence    REAL,
    grounded      INTEGER,
    safety_valve  INTEGER,
    safety_valve_reason TEXT,
    headline      TEXT,
    claims        TEXT,
    grounding_json TEXT NOT NULL DEFAULT '{}',
    evidence_path_ids TEXT,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verdicts_inv ON verdicts(investigation_id);

-- Actions
CREATE TABLE IF NOT EXISTS actions (
    id            TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    verdict_id    TEXT REFERENCES verdicts(id) ON DELETE SET NULL,
    kind          TEXT NOT NULL,
    status        TEXT NOT NULL,
    title         TEXT,
    body_md       TEXT,
    team          TEXT,
    slack_channel TEXT,
    on_call       TEXT,
    finding_ids   TEXT,
    outbox_path   TEXT,
    delivery      TEXT,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_actions_inv ON actions(investigation_id);

-- Feedback and lessons
CREATE TABLE IF NOT EXISTS feedback (
    id            TEXT PRIMARY KEY,
    verdict_id    TEXT NOT NULL REFERENCES verdicts(id) ON DELETE CASCADE,
    action        TEXT NOT NULL,
    new_kind      TEXT,
    note          TEXT,
    by_user       TEXT,
    lesson_id     TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lessons (
    id            TEXT PRIMARY KEY,
    text          TEXT NOT NULL,
    scope_kind    TEXT NOT NULL,
    scope_value   TEXT NOT NULL,
    effect        TEXT,
    strength      REAL,
    embedding     BLOB,
    uses          INTEGER DEFAULT 0,
    source_feedback_id TEXT REFERENCES feedback(id),
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_lessons_scope ON lessons(scope_kind, scope_value);

-- Lesson applicability
CREATE TABLE IF NOT EXISTS lesson_applies_to (
    lesson_id     TEXT NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
    node_id       TEXT NOT NULL,
    PRIMARY KEY (lesson_id, node_id)
);

-- Remediation simulations
CREATE TABLE IF NOT EXISTS simulations (
    id            TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    verdict_id    TEXT REFERENCES verdicts(id),
    baseline_weight REAL,
    baseline_paths INTEGER,
    after_weight  REAL,
    after_paths   INTEGER,
    fixes_json    TEXT NOT NULL,
    result_json   TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sims_inv ON simulations(investigation_id);

-- Agent messages (prose between tool calls)
CREATE TABLE IF NOT EXISTS agent_messages (
    id            TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    agent         TEXT NOT NULL,
    text          TEXT NOT NULL,
    seq           INTEGER NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_inv ON agent_messages(investigation_id);

-- Lessons used in an investigation
CREATE TABLE IF NOT EXISTS lessons_used (
    id            TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    lesson_id     TEXT NOT NULL REFERENCES lessons(id),
    similarity    REAL,
    via           TEXT,
    created_at    TEXT NOT NULL
);

-- Events
CREATE TABLE IF NOT EXISTS events (
    id            TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    n             INTEGER NOT NULL,
    type          TEXT NOT NULL,
    ts            TEXT NOT NULL,
    payload_json  TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
""";

_MIGRATION_1_TO_2 = """
-- Add scan comparison support, investigation preset indexing
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve);
INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '2');
"""

def _migrate_4_to_5(conn: sqlite3.Connection) -> None:
    """Add findings.reachability: supported | not_established | contradicted | unknown."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)").fetchall()}
    if "reachability" not in cols:
        conn.execute(
            "ALTER TABLE findings ADD COLUMN reachability TEXT NOT NULL DEFAULT 'not_established'"
        )
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', '5')")


def _migrate_3_to_4(conn: sqlite3.Connection) -> None:
    """Add verdicts.grounding_json so per-claim grounding survives a reload."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(verdicts)").fetchall()}
    if "grounding_json" not in cols:
        conn.execute("ALTER TABLE verdicts ADD COLUMN grounding_json TEXT NOT NULL DEFAULT '{}'")
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', '4')")


_MIGRATION_2_TO_3 = """
-- Add columns for graphify provenance and mapping confidence
CREATE INDEX IF NOT EXISTS idx_findings_scan_scanner ON findings(scan_id, scanner);
CREATE INDEX IF NOT EXISTS idx_mappings_match ON finding_mappings(match_kind, confidence);
INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '3');
"""
transaction = tx  # alias for backwards compatibility
