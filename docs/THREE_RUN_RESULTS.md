# Three-run demo results

PRD §15.3 item 10 and §19 require evidence from at least three repeat runs, with actual
outcomes rather than claimed ones. This records what was measured.

## Environment

| | |
|---|---|
| Date | 2026-10-24 |
| Platform | Windows 11, Python 3.10.11 (project targets ≥3.11; no 3.11-only syntax is used) |
| Graphify | `graphifyy` 0.9.95, `graphify.exe` on PATH — **available** |
| Trivy | not installed — reported `skipped` |
| Semgrep | not installed — reported `skipped` |
| Model provider | Ollama reachable with `qwen2.5:7b`; runs below used `AGENT_MODE=scripted` |
| Agent mode | `scripted` → investigation mode recorded as `deterministic` |
| Database | SQLite, fresh file per series |
| Target repository | local fixture `vulnshop` (outdated `lodash`, `express`, `jsonwebtoken`, `sqlite3`, `axios`, `pyyaml`, `flask`, `requests`, `urllib3`; one hardcoded secret; one interpolated SQL query) |

The LLM path was exercised separately and is reported under *Limitations* below: it works but is
impractically slow on this CPU-only machine.

## Results

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Scan wall clock | 1.68 s | 1.62 s | 1.67 s |
| Investigation wall clock | 1.08 s | 1.05 s | 1.06 s |
| Graphify stage | `completed` | `completed` | `completed` |
| Graphify nodes / edges | 29 / 36 | 29 / 36 | 29 / 36 |
| Total graph nodes / edges | 49 / 53 | 49 / 53 | 49 / 53 |
| Trivy / Semgrep | `skipped` / `skipped` | `skipped` / `skipped` | `skipped` / `skipped` |
| Local checks | `completed` | `completed` | `completed` |
| Findings | 11 | 11 | 11 |
| Findings mapped to a graph entity | 11 / 11 | 11 / 11 | 11 / 11 |
| Modelled routes to a flagged store | 1 | 1 | 1 |
| Top path score | 0.0754 | 0.0754 | 0.0754 |
| Path `reachability_verified` | `false` | `false` | `false` |
| Verdicts | 11 (6 FIX_NOW, 5 SCHEDULE) | 11 (6 / 5) | 11 (6 / 5) |
| Verdicts passing the grounding check | 11 / 11 | 11 / 11 | 11 / 11 |
| Hypotheses / challenges | 1 / 1 | 1 / 1 | 1 / 1 |
| Chokepoint fixes | 1 | 1 | 1 |
| Proposed actions | 1 | 1 | 1 |
| Persisted agent messages | 6 | 6 | 6 |
| Simulation | 1 → 0 routes, 100.0 % modelled risk removed | same | same |

**Deterministic across all three runs: yes.** Node and edge counts, finding count, verdict
dispositions, path score, chokepoint selection, simulation delta and the Case Board headline were
byte-identical.

## Mode honesty check

With `AGENT_MODE=scripted`, `/api/health` reported `agent_mode: scripted`, `model: deterministic`
and the reason `AGENT_MODE=scripted; no model reasoning is used.` Each investigation recorded
`mode: deterministic`. No run was labelled `live`.

With Ollama reachable, `/api/health` reported `agent_mode: live`, `model: qwen2.5:7b`, and the
investigation recorded `mode: live`.

## Negative control: an already-patched repository

A second fixture declares `lodash 4.17.21`, `express 4.21.2`, `pyyaml 6.0.1`, `flask 3.0.0` —
every dependency at or above its advisory's fixed version — plus one interpolated SQL query.

| | Result |
|---|---|
| Dependency findings | **0** (the version comparison rules them out) |
| Pattern findings | 1 (the interpolated SQL query) |

Before the fixes in this change set the same repository produced 5 findings, 4 of them false
positives, because the scanner matched package names without comparing versions.

## Security checks executed

| Input | Outcome |
|---|---|
| `http://github.com/o/r` | 400 — only HTTPS |
| `https://github.com.evil.example/o/r` | 400 — host not in the allow-list |
| `https://gitea.attacker.example/o/r` | 400 — host not in the allow-list |
| `https://user:pw@github.com/o/r` | 400 — embedded credentials rejected |
| `https://github.com:8443/o/r` | 400 — only port 443 |
| `scan-directory` with `/etc`, `/`, `../../../Windows`, `""` | 404 / 400 — confined to `CODEBASES_DIR` |
| ZIP containing `../../pwned.txt` | 400 — path traversal rejected; no file escaped |
| ZIP containing `/etc/pwned` | 400 — absolute member rejected |
| ZIP containing a symlink member | 400 — symlink members are not extracted |
| ZIP with a 1029:1 compression ratio | 400 — rejected as a zip bomb |
| Secret in source | stored as `API_KEY = "[REDACTED]"`; the value appears nowhere in the database |
| `DELETE`/`DROP`/`PRAGMA`/multi-statement in the Explorer | 400 — SELECT-only |
| `record_verdict` as `scout`, `post_hypothesis` as `skeptic`, `record_lesson` as `scribe` | refused by the MCP server's own role check |

## MCP tools

All 21 tools were invoked against the live server. 20 succeeded. `propose_action` correctly
refuses when its `verdict_id` names no verdict, which is the only path on which it returns an
error.

## Tests

`cd backend && python -m pytest tests -q` → **117 passed** in ~9 s, with no network access, no
scanners, no Graphify and no model provider.

Frontend: `npm run typecheck` passes with no errors; `npm run build` succeeds.

## Limitations of this evidence

- **Trivy and Semgrep were never executed.** Their adapters are covered by unit tests over
  captured JSON shapes, including the per-vendor CVSS map, but no real scanner ran on this
  machine. Those stages are honestly reported as `skipped`.
- **The LLM agent loop was exercised but did not complete.** With `qwen2.5:7b` on CPU a single
  trivial completion took 86 s, so each agent exceeded the 180 s turn budget. The loop did make
  real MCP tool calls and produced real reasoning over their results (observed in the ledger), and
  tool failures were correctly reported back to the model, but no run finished inside 15 minutes.
  The degraded-fallback path is therefore verified by test
  (`tests/test_runner_modes.py::test_degraded_fallback_runs_when_the_model_produces_nothing`)
  rather than by a timed end-to-end LLM run.
- **The frontend was not driven in a browser.** It typechecks, builds, serves and every endpoint
  it calls was validated against the live API for the fields its types declare, but no rendered
  page was visually inspected and no click-through was performed.
- **The target repository is a local fixture, not OWASP NodeGoat.** Cloning NodeGoat requires
  network access that was not used here. The `scan-url` path is covered by validation tests only;
  no real clone was performed.
- **The evaluation (`/api/evals/run`) was not meaningfully exercised.** Its ground truth belongs
  to the synthetic seed estate, so it returns zeros for a repository scan. It ran without error
  but its numbers carry no information about these runs.
