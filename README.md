# CHOKEPOINT

**Stop ranking vulnerabilities. Start cutting attack paths.**

A repository-focused, graph-based security analysis and remediation-prioritisation system.

CHOKEPOINT identifies security findings, connects them to code relationships where evidence supports
the connection, investigates which findings matter most, challenges weak conclusions, and recommends
the fixes that remove the most graph-supported attack-path risk.

---

## Why a graph

1. An attack path is a path. Finding "internet → ingress → service → service → IAM role → data
   store" is a multi-hop traversal with a predicate on every hop; a table cannot express it.
2. The chokepoint question — *which smallest set of fixes removes the most risk* — is weighted set
   cover over those paths, re-evaluated on a modified graph after each pick.
3. The three agents never talk to each other. They post hypotheses, challenges and verdicts as
   nodes and read each other's work back with one query. The graph **is** the shared context.
4. Memory is graph proximity. A lesson learned from an override is attached to the nodes it applies
   to, so the next investigation finds it by walking two hops from the service in question.
5. Explanations are subgraphs. Every claim in a verdict cites the step that produced it, and every
   step records the nodes it touched, so "why" is a traversal rather than a promise.

---

## Architecture

```
┌────────────────────┐   SSE / REST    ┌───────────────────────────────┐
│  Frontend (React)  │ ◄─────────────► │  Backend (FastAPI)            │
│  Cytoscape graph   │                 │  Orchestrator                 │
│  Ledger / Dossier  │                 │   ├─ Scout   (LLM loop)       │
└────────────────────┘                 │   ├─ Skeptic (LLM loop)       │
                                       │   └─ Scribe  (LLM loop)       │
                                       │  MCP Client ──────────┐       │
                                       └───────────────────────┼───────┘
                                                               │ MCP (streamable HTTP; stdio too)
                                       ┌───────────────────────▼───────┐
                                       │  MCP Server "chokepoint-mcp"  │
                                       │  tools: read/analysis/memory/ │
                                       │         blackboard/action     │
                                       └───────────────────────┬───────┘
                                                               │ NetworkX + SQLite persistence
                                       ┌───────────────────────▼───────┐
                                       │  Security Graph (in-memory)   │
                                       │  enriched from Graphify        │
                                       └───────────────────────────────┘
```

Two rules hold everywhere:

- **Agents never touch the database.** Every tool call goes out over MCP, and the server enforces
  the role allow-list again on arrival.
- **The model never computes a risk number.** Scores come from `mcp_server/scoring.py` and
  `mcp_server/solver.py`. The model picks tools, reads results, argues and writes the verdict.

---

## Quick start

```bash
cp .env.example .env
# Recommended: Run Ollama locally for LLM inference (no API keys needed)
#   ollama serve
#   ollama pull gemma3:4b
# Get a Graphify executable or install it from https://github.com/Graphify-Labs/graphify
# Get a scanner (Trivy, Semgrep) on PATH or in the container image.
docker compose up --build
```

The agents run on a **local Ollama model** (`OLLAMA_MODEL`, default `gemma3:4b`) when Ollama
is reachable at `OLLAMA_BASE_URL` and offers that model. `/api/health` probes the provider on
every call and reports `agent_mode: scripted` with `model: deterministic` when it is not
reachable; an investigation is then labelled `deterministic`, never `live`. `GEMINI_API_KEY` is
optional and only used if explicitly set.

A 7B-class model on CPU takes minutes per agent turn. For a demo on modest hardware either use a
small model (`gemma3:4b`) or set `AGENT_MODE=scripted`, which runs the same MCP tools
deterministically and says so in the UI.

Then open <http://localhost:8080>.

| Service | URL |
|---|---|
| Frontend | http://localhost:8080 |
| API | http://localhost:8050/api/health (`BACKEND_PORT`, default 8050) |
| OpenAPI | http://localhost:8050/docs |
| MCP server | http://localhost:8765/mcp |
| SQLite persistence | internal to the backend |
| Graphify workspaces | `/data/graphify-workspaces` |

The backend initialises SQLite, connects to the MCP server in the background and runs Graphify
per scan. It does **not** seed any data on startup: a fresh install has an empty graph until you
scan a repository (or run `make seed` for the synthetic estate). `make up`, `make test`,
`make seed`, `make delta`, `make evals`, `make logs` and `make mcp-stdio` wrap the same
operations and honour `BACKEND_PORT`.

**No model at all?** Leave `GEMINI_API_KEY` empty and do not run Ollama. `/api/health` reports
`agent_mode: scripted`, the masthead shows the mode badge, and the investigation runs a fixed
sequence of **real MCP tool calls** against the live graph. Every number on screen still comes
from the graph, and the run is recorded as `deterministic` so it is never mistaken for model
reasoning.

---

## Scanning a repository

This is the product flow. Nothing synthetic is involved.

```bash
# 1. put a repository where the API can reach it
mkdir -p data/codebases
git clone --depth 1 https://github.com/OWASP/NodeGoat data/codebases/nodegoat

# 2. scan it (or POST /api/codebases/scan-url with a github.com / gitlab.com /
#    bitbucket.org HTTPS URL, or upload a .zip to /api/codebases/scan-upload)
curl -fsS -X POST http://localhost:8000/api/codebases/scan-directory \
  -H 'Content-Type: application/json' -d '{"path":"nodegoat","name":"nodegoat"}'
```

`scan-directory` is confined to `CODEBASES_DIR`; a path outside it is rejected. The response
reports what actually ran, for example:

```json
{
  "graphify_status": "completed",
  "scanner_statuses": {"trivy": "skipped", "semgrep": "skipped", "local_checks": "completed"},
  "summary": "Analysed nodegoat: 29 Graphify code nodes and 36 code relationships; 11 findings
              from local checks only; 11 of 11 findings mapped to a graph entity. Coverage is
              limited to the scanners that ran; this is not a claim of complete detection."
}
```

Then:

1. **Case Board.** Headline counts come from the scan. `nodes_by_label` and
   `relationships_by_type` show what the graph is made of, including how much of it Graphify
   extracted versus how much CHOKEPOINT modelled.
2. **Triage the latest scan.** Watch `Memory → Scout → Skeptic → Rebuttal → Scribe`. The Scout
   names the findings that sit on a modelled route; the Skeptic counts how many findings have
   reachability `not established`, how many are unmapped, and how many hops on the route are
   modelled rather than extracted; the Scribe issues a verdict per finding.
3. **Every verdict carries the result of the grounding check.** A claim must cite the step that
   produced its numbers, and a number that appears in no cited step's result is reported as a
   failure. Hover a citation to highlight the ledger row and the nodes that step touched.
4. **Show simulation.** One chokepoint fix is applied to a deep copy of the graph. Before and
   after metrics, the routes removed and the stated assumptions come back together.
5. **Approve an action.** An outbox file appears. Nothing leaves the machine without approval.
6. **Override a verdict** with a reason. A lesson appears on **Memory**, scoped to the package,
   CVE or file the verdict was actually about, and linked to the feedback that produced it.
7. **Explorer.** Run the saved queries against the live schema, including "Extracted versus
   inferred relationships", which shows the two graph layers side by side.

Scan a second, already-patched repository to see the version comparison work: a manifest whose
dependencies are all at or above their fixed versions produces no dependency findings.

## Synthetic demo and evaluation

Separate from the product flow, `make seed` generates a synthetic infrastructure estate and
`/api/evals/run` ranks its findings three ways against ground truth that was planted when the
estate was generated. This is **not** a repository scan and the UI labels it as seeded data.

1. The naive view puts the CVSS 10.0 Log4Shell in `report-renderer` at the top.
2. Triage shows the five-hop route from `session.acme.example` to `payments-vault`, and the Scout
   explains why the CVSS 10.0 is on no path at all.
3. **Evals**: CVSS-first and KEV/EPSS-first against CHOKEPOINT on the planted ground truth.
4. **Apply day-2 scan**, then run **What changed since yesterday?** for the delta.

It measures whether path-aware ranking beats severity-first ranking *on data built to contain
that distinction*. It is an illustration of the mechanism, not a field trial, and it reports
zeros when pointed at a real repository scan, because the planted labels do not apply there.

## MCP tools

21 tools, discovered at run time. `GET /api/mcp/tools` returns exactly what the agents see.

| # | Tool | Group | Roles | What it is for |
|---|---|---|---|---|
| 1 | `graph_overview` | read | scout, skeptic, scribe, backend | Counts, scan ids, public ingress, crown jewels, live headline numbers |
| 2 | `find_entities` | read | all | Resolve free text to node ids |
| 3 | `get_service_context` | read | scout, skeptic, scribe | One service in full: owners, ingress, controls, data, calls, findings |
| 4 | `list_open_findings` | read | scout, skeptic, backend | The CVSS-sorted queue: the naive view |
| 5 | `owner_of` | read | scout, skeptic, scribe | Team, channel and on-call, resolved through the graph |
| 6 | `find_attack_paths` | analysis | scout, skeptic, backend | Internet-to-crown-jewel paths with every score component |
| 7 | `blast_radius` | analysis | scout, skeptic, scribe | What one compromise reaches over non-mTLS edges |
| 8 | `check_exploitability` | analysis | scout, skeptic | Live-exploit predicates, one boolean and one reason each |
| 9 | `rank_centrality` | analysis | scout, skeptic | Betweenness or PageRank, with the engine reported |
| 10 | `find_chokepoints` | analysis | scout, skeptic, scribe, backend | Greedy weighted set cover over the path set |
| 11 | `simulate_fix` | analysis | scout, skeptic | Counterfactual on a deep copy of the NetworkX graph; the baseline is untouched |
| 12 | `connected_components` | analysis | scout, skeptic | WCC over the call graph: which segments cannot reach each other |
| 13 | `shortest_path` | analysis | scout, skeptic | Cheap reachability proof, including proving there is none |
| 14 | `recall` | memory | all | Lessons by graph proximity and vector similarity, plus past verdicts |
| 15 | `diff_since_last` | memory | scout, skeptic, backend | New, resolved and changed since the last completed run |
| 16 | `post_hypothesis` | blackboard | scout | One falsifiable claim with its citations |
| 17 | `post_challenge` | blackboard | skeptic | A falsification attempt, upheld or rejected |
| 18 | `list_blackboard` | blackboard | scout, skeptic, scribe | The only way an agent sees another agent's work |
| 19 | `record_verdict` | action | scribe | Decision plus grounding check plus lesson safety valve |
| 20 | `propose_action` | action | scribe | Human-approved ticket, routed through the graph |
| 21 | `record_lesson` | action | backend | Lesson write. No agent role may call it |

### Claude Desktop (stdio)

```json
{ "mcpServers": { "chokepoint": { "command": "python", "args": ["-m", "mcp_server.server", "--transport", "stdio"], "env": { "SQLITE_PATH": "/data/chokepoint.db" } } } }
```

Run it from `backend/` with `SQLITE_PATH` pointing at the database the API uses.
`make mcp-stdio` does the same thing. There is no graph-database service to start.

---

## Graph schema

Three layers, linked so memory retrieval can walk from a component to past verdicts about its
neighbourhood.

A repository scan populates: `File`, `Function`, `CodeEntity` and `CODE_*` relations from
Graphify (`provenance: EXTRACTED`); `Package` and `DEPENDS_ON` from the manifests; and a modelled
`Internet`/`Ingress`/`Service`/`DataStore`/`Route` skeleton with `REACHES`, `ROUTES_TO`, `CALLS`,
`READS_FROM` and `DEFINES` (`provenance: INFERRED`). The estate shapes below are the full
vocabulary, most of which only the synthetic seed produces — `IAMRole`, `Control`, `Team` and
`Person` have no repository equivalent and are absent from a real scan.

**Estate.** `Internet`, `Ingress`, `Service`, `Package`, `Vulnerability`, `Finding`, `DataStore`,
`IAMRole`, `Control`, `Team`, `Person`.

```
(:Internet)-[:REACHES]->(:Ingress)-[:ROUTES_TO {path_prefix}]->(:Service)
(:Service)-[:CALLS {authz, protocol, rps}]->(:Service)
(:Service)-[:READS_FROM|:WRITES_TO]->(:DataStore)
(:Service)-[:ASSUMES]->(:IAMRole)-[:CAN_ACCESS]->(:DataStore)
(:Service)-[:DEPENDS_ON {direct}]->(:Package)-[:AFFECTED_BY {fixed_in}]->(:Vulnerability)
(:Service)-[:HAS_FINDING]->(:Finding)-[:OF]->(:Vulnerability)
(:Finding)-[:VIA]->(:Package)
(:Control)-[:PROTECTS {against}]->(:Service|:Ingress)
(:Team)-[:OWNS]->(:Service)   (:Person)-[:MEMBER_OF]->(:Team)   (:Person)-[:ON_CALL_FOR]->(:Service)
```

**Reasoning.** `Investigation`, `Step`, `AttackPath`, `Hypothesis`, `Challenge`, `Verdict`,
`Action`, `Event`, joined by `HAS_STEP`, `TOUCHED`, `FOUND_PATH`, `STEP`, `HAS_HYPOTHESIS`,
`HAS_CHALLENGE`, `ABOUT`, `BASED_ON`, `TARGETS`, `PRODUCED`, `ON`, `CITES`, `EVIDENCE`,
`RESULTED_IN`, `ROUTED_TO`, `NOTIFY`, `HAS_EVENT`.

**Memory.** `Feedback`, `Lesson`, joined by `ON`, `TAUGHT`, `APPLIES_TO`, `USED_LESSON`.

### Scoring

```
exploitability = max over live exploits on the path of 0.45·epss + 0.25·(cvss/10) + 0.30·kev
exposure       = 1.0 authn none | 0.6 basic | 0.35 oidc
impact         = 0.6·classification weight + 0.4·min(1, log10(records+1)/9)
length_penalty = clamp(0.92^(hops−3), 0.5, 1.0)
control_disc   = 0.5 per active control on the path
score          = exploitability · exposure · impact · length_penalty · control_disc
```

A finding is a **live exploit** when it is open, its service is active, the vector is `network` (or
`adjacent` after lateral movement), authentication is satisfied, the vulnerable code is reached, and
no active control blocks it. Fix effort is a proxy: `upgrade_package` costs
`1 + 0.3·(services using it)`, `patch_service_dependency` 1, `harden_edge` 2, `add_control` 1.5.

---

## Evaluation and its caveat

`GET /api/evals/run` ranks the same open findings three ways and scores each against
`backend/app/seed/ground_truth.json`:

- **CVSS-first** — descending CVSS, then EPSS.
- **KEV/EPSS-first** — KEV, then EPSS, then CVSS.
- **CHOKEPOINT** — findings with a `FIX_NOW` verdict, ordered by their best attack-path score.

Metrics: precision@10 of truly exploitable findings, recall at depth 20 of the exploitable set,
decoys in the top 10, fixes needed to remove 90% of weighted path risk, the share of verdict
claims that passed the grounding check, and mean tool calls per investigation.

**The caveat, stated plainly:** the estate is synthetic and the labels were planted when it was
generated, so this only applies to seeded data — see *Synthetic demo and evaluation* above.
Public CVE ids carry approximate real severity; ids beginning `ACME-` or `SYN-` are invented, as
are all internal package names.

The planted cases are S1 decoy CVSS 10.0 with no route, S2 the quiet five-hop killer, S3 the
shared internal HTTP client behind most paths, S4 a mitigated finding, S5 a decommissioned
zombie, S6 a sandbox cluster with no route to production data, and S7 the day-2 delta.

## What it does and does not claim

Read this before reading a number on screen.

- **Detection is only as wide as the scanners that ran.** Trivy and Semgrep are optional. When
  they are absent the scan reports them `skipped` and falls back to a small bundled advisory
  table plus two regex source rules. CHOKEPOINT never claims to find every vulnerability in a
  repository, and `/api/codebases/scan-*` returns the coverage it actually had.
- **The bundled advisory table is not a vulnerability database.** It holds a handful of well
  known advisories and compares them against the version declared in the manifest. A package it
  does not know about produces no finding. Its EPSS and KEV values are table estimates, labelled
  as such in every finding's evidence, not readings from a live feed.
- **Reachability is three-state, and "not established" is not "unreachable".** A dependency
  finding is reported with `reachability: not_established` unless something actually showed the
  vulnerable code being reached. Such a finding still counts as a candidate — unknown is not safe —
  but its exploitability signal is discounted by a documented 50% factor so it cannot outrank a
  finding with real evidence. Only `contradicted` removes a finding from consideration.
- **The estate layer is a model, not observed infrastructure.** A repository does not tell you
  about ingress, authentication or data stores. CHOKEPOINT synthesises an `Internet → Ingress →
  Service → DataStore` skeleton from repository structure so the path engine has something to
  walk, and marks every one of those nodes and edges `provenance: INFERRED` with the heuristic
  that produced it. Graphify's real code relationships are stored separately as `CODE_*` edges
  with `provenance: EXTRACTED`. The graph explorer and `/api/schema` show the split.
- **A path is a hypothesis.** Every attack path carries `reachability_verified` and an
  `evidence_note`. When it is false, the route supports a hypothesis and is not proof of
  exploitability.
- **Data classification and record counts are unknown, not assumed.** They cannot be read from
  source, so impact uses a documented default weight and the score reports its own coverage
  (`components.coverage`, `components.coverage_pct`). A score is a prioritisation heuristic, not a
  probability of compromise.
- **Secret values are redacted** before they are stored, shown or put in a model prompt. The
  evidence keeps the shape of the match (`API_KEY = "[REDACTED]"`), never the value.
- **Heuristic effort costs.** Fix costs are proxies, not estimates from your backlog. They change
  which fix the greedy solver picks first, so treat the ordering as a hypothesis.
- **Simulation only.** A fix is applied to a deep copy of the NetworkX graph. No source file is
  changed, no pull request is opened and no ticket leaves the machine without approval. A graph
  simulation predicts an effect under modelled assumptions; it does not prove a patch is correct.
- **Agent mode is reported, never assumed.** `/api/health` probes the model provider. With no
  provider reachable the mode is `scripted`/`deterministic` and the investigation is labelled
  `deterministic` — never `live`. If an LLM run produces nothing usable, the run is relabelled
  `deterministic (LLM failed)`, a `degraded` event is emitted and the deterministic pipeline
  finishes the work.
- **Synthetic seed data.** `make seed` and `/api/seed/reset` generate the original synthetic
  infrastructure estate. It exists for the evaluation illustration and for fixtures; it is not a
  repository scan. The evaluation's ground truth was planted when that estate was generated, so
  `/api/evals/run` is meaningful only against seeded data and returns zeros for a real scan.
- **Single tenant, no auth.** Anyone who can reach the port can run an investigation and approve
  an action. There is no user model and no audit identity beyond the `by` field on feedback.
- **Exactly one light theme.** No dark mode, and the three-pane layout wants 1280px or more.
- **Bounded search.** Paths are capped at 7 hops and the candidate query is limited, so a very
  large repository will be summarised rather than enumerated; the tool result says when it
  truncated.
- **Supported languages.** The built-in structural reader understands `package.json`,
  `requirements*.txt`, `go.mod` and Python ASTs. Graphify covers more; what it extracted is
  reported per scan.

## Tests

```bash
make test          # or: cd backend && python -m pytest tests -q
```

Measured results from three repeat runs, including what was *not* exercised, are in
[`docs/THREE_RUN_RESULTS.md`](docs/THREE_RUN_RESULTS.md).

The suite needs no network access, no scanners, no Graphify and no model provider: it runs
against a temporary SQLite database and checked-in fixtures. It covers version comparison and
secret redaction in the scanner adapters, the Graphify node-link schema, the estate layer's
provenance labelling, scoring boundaries and reproducibility, graph-copy isolation, the grounding
check, MCP role enforcement, every frontend-consumed API route, and a full
repository → graph → findings → investigation → simulation run.

## Troubleshooting

**Ollama not reachable.** The backend expects Ollama at `OLLAMA_BASE_URL` (default `http://localhost:11434`).
Run `ollama serve` and pull the model: `ollama pull gemma3:4b`. Check `docker compose logs mcp` for
`Ollama health check` messages. If Ollama is unavailable, agents fall back to scripted mode.

**`/api/health` says `mcp: false`.** The MCP container starts alongside the backend and the backend
reconnects in the background; give it a few seconds and reload. `docker compose logs mcp` should
show `chokepoint-mcp starting on streamable-http`. The health document carries the last connection
error verbatim.

**Missing API key (optional).** `GEMINI_API_KEY` is optional. Leave it empty to use Ollama or scripted
mode. `/api/health` reports `agent_mode` and the UI shows the current mode badge.

**Embeddings on first run.** `fastembed` downloads `BAAI/bge-small-en-v1.5` the first time a lesson
is embedded, which takes a few tens of seconds and needs network access. Without it the status
strip reads `vector memory off` and `recall` falls back to keyword matching plus graph proximity,
which is enough for the demo. Set `EMBEDDINGS=none` to skip it deliberately.

**Algorithms report `networkx`.** All graph algorithms run on NetworkX (no native database procedures).
Each tool result names the `engine` it used (`networkx`). `rank_centrality` with `pagerank`
needs `scipy`, which is in `requirements.txt`.

**The graph looks wrong after experimenting.** `make seed` drops and regenerates it deterministically
and rewrites `ground_truth.json`. `make delta` applies the day-2 scan; it is idempotent.

**Graphify not available.** The Graphify CLI is optional. If not on PATH, the graph builder reports
"unavailable" and skips code extraction. Install from https://github.com/Graphify-Labs/graphify
to enable code relationship extraction.

---

## Repository layout

```
backend/app          FastAPI app, orchestrator, providers, prompts, memory, seed, evals, actions
backend/mcp_server   chokepoint-mcp: scoring, attack paths, solver, algorithms, grounding, tools
frontend/src         React 18 + Vite + Cytoscape, plain CSS with paper/ink tokens
backend/tests        pytest suite: scanners, scoring, graph, grounding, API, end-to-end
docker-compose.yml   ollama · mcp · backend · frontend
```

Checks you can run yourself: `make typecheck` for the frontend, `make lint` for the Python source
(both install their own tooling).
