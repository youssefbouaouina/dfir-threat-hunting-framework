# CONTRIBUTING.md — Development Conventions

This document defines the conventions every contributor must follow. It is the human-facing companion to [AI_RULES.md](AI_RULES.md) (which governs AI modifications). Where a change violates these conventions, PR review should reject it.

---

## 1. Python style

- **Formatter:** Black-compatible formatting (double quotes preferred, 100-char lines). The codebase currently uses ~100-char lines and double quotes — match the surrounding file.
- **Linter:** `ruff` (planned in Phase 1 CI). Keep code `ruff`-clean: no unused imports, no `print()` in logic, consistent import ordering (stdlib → third-party → local).
- **Typing:** all function signatures annotated (see AI_RULES.md §6).
- **Docstrings:** PEP 257; module docstring + public function/class docstrings (see AI_RULES.md §7).
- **Compatibility:** Python ≥ 3.9 for the backend; keep collector importable on both Windows and Linux (lazy platform imports).
- **Exceptions:** catch specific exceptions (`psutil.NoSuchProcess`, `subprocess.CalledProcessError`); avoid bare `except:` except at documented boundaries (scheduler job, soft-fail intel lookups) where a comment explains why.
- No `TODO` left without an owner or linked issue; no commented-out code in merged changes.

## 2. Folder structure

Keep the existing layout. Do not invent parallel copies (the `detection/` duplication was a mistake).

```
backend/                  # FastAPI ingest + detection API
  main.py                 # app assembly + core routes (thin)
  detection_routes.py     # detection endpoints (thin)
  models.py               # SQLAlchemy ORM models
  schemas.py              # Pydantic request/response models
  database.py             # engine / session / get_db
  services/               # business logic (Phase 1+: extract here)
  sigma_matcher.py        # rule engine
  hash_checker.py         # IOC hash matching
  ioc_correlation.py      # network IOC matching
  attck_mapper.py         # ATT&CK enrichment
  scheduler.py            # background detection
  push_samples.py         # offline sample ingestion tool
  iocs/                   # threat-intel data (hashes, IPs)
  sigma_rules/            # behavioral YAML rules
  yara_rules/             # YARA rules
  tests/                  # pytest suite (Phase 1+)

collector/                # endpoint agent
  collector_agent.py      # orchestrator (CLI)
  modules/                # one file per artifact type + common.py
  output/                 # collection output (gitignored)

sample_data/              # collected artifact folders (replay/offline use)
docs/                     # design docs
```

Guidelines:
- New backend logic → `backend/services/<name>.py`; keep `main.py`/routes thin.
- New collector capability → new module in `collector/modules/` (mirroring the 6 existing ones) wired into `collector_agent.py`.
- Rules/data live with their consumers (`sigma_rules/`, `yara_rules/`, `iocs/`).
- Tests mirror the package: `backend/tests/test_<module>.py`.
- Never create a second tree that duplicates backend or collector code.

## 3. Logging

- Use the `logging` module with a module-level logger.
  - Backend: `logger = logging.getLogger(__name__)`
  - Collector: `logger = logging.getLogger("dfir.collector.<module>")`
- `print()` is allowed **only** for: CLI progress in standalone scripts (`collector_agent.py`, `push_samples.py`) and `__main__` smoke tests.
- Levels: `debug` (detail), `info` (lifecycle events, e.g. scheduler cycles), `warning` (degraded-but-working, e.g. skipped feed), `error`/`exception` (failures).
- Log structured, useful messages — include host, artifact_type, counts where relevant. Never log secrets, keys, or full payloads of sensitive data.
- Match the existing scheduler style (`logger.info("... %s ...", value)` — lazy formatting, never f-strings in log calls).

## 4. Testing

- **Every feature ships with tests** (Phase 1 establishes the suite; from then on tests are mandatory for new code).
- Framework: `pytest`. Layout: `backend/tests/`, one file per module under test.
- Coverage expectations:
  - Rule engines: `sigma_matcher`, `hash_checker`, `ioc_correlation` (mock the live feed) — pure function tests with fixtures.
  - API: round-trip tests for `/ingest` → query → `/detect` → `/detections`, using a temp SQLite DB (override `database.SessionLocal`).
  - Service functions: direct unit tests (they already take `db` as a parameter — easy to inject a test session).
- Do not depend on network, the real AbuseIPDB key, or the external STIX dataset in tests — mock or skip.
- Run before opening a PR:
  ```bash
  cd backend && pytest
  ```
- Smoke-test pattern to keep working: each module's `if __name__ == "__main__":` block.

## 5. Documentation

- **Modules:** module docstring — purpose, key functions, design rationale (the codebase already does this well; keep it up).
- **API:** every new/changed endpoint keeps its behavior documented in [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) (§5 Endpoints table + details) and reflected in the auto-generated `/docs`.
- **Schema changes:** update [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) (§3) and add an Alembic migration (Phase 2+).
- **Architecture/plans:** changes that alter the roadmap update [ROADMAP.md](ROADMAP.md); structural changes update [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md).
- **No doc drift:** if a file/behavior is removed, remove/update its documentation in the same change.
- New users should be able to go from README → PROJECT_OVERVIEW.md → relevant module docs without asking.

## 6. Naming conventions

- **Files:** lowercase with underscores (`detection_routes.py`, `known_bad_hashes.txt`). Match existing names.
- **Modules/variables/functions:** `snake_case`. Private helpers prefixed `_` (`_persist_detection`, `_extract_ip`).
- **Classes:** `PascalCase` (`Artifact`, `IngestResponse`, `Host`).
- **Constants:** `UPPER_SNAKE_CASE` (`DEFAULT_HASH_LIST`, `DETECTION_INTERVAL_SECONDS`).
- **DB columns / Pydantic fields:** `snake_case` (`artifact_type`, `collected_at`, `matched_data`).
- **Rule IDs:** `rule-XXX` for sigma rules, `yara-<RuleName>` for YARA-driven detections, descriptive slugs for IOC rules (`ioc-local-blocklist`). Never reuse an existing `rule_id` (duplicate IDs caused real duplicate detections).
- **Endpoints:** plural resource nouns (`/detections`, `/endpoints`); action endpoints as POST (`/detect`).

## 7. Commit conventions

- **Atomic commits:** one logical change per commit; no unrelated edits mixed in.
- **Imperative subject line, ≤ 72 chars**, e.g.:
  ```
  fix: dedupe sigma rules loaded from sigma_rules dir
  feat: add detection run history endpoint
  refactor: extract ingest logic into services/ingest.py
  test: cover ioc_correlation with mocked feed
  docs: document /detect rescan option
  chore: add ruff to requirements-dev
  ```
- Conventional-commit prefixes: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `perf:`, `ci:`.
- Body (optional but preferred for non-trivial changes): explain *why*, reference the rule/issue, note any API contract changes, note any code removed and why (AI_RULES.md §13).
- Stage only intended files. Never commit: secrets/`.env*`, `*.db`, `collector/output/`, venvs, pyc files.
- Verify before committing: `git status`, `git diff` — then commit. Do not amend or force-push without a maintainer request.

## 8. Pull request conventions

- **Branch:** short descriptive branch off `main`, e.g. `feat/detection-run-history`, `fix/requirements-encoding`.
- **PR title:** mirrors the conventional commit of its primary change.
- **PR description includes:**
  - What & why (context, linked issue/roadmap phase).
  - Test plan: what you ran (`pytest ...`, smoke commands, curl checks).
  - Any behavior/API changes (with before/after where relevant).
  - Any deletions + justification (AI_RULES.md §13–14).
  - Screenshots for dashboard/UI changes (Phase 3+).
- **Keep PRs small and reviewable** (< ~400 lines of diff where practical); split large features across PRs that each land green.
- **CI must pass** (Phase 1+): lint, tests, secret scan. A red pipeline blocks merge.
- **Review checklist (merge gate):**
  - [ ] No broken existing functionality (tests pass)
  - [ ] No duplicated logic
  - [ ] Typing + docstrings present
  - [ ] No `print()` in logic; logging used
  - [ ] Endpoints thin; logic in services
  - [ ] Docs updated (PROJECT_OVERVIEW.md / ROADMAP.md as needed)
  - [ ] No secrets or runtime data committed
  - [ ] No unexplained deletions
- **Merge:** squash-merge to `main` preferred; delete the feature branch after merge.

---

*Last updated with the initial conventions. Amend this file when the team agrees on changes.*
