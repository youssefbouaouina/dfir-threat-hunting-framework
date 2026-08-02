# AI_RULES.md — Binding Rules for Future Modifications

These rules are **mandatory** for any AI agent (or human) modifying this repository. They exist to keep the codebase stable, maintainable, and consistent as the project grows into the enterprise-grade platform described in [ROADMAP.md](ROADMAP.md).

> Scope: every change to this repository, in every phase of the roadmap. If a rule conflicts with a user request, the user request wins — but you must flag the conflict explicitly before proceeding.

---

## 1. Never break existing functionality

- The current pipeline (collect → ingest → detect → query) must keep working end-to-end after every change.
- Before and after any change, verify the affected paths still behave: `pytest` if present, module `__main__` smoke blocks, and the documented API endpoints (`/health`, `/ingest`, `/detect`, `/detections`).
- If a change alters an API contract or removes behavior, call it out explicitly in the commit/PR message.
- Backwards compatibility is preferred. When breaking it is unavoidable (e.g. a schema migration), provide a migration path (Alembic) and document it.

## 2. Prefer modular code

- One module, one clear responsibility. Mirror the existing structure (collector modules, backend services, rules, iocs).
- New capability = new module (or new function in the right existing module), not a grab-bag of unrelated helpers.
- Keep modules small enough to be understood by reading them top to bottom.

## 3. Never duplicate logic

- If you need behavior that already exists, **import it** — do not re-implement it.
- Shared helpers live in `collector/modules/common.py` (collector side) and dedicated `services/` modules (backend side, see below).
- Before writing a helper, grep the codebase for an existing one.
- Examples of current anti-patterns to avoid repeating: the duplicated `detection/` tree, duplicate sigma rule files with the same `rule_id`, the envelope-building logic existing only in `common.py` (keep it that way — single source of truth).

## 4. Prefer dependency injection

- Pass dependencies explicitly (DB sessions, rule loaders, HTTP clients, config) into functions/classes rather than reaching for globals or instantiating them inside.
- FastAPI: keep using `Depends(get_db)` and similar; service functions receive the session as a parameter (as `run_detection_job(db)` already does).
- This makes logic testable — a hard requirement given the zero-test current state.
- Module-level caches (`_cache`, `_ip_cache`) are acceptable for read-heavy lookups but must be documented and bounded.

## 5. Keep functions under 50 lines where practical

- If a function approaches ~50 lines, extract cohesive sub-steps into private helpers (`_helper()`).
- `collector_agent.py::run_collection` and `detection_routes.py::run_detection_job` are the current upper bounds and should shrink as features are added.
- Readability beats brevity; the 50-line limit is a target, not a hard cap.

## 6. Use Python typing

- Annotate all function signatures (params and return types). Use `Optional[...]`, `List[...]`, `Dict[...]`, `Set[...]` etc. from `typing` (or builtin generics for Python ≥3.9).
- Annotate module/class-level data structures where it aids clarity.
- Gradual typing with `mypy` is planned (Phase 1); writing annotated code now makes adoption trivial.

## 7. Write docstrings

- Every module gets a module docstring: purpose, key functions, and any design rationale (this codebase's strong existing habit — keep it).
- Every public function/class gets a docstring: one-line summary, parameters, return value, and exceptions where relevant.
- Where behavior is non-obvious (e.g. lazy imports, offline-first fail-soft), document *why*.

## 8. Use logging instead of print()

- Use the `logging` module with a module-level logger: `logger = logging.getLogger(__name__)` (backend) or `logger = logging.getLogger("dfir.collector.<module>")` (collector).
- Reserve `print()` for: CLI user-facing progress in standalone scripts (`collector_agent.py`, `push_samples.py`) and `__main__` smoke-test output.
- No `print()` inside service/pipeline logic.
- Log levels: `debug` for detail, `info` for lifecycle, `warning` for degraded-but-working states, `error`/`exception` for failures.

## 9. Keep FastAPI endpoints thin

- Endpoints parse/validate input and return a response. All business logic goes in services.
- Rule of thumb: an endpoint body is a few lines — fetch service, call it, return.

## 10. Put business logic into services

- Backend business logic belongs in a `backend/services/` package (e.g. `services/detection.py`, `services/ingest.py`, `services/endpoints.py`), not inside route handlers.
- Routes (`backend/main.py`, `backend/detection_routes.py`) stay thin; keep the existing pattern where `run_detection_job` is a plain function callable by both the route and the scheduler.
- Collector business logic belongs in `collector/modules/`; the orchestrator stays in `collector_agent.py`.

## 11. Avoid circular imports

- Import direction: `main.py` → routes → services → models/database. Never import upward.
- When two modules need each other, extract the shared piece into a lower-level module instead of importing in both directions.
- Lazy imports inside functions are acceptable for optional/heavy dependencies (existing pattern in `attck_mapper.py`, `file_scan.py`, `persistence.py`) — but never as a circular-import workaround.

## 12. Keep APIs RESTful

- Use HTTP verbs meaningfully: `GET` for reads, `POST` for actions/creates, `PUT/PATCH` for updates, `DELETE` for removal.
- Resources are plural nouns (`/detections`, `/endpoints`); actions that aren't CRUD are expressed as sub-resources or POST actions (`POST /detect` is an existing, acceptable action endpoint).
- Consistent query params, consistent error shapes (FastAPI `HTTPException` with `detail`), consistent status codes.

## 13. Never remove code without explanation

- Every deletion must be justified in the commit message and/or PR description: why it's dead, superseded, or broken.
- If code is being replaced, note the replacement (e.g. "removing detection/ tree — superseded by backend/, which is the canonical copy").
- Prefer deprecation + one-cycle removal over abrupt deletion when the code is still referenced.

## 14. Ask before deleting files

- **Never delete a file without explicit user approval.** Present the proposed deletion, the reason, and any referenced code, and wait for confirmation.
- This includes files identified as dead in PROJECT_OVERVIEW.md (e.g. `detection/`, `backend/yara_engine.py`, empty placeholders) — they may be removed during Phase 1, but only after approval.

---

## Enforcement

- Follow these rules in every edit; a change that violates them should be caught in PR review.
- CI (Phase 1+): lint (`ruff`) and tests gate merges; mypy is planned.
- When in doubt, favor the smallest change that satisfies the user's request without violating these rules — and document any tradeoff.

*This file is living documentation. Amendments require an explicit user request.*
