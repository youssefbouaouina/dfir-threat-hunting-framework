# Phase 6 — CI/CD Architecture

## 1. Goals

- Free ($0/month), GitHub-hosted, reproducible.
- Detect breakage on every push to `youssef_V2` and `main`.
- Build + test backend and Linux endpoint images; test the exact SHA built.
- Run a real endpoint lifecycle integration test inside CI.
- Security scanning without blocking normal dev velocity.

## 2. Tooling (all free)

| Tool | Use | Cost |
|---|---|---|
| GitHub Actions | pipeline | public repo → unlimited minutes |
| ghcr.io (GitHub Container Registry) | image storage | free |
| pytest | unit/integration tests | OSS |
| ruff | lint | OSS |
| trivy | container image CVE scan | OSS |
| docker compose | integration environment | free |

## 3. Workflow (`ci-cd.yml`)

Triggers: `push` + `pull_request` on `youssef_V2` and `main`, plus `workflow_dispatch`.

```
lint-and-unit          (ubuntu-latest)
  ├─ checkout
  ├─ setup-python 3.12
  ├─ pip install -r backend/requirements.txt + pytest + ruff
  ├─ ruff check backend collector
  ├─ python -c "import main" (backend import sanity)
  ├─ validate sigma + yara rules load
  └─ pytest backend/tests (unit suite)

build-images           (needs lint-and-unit; ubuntu-latest)
  ├─ buildx
  ├─ build backend -> ghcr.io/<owner>/framework-backend:<sha>  (+ cache)
  ├─ build endpoint -> ghcr.io/<owner>/framework-endpoint-linux:<sha>
  ├─ trivy scan (fs + images); PR = report only, main = fail on HIGH+
  └─ publish to ghcr (main only, git-sha + minor tag)

integration            (needs build-images; ubuntu-latest)
  ├─ checkout + buildx
  ├─ create .env + ssh dir skeleton
  ├─ docker compose -f docker-compose.yml -f docker-compose.ci.yml up -d --build
       (backend + endpoint-manager + one Linux endpoint container)
  ├─ run tests/integration/run_integration.sh
       wait /health → create endpoint (container) → heartbeat seen →
       scan → artifacts ingested → detect → detections present →
       report generated → stop → start → verify recovery
  └─ teardown (compose down -v) + upload logs on failure
```

## 4. Versioning

Images are tagged with the git SHA; CI integration tests use exactly the SHA it built.

```
ghcr.io/<owner>/framework-backend:<git-sha>
ghcr.io/<owner>/framework-endpoint-linux:<git-sha>
```

`latest` is only pushed on `main` for convenience, never used as a test target.

## 5. Environment variables / secrets

- `DOCKER_*` / ghcr auth uses the built-in `GITHUB_TOKEN` (free, no PAT required).
- `ABUSEIPDB_API_KEY` optional secret — integration tolerates its absence (soft-fail).
- Endpoint image pull/run happens on the runner via the endpoint-manager → docker socket.

## 6. Rollback strategy

- Every image is immutable and SHA-pinned; the previous SHA image remains available on
  ghcr for instant rollback.
- `main` is the deployment gate: integration must pass before publishing to ghcr.
- A failing integration job marks the run failed (CI = FAILED) and no deployment step runs.

## 7. Why this stays $0

- Public repo → GitHub Actions minutes unlimited, cache included.
- ghcr.io hosting is free.
- All test/runtime tools are open source.
- No paid cloud: the test environment is a Linux runner with docker compose.
