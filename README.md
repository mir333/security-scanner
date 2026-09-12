# devsecops-stack

One `docker compose` file that runs **OWASP DefectDojo** (single-pane dashboard),
**Semgrep** (SAST) and **OWASP ZAP** (DAST), with scan results pushed straight into
DefectDojo through its API. DefectDojo deduplicates and tracks findings across runs.

```
┌──────────┐  semgrep.json  ┌───────────────┐
│ Semgrep  │───────────────▶│               │
└──────────┘                │  DefectDojo   │  http://localhost:8080
┌──────────┐  zap-*.xml     │  (nginx/uwsgi │
│ OWASP ZAP│───────────────▶│  celery/pg)   │
└──────────┘  /api/v2/      └───────────────┘
              import-scan/
```

## Setup

### Guided (recommended)

```bash
./setup.sh
```

An interactive wizard: checks Docker, creates `.env` (generating the secret keys
and, optionally, the admin password), asks for the repo to scan and the URL to
attack, starts DefectDojo, opens the dashboard and runs the scans you pick.
Safe to re-run — existing values are offered as defaults.

### Manual

```bash
cp .env.example .env
# edit .env — at minimum: DD_ADMIN_PASSWORD, DD_SECRET_KEY, DD_CREDENTIAL_AES_256_KEY,
#                         SCAN_PATH, ZAP_TARGET, DD_PRODUCT_NAME
docker compose up -d
```

Compose refuses to parse without those variables (`${VAR:?}`), so a missing `.env`
fails fast instead of starting a half-configured stack. First boot takes ~1–2 min
(migrations + seed data). Log in at http://localhost:8080 with `DD_ADMIN_USER` /
`DD_ADMIN_PASSWORD`.

## Running scans

Each `import-*` service runs its scanner first (via `depends_on`), then uploads the
report. Reports also land in `./reports/` for local inspection.

| Command | What it does | Engagement in DefectDojo |
|---|---|---|
| `docker compose --profile scan run --rm import-semgrep` | Semgrep over `SCAN_PATH` with `SEMGREP_CONFIG` rules | `Semgrep SAST` |
| `docker compose --profile scan run --rm import-trivy` | Trivy filesystem scan over `SCAN_PATH`: dependency CVEs + IaC misconfig + secrets | `Trivy SCA` |
| `docker compose --profile scan run --rm import-sonarqube` | Pulls issues + hotspots from an existing SonarQube/SonarCloud analysis (`SONAR_BRANCH`, or `SONAR_PR` to test) | `SonarQube` |
| `docker compose --profile scan run --rm import-zap` | ZAP **baseline**: spider + passive rules. Safe. | `ZAP Baseline DAST` |
| `docker compose --profile scan run --rm import-zap-full` | ZAP **full**: spider + AJAX spider + **active attack scan**. Slow, noisy, only against targets you own/are authorised to test. | `ZAP Full DAST` |

Override anything per-run without editing `.env`:

```bash
SCAN_PATH=/path/to/other/repo DD_PRODUCT_NAME=other-app \
  docker compose --profile scan run --rm import-semgrep
```

Re-running the same scan re-imports into the same product/engagement:
DefectDojo dedups existing findings and closes ones that disappeared
(`close_old_findings=true` in `import.sh`).

### Pointing ZAP at an app

* App in another compose project / container: attach it to this network
  (`docker network connect devsecops-stack_default <container>`) and use
  `ZAP_TARGET=http://<container>:<port>`.
* App on the host: `ZAP_TARGET=http://host.docker.internal:<port>` and add
  `extra_hosts: ["host.docker.internal:host-gateway"]` to the `zap`/`zap-full`
  services (needed on Linux).
* `ZAP_EXTRA_ARGS` passes flags through, e.g. `-j` (AJAX spider for baseline),
  `-m 10` (spider time limit), `-c rules.conf` (per-rule WARN/FAIL/IGNORE, file
  goes in `./reports/`).

## In CI

The same commands work in a pipeline; the runner only needs Docker and network
access to the DefectDojo instance. Set `DD_URL` in `import.sh`'s environment to
the real host instead of `http://nginx:8080` if DefectDojo lives elsewhere.

## Notes

* `docker compose run` re-checks the whole dependency chain, so the one-shot
  `initializer` runs again (idempotent, ~20 s) before each scan. Harmless.
* `reports/semgrep.json` is root-owned (Semgrep image runs as root); `sudo rm` if you need to clean it.
* Tear down: `docker compose --profile scan down` (add `-v` to wipe the database).
* Upgrading DefectDojo: bump `DEFECTDOJO_VERSION`, `docker compose pull`,
  `docker compose up -d` — the initializer applies migrations.
