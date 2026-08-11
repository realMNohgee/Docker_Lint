# Docker_Lint

**Dockerfile best-practice linter.** Catch no-root, no-latest, layer bloat, and security issues. Zero dependencies — Python stdlib only.

📦 Find this tool on the [Hermtica Marketplace](https://hermtica.com/tools/docker-lint).

## Install

```bash
curl -O https://raw.githubusercontent.com/realMNohgee/Docker_Lint/main/docker_lint.py
chmod +x docker_lint.py
```

Or clone:

```bash
git clone git@github.com:realMNohgee/Docker_Lint.git
```

## Usage

### Check — full lint scan

```bash
./docker_lint.py check Dockerfile
./docker_lint.py check Dockerfile --format json
```

### Rules — list all lint rules

```bash
./docker_lint.py rules
./docker_lint.py rules --format json
```

### Score — grade your Dockerfile 0–100

```bash
./docker_lint.py score Dockerfile
```

Grades: **A** (90+), **B** (75–89), **C** (60–74), **D** (40–59), **F** (<40).

### Fix — auto-fix simple issues

```bash
./docker_lint.py fix Dockerfile --dry-run   # preview changes
./docker_lint.py fix Dockerfile             # apply fixes
```

## Rules

| ID | Severity | Rule | Description |
|----|----------|------|-------------|
| DL001 | warning | `no-latest-tag` | FROM should pin a specific version, not `:latest` |
| DL002 | error | `no-root-user` | Container should not run as root |
| DL003 | warning | `apt-no-install-recommends` | apt-get install needs `--no-install-recommends` |
| DL004 | warning | `apt-no-cleanup` | apt-get install should clean up `/var/lib/apt/lists/*` |
| DL005 | warning | `add-instead-of-copy` | Use COPY for local files, ADD only for URLs/tar |
| DL006 | info | `combine-run-layers` | Consecutive RUN layers can be combined with `&&` |
| DL007 | info | `expose-all-ports` | Document your listening ports with EXPOSE |
| DL008 | warning | `no-healthcheck` | Add a HEALTHCHECK for orchestrator monitoring |
| DL009 | error | `env-for-secrets` | Don't use ENV for secrets — use ARG or secrets manager |
| DL010 | warning | `pip-no-cache-dir` | pip install needs `--no-cache-dir` |

## Example Output

```
❌ [DL002] ERROR — global: No USER instruction found — container will run as root by default.
❌ [DL009] ERROR — line 11: ENV 'SECRET_KEY' looks like a secret.
⚠️  [DL001] WARNING — line 2: FROM uses ':latest' tag — pin a specific version instead.
⚠️  [DL003] WARNING — line 5: apt-get install is missing --no-install-recommends.
ℹ️  [DL006] INFO — line 5: Lines 5, 6: 2 consecutive RUN instructions can be combined with &&.

─── 2 error(s), 3 warning(s), 1 info(s) ───
```

## Requirements

- Python 3.9+
- Zero external dependencies

## License

MIT — see [LICENSE](LICENSE).
