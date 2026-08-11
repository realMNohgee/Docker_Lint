#!/usr/bin/env python3
"""
Docker_Lint — Dockerfile best-practice linter.
Catch no-root, no-latest, layer bloat, and security issues.
Zero dependencies — Python stdlib only.
"""

import argparse
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

VERSION = "1.0.0"

# ──────────────────────────────────────────────────────────────
#  Rule definitions
# ──────────────────────────────────────────────────────────────

RULES = OrderedDict([
    ("no-latest-tag", {
        "id": "DL001",
        "name": "no-latest-tag",
        "description": "Avoid using the `latest` tag in FROM instructions — pin a specific version.",
        "severity": "warning",
        "weight": 10,
        "fixable": True,
    }),
    ("no-root-user", {
        "id": "DL002",
        "name": "no-root-user",
        "description": "Do not run as root — add a USER instruction after creating a non-root user.",
        "severity": "error",
        "weight": 15,
        "fixable": False,
    }),
    ("apt-no-install-recommends", {
        "id": "DL003",
        "name": "apt-no-install-recommends",
        "description": "apt-get install should use --no-install-recommends to reduce image size.",
        "severity": "warning",
        "weight": 10,
        "fixable": True,
    }),
    ("apt-no-cleanup", {
        "id": "DL004",
        "name": "apt-no-cleanup",
        "description": "apt-get install should be followed by cleanup (rm -rf /var/lib/apt/lists/*).",
        "severity": "warning",
        "weight": 10,
        "fixable": True,
    }),
    ("add-instead-of-copy", {
        "id": "DL005",
        "name": "add-instead-of-copy",
        "description": "Use COPY instead of ADD for local files — ADD only for remote URLs / tar extraction.",
        "severity": "warning",
        "weight": 10,
        "fixable": True,
    }),
    ("combine-run-layers", {
        "id": "DL006",
        "name": "combine-run-layers",
        "description": "Multiple consecutive RUN instructions can be combined with && to reduce layers.",
        "severity": "info",
        "weight": 5,
        "fixable": False,
    }),
    ("expose-all-ports", {
        "id": "DL007",
        "name": "expose-all-ports",
        "description": "EXPOSE the ports your application listens on for documentation purposes.",
        "severity": "info",
        "weight": 5,
        "fixable": False,
    }),
    ("no-healthcheck", {
        "id": "DL008",
        "name": "no-healthcheck",
        "description": "Add a HEALTHCHECK instruction so the orchestrator knows when the container is healthy.",
        "severity": "warning",
        "weight": 10,
        "fixable": False,
    }),
    ("env-for-secrets", {
        "id": "DL009",
        "name": "env-for-secrets",
        "description": "Do not use ENV for secrets — use ARG (build-time) or a secrets manager (runtime).",
        "severity": "error",
        "weight": 15,
        "fixable": False,
    }),
    ("pip-no-cache-dir", {
        "id": "DL010",
        "name": "pip-no-cache-dir",
        "description": "pip install should use --no-cache-dir to avoid caching in the image layer.",
        "severity": "warning",
        "weight": 10,
        "fixable": True,
    }),
])


# ──────────────────────────────────────────────────────────────
#  Dockerfile parsing helpers
# ──────────────────────────────────────────────────────────────


def parse_dockerfile(path):
    """Parse a Dockerfile into a list of (line_number, raw_line, instruction, args)."""
    instructions = []
    content = Path(path).read_text()
    continuation = ""
    continuation_start = 0

    for i, raw in enumerate(content.splitlines(), 1):
        line = raw.rstrip()

        # Handle line continuations (trailing backslash)
        if continuation:
            continuation += " " + line.rstrip("\\").strip()
            if not line.endswith("\\"):
                # Continuation ended
                instr, args = _split_instruction(continuation)
                instructions.append((continuation_start, continuation, instr, args))
                continuation = ""
                continuation_start = 0
            continue

        if line.endswith("\\"):
            continuation = line.rstrip("\\").strip()
            continuation_start = i
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            instructions.append((i, raw, "COMMENT" if stripped.startswith("#") else "EMPTY", stripped))
            continue

        instr, args = _split_instruction(stripped)
        instructions.append((i, raw, instr, args))

    # Unfinished continuation
    if continuation:
        instr, args = _split_instruction(continuation)
        instructions.append((continuation_start, continuation, instr, args))

    return instructions


def _split_instruction(line):
    """Split a Dockerfile instruction line into (INSTRUCTION, args)."""
    parts = line.split(None, 1)
    instruction = parts[0].upper() if parts else ""
    args = parts[1] if len(parts) > 1 else ""
    return instruction, args


# ──────────────────────────────────────────────────────────────
#  Lint rules
# ──────────────────────────────────────────────────────────────


def _find_secret_env_names():
    """Return a set of env var names that look like secrets."""
    secret_patterns = [
        r"(?i).*secret.*",
        r"(?i).*password.*",
        r"(?i).*passwd.*",
        r"(?i).*token.*",
        r"(?i).*api[_-]?key.*",
        r"(?i).*private[_-]?key.*",
        r"(?i).*credential.*",
        r"(?i).*auth[_-]?token.*",
        r"(?i).*access[_-]?key.*",
        r"(?i).*db[_-]?pass.*",
        r"(?i).*database[_-]?url.*",
    ]
    return secret_patterns


def check_no_latest_tag(instructions):
    """DL001: FROM should not use the `latest` tag."""
    findings = []
    for lineno, raw, instr, args in instructions:
        if instr != "FROM":
            continue
        # Match FROM <image> or FROM <image>:<tag> or FROM --platform=... <image>
        image_part = args.split()[-1] if args else ""
        if ":" in image_part:
            tag = image_part.split(":")[-1]
            if tag == "latest":
                findings.append({
                    "rule_id": "DL001",
                    "rule": "no-latest-tag",
                    "severity": "warning",
                    "line": lineno,
                    "message": f"FROM uses ':latest' tag — pin a specific version instead.",
                    "snippet": raw.strip(),
                })
        # No tag at all defaults to latest — also flag
        elif image_part and "/" in image_part or image_part and not any(
            c in image_part for c in [":", "@"]
        ):
            # Check if it's a digest reference
            if "@" not in args:
                findings.append({
                    "rule_id": "DL001",
                    "rule": "no-latest-tag",
                    "severity": "warning",
                    "line": lineno,
                    "message": f"FROM has no explicit tag (defaults to ':latest') — pin a version.",
                    "snippet": raw.strip(),
                })
    return findings


def check_no_root_user(instructions):
    """DL002: USER should not be root."""
    findings = []
    has_user = False
    last_user_line = 0
    last_user_value = ""

    for lineno, raw, instr, args in instructions:
        if instr == "USER":
            has_user = True
            last_user_line = lineno
            last_user_value = args.strip()

    if not has_user:
        findings.append({
            "rule_id": "DL002",
            "rule": "no-root-user",
            "severity": "error",
            "line": 0,
            "message": "No USER instruction found — container will run as root by default.",
            "snippet": "(none)",
        })
    elif last_user_value in ("root", "0"):
        findings.append({
            "rule_id": "DL002",
            "rule": "no-root-user",
            "severity": "error",
            "line": last_user_line,
            "message": "USER is set to 'root' — switch to a non-root user.",
            "snippet": f"USER {last_user_value}",
        })

    return findings


def check_apt_no_install_recommends(instructions):
    """DL003: apt-get install should use --no-install-recommends."""
    findings = []
    for lineno, raw, instr, args in instructions:
        if instr != "RUN":
            continue
        if re.search(r"apt(?:-get)?\s+install\b", args) and "--no-install-recommends" not in args:
            findings.append({
                "rule_id": "DL003",
                "rule": "apt-no-install-recommends",
                "severity": "warning",
                "line": lineno,
                "message": "apt-get install is missing --no-install-recommends.",
                "snippet": raw.strip()[:120],
            })
    return findings


def check_apt_no_cleanup(instructions):
    """DL004: apt-get install should be followed by cleanup."""
    findings = []
    for i, (lineno, raw, instr, args) in enumerate(instructions):
        if instr != "RUN":
            continue
        if not re.search(r"apt(?:-get)?\s+install\b", args):
            continue

        # Check this RUN line and the next line for cleanup
        combined = args
        if i + 1 < len(instructions) and instructions[i + 1][2] == "RUN":
            combined += " " + instructions[i + 1][3]

        cleanup_patterns = [
            r"rm\s+-rf\s+/var/lib/apt/lists/\*",
            r"apt(?:-get)?\s+(?:clean|autoclean|purge)",
            r"rm\s+-rf\s+/var/cache/apt",
        ]
        has_cleanup = any(re.search(p, combined) for p in cleanup_patterns)

        if not has_cleanup:
            findings.append({
                "rule_id": "DL004",
                "rule": "apt-no-cleanup",
                "severity": "warning",
                "line": lineno,
                "message": "apt-get install should include cleanup (rm -rf /var/lib/apt/lists/*) in the same layer.",
                "snippet": raw.strip()[:120],
            })
    return findings


def check_add_instead_of_copy(instructions):
    """DL005: Use COPY instead of ADD for local files."""
    findings = []
    for lineno, raw, instr, args in instructions:
        if instr != "ADD":
            continue
        # ADD with a URL or tar archive is fine; flag local paths
        parts = args.split()
        if len(parts) >= 1:
            src = parts[0]
            # If source is a URL, ADD is appropriate
            if src.startswith(("http://", "https://")):
                continue
            # If source looks like a tar archive that needs extraction, ADD might be intentional
            if src.endswith((".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2")):
                continue
            findings.append({
                "rule_id": "DL005",
                "rule": "add-instead-of-copy",
                "severity": "warning",
                "line": lineno,
                "message": "Use COPY instead of ADD for local files — ADD only for remote URLs or tar extraction.",
                "snippet": raw.strip()[:120],
            })
    return findings


def check_combine_run_layers(instructions):
    """DL006: Consecutive RUN instructions can be combined."""
    findings = []
    run_indices = []
    for idx, (lineno, raw, instr, args) in enumerate(instructions):
        if instr == "RUN":
            run_indices.append(idx)

    # Find consecutive RUNs
    i = 0
    while i < len(run_indices) - 1:
        group_start = run_indices[i]
        group = [group_start]
        j = i + 1
        while j < len(run_indices) and run_indices[j] == run_indices[j - 1] + 1:
            group.append(run_indices[j])
            j += 1

        if len(group) >= 2:
            lines = [instructions[idx][0] for idx in group]
            findings.append({
                "rule_id": "DL006",
                "rule": "combine-run-layers",
                "severity": "info",
                "line": lines[0],
                "message": f"Lines {', '.join(map(str, lines))}: {len(group)} consecutive RUN instructions can be combined with && to reduce layers.",
                "snippet": instructions[group[0]][1].strip()[:120],
            })
        i = j if j > i + 1 else i + 1

    return findings


def check_expose_all_ports(instructions):
    """DL007: Flag if EXPOSE is missing entirely or note what's exposed."""
    findings = []
    expose_lines = []
    for lineno, raw, instr, args in instructions:
        if instr == "EXPOSE":
            expose_lines.append(lineno)

    if not expose_lines:
        findings.append({
            "rule_id": "DL007",
            "rule": "expose-all-ports",
            "severity": "info",
            "line": 0,
            "message": "No EXPOSE instruction found — document your listening ports.",
            "snippet": "(none)",
        })
    return findings


def check_no_healthcheck(instructions):
    """DL008: HEALTHCHECK should be present."""
    findings = []
    has_healthcheck = False
    for lineno, raw, instr, args in instructions:
        if instr == "HEALTHCHECK":
            has_healthcheck = True

    if not has_healthcheck:
        findings.append({
            "rule_id": "DL008",
            "rule": "no-healthcheck",
            "severity": "warning",
            "line": 0,
            "message": "No HEALTHCHECK instruction found — add one so the orchestrator can monitor container health.",
            "snippet": "(none)",
        })
    return findings


def check_env_for_secrets(instructions):
    """DL009: ENV should not be used for secret values."""
    findings = []
    secret_patterns = _find_secret_env_names()

    for lineno, raw, instr, args in instructions:
        if instr != "ENV":
            continue
        # ENV can be KEY value or KEY=value
        parts = args.split(None, 1)
        if parts:
            key = parts[0].split("=")[0].strip()
            for pat in secret_patterns:
                if re.match(pat, key):
                    findings.append({
                        "rule_id": "DL009",
                        "rule": "env-for-secrets",
                        "severity": "error",
                        "line": lineno,
                        "message": f"ENV '{key}' looks like a secret — use ARG (build-time) or a secrets manager instead.",
                        "snippet": raw.strip()[:120],
                    })
                    break
    return findings


def check_pip_no_cache_dir(instructions):
    """DL010: pip install should use --no-cache-dir."""
    findings = []
    for lineno, raw, instr, args in instructions:
        if instr != "RUN":
            continue
        # Check for pip install patterns
        pip_patterns = [
            r"\bpip3?\s+install\b",
            r"\bpip\s+install\b",
            r"\bpip3?\s+install\b",
        ]
        has_pip = any(re.search(p, args) for p in pip_patterns)
        if has_pip and "--no-cache-dir" not in args:
            findings.append({
                "rule_id": "DL010",
                "rule": "pip-no-cache-dir",
                "severity": "warning",
                "line": lineno,
                "message": "pip install is missing --no-cache-dir — add it to avoid caching in the image layer.",
                "snippet": raw.strip()[:120],
            })
    return findings


# Collect all check functions
_CHECKS = [
    check_no_latest_tag,
    check_no_root_user,
    check_apt_no_install_recommends,
    check_apt_no_cleanup,
    check_add_instead_of_copy,
    check_combine_run_layers,
    check_expose_all_ports,
    check_no_healthcheck,
    check_env_for_secrets,
    check_pip_no_cache_dir,
]


# ──────────────────────────────────────────────────────────────
#  Score calculation
# ──────────────────────────────────────────────────────────────


def calculate_score(findings):
    """Calculate an overall score 0-100 based on findings."""
    total_weight = sum(r["weight"] for r in RULES.values())
    penalty = 0

    # Group findings by rule — each rule can only penalize once
    rules_triggered = set()
    for f in findings:
        if f["rule_id"] not in rules_triggered:
            rules_triggered.add(f["rule_id"])
            rule = None
            for r in RULES.values():
                if r["id"] == f["rule_id"]:
                    rule = r
                    break
            if rule:
                penalty += rule["weight"]

    score = max(0, 100 - (penalty / total_weight) * 100)
    return round(score, 1)


# ──────────────────────────────────────────────────────────────
#  Fix logic
# ──────────────────────────────────────────────────────────────


def fix_dockerfile(instructions, path, dry_run=False):
    """Auto-fix simple issues in the Dockerfile. Returns list of changes and the fixed content."""
    content = Path(path).read_text()
    lines = content.splitlines()
    changes = []
    new_lines = list(lines)

    # We need to apply fixes bottom-up to preserve line numbers
    fixes_by_line = {}

    for lineno, raw, instr, args in instructions:
        if instr != "RUN":
            continue

        # DL003: Add --no-install-recommends to apt-get install
        if re.search(r"apt(?:-get)?\s+install\b", args) and "--no-install-recommends" not in args:
            old_line = raw
            # Insert --no-install-recommends after 'install'
            new_line = re.sub(
                r"(apt(?:-get)?\s+install)\b",
                r"\1 --no-install-recommends",
                raw,
                count=1,
            )
            if new_line != old_line:
                fixes_by_line[lineno] = new_line
                changes.append({
                    "line": lineno,
                    "rule": "DL003",
                    "description": "Added --no-install-recommends to apt-get install",
                })

        # DL010: Add --no-cache-dir to pip install
        pip_patterns = [r"\bpip3?\s+install\b", r"\bpip\s+install\b"]
        has_pip = any(re.search(p, args) for p in pip_patterns)
        if has_pip and "--no-cache-dir" not in args:
            current = fixes_by_line.get(lineno, raw)
            new_line = re.sub(
                r"(pip3?\s+install)\b",
                r"\1 --no-cache-dir",
                current,
                count=1,
            )
            if new_line != current:
                fixes_by_line[lineno] = new_line
                changes.append({
                    "line": lineno,
                    "rule": "DL010",
                    "description": "Added --no-cache-dir to pip install",
                })

    # DL005: Convert ADD to COPY for local files
    for lineno, raw, instr, args in instructions:
        if instr != "ADD":
            continue
        parts = args.split()
        if parts:
            src = parts[0]
            if src.startswith(("http://", "https://")):
                continue
            if src.endswith((".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2")):
                continue
            # Convert ADD to COPY
            current = fixes_by_line.get(lineno, raw)
            new_line = current.replace("ADD ", "COPY ", 1) if current.startswith("ADD ") else current
            if new_line != current:
                fixes_by_line[lineno] = new_line
                changes.append({
                    "line": lineno,
                    "rule": "DL005",
                    "description": "Converted ADD to COPY for local file",
                })

    # Apply fixes to lines (descending order to preserve indices)
    for lineno in sorted(fixes_by_line.keys(), reverse=True):
        new_lines[lineno - 1] = fixes_by_line[lineno]

    if dry_run:
        return changes, None

    # Write back
    new_content = "\n".join(new_lines) + ("\n" if content.endswith("\n") else "")
    Path(path).write_text(new_content)
    return changes, new_content


# ──────────────────────────────────────────────────────────────
#  Subcommands
# ──────────────────────────────────────────────────────────────


def cmd_check(args):
    """Run all lint checks on a Dockerfile."""
    path = Path(args.dockerfile)
    if not path.exists():
        print(f"Error: {args.dockerfile} not found.", file=sys.stderr)
        sys.exit(1)

    instructions = parse_dockerfile(path)
    all_findings = []
    for check_fn in _CHECKS:
        all_findings.extend(check_fn(instructions))

    if args.format == "json":
        output = {
            "file": str(path.resolve()),
            "total_findings": len(all_findings),
            "findings": all_findings,
        }
        print(json.dumps(output, indent=2))
    else:
        if not all_findings:
            print(f"No issues found in {args.dockerfile}")
        else:
            # Group by severity
            severity_order = {"error": 0, "warning": 1, "info": 2}
            all_findings.sort(key=lambda f: severity_order.get(f["severity"], 3))

            for f in all_findings:
                icon = {"error": "❌", "warning": "⚠️ ", "info": "ℹ️ "}.get(f["severity"], "  ")
                line_info = f"line {f['line']}" if f["line"] else "global"
                print(f"{icon} [{f['rule_id']}] {f['severity'].upper()} — {line_info}: {f['message']}")

            # Summary
            errors = sum(1 for f in all_findings if f["severity"] == "error")
            warnings = sum(1 for f in all_findings if f["severity"] == "warning")
            infos = sum(1 for f in all_findings if f["severity"] == "info")
            print(f"\n─── {errors} error(s), {warnings} warning(s), {infos} info(s) ───")

    return all_findings


def cmd_rules(args):
    """List all lint rules."""
    if args.format == "json":
        print(json.dumps(list(RULES.values()), indent=2))
    else:
        print(f"{'ID':<8} {'Severity':<10} {'Rule':<35} Description")
        print("-" * 100)
        for rule in RULES.values():
            print(f"{rule['id']:<8} {rule['severity']:<10} {rule['name']:<35} {rule['description']}")


def cmd_score(args):
    """Score a Dockerfile 0-100."""
    path = Path(args.dockerfile)
    if not path.exists():
        print(f"Error: {args.dockerfile} not found.", file=sys.stderr)
        sys.exit(1)

    instructions = parse_dockerfile(path)
    all_findings = []
    for check_fn in _CHECKS:
        all_findings.extend(check_fn(instructions))

    score = calculate_score(all_findings)

    if args.format == "json":
        output = {
            "file": str(path.resolve()),
            "score": score,
            "max_score": 100,
            "findings_count": len(all_findings),
        }
        print(json.dumps(output, indent=2))
    else:
        # Grade
        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        print(f"\n  Score: {score}/100  ({grade})")
        print(f"  Issues found: {len(all_findings)}")
        print(f"  File: {path.resolve()}\n")

    return score


def cmd_fix(args):
    """Auto-fix simple issues in a Dockerfile."""
    path = Path(args.dockerfile)
    if not path.exists():
        print(f"Error: {args.dockerfile} not found.", file=sys.stderr)
        sys.exit(1)

    instructions = parse_dockerfile(path)
    changes, new_content = fix_dockerfile(instructions, path, dry_run=args.dry_run)

    if args.format == "json":
        output = {
            "file": str(path.resolve()),
            "dry_run": args.dry_run,
            "changes_count": len(changes),
            "changes": changes,
        }
        print(json.dumps(output, indent=2))
    else:
        if not changes:
            print("No auto-fixable issues found.")
        elif args.dry_run:
            print(f"Would make {len(changes)} change(s) (dry-run):")
            for c in changes:
                print(f"  - Line {c['line']}: [{c['rule']}] {c['description']}")
        else:
            print(f"Applied {len(changes)} fix(es):")
            for c in changes:
                print(f"  - Line {c['line']}: [{c['rule']}] {c['description']}")

    return changes


# ──────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        prog="docker_lint",
        description="Docker_Lint — Dockerfile best-practice linter. Zero dependencies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  docker_lint check Dockerfile
  docker_lint rules
  docker_lint score Dockerfile
  docker_lint fix Dockerfile --dry-run
  docker_lint check Dockerfile --format json
        """,
    )
    parser.add_argument("--version", action="version", version=f"Docker_Lint {VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # check
    p_check = subparsers.add_parser("check", help="Lint a Dockerfile with all rules")
    p_check.add_argument("dockerfile", help="Path to Dockerfile")
    p_check.add_argument("--format", choices=["text", "json"], default="text",
                         help="Output format (default: text)")

    # rules
    p_rules = subparsers.add_parser("rules", help="List all lint rules")
    p_rules.add_argument("--format", choices=["text", "json"], default="text",
                         help="Output format (default: text)")

    # score
    p_score = subparsers.add_parser("score", help="Score a Dockerfile 0-100")
    p_score.add_argument("dockerfile", help="Path to Dockerfile")
    p_score.add_argument("--format", choices=["text", "json"], default="text",
                         help="Output format (default: text)")

    # fix
    p_fix = subparsers.add_parser("fix", help="Auto-fix simple Dockerfile issues")
    p_fix.add_argument("dockerfile", help="Path to Dockerfile")
    p_fix.add_argument("--dry-run", action="store_true",
                       help="Show what would change without writing")
    p_fix.add_argument("--format", choices=["text", "json"], default="text",
                       help="Output format (default: text)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "check":
        cmd_check(args)
    elif args.command == "rules":
        cmd_rules(args)
    elif args.command == "score":
        cmd_score(args)
    elif args.command == "fix":
        cmd_fix(args)


if __name__ == "__main__":
    main()
