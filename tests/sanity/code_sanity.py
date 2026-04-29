#!/usr/bin/env python3
# Copyright 2019-2026 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries

"""
Executes checks on the codebase to ensure it meets the standards.
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from pprint import pformat
from shutil import which

COPYRIGHT_EXCLUDES = [
    # Exact file names or paths
    ".gitignore",
    "COPYING",
    "LICENSE",
    # Regex patterns
    re.compile(r".*\.rst$"),
    re.compile(r"LICENSES/.*"),
]

# Warnings overrides: Ruff rules that should be treated as warnings instead of errors
RUFF_WARNING_RULES = {
    "S",  # flake8-bandit (security checks)
    "SIM",  # flake8-simplify (style suggestions)
    "F841",  # unused variable
    "B007",  # unused loop variable
    "B905",  # zip without strict
    "N",  # pep8-naming (legacy camelCase in Brocade API utils)
    "PTH",  # flake8-use-pathlib (modernization, not a bug)
}

# Rules enforced even when their prefix is in RUFF_WARNING_RULES
RUFF_ENFORCED_OVERRIDES = {
    "SIM103",  # return condition directly
    "SIM108",  # use ternary operator
    "SIM115",  # use context manager for opening files (prevents resource leaks)
    "SIM201",  # use != instead of not == (auto-fixable, clear improvement)
}

# ANSI color codes (disabled if NO_COLOR is set)
_NO_COLOR = os.environ.get("NO_COLOR", "").strip().lower() in ("1", "true", "yes")
_RESET = "\033[0m" if not _NO_COLOR else ""
_CYAN = "\033[36m" if not _NO_COLOR else ""
_GREEN = "\033[32m" if not _NO_COLOR else ""
_YELLOW = "\033[33m" if not _NO_COLOR else ""
_RED = "\033[31m" if not _NO_COLOR else ""
_BOLD = "\033[1m" if not _NO_COLOR else ""

# Timestamp format for log formatters: YYYYMMDD-HHMMSS
_LOG_DATEFMT = "%Y%m%d-%H%M%S"

# Timeout in seconds for each linter (ansible-lint in collection repos can be slow)
LINTER_TIMEOUT = 300


class ColoredFormatter(logging.Formatter):
    """Format log messages with level-based colors for console."""

    LEVEL_COLORS = {
        logging.DEBUG: _CYAN,
        logging.INFO: _GREEN,
        logging.WARNING: _YELLOW,
        logging.ERROR: _RED,
        logging.CRITICAL: _BOLD + _RED,
    }

    def __init__(self, fmt: str = "%(asctime)s %(message)s", datefmt: str | None = _LOG_DATEFMT, **kwargs):  # noqa: ANN003
        super().__init__(fmt, datefmt=datefmt, **kwargs)

    def format(self, record: logging.LogRecord) -> str:
        color = self.LEVEL_COLORS.get(record.levelno, _RESET)
        msg = super().format(record)
        if color:
            return f"{color}{msg}{_RESET}"
        return msg


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure colored console logging and a timestamped log file. Returns the module logger."""
    log = logging.getLogger(__name__)
    if log.handlers:
        return log
    log.setLevel(logging.DEBUG)

    # Log file in same directory as script: tests/sanity/code_sanity_<timestamp>.log
    script_dir = Path(__file__).resolve().parent
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = script_dir / f"code_sanity_{timestamp}.log"
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt=_LOG_DATEFMT))
    log.addHandler(file_handler)

    # Stdout: INFO and WARNING (and DEBUG when verbose)
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_handler.addFilter(lambda r: r.levelno < logging.ERROR)
    stdout_handler.setFormatter(ColoredFormatter("%(asctime)s %(message)s"))
    log.addHandler(stdout_handler)

    # Stderr: ERROR and CRITICAL
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.ERROR)
    stderr_handler.setFormatter(ColoredFormatter("%(asctime)s %(message)s"))
    log.addHandler(stderr_handler)

    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    return log


def check_dependencies(log: logging.Logger) -> None:
    """Check that ruff and ansible-lint are available. Exit with error message if not."""
    missing = []
    if not which("ruff"):
        missing.append("ruff")
    if not which("ansible-lint"):
        missing.append("ansible-lint")
    if missing:
        log.error(f"Required tools not found. Install missing packages with:\n  pip install {' '.join(missing)}")
        sys.exit(2)

    if sys.prefix != sys.base_prefix:
        log.debug(f"Python virtual env in being used: {sys.prefix}")
        python_path = sys.prefix
    else:
        python_path = sys.base_prefix

    return {"ansible-lint": which("ansible-lint"), "ruff": which("ruff"), "python": f"{python_path}/bin/python"}


def find_repo_root(start: Path) -> Path:
    """Find repository root (directory containing .git or .ansible-lint or galaxy.yml)."""
    current = start.resolve()
    for _ in range(20):
        if (current / ".git").exists():
            return current
        if (current / ".ansible-lint").exists():
            return current
        if (current / "galaxy.yml").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return start.resolve()


def collect_files(path: Path, repo_root: Path) -> tuple[list[Path], list[Path]]:
    """Return (py_files, yaml_files) under path (file or directory), paths relative to repo_root."""
    path = path.resolve()
    py_files: list[Path] = []
    yaml_files: list[Path] = []

    try:
        path = path.resolve()
        path.relative_to(repo_root)
    except ValueError:
        return py_files, yaml_files

    if path.is_file():
        try:
            rel = path.relative_to(repo_root)
        except ValueError:
            return py_files, yaml_files
        if path.suffix == ".py":
            py_files.append(rel)
        elif path.suffix in (".yml", ".yaml"):
            yaml_files.append(rel)
        return py_files, yaml_files

    for f in path.rglob("*"):
        if any(part.startswith(".") for part in f.parts):
            continue

        if not f.is_file():
            continue
        try:
            rel = f.relative_to(repo_root)
        except ValueError:
            continue
        if rel.suffix == ".py":
            py_files.append(rel)
        elif rel.suffix in (".yml", ".yaml"):
            yaml_files.append(rel)

    return py_files, yaml_files


def run_ruff(**kwargs) -> tuple[list[dict], int]:
    """
    Run ruff format (if fix=True) and then ruff check on paths. Return (list of violation dicts, exit_code)
    """
    repo_root = kwargs["repo"]
    paths = kwargs["files"]
    fix = kwargs["fix"]
    verbose = kwargs["verbose"]
    if not paths:
        return [], 0

    full_paths = [str(repo_root / p) for p in paths]
    log = logging.getLogger(__name__)

    # Run formatter first if we are fixing
    if fix:
        fmt_cmd = ["ruff", "format"] + full_paths
        if verbose:
            log.info(f"Running: {' '.join(fmt_cmd)}")
        try:
            subprocess.run(
                fmt_cmd,
                cwd=repo_root,
                capture_output=True,
                text=True,
                timeout=LINTER_TIMEOUT,
            )
        except FileNotFoundError:
            log.error("Ruff not found. Install it with: pip install ruff")
            return [], 2
        except subprocess.TimeoutExpired:
            log.error("Ruff format timed out.")
            return [], -1

    # Run linter
    cmd = [
        "ruff",
        "check",
        "--output-format",
        "json",
    ]
    if fix:
        cmd.append("--fix")
    cmd.extend(full_paths)

    if verbose:
        log.info(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=LINTER_TIMEOUT,
        )
    except FileNotFoundError:
        logging.getLogger(__name__).error("Ruff not found. Install it with: pip install ruff")
        return [], 2
    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).error("Ruff timed out.")
        return [], -1

    violations = []
    if result.stdout.strip():
        try:
            data = json.loads(result.stdout)
            if isinstance(data, list):
                violations = data
            elif isinstance(data, dict) and "messages" in data:
                violations = data["messages"]
        except json.JSONDecodeError:
            pass

    out = []
    fixed = []
    for v in violations:
        filename = v.get("filename", "")
        if filename and repo_root:
            try:
                p = Path(filename).resolve().relative_to(repo_root)
                filename = str(p)
            except (ValueError, TypeError):
                pass
        loc = v.get("location", {}) or v.get("end_location", {})
        row = loc.get("row") if isinstance(loc, dict) else None
        fix_info = v.get("fix")
        suggested = (fix_info.get("message") if isinstance(fix_info, dict) else None) or "—"

        rule_code = v.get("code", "")
        severity = v.get("severity", "Error")
        if isinstance(severity, dict):
            severity = severity.get("name", "Error")

        # Downgrade specific rules to warnings (unless in enforced overrides)
        is_warning_override = (
            any(rule_code.startswith(prefix) for prefix in RUFF_WARNING_RULES)
            and rule_code not in RUFF_ENFORCED_OVERRIDES
        )
        if is_warning_override:
            violation_type = "Warning"
        else:
            violation_type = "Error" if severity and "Error" in str(severity) else "Warning"

        violation_data = {
            "violation_type": violation_type,
            "violation": rule_code,
            "description": v.get("message", "—"),
            "file_path": filename,
            "line": row,
            "suggested_fix": suggested,
        }

        if fix and fix_info and fix_info.get("is_fixed", False) or fix and v.get("status") == "fixed":
            fixed.append(violation_data)
        else:
            out.append(violation_data)

    if fix:
        return fixed, 0

    if any(v.get("violation_type") == "Error" for v in out):
        rc_code = 1
        logging.getLogger(__name__).error("Ruff violations seen")
    elif result.returncode != 0:
        rc_code = result.returncode
        logging.getLogger(__name__).error(f"Ruff exited with code {rc_code}")
        if result.stderr:
            logging.getLogger(__name__).error(f"Ruff stderr: {result.stderr.strip()}")
    else:
        rc_code = 0
    return out, rc_code


def run_ansible_lint(**kwargs) -> tuple[list[dict], int]:
    """
    Run ansible-lint on paths. Return (list of violation dicts, exit_code).
    """
    repo_root = kwargs["repo"]
    paths = kwargs["files"]
    fix = kwargs["fix"]
    verbose = kwargs["verbose"]

    if not paths:
        return [], 0
    cmd = [
        "ansible-lint",
        "-f",
        "json",
        "--config-file",
        f"{repo_root}/.ansible-lint",
        "--profile",
        "production",
        "--offline",
    ]
    if fix:
        cmd.append("--fix")
    full_paths = [str(repo_root / p) for p in paths]
    cmd.extend(full_paths)
    if verbose:
        log = logging.getLogger(__name__)
        log.debug(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=LINTER_TIMEOUT,
        )
    except FileNotFoundError:
        logging.getLogger(__name__).error("Ansible-lint not found. Install it with: pip install ansible-lint")
        return [], 2
    except subprocess.TimeoutExpired:
        logging.getLogger(__name__).error(f"Ansible-lint timed out after {LINTER_TIMEOUT}")
        return [], -1

    violations = []
    if result.stdout.strip():
        try:
            data = json.loads(result.stdout)
            if isinstance(data, list):
                violations = data
            elif isinstance(data, dict) and "files" in data:
                for file_data in data.get("files", {}).values():
                    if isinstance(file_data, dict) and "matches" in file_data:
                        violations.extend(file_data["matches"])
            elif isinstance(data, dict) and "matches" in data:
                violations = data["matches"]
        except json.JSONDecodeError:
            pass

    out = []
    fixed = []
    for v in violations:
        if isinstance(v, dict):
            loc = v.get("location", v.get("position", {}))
            path = loc.get("path", loc.get("filename", "")) if isinstance(loc, dict) else ""
            lines = loc.get("lines", loc) if isinstance(loc, dict) else {}
            if isinstance(lines, dict):
                line = lines.get("begin", lines.get("start", ""))
            else:
                line = getattr(loc, "line", "") if hasattr(loc, "line") else ""
            if path and repo_root:
                try:
                    p = Path(path).resolve().relative_to(repo_root)
                    path = str(p)
                except (ValueError, TypeError):
                    pass
            rule = v.get("rule", v.get("ruleId", v.get("check_name", "")))
            if isinstance(rule, dict):
                rule = rule.get("id", rule.get("name", ""))
            severity = v.get("severity", v.get("type", "warning"))
            if isinstance(severity, dict):
                severity = severity.get("name", "warning")
            violation_type = "Error" if str(severity).lower() in ("error", "major", "critical") else "Warning"
            desc = v.get("message", v.get("description", "—"))
            fix_hint = v.get("fix", v.get("remediation_points"))
            suggested = "—"
            if isinstance(fix_hint, dict) and fix_hint.get("message"):
                suggested = fix_hint["message"]
            elif isinstance(fix_hint, str):
                suggested = fix_hint

            violation_data = {
                "violation_type": violation_type,
                "violation": str(rule),
                "description": str(desc)[:200] if desc else "—",
                "file_path": path or "—",
                "line": line,
                "suggested_fix": suggested,
            }

            if fix and v.get("status") == "fixed":
                fixed.append(violation_data)
            else:
                out.append(violation_data)

    if fix:
        return fixed, 0

    if result.returncode != 0:
        rc_code = result.returncode
        logging.getLogger(__name__).error(f"ansible-lint exited with code {rc_code}")
        if result.stderr:
            logging.getLogger(__name__).error(f"ansible-lint stderr: {result.stderr.strip()}")
    elif out:
        rc_code = 1
        logging.getLogger(__name__).error("ansible-lint violations seen")
    else:
        rc_code = 0

    return out, rc_code


def run_copyright_check(repo_root: Path, files: list[Path], fix: bool = False) -> tuple[list[dict], int]:
    """
    Check files for correct copyright statement and year.
    If fix=True, attempts to add/update the copyright statement.
    Returns (list of violation dicts, exit_code).
    """
    out = []
    fixed = []
    rc_code = 0
    current_year = datetime.now().year

    # Pattern looks for "Copyright [optional start year-]end year Broadcom"
    # e.g. "Copyright 2019-2026 Broadcom" or "Copyright 2026 Broadcom"
    pattern_any = re.compile(r"Copyright\s+(?:\d{4}-)?\d{4}\s+(?:Broadcom|Brocade)", re.IGNORECASE)
    pattern_correct = re.compile(rf"Copyright\s+(?:\d{{4}}-)?{current_year}\s+Broadcom", re.IGNORECASE)

    copyright_text = (
        f"# Copyright 2019-{current_year} Broadcom. All rights reserved.\n"
        "# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries\n"
    )

    for p in files:
        filename = str(p)

        is_excluded = False
        for exc in COPYRIGHT_EXCLUDES:
            if isinstance(exc, str):
                if filename == exc or filename.endswith("/" + exc):
                    is_excluded = True
                    break
            elif hasattr(exc, "search") and exc.search(filename):
                is_excluded = True
                break

        if is_excluded:
            if not fix:
                out.append(
                    {
                        "violation_type": "Warning",
                        "violation": "copyright[excluded]",
                        "description": "File excluded from copyright check",
                        "file_path": filename,
                        "line": "—",
                        "suggested_fix": "—",
                    }
                )
            continue

        full_path = repo_root / p
        try:
            content = full_path.read_text(encoding="utf-8")
        except Exception as e:
            if not fix:
                out.append(
                    {
                        "violation_type": "Error",
                        "violation": "copyright[read_error]",
                        "description": f"Could not read file: {e}",
                        "file_path": filename,
                        "line": "—",
                        "suggested_fix": "—",
                    }
                )
                rc_code = 1
            continue

        if not pattern_any.search(content):
            if fix:
                lines = content.splitlines(keepends=True)
                if filename.endswith(".py"):
                    if len(lines) > 0 and lines[0].startswith("#!"):
                        lines.insert(1, copyright_text + "\n")
                    else:
                        lines.insert(0, copyright_text + "\n")
                elif filename.endswith((".yml", ".yaml")):
                    if len(lines) > 0 and lines[0].startswith("---"):
                        lines.insert(1, copyright_text + "\n")
                    else:
                        lines.insert(0, copyright_text + "\n")
                else:
                    lines.insert(0, copyright_text + "\n")
                full_path.write_text("".join(lines), encoding="utf-8")
                fixed.append(
                    {
                        "violation_type": "Fixed",
                        "violation": "copyright[missing]",
                        "description": "Missing copyright statement",
                        "file_path": filename,
                        "line": "1",
                        "suggested_fix": "Added copyright statement",
                    }
                )
            else:
                out.append(
                    {
                        "violation_type": "Error",
                        "violation": "copyright[missing]",
                        "description": "Missing copyright statement",
                        "file_path": filename,
                        "line": "—",
                        "suggested_fix": f"Add: Copyright {current_year} Broadcom. All rights reserved.",
                    }
                )
                rc_code = 1
        elif not pattern_correct.search(content):
            if fix:
                # Replace the old copyright line with the new one
                new_content = pattern_any.sub(f"Copyright 2019-{current_year} Broadcom", content)
                full_path.write_text(new_content, encoding="utf-8")
                fixed.append(
                    {
                        "violation_type": "Fixed",
                        "violation": "copyright[outdated]",
                        "description": f"Copyright year is not {current_year}",
                        "file_path": filename,
                        "line": "—",
                        "suggested_fix": f"Updated year to {current_year}",
                    }
                )
            else:
                out.append(
                    {
                        "violation_type": "Error",
                        "violation": "copyright[outdated]",
                        "description": f"Copyright year is not {current_year}",
                        "file_path": filename,
                        "line": "—",
                        "suggested_fix": f"Update year to {current_year}",
                    }
                )
                rc_code = 1

    if fix:
        return fixed, 0

    return out, rc_code


def sort_key(row: dict) -> tuple[int, str, str]:
    """Sort by violation_type (errors first), then file_path, then line."""
    order = 0 if row.get("violation_type") == "Error" else 1
    return (order, str(row.get("file_path", "")), str(row.get("line", "")))


def format_table(rows: list[dict]) -> list[str]:
    """Format rows as a markdown-style table. Returns list of lines."""
    if not rows:
        return []
    columns = ["violation_type", "violation", "description", "file_path", "line", "suggested_fix"]
    headers = ["Violation type", "Violation", "Violation description", "File path", "Line(s)", "Suggested fix"]
    widths = [len(h) for h in headers]
    for r in rows:
        for i, col in enumerate(columns):
            val = str(r.get(col, ""))[:60]
            widths[i] = max(widths[i], len(val))
    fmt = "\u2502 " + " \u2502 ".join(f"{{:<{w}}}" for w in widths) + " \u2502"
    sep = "\u2502 " + " \u2502 ".join("\u2500" * w for w in widths) + " \u2502"
    lines = [fmt.format(*headers), sep]
    for r in rows:
        lines.append(fmt.format(*(str(r.get(c, ""))[:60] for c in columns)))
    return lines


def generate_fix_summary_log(
    ruff_fixes: list[dict],
    ansible_fixes: list[dict],
    copyright_fixes: list[dict],
) -> str:
    """
    Generate a summary log message for automatically applied fixes.
    Returns log_message_string.
    """
    log_messages = []

    # Add tool name to each fix
    for v in ruff_fixes:
        v["tool"] = "Ruff"
    for v in ansible_fixes:
        v["tool"] = "Ansible-lint"
    for v in copyright_fixes:
        v["tool"] = "Copyright"

    all_fixes = ruff_fixes + ansible_fixes + copyright_fixes

    if not all_fixes:
        return "No automatic fixes were applied."

    log_messages.append("\n\u2500\u2500 Fixes Applied \u2500\u2500\n")

    # Format the consolidated table
    columns = ["tool", "file_path", "line", "violation", "suggested_fix"]
    headers = ["Tool", "File path", "Line(s)", "Violation", "Fix applied"]
    widths = [len(h) for h in headers]

    for r in all_fixes:
        for i, col in enumerate(columns):
            val = str(r.get(col, ""))[:60]
            widths[i] = max(widths[i], len(val))

        fmt_parts = [f"{{{c}:<{widths[i]}}}" for i, c in enumerate(columns)]
        fmt = "\u2502 " + " \u2502 ".join(fmt_parts) + " \u2502"
        top = "\u250c\u2500" + "\u2500\u252c\u2500".join("\u2500" * w for w in widths) + "\u2500\u2510"
        mid = "\u251c\u2500" + "\u2500\u253c\u2500".join("\u2500" * w for w in widths) + "\u2500\u2524"
        bot = "\u2514\u2500" + "\u2500\u2534\u2500".join("\u2500" * w for w in widths) + "\u2500\u2518"

    log_messages.append(top)
    log_messages.append(fmt.format(**{c: h for c, h in zip(columns, headers, strict=False)}))
    log_messages.append(mid)
    for r in all_fixes:
        row_data = {c: str(r.get(c, ""))[:60] for c in columns}
        log_messages.append(f"{_GREEN}{fmt.format(**row_data)}{_RESET}")
    log_messages.append(bot)

    log_messages.append(
        f"\n{_YELLOW}Note: Files were automatically modified. Please review the "
        f"changes and re-run code_sanity.py to ensure no further violations remain.{_RESET}"
    )

    return "\n".join(log_messages)


def generate_summary_log(
    ruff_violations: list[dict],
    ruff_rc: int,
    run_ruff_check: bool,
    ansible_violations: list[dict],
    ansible_rc: int,
    run_ansible_lint_check: bool,
    copyright_violations: list[dict],
    copyright_rc: int,
    run_copyright: bool,
    suppress_warnings: bool = False,
) -> tuple[str, int]:
    """
    Generate a consolidated summary log message and determine the final exit code.
    Returns (log_message_string, exit_code).
    """
    log_messages = []

    # Add tool name to each violation
    for v in ruff_violations:
        v["tool"] = "Ruff"
    for v in ansible_violations:
        v["tool"] = "Ansible-lint"
    for v in copyright_violations:
        v["tool"] = "Copyright"

    all_violations = ruff_violations + ansible_violations + copyright_violations

    ruff_errs = sum(1 for r in ruff_violations if r.get("violation_type") == "Error")
    ruff_warns = len(ruff_violations) - ruff_errs
    ansible_errs = sum(1 for r in ansible_violations if r.get("violation_type") == "Error")
    ansible_warns = len(ansible_violations) - ansible_errs
    copyright_errs = sum(1 for r in copyright_violations if r.get("violation_type") == "Error")
    copyright_warns = len(copyright_violations) - copyright_errs

    # Print tool-level failure messages for non-zero exits
    if run_ruff_check and ruff_rc not in (0, 1):
        log_messages.append(f"{_RED}\nRuff exited with non-zero status '{ruff_rc}'{_RESET}")
    if run_ansible_lint_check and ansible_rc not in (0, 1):
        log_messages.append(f"{_RED}\nAnsible-lint exited with non-zero status '{ansible_rc}'{_RESET}")
    if run_copyright and copyright_rc not in (0, 1):
        log_messages.append(f"{_RED}\nCopyright check exited with non-zero status '{copyright_rc}'{_RESET}")

    if all_violations:
        # Format the consolidated table
        columns = ["tool", "violation_type", "violation", "description", "file_path", "line", "suggested_fix"]
        headers = ["Tool", "Type", "Violation", "Description", "File path", "Line(s)", "Suggested fix"]

        # Filter warnings if requested
        display_violations = all_violations
        if suppress_warnings:
            display_violations = [v for v in all_violations if v.get("violation_type") != "Warning"]

        if display_violations:
            log_messages.append("\n\u2500\u2500 All Violations \u2500\u2500\n")
            widths = [len(h) for h in headers]

            for r in display_violations:
                for i, col in enumerate(columns):
                    val = str(r.get(col, ""))[:60]
                    widths[i] = max(widths[i], len(val))

            fmt_parts = [f"{{{c}:<{widths[i]}}}" for i, c in enumerate(columns)]
            fmt = "\u2502 " + " \u2502 ".join(fmt_parts) + " \u2502"
            top = "\u250c\u2500" + "\u2500\u252c\u2500".join("\u2500" * w for w in widths) + "\u2500\u2510"
            mid = "\u251c\u2500" + "\u2500\u253c\u2500".join("\u2500" * w for w in widths) + "\u2500\u2524"
            bot = "\u2514\u2500" + "\u2500\u2534\u2500".join("\u2500" * w for w in widths) + "\u2500\u2518"

            log_messages.append(top)
            log_messages.append(fmt.format(**{c: h for c, h in zip(columns, headers, strict=False)}))
            log_messages.append(mid)
            for r in display_violations:
                row_data = {c: str(r.get(c, ""))[:60] for c in columns}
                if r.get("violation_type") == "Error":
                    log_messages.append(f"{_RED}{fmt.format(**row_data)}{_RESET}")
                else:
                    log_messages.append(fmt.format(**row_data))
            log_messages.append(bot)
        else:
            log_messages.append("\n  (Only warnings found, suppressed from output)")

    log_messages.append("\nCODE SANITY SUMMARY")

    summary_rows = []
    if run_ruff_check:
        status = "FAIL" if ruff_errs > 0 or ruff_rc not in (0, 1) else "PASS"
        summary_rows.append({"Check": "Ruff", "Status": status, "Errors": str(ruff_errs), "Warnings": str(ruff_warns)})
    if run_ansible_lint_check:
        status = "FAIL" if ansible_errs > 0 or ansible_rc not in (0, 1) else "PASS"
        summary_rows.append(
            {"Check": "Ansible-lint", "Status": status, "Errors": str(ansible_errs), "Warnings": str(ansible_warns)}
        )
    if run_copyright:
        status = "FAIL" if copyright_errs > 0 or copyright_rc not in (0, 1) else "PASS"
        summary_rows.append(
            {"Check": "Copyright", "Status": status, "Errors": str(copyright_errs), "Warnings": str(copyright_warns)}
        )

    if not summary_rows:
        log_messages.append("Did not generate a summary")
    else:
        cols = ["Check", "Status", "Errors", "Warnings"]
        widths = [max(len(str(r[c])) for r in summary_rows + [{c: c}]) for c in cols]

        fmt_parts = [f"{{{c}:<{widths[i]}}}" for i, c in enumerate(cols)]
        fmt = "\u2502 " + " \u2502 ".join(fmt_parts) + " \u2502"
        top = "\u250c\u2500" + "\u2500\u252c\u2500".join("\u2500" * w for w in widths) + "\u2500\u2510"
        mid = "\u251c\u2500" + "\u2500\u253c\u2500".join("\u2500" * w for w in widths) + "\u2500\u2524"
        bot = "\u2514\u2500" + "\u2500\u2534\u2500".join("\u2500" * w for w in widths) + "\u2500\u2518"

        log_messages.append(top)
        log_messages.append(fmt.format(**{c: c for c in cols}))
        log_messages.append(mid)
        for r in summary_rows:
            if r["Status"] == "FAIL":
                log_messages.append(f"{_RED}{fmt.format(**r)}{_RESET}")
            else:
                log_messages.append(fmt.format(**r))
        log_messages.append(bot)

    total_warns = ruff_warns + ansible_warns + copyright_warns
    if suppress_warnings and total_warns > 0:
        log_messages.append(
            f"\n{_YELLOW}Note: {total_warns} warning(s) were suppressed. "
            f"Run without --suppress-warnings to view them.{_RESET}"
        )

    linter_failed = ruff_rc not in (0, 1) or ansible_rc not in (0, 1) or copyright_rc not in (0, 1)
    has_error_violations = any(v.get("violation_type") == "Error" for v in all_violations)
    exit_code = 2 if linter_failed else (1 if has_error_violations else 0)

    if exit_code == 0:
        log_messages.append("\nNo violations found")
    else:
        log_messages.append(f"\nExit code: {exit_code}")

    return "\n".join(log_messages), exit_code


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run linter checks on a path",
        epilog="Examples:\n"
        "  %(prog)s                                    validate entire repository\n"
        "  %(prog)s --path ~/repos/ansible_int/module_compatibility.yml   validate one file\n"
        "  %(prog)s --path path/to/dir --fix            auto-fix then report\n"
        "  %(prog)s -h                                 show this help",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--path",
        "-p",
        default=None,
        nargs="+",
        metavar="PATH",
        help="File or directory to check (default: entire repository). Can specify multiple paths.",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Run ruff and ansible-lint with --fix to auto-fix violations where possible",
    )
    parser.add_argument(
        "--checks",
        "-c",
        nargs="+",
        choices=["ruff", "ansible-lint", "copyright", "all"],
        default=["all"],
        help="Which sanity checks to run (default: all). Can specify multiple.",
    )
    parser.add_argument(
        "--suppress-warnings",
        action="store_true",
        help="Hide warning-level violations from the detailed output",
    )
    args = parser.parse_args()

    run_ruff_check = "all" in args.checks or "ruff" in args.checks
    run_ansible_lint_check = "all" in args.checks or "ansible-lint" in args.checks
    run_copyright = "all" in args.checks or "copyright" in args.checks

    log = setup_logging(verbose=args.verbose)
    dependency_paths = check_dependencies(log)

    # Find repository root: from script location, or from cwd if script is not in a repo
    script_dir = Path(__file__).resolve().parent
    repo_root = find_repo_root(script_dir)
    if not (repo_root / ".git").exists():
        repo_root = find_repo_root(Path.cwd())
    if not (repo_root / ".git").exists():
        log.error("No Ansible collection repository found.")
        log.error("Run this script from inside a repo, or use the copy in the repo (e.g. tests/sanity/code_sanity.py)")
        parser.print_usage(sys.stderr)
        return 2

    # Resolve paths: relative paths are relative to cwd
    py_files = []
    yaml_files = []

    if args.path is None:
        log.info(f"No path specified. Validating entire collection: {repo_root.resolve()}")
        py_files, yaml_files = collect_files(repo_root, repo_root)
    else:
        for path_str in args.path:
            path_str = Path(path_str).expanduser()
            path_arg = Path(path_str)
            path_arg = (Path.cwd() / path_arg).resolve() if not path_arg.is_absolute() else path_arg.resolve()

            if not path_arg.exists():
                log.error(f"Path does not exist: {path_arg}")
                continue

            log.info(f"Validating: {path_arg}")
            p_files, y_files = collect_files(path_arg, repo_root)
            py_files.extend(p_files)
            yaml_files.extend(y_files)

        # Deduplicate files
        py_files = list(set(py_files))
        yaml_files = list(set(yaml_files))

    if not py_files and not yaml_files:
        log.warning("No Python or YAML files found under the given path(s) (paths must be under repository root)")
        return 0

    # When --fix: run fix pass first (modifies files), then run lint without fix to get summary
    ruff_fixes = []
    ansible_fixes = []
    copyright_fixes = []

    if args.fix:
        if py_files and run_ruff_check:
            log.info(f"Running Ruff (fix pass) on {len(py_files)} file(s)")
            for p in py_files:
                log.info(f"  {p}")
            _start = time.monotonic()
            ruff_fixes, _ = run_ruff(
                repo=repo_root,
                files=py_files,
                fix=True,
                verbose=args.verbose,
            )
            log.info("Ruff (fix pass) finished (%.1fs)", time.monotonic() - _start)
        if yaml_files and run_ansible_lint_check:
            log.info(f"Running Ansible-lint (fix pass) on {len(yaml_files)} file(s)")
            files = list()
            for p in yaml_files:
                files.append(str(p))
            log.debug(f"Ansible-lint sanity on:\n{pformat(files, indent=4)}")
            _start = time.monotonic()
            ansible_fixes, _ = run_ansible_lint(
                repo=repo_root,
                files=yaml_files,
                fix=True,
                verbose=args.verbose,
            )
            log.info("Ansible-lint (fix pass) finished (%.1fs)", time.monotonic() - _start)

        if run_copyright:
            all_files = py_files + yaml_files
            if all_files:
                log.info(f"Running Copyright check (fix pass) on {len(all_files)} file(s)")
                _start = time.monotonic()
                copyright_fixes, _ = run_copyright_check(repo_root, all_files, fix=True)
                log.info("Copyright check (fix pass) finished (%.1fs)", time.monotonic() - _start)

    if py_files and run_ruff_check:
        log.info(f"Running Ruff on {len(py_files)} file(s)")
        files = list()
        for p in py_files:
            files.append(str(p))
        log.debug(f"Ruff sanity on:\n{pformat(files, indent=4)}")
        _start = time.monotonic()
        ruff_violations, ruff_rc = run_ruff(
            repo=repo_root, files=py_files, fix=False, verbose=args.verbose, python=dependency_paths["python"]
        )
        log.info("Ruff finished (%.1fs)", time.monotonic() - _start)
    else:
        ruff_violations, ruff_rc = [], 0

    if yaml_files and run_ansible_lint_check:
        files = list()
        for p in yaml_files:
            files.append(str(p))
        log.info(f"Running Ansible-lint on {len(yaml_files)} file(s)")
        log.debug(f"Ansible-lint on:\n{pformat(files, indent=4)}")
        _start = time.monotonic()
        ansible_violations, ansible_rc = run_ansible_lint(
            repo=repo_root, files=yaml_files, fix=False, verbose=args.verbose, python=dependency_paths["python"]
        )
        log.info("Ansible-lint finished (%.1fs)", time.monotonic() - _start)
    else:
        ansible_violations, ansible_rc = [], 0

    if not run_copyright:
        log.warning("Skipping copyright check as requested")
        copyright_violations, copyright_rc = [], 0
    else:
        all_files = py_files + yaml_files
        if all_files:
            log.info(f"Running Copyright check on {len(all_files)} file(s)")
            _start = time.monotonic()
            copyright_violations, copyright_rc = run_copyright_check(repo_root, all_files)
            log.info("Copyright check finished (%.1fs)", time.monotonic() - _start)
        else:
            copyright_violations, copyright_rc = [], 0

    # Sort and build summary; show error in place of a tool's section if it exited with non-zero (not 0/1)
    ruff_violations.sort(key=sort_key)
    ansible_violations.sort(key=sort_key)
    copyright_violations.sort(key=sort_key)

    if args.fix:
        fix_summary = generate_fix_summary_log(
            ruff_fixes=ruff_fixes,
            ansible_fixes=ansible_fixes,
            copyright_fixes=copyright_fixes,
        )
        log.info(fix_summary)

        display_violations = list()
        # If there are remaining violations that couldn't be fixed, show them
        all_remaining = ruff_violations + ansible_violations + copyright_violations
        if all_remaining:
            log.info("\n\u2500\u2500 Remaining Unfixed Violations \u2500\u2500\n")

            # Format the consolidated table for remaining violations
            columns = ["tool", "violation_type", "violation", "description", "file_path", "line", "suggested_fix"]
            headers = ["Tool", "Type", "Violation", "Description", "File path", "Line(s)", "Suggested fix"]

            display_violations = all_remaining
            if args.suppress_warnings:
                display_violations = [v for v in all_remaining if v.get("violation_type") != "Warning"]

        if display_violations:
            widths = [len(h) for h in headers]

            for r in display_violations:
                # Add tool names if they aren't there
                if "tool" not in r:
                    if r in ruff_violations:
                        r["tool"] = "Ruff"
                    elif r in ansible_violations:
                        r["tool"] = "Ansible-lint"
                    elif r in copyright_violations:
                        r["tool"] = "Copyright"

                for i, col in enumerate(columns):
                    val = str(r.get(col, ""))[:60]
                    widths[i] = max(widths[i], len(val))

            fmt_parts = [f"{{{c}:<{widths[i]}}}" for i, c in enumerate(columns)]
            fmt = "\u2502 " + " \u2502 ".join(fmt_parts) + " \u2502"
            top = "\u250c\u2500" + "\u2500\u252c\u2500".join("\u2500" * w for w in widths) + "\u2500\u2510"
            mid = "\u251c\u2500" + "\u2500\u253c\u2500".join("\u2500" * w for w in widths) + "\u2500\u2524"
            bot = "\u2514\u2500" + "\u2500\u2534\u2500".join("\u2500" * w for w in widths) + "\u2500\u2518"

            log_messages = [top, fmt.format(**{c: h for c, h in zip(columns, headers, strict=False)}), mid]
            for r in display_violations:
                row_data = {c: str(r.get(c, ""))[:60] for c in columns}
                if r.get("violation_type") == "Error":
                    log_messages.append(f"{_RED}{fmt.format(**row_data)}{_RESET}")
                else:
                    log_messages.append(fmt.format(**row_data))
            log_messages.append(bot)

            log.info("\n".join(log_messages))
        else:
            log.info("  (Only warnings remain, suppressed from output)")

        linter_failed = ruff_rc not in (0, 1) or ansible_rc not in (0, 1) or copyright_rc not in (0, 1)
        has_error_violations = any(v.get("violation_type") == "Error" for v in all_remaining)
        return 2 if linter_failed else (1 if has_error_violations else 0)

    summary_log, exit_code = generate_summary_log(
        ruff_violations=ruff_violations,
        ruff_rc=ruff_rc,
        run_ruff_check=run_ruff_check,
        ansible_violations=ansible_violations,
        ansible_rc=ansible_rc,
        run_ansible_lint_check=run_ansible_lint_check,
        copyright_violations=copyright_violations,
        copyright_rc=copyright_rc,
        run_copyright=run_copyright,
        suppress_warnings=args.suppress_warnings,
    )

    # Output everything as a single log message
    if exit_code == 0:
        log.info(summary_log)
    else:
        log.error(summary_log)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
