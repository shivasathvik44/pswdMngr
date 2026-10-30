#!/usr/bin/env python3
"""
VaultSync Secret Scanner & Policy Enforcement Tool

Audits repository files and configurations for accidental leaks of credentials,
API keys, tokens, private keys, database passwords, and signing secrets.
Reads rules and allowlists from .gitleaks.toml or built-in defaults.

Exit Codes:
  0 = Clean scan (no secrets detected or all matches covered by approved allowlists).
  1 = Actionable secret leaks detected.
  2 = Scanner error, invalid configuration, or failure.

Mandatory Safety Guarantees:
  - NEVER prints, outputs, or logs secret values.
  - NEVER touches, inspects, or queries 'vaultsync.db'.
  - NEVER touches, inspects, or modifies '*.apk' files.
  - Strictly ignores '.git', '.venv', and build caches.
"""

from __future__ import annotations

import argparse
import datetime
import json
import math
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

FORBIDDEN_FILES = {"vaultsync.db"}
FORBIDDEN_EXTS = {".apk"}
DEFAULT_SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".gradle",
    "build",
    "dist",
    ".idea",
    ".vscode",
}


@dataclass
class SecretRule:
    id: str
    description: str
    regex: re.Pattern
    keywords: List[str] = field(default_factory=list)
    allowlist_regexes: List[re.Pattern] = field(default_factory=list)


@dataclass
class SecretFinding:
    rule_id: str
    description: str
    file_path: str
    line_number: int
    matched_length: int
    line_entropy: float
    redacted_preview: str  # e.g., "[REDACTED:len=40]"


@dataclass
class ScanSummary:
    timestamp: str
    scanner: str
    root_dir: str
    total_files_scanned: int
    total_findings: int
    rules_applied: int
    findings: List[SecretFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    status: str = "PASS"  # PASS, FAIL, ERROR


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for char in set(data):
        prob = float(data.count(char)) / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return round(entropy, 2)


def load_gitleaks_config(config_path: Path) -> Tuple[List[re.Pattern], List[re.Pattern], List[str], List[SecretRule]]:
    """Loads and compiles rules and allowlists from .gitleaks.toml."""
    global_path_allowlist: List[re.Pattern] = []
    global_regex_allowlist: List[re.Pattern] = []
    global_stopwords: List[str] = []
    rules: List[SecretRule] = []

    if not config_path.exists():
        # Fall back to built-in rules if config is absent
        return global_path_allowlist, global_regex_allowlist, global_stopwords, get_builtin_rules()

    if tomllib is None:
        raise RuntimeError("tomllib is required to parse .gitleaks.toml (Python 3.11+).")

    with open(config_path, "rb") as f:
        data = tomllib.load(f)

    # Global allowlist
    allowlist_data = data.get("allowlist", {})
    for p in allowlist_data.get("paths", []):
        try:
            global_path_allowlist.append(re.compile(p))
        except re.error as e:
            raise ValueError(f"Invalid regex in allowlist paths: {p} ({e})")

    for r in allowlist_data.get("regexes", []):
        try:
            global_regex_allowlist.append(re.compile(r))
        except re.error as e:
            raise ValueError(f"Invalid regex in allowlist regexes: {r} ({e})")

    global_stopwords = [sw.strip() for sw in allowlist_data.get("stopwords", []) if sw.strip()]

    # Rules
    for rdata in data.get("rules", []):
        rule_id = rdata.get("id", "unnamed-rule")
        desc = rdata.get("description", "Potential secret leak")
        pattern_str = rdata.get("regex", "")
        keywords = rdata.get("keywords", [])

        if not pattern_str:
            continue

        try:
            compiled_regex = re.compile(pattern_str)
        except re.error as e:
            raise ValueError(f"Invalid regex for rule {rule_id}: {pattern_str} ({e})")

        rule_allowlists: List[re.Pattern] = []
        rule_allow_data = rdata.get("allowlist", {})
        for rar in rule_allow_data.get("regexes", []):
            try:
                rule_allowlists.append(re.compile(rar))
            except re.error as e:
                raise ValueError(f"Invalid regex in rule {rule_id} allowlist: {rar} ({e})")

        rules.append(SecretRule(
            id=rule_id,
            description=desc,
            regex=compiled_regex,
            keywords=keywords,
            allowlist_regexes=rule_allowlists,
        ))

    return global_path_allowlist, global_regex_allowlist, global_stopwords, rules


def get_builtin_rules() -> List[SecretRule]:
    """Provides fallback rules if no configuration file is present."""
    return [
        SecretRule(
            id="builtin-private-key",
            description="Detected Private Key PEM Block",
            regex=re.compile(r"-----BEGIN (?:[A-Z0-9 ]+)?PRIVATE KEY-----"),
            keywords=["PRIVATE KEY"],
        ),
        SecretRule(
            id="builtin-github-pat",
            description="Detected GitHub Personal Access Token",
            regex=re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b"),
            keywords=["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        ),
        SecretRule(
            id="builtin-aws-access-key",
            description="Detected AWS Access Key ID",
            regex=re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
            keywords=["AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA"],
        ),
        SecretRule(
            id="builtin-database-uri-password",
            description="Detected Database Connection URL containing embedded password",
            regex=re.compile(r"""(?i)(?:postgres|mysql|sqlite|mongodb|redis)(?:ql)?(?:\+[a-z0-9_]+)?:\/\/[a-zA-Z0-9_\-\.]+:(?!(?:password|\$|\{|CHANGE_ME))[^\s@'"]+@"""),
            keywords=["postgresql://", "postgres://", "mysql://"],
        ),
    ]


def is_path_allowlisted(rel_path_str: str, path_allowlist: List[re.Pattern]) -> bool:
    """Checks if a normalized relative path is covered by any path allowlist regex."""
    for pattern in path_allowlist:
        if pattern.search(rel_path_str):
            return True
    return False


def is_match_allowlisted(
    matched_text: str,
    line_text: str,
    rule: SecretRule,
    global_regex_allowlist: List[re.Pattern],
    global_stopwords: List[str]
) -> bool:
    """Checks if a detected match is suppressed by global or rule allowlists.

    SECURITY NOTE: Allowlists are evaluated strictly against 'matched_text' (the
    detected secret candidate), NEVER against 'line_text', to prevent inline comments
    (e.g. '# TODO: CHANGE_ME') from masking real credentials.
    """
    # Check global stopwords strictly on matched candidate
    for sw in global_stopwords:
        if sw in matched_text:
            return True

    # Check global regex allowlists strictly on matched candidate
    for r in global_regex_allowlist:
        if r.search(matched_text):
            return True

    # Check rule-specific regex allowlists strictly on matched candidate
    for r in rule.allowlist_regexes:
        if r.search(matched_text):
            return True

    return False


def scan_single_file(
    file_path: Path,
    rel_path_str: str,
    rules: List[SecretRule],
    global_regex_allowlist: List[re.Pattern],
    global_stopwords: List[str],
) -> Tuple[List[SecretFinding], Optional[str]]:
    """Scans an individual file line by line without leaking secret values."""
    findings: List[SecretFinding] = []

    # Defense-in-depth: Never follow symlinks
    if file_path.is_symlink():
        return [], None

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return [], f"Failed to read file '{rel_path_str}': {exc}"

    lines = content.splitlines()
    for line_idx, line in enumerate(lines, 1):
        clean_line = line.strip()
        if not clean_line:
            continue

        entropy = shannon_entropy(clean_line)
        clean_line_lower = clean_line.lower()

        for rule in rules:
            # Case-insensitive keyword pre-filter to prevent uppercase false negatives
            if rule.keywords and not any(kw.lower() in clean_line_lower for kw in rule.keywords):
                continue

            match = rule.regex.search(clean_line)
            if match:
                matched_str = match.group(0)
                # Check allowlists
                if is_match_allowlisted(
                    matched_str,
                    clean_line,
                    rule,
                    global_regex_allowlist,
                    global_stopwords
                ):
                    continue

                # Never store or expose actual secret value
                finding = SecretFinding(
                    rule_id=rule.id,
                    description=rule.description,
                    file_path=rel_path_str,
                    line_number=line_idx,
                    matched_length=len(matched_str),
                    line_entropy=entropy,
                    redacted_preview=f"[REDACTED:len={len(matched_str)}]",
                )
                findings.append(finding)

    return findings, None


def scan_workspace(
    target_path: Path,
    rules: List[SecretRule],
    global_path_allowlist: List[re.Pattern],
    global_regex_allowlist: List[re.Pattern],
    global_stopwords: List[str],
    skip_dirs: Optional[Set[str]] = None,
    ignore_allowlists: bool = False,
) -> Tuple[int, List[SecretFinding], List[str]]:
    """Walks the directory hierarchy and scans eligible files."""
    if skip_dirs is None:
        skip_dirs = DEFAULT_SKIP_DIRS

    total_files = 0
    all_findings: List[SecretFinding] = []
    read_errors: List[str] = []

    # Defense-in-depth: Do not scan target_path if it is a symlink
    if target_path.is_symlink():
        return 0, [], ["Target path is a symlink. Symlinks are not followed for security isolation."]

    if target_path.is_file():
        # Single file scan mode
        if target_path.name in FORBIDDEN_FILES or target_path.suffix in FORBIDDEN_EXTS:
            return 0, [], []
        rel_str = str(target_path).replace("\\", "/")
        if not ignore_allowlists and is_path_allowlisted(rel_str, global_path_allowlist):
            return 0, [], []
        findings, err = scan_single_file(
            target_path,
            rel_str,
            rules,
            [] if ignore_allowlists else global_regex_allowlist,
            [] if ignore_allowlists else global_stopwords,
        )
        if err:
            read_errors.append(err)
        return 1, findings, read_errors

    # Directory walk mode
    for dirpath, dirnames, filenames in os.walk(target_path):
        # Filter directories in-place and skip symlinked directories
        dirnames[:] = [
            d for d in dirnames
            if d not in skip_dirs
            and not d.startswith(".git")
            and not (Path(dirpath) / d).is_symlink()
        ]

        for fname in filenames:
            # Strictly enforce forbidden safety rules
            if fname in FORBIDDEN_FILES or fname.endswith(tuple(FORBIDDEN_EXTS)):
                continue

            fpath = Path(dirpath) / fname

            # Skip symlinks entirely to prevent path traversal or symlink loops
            if fpath.is_symlink():
                continue

            try:
                rel_str = str(fpath.relative_to(target_path)).replace("\\", "/")
            except ValueError:
                rel_str = str(fpath).replace("\\", "/")

            if not ignore_allowlists and is_path_allowlisted(rel_str, global_path_allowlist):
                continue

            total_files += 1
            file_findings, err = scan_single_file(
                fpath,
                rel_str,
                rules,
                [] if ignore_allowlists else global_regex_allowlist,
                [] if ignore_allowlists else global_stopwords,
            )
            if err:
                read_errors.append(err)
            all_findings.extend(file_findings)

    return total_files, all_findings, read_errors


def generate_sarif_report(summary: ScanSummary) -> Dict[str, Any]:
    """Generates a standard SARIF v2.1.0 document for GitHub Code Scanning."""
    sarif_rules: List[Dict[str, Any]] = []
    rule_ids_seen: Set[str] = set()
    results: List[Dict[str, Any]] = []

    for f in summary.findings:
        if f.rule_id not in rule_ids_seen:
            sarif_rules.append({
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.description},
                "defaultConfiguration": {"level": "error"},
                "properties": {
                    "tags": ["security", "secrets"],
                    "precision": "high",
                },
            })
            rule_ids_seen.add(f.rule_id)

        results.append({
            "ruleId": f.rule_id,
            "message": {
                "text": f"Potential credential leak detected: {f.description} (Length: {f.matched_length} chars, Entropy: {f.line_entropy})."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.line_number,
                            "startColumn": 1,
                        },
                    }
                }
            ],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VaultSync Secret Scanner",
                        "informationUri": "https://github.com/vaultsync/vaultsync",
                        "version": "1.0.0",
                        "rules": sarif_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def generate_markdown_summary(summary: ScanSummary) -> str:
    """Formats scan results into human-readable markdown without exposing secrets."""
    lines: List[str] = [
        "# VaultSync Secret Scanning & Credential Leak Audit Report",
        "",
        f"- **Timestamp**: `{summary.timestamp}`",
        f"- **Scanner**: `{summary.scanner}`",
        f"- **Root Path**: `{summary.root_dir}`",
        f"- **Rules Enforced**: {summary.rules_applied}",
        f"- **Files Audited**: {summary.total_files_scanned}",
        f"- **Status**: **{summary.status}**",
        "",
        "## Summary Metrics",
        "",
        "| Metric | Count |",
        "|---|:---:|",
        f"| Total Files Audited | {summary.total_files_scanned} |",
        f"| Active Rules Evaluated | {summary.rules_applied} |",
        f"| **Actionable Secret Leaks Detected** | **{summary.total_findings}** |",
        f"| Scanner Errors | {len(summary.errors)} |",
        "",
    ]

    if summary.errors:
        lines.append("## Scanner Errors")
        lines.append("")
        for err in summary.errors:
            lines.append(f"> [!CAUTION]\n> **Scanner Failure**: {err}\n")

    if summary.findings:
        lines.append("## Secret Leak Detections (Values Strictly Redacted)")
        lines.append("")
        lines.append("| Rule ID | Description | Location | Length | Line Entropy | Redacted Preview |")
        lines.append("|---|---|---|:---:|:---:|:---:|")
        for item in summary.findings:
            loc = f"`{item.file_path}:{item.line_number}`"
            lines.append(
                f"| `{item.rule_id}` | {item.description} | {loc} | {item.matched_length} | {item.line_entropy} | `{item.redacted_preview}` |"
            )
        lines.append("")
        lines.append("> [!WARNING]")
        lines.append("> **Action Required**: True secret exposures must be revoked immediately, rotated at the issuer, and scrubbed from history.")
    else:
        lines.append("> [!NOTE]")
        lines.append("> No actionable credentials or exposed private keys were detected in the audited workspace files.")

    return "\n".join(lines)


def run_scanner(
    scan_path: Path,
    config_path: Path,
    output_json_path: Optional[Path] = None,
    output_sarif_path: Optional[Path] = None,
    ignore_allowlist: bool = False,
    fail_on_secrets: bool = True,
) -> int:
    """Executes secret scanner and generates configured reports."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    errors: List[str] = []

    try:
        path_allowlist, regex_allowlist, stopwords, rules = load_gitleaks_config(config_path)
    except Exception as e:
        errors.append(f"Failed to load secret scanner configuration: {e}")
        summary = ScanSummary(
            timestamp=timestamp,
            scanner="VaultSync Native Scanner & Policy Enforcement",
            root_dir=str(scan_path),
            total_files_scanned=0,
            total_findings=0,
            rules_applied=0,
            errors=errors,
            status="ERROR",
        )
        print(generate_markdown_summary(summary), file=sys.stderr)
        return 2

    total_files, findings, read_errors = scan_workspace(
        target_path=scan_path,
        rules=rules,
        global_path_allowlist=path_allowlist,
        global_regex_allowlist=regex_allowlist,
        global_stopwords=stopwords,
        ignore_allowlists=ignore_allowlist,
    )
    if read_errors:
        errors.extend(read_errors)

    if errors:
        status = "ERROR"
    elif findings and fail_on_secrets:
        status = "FAIL"
    else:
        status = "PASS"

    summary = ScanSummary(
        timestamp=timestamp,
        scanner=f"VaultSync Secret Scanner (.gitleaks.toml rules: {len(rules)})",
        root_dir=str(scan_path),
        total_files_scanned=total_files,
        total_findings=len(findings),
        rules_applied=len(rules),
        findings=findings,
        errors=errors,
        status=status,
    )

    print(generate_markdown_summary(summary))

    if output_json_path:
        output_json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_json_path, "w", encoding="utf-8") as f:
            json.dump(asdict(summary), f, indent=2)

    if output_sarif_path:
        output_sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_data = generate_sarif_report(summary)
        with open(output_sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)

    if errors:
        return 2
    if findings and fail_on_secrets:
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="VaultSync Secret Scanning & Policy Enforcement Tool")
    parser.add_argument(
        "--scan-dir",
        type=Path,
        default=Path("."),
        help="Path to repository or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(".gitleaks.toml"),
        help="Path to .gitleaks.toml configuration file",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Path to write machine-readable JSON report",
    )
    parser.add_argument(
        "--output-sarif",
        type=Path,
        default=None,
        help="Path to write SARIF report for GitHub Code Scanning integration",
    )
    parser.add_argument(
        "--ignore-allowlist",
        action="store_true",
        help="Ignore all allowlists (used for testing synthetic leak fixtures)",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Always return exit code 0 even if secrets are detected",
    )

    args = parser.parse_args()

    code = run_scanner(
        scan_path=args.scan_dir,
        config_path=args.config,
        output_json_path=args.output_json,
        output_sarif_path=args.output_sarif,
        ignore_allowlist=args.ignore_allowlist,
        fail_on_secrets=not args.no_fail,
    )
    sys.exit(code)


if __name__ == "__main__":
    main()
