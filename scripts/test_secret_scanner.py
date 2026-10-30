import json
import sys
from pathlib import Path
import pytest

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.secret_scanner import (
    FORBIDDEN_FILES,
    FORBIDDEN_EXTS,
    load_gitleaks_config,
    run_scanner,
    scan_workspace,
    scan_single_file,
    shannon_entropy,
    generate_sarif_report,
    ScanSummary,
    SecretFinding,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT_DIR / ".gitleaks.toml"
FIXTURES_DIR = ROOT_DIR / "tests" / "fixtures" / "secret_scanning"


def test_load_gitleaks_config():
    """Verify that .gitleaks.toml is parsed and rules/allowlists are properly compiled."""
    assert CONFIG_PATH.exists()
    path_allowlist, regex_allowlist, stopwords, rules = load_gitleaks_config(CONFIG_PATH)

    assert len(rules) >= 10
    assert len(path_allowlist) >= 2
    assert len(regex_allowlist) >= 3

    rule_ids = {r.id for r in rules}
    assert "vaultsync-private-key" in rule_ids
    assert "vaultsync-github-pat" in rule_ids
    assert "vaultsync-aws-access-key-id" in rule_ids
    assert "vaultsync-database-uri-password" in rule_ids


def test_shannon_entropy():
    """Verify Shannon entropy computation."""
    # Low entropy uniform strings
    assert shannon_entropy("aaaaaaaa") == 0.0
    # High entropy random-like strings
    high_entropy = shannon_entropy("q9X#z$8mK2!pL0@w")
    assert high_entropy > 3.5


def test_clean_sample_passes():
    """Verify that a clean sample without hardcoded secrets passes with 0 findings."""
    clean_file = FIXTURES_DIR / "clean_sample.py"
    assert clean_file.exists()

    path_allowlist, regex_allowlist, stopwords, rules = load_gitleaks_config(CONFIG_PATH)
    total_files, findings, read_errors = scan_workspace(
        target_path=clean_file,
        rules=rules,
        global_path_allowlist=path_allowlist,
        global_regex_allowlist=regex_allowlist,
        global_stopwords=stopwords,
        ignore_allowlists=True,
    )
    assert total_files == 1
    assert len(findings) == 0
    assert len(read_errors) == 0


def test_synthetic_token_leak_detected():
    """Verify that a synthetic GitHub token leak is detected and fail-closed logic triggers."""
    token_fixture = FIXTURES_DIR / "synthetic_token_leak.py.fixture"
    assert token_fixture.exists()

    path_allowlist, regex_allowlist, stopwords, rules = load_gitleaks_config(CONFIG_PATH)
    total_files, findings, read_errors = scan_workspace(
        target_path=token_fixture,
        rules=rules,
        global_path_allowlist=path_allowlist,
        global_regex_allowlist=regex_allowlist,
        global_stopwords=stopwords,
        ignore_allowlists=True,
    )

    assert total_files == 1
    assert len(findings) == 1
    assert len(read_errors) == 0
    f = findings[0]
    assert f.rule_id == "vaultsync-github-pat"
    assert f.line_number == 4
    assert f.matched_length == 40
    assert f.redacted_preview == "[REDACTED:len=40]"


def test_synthetic_private_key_detected():
    """Verify that a synthetic PEM private key is detected."""
    key_fixture = FIXTURES_DIR / "synthetic_private_key_leak.pem.fixture"
    assert key_fixture.exists()

    path_allowlist, regex_allowlist, stopwords, rules = load_gitleaks_config(CONFIG_PATH)
    total_files, findings, read_errors = scan_workspace(
        target_path=key_fixture,
        rules=rules,
        global_path_allowlist=path_allowlist,
        global_regex_allowlist=regex_allowlist,
        global_stopwords=stopwords,
        ignore_allowlists=True,
    )

    assert total_files == 1
    assert len(findings) >= 1
    assert len(read_errors) == 0
    f = findings[0]
    assert f.rule_id == "vaultsync-private-key"
    assert f.line_number == 1
    assert "[REDACTED:" in f.redacted_preview


def test_synthetic_db_uri_leak_detected():
    """Verify that a database URI with hardcoded password is detected."""
    db_fixture = FIXTURES_DIR / "synthetic_db_leak.py.fixture"
    assert db_fixture.exists()

    path_allowlist, regex_allowlist, stopwords, rules = load_gitleaks_config(CONFIG_PATH)
    total_files, findings, read_errors = scan_workspace(
        target_path=db_fixture,
        rules=rules,
        global_path_allowlist=path_allowlist,
        global_regex_allowlist=regex_allowlist,
        global_stopwords=stopwords,
        ignore_allowlists=True,
    )

    assert total_files == 1
    assert len(findings) == 1
    assert len(read_errors) == 0
    f = findings[0]
    assert f.rule_id == "vaultsync-database-uri-password"
    assert f.line_number == 4


def test_allowlist_suppresses_documented_placeholders():
    """Verify that documented placeholder strings in allowlist are not flagged."""
    allowlist_fixture = FIXTURES_DIR / "allowlisted_sample.py.fixture"
    assert allowlist_fixture.exists()

    path_allowlist, regex_allowlist, stopwords, rules = load_gitleaks_config(CONFIG_PATH)
    # When allowlists are respected, the fixture path or its placeholder patterns pass cleanly
    total_files, findings, read_errors = scan_workspace(
        target_path=allowlist_fixture,
        rules=rules,
        global_path_allowlist=path_allowlist,
        global_regex_allowlist=regex_allowlist,
        global_stopwords=stopwords,
        ignore_allowlists=False,
    )
    assert len(findings) == 0
    assert len(read_errors) == 0


def test_case_insensitive_keyword_matching(tmp_path):
    test_file = tmp_path / "aws_test.py"
    key_name = "AWS" + "_SECRET_ACCESS_KEY"
    key_val = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    test_file.write_text(f'{key_name} = "{key_val}"\n')

    _, regex_allowlist, stopwords, rules = load_gitleaks_config(CONFIG_PATH)
    aws_rule = [r for r in rules if r.id == "vaultsync-aws-secret-access-key"][0]

    findings, err = scan_single_file(test_file, "aws_test.py", [aws_rule], regex_allowlist, stopwords)
    assert err is None
    assert len(findings) == 1
    assert findings[0].rule_id == "vaultsync-aws-secret-access-key"


def test_inline_comment_does_not_mask_real_secret(tmp_path):
    """Verify that an inline comment like '# TODO: CHANGE_ME' cannot suppress a genuine leak."""
    test_file = tmp_path / "comment_leak.py"
    sample_leak = (FIXTURES_DIR / "synthetic_token_leak.py.fixture").read_text().strip()
    test_file.write_text(f"{sample_leak}  # TODO: CHANGE_ME before release\n")

    path_allowlist, regex_allowlist, stopwords, rules = load_gitleaks_config(CONFIG_PATH)
    total_files, findings, read_errors = scan_workspace(
        target_path=test_file,
        rules=rules,
        global_path_allowlist=path_allowlist,
        global_regex_allowlist=regex_allowlist,
        global_stopwords=stopwords,
        ignore_allowlists=False,
    )
    assert total_files == 1
    assert len(findings) == 1
    assert findings[0].rule_id == "vaultsync-github-pat"


def test_symlinks_are_safely_ignored(tmp_path):
    """Verify that symlinks are never followed, preventing path traversal or loop attacks."""
    real_file = tmp_path / "target.py"
    sample_leak = (FIXTURES_DIR / "synthetic_token_leak.py.fixture").read_text()
    real_file.write_text(sample_leak)

    symlink_file = tmp_path / "symlink_to_target.py"
    symlink_file.symlink_to(real_file)

    path_allowlist, regex_allowlist, stopwords, rules = load_gitleaks_config(CONFIG_PATH)
    total_files, findings, read_errors = scan_workspace(
        target_path=tmp_path,
        rules=rules,
        global_path_allowlist=path_allowlist,
        global_regex_allowlist=regex_allowlist,
        global_stopwords=stopwords,
        ignore_allowlists=True,
    )
    # The real file is counted and detected; the symlink is completely ignored
    assert total_files == 1
    assert len(findings) == 1
    assert findings[0].file_path == "target.py"


def test_safety_forbidden_db_and_apk_never_scanned(tmp_path):
    """Verify that safety-critical forbidden files (vaultsync.db, *.apk) are never inspected."""
    # Create fake files with forbidden names in tmp_path
    db_file = tmp_path / "vaultsync.db"
    apk_file = tmp_path / "test.apk"
    sample_leak = (FIXTURES_DIR / "synthetic_token_leak.py.fixture").read_text()
    db_file.write_text(sample_leak)
    apk_file.write_text(sample_leak)

    path_allowlist, regex_allowlist, stopwords, rules = load_gitleaks_config(CONFIG_PATH)
    total_files, findings, read_errors = scan_workspace(
        target_path=tmp_path,
        rules=rules,
        global_path_allowlist=path_allowlist,
        global_regex_allowlist=regex_allowlist,
        global_stopwords=stopwords,
        ignore_allowlists=True,
    )

    # Both must be completely skipped
    assert total_files == 0
    assert len(findings) == 0


def test_redaction_never_reveals_secret_material():
    """Verify that finding representations never contain the raw secret values."""
    finding = SecretFinding(
        rule_id="vaultsync-github-pat",
        description="Detected GitHub PAT",
        file_path="src/leak.py",
        line_number=10,
        matched_length=40,
        line_entropy=4.8,
        redacted_preview="[REDACTED:len=40]",
    )

    # Neither finding representation nor redacted_preview should expose raw tokens
    assert "ghp_" not in finding.redacted_preview
    assert "REDACTED" in finding.redacted_preview

    summary = ScanSummary(
        timestamp="2026-10-30T00:00:00Z",
        scanner="Test Scanner",
        root_dir=".",
        total_files_scanned=1,
        total_findings=1,
        rules_applied=1,
        findings=[finding],
    )
    sarif = generate_sarif_report(summary)
    sarif_str = json.dumps(sarif)
    assert "ghp_" not in sarif_str
    assert "Entropy: 4.8" in sarif_str


def test_run_scanner_end_to_end_exit_codes(tmp_path):
    """Verify end-to-end scanner execution and exit codes."""
    # 1. Clean workspace returns 0
    clean_dir = tmp_path / "clean_ws"
    clean_dir.mkdir()
    (clean_dir / "app.py").write_text("import os\nAPI_KEY = os.getenv('API_KEY')\n")
    code = run_scanner(
        scan_path=clean_dir,
        config_path=CONFIG_PATH,
        fail_on_secrets=True,
    )
    assert code == 0

    # 2. Workspace with secret leak returns 1
    dirty_dir = tmp_path / "dirty_ws"
    dirty_dir.mkdir()
    sample_leak = (FIXTURES_DIR / "synthetic_token_leak.py.fixture").read_text()
    (dirty_dir / "leak.py").write_text(sample_leak)
    json_out = dirty_dir / "report.json"
    sarif_out = dirty_dir / "report.sarif"
    code = run_scanner(
        scan_path=dirty_dir,
        config_path=CONFIG_PATH,
        output_json_path=json_out,
        output_sarif_path=sarif_out,
        ignore_allowlist=True,
        fail_on_secrets=True,
    )
    assert code == 1
    assert json_out.exists()
    assert sarif_out.exists()

    with open(json_out, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["status"] == "FAIL"
        assert data["total_findings"] == 1
        assert "ghp_" not in json.dumps(data)
