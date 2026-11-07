# ==============================================================================
# Product:       lh-api-auditor (lh-api)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the CLI interface using Typer CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_api_auditor.cli import app

runner = CliRunner()
CLI_ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_help() -> None:
    """Test CLI top-level and subcommand help commands."""
    res = runner.invoke(app, ["--help"], env=CLI_ENV)
    assert res.exit_code == 0
    assert "Enterprise OpenAPI and GraphQL security analyzer" in res.stdout

    res_scan = runner.invoke(app, ["scan", "--help"], env=CLI_ENV)
    assert res_scan.exit_code == 0
    assert "--format" in res_scan.stdout
    assert "--min-severity" in res_scan.stdout
    assert "--fail-on" in res_scan.stdout

    res_rules = runner.invoke(app, ["rules", "--help"], env=CLI_ENV)
    assert res_rules.exit_code == 0
    assert "List all supported LH-API security posture detection rules" in res_rules.stdout


def test_cli_rules_list() -> None:
    """Test listing all 10 LH-API detection rules."""
    res = runner.invoke(app, ["rules"], env=CLI_ENV)
    assert res.exit_code == 0
    for i in range(1, 11):
        rule_id = f"LH-API-{i:03d}"
        assert rule_id in res.stdout


def test_cli_scan_clean_openapi(tmp_path: Path, sample_clean_openapi: str) -> None:
    """Test scanning a secure OpenAPI file produces exit code 0."""
    spec_file = tmp_path / "openapi.yaml"
    spec_file.write_text(sample_clean_openapi, encoding="utf-8")

    res = runner.invoke(app, ["scan", str(spec_file)], env=CLI_ENV)
    assert res.exit_code == 0
    assert "Clean Audit" in res.stdout


def test_cli_scan_violations_openapi(tmp_path: Path) -> None:
    """Test scanning a vulnerable OpenAPI file produces exit code 1 with default fail-on HIGH."""
    vuln_spec = tmp_path / "openapi.yaml"
    vuln_spec.write_text(
        "openapi: 3.0.0\n"
        "info:\n  title: Insecure API\n  version: 1.0.0\n"
        "paths:\n"
        "  /users:\n"
        "    post:\n"
        "      summary: Create user\n"
        "      responses:\n        '201':\n          description: Created\n",
        encoding="utf-8",
    )

    res = runner.invoke(app, ["scan", str(vuln_spec)], env=CLI_ENV)
    assert res.exit_code == 1
    assert "LH-API-001" in res.stdout


def test_cli_scan_clean_graphql(tmp_path: Path, sample_clean_graphql: str) -> None:
    """Test scanning a clean GraphQL schema produces exit code 0."""
    schema_file = tmp_path / "schema.graphql"
    schema_file.write_text(sample_clean_graphql, encoding="utf-8")

    res = runner.invoke(app, ["scan", str(schema_file)], env=CLI_ENV)
    assert res.exit_code == 0
    assert "Clean Audit" in res.stdout


def test_cli_scan_violations_graphql(tmp_path: Path) -> None:
    """Test scanning a vulnerable GraphQL schema produces exit code 1."""
    vuln_schema = tmp_path / "schema.graphql"
    vuln_schema.write_text(
        "type Mutation {\n  deleteAccount(id: ID!): Boolean\n}\n",
        encoding="utf-8",
    )

    res = runner.invoke(app, ["scan", str(vuln_schema)], env=CLI_ENV)
    assert res.exit_code == 1
    assert "LH-API-001" in res.stdout


def test_cli_scan_json_output(tmp_path: Path) -> None:
    """Test CLI output in JSON format."""
    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        "openapi: 3.0.0\ninfo:\n  title: Test\n  version: 1.0\npaths: {}\n",
        encoding="utf-8",
    )

    res = runner.invoke(app, ["scan", str(spec), "--format", "json"], env=CLI_ENV)
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["report_type"] == "api_security_audit"
    assert "summary" in data


def test_cli_scan_sarif_output(tmp_path: Path) -> None:
    """Test CLI output in SARIF format."""
    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        "openapi: 3.0.0\ninfo:\n  title: Test\n  version: 1.0\n"
        "paths:\n  /items:\n    post:\n      responses:\n        '200':\n          desc: ok\n",
        encoding="utf-8",
    )

    res = runner.invoke(
        app,
        ["scan", str(spec), "--format", "sarif", "--fail-on", "CRITICAL"],
        env=CLI_ENV,
    )
    assert res.exit_code == 1
    data = json.loads(res.stdout)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1


def test_cli_scan_output_file(tmp_path: Path) -> None:
    """Test writing scan results to an output file."""
    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        "openapi: 3.0.0\ninfo:\n  title: Test\n  version: 1.0\npaths: {}\n",
        encoding="utf-8",
    )
    out_file = tmp_path / "report.json"

    res = runner.invoke(
        app,
        ["scan", str(spec), "--format", "json", "--output", str(out_file)],
        env=CLI_ENV,
    )
    assert res.exit_code == 0
    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["report_type"] == "api_security_audit"


def test_cli_scan_fail_on_threshold(tmp_path: Path) -> None:
    """Test --fail-on threshold logic."""
    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        "openapi: 3.0.0\ninfo:\n  title: Test\n  version: 1.0\n"
        "paths:\n"
        "  /data:\n"
        "    get:\n"
        "      responses:\n        '200':\n          description: ok\n",
        encoding="utf-8",
    )

    # Missing rate limiting is MEDIUM: fail-on HIGH should exit 0
    res_high = runner.invoke(
        app,
        ["scan", str(spec), "--fail-on", "HIGH"],
        env=CLI_ENV,
    )
    assert res_high.exit_code == 0

    # Fail on MEDIUM: should fail (exit 1)
    res_med = runner.invoke(
        app,
        ["scan", str(spec), "--fail-on", "MEDIUM"],
        env=CLI_ENV,
    )
    assert res_med.exit_code == 1


def test_cli_scan_min_severity_filter(tmp_path: Path) -> None:
    """Test --min-severity filtering out lower severity findings."""
    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        "openapi: 3.0.0\ninfo:\n  title: Test\n  version: 1.0\n"
        "paths:\n"
        "  /data:\n"
        "    get:\n"
        "      responses:\n        '200':\n          description: ok\n",
        encoding="utf-8",
    )

    res = runner.invoke(
        app,
        ["scan", str(spec), "--min-severity", "CRITICAL", "--format", "json"],
        env=CLI_ENV,
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["summary"]["total_findings"] == 0


def test_cli_scan_directory(tmp_path: Path) -> None:
    """Test directory scanning finds OpenAPI and GraphQL specifications."""
    dir_path = tmp_path / "specs"
    dir_path.mkdir()

    f1 = dir_path / "api.yaml"
    f1.write_text("openapi: 3.0.0\ninfo:\n  title: T\n  version: 1\npaths: {}\n")

    f2 = dir_path / "schema.graphql"
    f2.write_text("type Query { ping: String }\n")

    res = runner.invoke(app, ["scan", str(dir_path), "--format", "json"], env=CLI_ENV)
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["summary"]["total_targets"] == 2


def test_cli_scan_nonexistent_target() -> None:
    """Test CLI error exit on missing file or directory."""
    res = runner.invoke(app, ["scan", "/nonexistent/path/spec.yaml"], env=CLI_ENV)
    assert res.exit_code == 2
    assert "does not exist" in res.stdout
