# ==============================================================================
# Product:       lh-api-auditor (lh-api)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for report exporters (Table, JSON, SARIF)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from lh_api_auditor.exporters import (
    _get_severity_badge,
    _severity_to_sarif_level,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_api_auditor.models import (
    RULES_REGISTRY,
    AuditReport,
    FindingCategory,
    FindingSeverity,
    ScanTargetResult,
    TargetType,
    create_finding,
)


def test_export_json() -> None:
    """Test exporting an AuditReport to structured JSON."""
    finding = create_finding(
        rule_id="LH-API-001",
        target="openapi.yaml",
        message="Unauthenticated POST /items",
        line_number=12,
        endpoint="/items",
        method="POST",
    )
    result = ScanTargetResult(
        target="openapi.yaml",
        target_type=TargetType.OPENAPI,
        findings=[finding],
    )
    report = AuditReport(
        report_type="api_security_audit",
        generated_at=datetime.now(UTC),
        results=[result],
    )

    json_str = export_json(report)
    data = json.loads(json_str)

    assert data["report_type"] == "api_security_audit"
    assert data["summary"]["critical"] == 1
    assert len(data["results"]) == 1
    assert data["results"][0]["findings"][0]["rule_id"] == "LH-API-001"


def test_export_sarif() -> None:
    """Test exporting an AuditReport to OASIS SARIF v2.1.0."""
    finding = create_finding(
        rule_id="LH-API-002",
        target="openapi.yaml",
        message="BOLA integer path parameter /accounts/{id}",
        line_number=25,
        endpoint="/accounts/{id}",
    )
    result = ScanTargetResult(
        target="openapi.yaml",
        target_type=TargetType.OPENAPI,
        findings=[finding],
    )
    report = AuditReport(
        report_type="api_security_audit",
        generated_at=datetime.now(UTC),
        results=[result],
    )

    sarif_str = export_sarif(report)
    sarif = json.loads(sarif_str)

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "lh-api-auditor"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "LH-API-002"
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 25


def test_render_table_report() -> None:
    """Test rendering rich terminal table output with findings."""
    finding = create_finding(
        rule_id="LH-API-003",
        target="openapi.yaml",
        message="Cleartext HTTP transport allowed",
        line_number=5,
    )
    result = ScanTargetResult(
        target="openapi.yaml",
        target_type=TargetType.OPENAPI,
        findings=[finding],
    )
    report = AuditReport(
        report_type="api_security_audit",
        generated_at=datetime.now(UTC),
        results=[result],
    )

    output = render_table_report(report)
    assert "lh-api-auditor" in output
    assert "LH-API-003" in output
    assert "Audit Executive Summary" in output


def test_render_table_clean_report() -> None:
    """Test rendering rich terminal table output for a clean audit."""
    result = ScanTargetResult(
        target="clean.yaml",
        target_type=TargetType.OPENAPI,
        findings=[],
    )
    report = AuditReport(
        report_type="api_security_audit",
        generated_at=datetime.now(UTC),
        results=[result],
    )

    output = render_table_report(report)
    assert "Clean Audit" in output


def test_rule_definition_and_badges() -> None:
    """Test severity badge styling and SARIF conversion helpers."""
    assert _severity_to_sarif_level(FindingSeverity.CRITICAL) == "error"
    assert _severity_to_sarif_level(FindingSeverity.HIGH) == "error"
    assert _severity_to_sarif_level(FindingSeverity.MEDIUM) == "warning"
    assert _severity_to_sarif_level(FindingSeverity.LOW) == "note"

    badge_crit = _get_severity_badge(FindingSeverity.CRITICAL)
    assert "CRITICAL" in badge_crit.plain

    assert len(RULES_REGISTRY) == 10
    rule_001 = RULES_REGISTRY["LH-API-001"]
    assert rule_001.category == FindingCategory.AUTHENTICATION
    assert TargetType.OPENAPI in rule_001.targets
