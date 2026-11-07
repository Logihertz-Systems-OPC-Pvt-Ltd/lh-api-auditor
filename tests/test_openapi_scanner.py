# ==============================================================================
# Product:       lh-api-auditor (lh-api)
# Module:        tests.test_openapi_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for OpenAPIScanner."""

from __future__ import annotations

import json
from pathlib import Path

from lh_api_auditor.models import FindingSeverity
from lh_api_auditor.openapi_scanner import OpenAPIScanner, scan_openapi


def test_openapi_clean_spec(sample_clean_openapi: str) -> None:
    """Test that a compliant specification yields zero security violations."""
    scanner = OpenAPIScanner(sample_clean_openapi, "clean.yaml")
    res = scanner.scan()
    assert not res.has_error
    assert len(res.findings) == 0
    # --------------------------------------------------------------------------
    # --- Rule LH-API-001: Unauthenticated Endpoint (CRITICAL) ---
    # Evaluates security posture against unauthenticated endpoint.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_openapi_unauthenticated_state_changing_ops() -> None:
    """Test LH-API-001: Unauthenticated POST/PUT/DELETE/PATCH endpoints."""
    spec = """
    openapi: 3.0.0
    info:
      title: Insecure API
      version: 1.0.0
    paths:
      /items:
        post:
          summary: Create item
          responses:
            '201':
              description: Created
        put:
          summary: Update item
          security: []
          responses:
            '200':
              description: Updated
      /public-items:
        get:
          summary: Read items
          responses:
            '200':
              description: List of items
    """
    scanner = OpenAPIScanner(spec)
    res = scanner.scan()
    findings_001 = [f for f in res.findings if f.rule_id == "LH-API-001"]
    assert len(findings_001) == 2
    for f in findings_001:
        assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-API-002: Broken Object Level Authorization (BOLA/IDOR) Risk (HIGH) ---
    # Evaluates security posture against broken object level authorization
    # (bola/idor) risk.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_openapi_bola_idor_integer_path_params() -> None:
    """Test LH-API-002: Predictable sequential integer IDs susceptible to BOLA/IDOR."""
    spec = """
    openapi: 3.0.0
    info:
      title: BOLA Test API
      version: 1.0.0
    paths:
      /accounts/{accountId}:
        get:
          summary: Get account details
          parameters:
            - name: accountId
              in: path
              required: true
              schema:
                type: integer
          responses:
            '200':
              description: OK
      /orders/{order_id}:
        get:
          summary: Get order
          parameters:
            - name: order_id
              in: path
              required: true
              schema:
                type: string
          responses:
            '200':
              description: OK
    """
    scanner = OpenAPIScanner(spec)
    res = scanner.scan()
    findings_002 = [f for f in res.findings if f.rule_id == "LH-API-002"]
    assert len(findings_002) == 2
    for f in findings_002:
        assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-API-003: Cleartext HTTP Transport Allowed (HIGH) ---
    # Evaluates security posture against cleartext http transport allowed.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_openapi_cleartext_http_transport() -> None:
    """Test LH-API-003: Cleartext HTTP allowed in servers list or Swagger schemes."""
    spec_v3 = """
    openapi: 3.0.0
    info:
      title: HTTP API
      version: 1.0.0
    servers:
      - url: http://api.unencrypted.com/v1
    paths: {}
    """
    scanner_v3 = OpenAPIScanner(spec_v3)
    res_v3 = scanner_v3.scan()
    findings_003 = [f for f in res_v3.findings if f.rule_id == "LH-API-003"]
    assert len(findings_003) == 1

    spec_v2 = """
    swagger: "2.0"
    info:
      title: Swagger API
      version: 1.0.0
    schemes:
      - http
      - https
    paths: {}
    """
    scanner_v2 = OpenAPIScanner(spec_v2)
    res_v2 = scanner_v2.scan()
    findings_v2 = [f for f in res_v2.findings if f.rule_id == "LH-API-003"]
    assert len(findings_v2) == 1
    # --------------------------------------------------------------------------
    # --- Rule LH-API-004: Weak or Insecure Authentication Scheme (CRITICAL) ---
    # Evaluates security posture against weak or insecure authentication scheme.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_openapi_insecure_auth_schemes() -> None:
    """Test LH-API-004: Insecure authentication mechanisms."""
    spec = """
    openapi: 3.0.0
    info:
      title: Insecure Schemes
      version: 1.0.0
    paths: {}
    components:
      securitySchemes:
        QueryApiKey:
          type: apiKey
          name: api_key
          in: query
        BasicAuthentication:
          type: http
          scheme: basic
        ImplicitOAuth:
          type: oauth2
          flows:
            implicit:
              authorizationUrl: https://auth.example.com
              scopes: {}
    """
    scanner = OpenAPIScanner(spec)
    res = scanner.scan()
    findings_004 = [f for f in res.findings if f.rule_id == "LH-API-004"]
    assert len(findings_004) == 3
    for f in findings_004:
        assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-API-005: Missing Rate-Limiting Specification (MEDIUM) ---
    # Evaluates security posture against missing rate-limiting specification.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_openapi_missing_rate_limiting() -> None:
    """Test LH-API-005: Missing rate limiting response or headers."""
    spec = """
    openapi: 3.0.0
    info:
      title: No Rate Limits
      version: 1.0.0
    paths:
      /transfer:
        post:
          summary: Transfer money
          responses:
            '200':
              description: Success
    """
    scanner = OpenAPIScanner(spec)
    res = scanner.scan()
    findings_005 = [f for f in res.findings if f.rule_id == "LH-API-005"]
    assert len(findings_005) == 1
    assert findings_005[0].severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-API-006: Mass Assignment / Excessive Data Exposure (HIGH) ---
    # Evaluates security posture against mass assignment / excessive data exposure.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_openapi_mass_assignment() -> None:
    """Test LH-API-006: additionalProperties true in request bodies or schemas."""
    spec = """
    openapi: 3.0.0
    info:
      title: Mass Assignment API
      version: 1.0.0
    paths:
      /users:
        post:
          summary: Create user
          requestBody:
            content:
              application/json:
                schema:
                  type: object
                  additionalProperties: true
                  properties:
                    username:
                      type: string
          responses:
            '200':
              description: Created
    components:
      schemas:
        ProfileModel:
          type: object
          additionalProperties: true
    """
    scanner = OpenAPIScanner(spec)
    res = scanner.scan()
    findings_006 = [f for f in res.findings if f.rule_id == "LH-API-006"]
    assert len(findings_006) == 2
    for f in findings_006:
        assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-API-007: Unbounded Array or String Parameter (MEDIUM) ---
    # Evaluates security posture against unbounded array or string parameter.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_openapi_unbounded_inputs() -> None:
    """Test LH-API-007: Unbounded array and string parameters."""
    spec = """
    openapi: 3.0.0
    info:
      title: Unbounded Inputs API
      version: 1.0.0
    paths:
      /search:
        get:
          summary: Search records
          parameters:
            - name: query
              in: query
              schema:
                type: string
            - name: tags
              in: query
              schema:
                type: array
                items:
                  type: string
          responses:
            '200':
              description: OK
    """
    scanner = OpenAPIScanner(spec)
    res = scanner.scan()
    findings_007 = [f for f in res.findings if f.rule_id == "LH-API-007"]
    assert len(findings_007) == 2
    # --------------------------------------------------------------------------
    # --- Rule LH-API-008: Server-Side Request Forgery (SSRF) Vector (HIGH) ---
    # Evaluates security posture against server-side request forgery (ssrf) vector.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_openapi_ssrf_vector() -> None:
    """Test LH-API-008: URL/callback parameter lacking regex allowlist."""
    spec = """
    openapi: 3.0.0
    info:
      title: SSRF Vector API
      version: 1.0.0
    paths:
      /webhooks:
        post:
          summary: Register webhook
          requestBody:
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    callback:
                      type: string
          responses:
            '200':
              description: Registered
    """
    scanner = OpenAPIScanner(spec)
    res = scanner.scan()
    findings_008 = [f for f in res.findings if f.rule_id == "LH-API-008"]
    assert len(findings_008) == 1
    assert findings_008[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-API-009: Exposed Administrative Route (MEDIUM) ---
    # Evaluates security posture against exposed administrative route.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_openapi_exposed_admin_route() -> None:
    """Test LH-API-009: Exposed admin or debug routes."""
    spec = """
    openapi: 3.0.0
    info:
      title: Admin API
      version: 1.0.0
    paths:
      /admin/users:
        get:
          responses:
            '200':
              description: Admin user list
      /actuator/health:
        get:
          responses:
            '200':
              description: Actuator health status
    """
    scanner = OpenAPIScanner(spec)
    res = scanner.scan()
    findings_009 = [f for f in res.findings if f.rule_id == "LH-API-009"]
    assert len(findings_009) == 2
    # --------------------------------------------------------------------------
    # --- Rule LH-API-010: Hardcoded Secret Leaked in Specification (CRITICAL) ---
    # Evaluates security posture against hardcoded secret leaked in specification.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_openapi_hardcoded_secrets() -> None:
    """Test LH-API-010: Hardcoded secrets in examples and defaults."""
    spec = """
    openapi: 3.0.0
    info:
      title: Leaked Secrets API
      version: 1.0.0
    paths:
      /auth:
        post:
          requestBody:
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    api_key:
                      type: string
                      example: "AKIAIOSFODNN7EXAMPLE"
                    password:
                      type: string
                      default: "SuperSecretPassword123!"
          responses:
            '200':
              description: OK
    """
    scanner = OpenAPIScanner(spec)
    res = scanner.scan()
    findings_010 = [f for f in res.findings if f.rule_id == "LH-API-010"]
    assert len(findings_010) >= 2


def test_openapi_json_parsing(tmp_path: Path) -> None:
    """Test scanning a valid OpenAPI specification formatted as JSON."""
    data = {
        "openapi": "3.0.0",
        "info": {"title": "JSON API", "version": "1.0"},
        "servers": [{"url": "http://insecure.test"}],
        "paths": {},
    }
    file_path = tmp_path / "openapi.json"
    file_path.write_text(json.dumps(data), encoding="utf-8")

    res = scan_openapi(file_path)
    assert not res.has_error
    assert any(f.rule_id == "LH-API-003" for f in res.findings)


def test_openapi_error_handling(tmp_path: Path) -> None:
    """Test scanner error reporting on invalid files and syntax errors."""
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("openapi: 3.0.0\npaths: [unclosed list", encoding="utf-8")

    res = scan_openapi(bad_yaml)
    assert res.has_error
    assert "parsing error" in (res.error_message or "").lower()

    nonexistent = tmp_path / "missing.yaml"
    res_missing = scan_openapi(nonexistent)
    assert res_missing.has_error
