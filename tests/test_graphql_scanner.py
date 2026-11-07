# ==============================================================================
# Product:       lh-api-auditor (lh-api)
# Module:        tests.test_graphql_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for GraphQLScanner."""

from __future__ import annotations

from pathlib import Path

from lh_api_auditor.graphql_scanner import GraphQLScanner, scan_graphql
from lh_api_auditor.models import FindingSeverity


def test_graphql_clean_schema(sample_clean_graphql: str) -> None:
    """Test that a compliant GraphQL schema yields no findings."""
    scanner = GraphQLScanner(sample_clean_graphql, "clean.graphql")
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


def test_graphql_unauthenticated_mutations() -> None:
    """Test LH-API-001: Mutations lacking authorization directives."""
    schema = """
    type Mutation {
      createRecord(name: String!): Boolean
      protectedAction(id: ID!): Boolean @auth(role: "ADMIN")
      unprotectedAction(data: String): Boolean
    }
    """
    scanner = GraphQLScanner(schema)
    res = scanner.scan()
    findings_001 = [f for f in res.findings if f.rule_id == "LH-API-001"]
    assert len(findings_001) == 2
    for f in findings_001:
        assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-API-006: Mass Assignment / Excessive Data Exposure (HIGH) ---
    # Evaluates security posture against mass assignment / excessive data exposure.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_graphql_mass_assignment_dynamic_scalars() -> None:
    """Test LH-API-006: Input types with dynamic unvalidated scalars."""
    schema = """
    input UserInput {
      username: String!
      metadata: JSON
      payload: Any
    }
    """
    scanner = GraphQLScanner(schema)
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
    # --------------------------------------------------------------------------
    # --- Rule LH-API-008: Server-Side Request Forgery (SSRF) Vector (HIGH) ---
    # Evaluates security posture against server-side request forgery (ssrf) vector.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_graphql_unbounded_list_and_ssrf() -> None:
    """Test LH-API-007 (unbounded lists) and LH-API-008 (SSRF callback args)."""
    schema = """
    type Query {
      search(tags: [String]): [String]
      registerHook(callback: String): Boolean
    }
    """
    scanner = GraphQLScanner(schema)
    res = scanner.scan()
    findings_007 = [f for f in res.findings if f.rule_id == "LH-API-007"]
    findings_008 = [f for f in res.findings if f.rule_id == "LH-API-008"]
    assert len(findings_007) == 1
    assert len(findings_008) == 1
    # --------------------------------------------------------------------------
    # --- Rule LH-API-009: Exposed Administrative Route (MEDIUM) ---
    # Evaluates security posture against exposed administrative route.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_graphql_introspection_and_recursion() -> None:
    """Test LH-API-009: Admin fields and recursive cyclic type relationships."""
    schema = """
    type Query {
      adminConsole: String
      __schema: String
    }

    type User {
      id: ID!
      posts: [Post]
    }

    type Post {
      id: ID!
      author: User
    }
    """
    scanner = GraphQLScanner(schema)
    res = scanner.scan()
    findings_009 = [f for f in res.findings if f.rule_id == "LH-API-009"]
    assert len(findings_009) >= 2
    # --------------------------------------------------------------------------
    # --- Rule LH-API-010: Hardcoded Secret Leaked in Specification (CRITICAL) ---
    # Evaluates security posture against hardcoded secret leaked in specification.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_graphql_hardcoded_secrets() -> None:
    """Test LH-API-010: Hardcoded credentials or tokens in schema defaults."""
    schema = """
    type Query {
      connect(apiKey: String = "AKIAIOSFODNN7EXAMPLE"): Boolean
      login(password: String = "SuperSecretPassword123!"): String
    }
    """
    scanner = GraphQLScanner(schema)
    res = scanner.scan()
    findings_010 = [f for f in res.findings if f.rule_id == "LH-API-010"]
    assert len(findings_010) >= 2


def test_graphql_error_handling(tmp_path: Path) -> None:
    """Test error reporting on unreadable GraphQL schema files."""
    missing = tmp_path / "missing.graphql"
    res = scan_graphql(missing)
    assert res.has_error
    assert "failed to read file" in (res.error_message or "").lower()
