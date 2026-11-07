# ==============================================================================
# Product:       lh-api-auditor (lh-api)
# Module:        src.lh_api_auditor.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and findings representations for lh-api-auditor.

Provides structured types for API specification targets, security findings,
severity classifications, detection rule definitions, and audit reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity classification for API security posture findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparisons."""
        order = {
            FindingSeverity.LOW: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.HIGH: 3,
            FindingSeverity.CRITICAL: 4,
        }
        return order[self]

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


class FindingCategory(StrEnum):
    """Categories aligning with OWASP API Security Top 10."""

    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION_BOLA = "AUTHORIZATION_BOLA"
    TRANSPORT_SECURITY = "TRANSPORT_SECURITY"
    RATE_LIMITING = "RATE_LIMITING"
    DATA_EXPOSURE = "DATA_EXPOSURE"
    RESOURCE_MANAGEMENT = "RESOURCE_MANAGEMENT"
    SSRF_INJECTION = "SSRF_INJECTION"
    EXPOSURE_RISK = "EXPOSURE_RISK"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"  # nosec B105


class TargetType(StrEnum):
    """Specification format and dialect of scanned target."""

    OPENAPI = "OPENAPI"
    GRAPHQL = "GRAPHQL"
    UNKNOWN = "UNKNOWN"


@dataclass
class RuleDefinition:
    """Metadata definition for a built-in LH-API posture audit rule."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: FindingCategory
    description: str
    remediation: str
    targets: list[TargetType]


@dataclass
class Finding:
    """Represents a specific API security misconfiguration or flaw."""

    rule_id: str
    title: str
    category: FindingCategory
    severity: FindingSeverity
    target: str
    message: str
    line_number: int | None = None
    endpoint: str | None = None
    method: str | None = None
    resource: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "target": self.target,
            "line_number": self.line_number,
            "endpoint": self.endpoint or self.resource,
            "method": self.method,
            "resource": self.resource or self.endpoint,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ScanTargetResult:
    """Analysis results for a single target file."""

    target: str
    target_type: TargetType
    findings: list[Finding] = field(default_factory=list)
    error_message: str | None = None

    @property
    def has_error(self) -> bool:
        """Whether target analysis encountered an execution error."""
        return self.error_message is not None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message,
        }


@dataclass
class AuditReport:
    """Complete aggregated audit report across all analyzed targets."""

    report_type: str = "api_security_audit"
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    parameters: dict[str, Any] = field(default_factory=dict)
    results: list[ScanTargetResult] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def compute_summary(self) -> None:
        """Recalculate summary totals from all scanned target results."""
        all_findings = [f for r in self.results for f in r.findings]
        self.summary = {
            "total_targets": len(self.results),
            "total_findings": len(all_findings),
            "critical": sum(1 for f in all_findings if f.severity == FindingSeverity.CRITICAL),
            "high": sum(1 for f in all_findings if f.severity == FindingSeverity.HIGH),
            "medium": sum(1 for f in all_findings if f.severity == FindingSeverity.MEDIUM),
            "low": sum(1 for f in all_findings if f.severity == FindingSeverity.LOW),
        }

    def filter_min_severity(self, min_severity: FindingSeverity | None) -> None:
        """Filter out findings with severity lower than min_severity."""
        if min_severity is None:
            return
        for r in self.results:
            r.findings = [f for f in r.findings if f.severity.meets_threshold(min_severity)]
        self.compute_summary()

    def has_failures(self, fail_on: FindingSeverity | None) -> bool:
        """Check if any finding meets or exceeds the fail_on threshold."""
        if fail_on is None:
            return False
        for r in self.results:
            if r.error_message:
                return True
            for f in r.findings:
                if f.severity.meets_threshold(fail_on):
                    return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete audit report to dictionary."""
        self.compute_summary()
        return {
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "parameters": self.parameters,
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
        }


RULES_REGISTRY: dict[str, RuleDefinition] = {
    "LH-API-001": RuleDefinition(
        rule_id="LH-API-001",
        title="Unauthenticated API endpoint on state-changing operations",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.AUTHENTICATION,
        description=(
            "Operation lacks global and operation-level security schemes or explicitly "
            "declares empty security: [] on state-changing POST/PUT/DELETE/PATCH routes."
        ),
        remediation=(
            "Apply a global security requirement or declare operation-level OAuth2, "
            "OpenID Connect, Bearer JWT, or API key security requirements."
        ),
        targets=[TargetType.OPENAPI, TargetType.GRAPHQL],
    ),
    "LH-API-002": RuleDefinition(
        rule_id="LH-API-002",
        title="BOLA / IDOR vulnerability on sequential integer path IDs",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.AUTHORIZATION_BOLA,
        description=(
            "Path parameter relies on sequential integer/number types without UUID format, "
            "regex pattern validation, or object-level authorization controls."
        ),
        remediation=(
            "Replace sequential integer IDs with UUIDs (format: uuid) or enforce strict "
            "authorization checks and cryptographically secure random identifiers."
        ),
        targets=[TargetType.OPENAPI],
    ),
    "LH-API-003": RuleDefinition(
        rule_id="LH-API-003",
        title="Cleartext HTTP transport allowed in servers or schemes",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.TRANSPORT_SECURITY,
        description=(
            "OpenAPI v3 servers list or Swagger v2 schemes allows unencrypted cleartext "
            "HTTP transport, exposing credentials and payload data in transit."
        ),
        remediation=(
            "Remove http:// schemes from server URLs and enforce https:// exclusively across "
            "all staging and production API endpoints."
        ),
        targets=[TargetType.OPENAPI],
    ),
    "LH-API-004": RuleDefinition(
        rule_id="LH-API-004",
        title="Insecure authentication scheme (query API key, basic auth, implicit grant)",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.AUTHENTICATION,
        description=(
            "Security scheme specifies API key passed in query string (in: query), HTTP Basic "
            "auth, or deprecated OAuth2 implicit/password grant flows."
        ),
        remediation=(
            "Pass API keys in request headers (in: header) and migrate to OAuth 2.1 "
            "authorization code flow with PKCE or Bearer JWT."
        ),
        targets=[TargetType.OPENAPI],
    ),
    "LH-API-005": RuleDefinition(
        rule_id="LH-API-005",
        title="Missing rate-limiting specification (lacks 429 response or headers)",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.RATE_LIMITING,
        description=(
            "API operation does not document HTTP 429 (Too Many Requests) response or "
            "rate limiting response headers (X-RateLimit-* / Retry-After)."
        ),
        remediation=(
            "Define HTTP 429 responses and document standard rate limiting headers "
            "(Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining)."
        ),
        targets=[TargetType.OPENAPI],
    ),
    "LH-API-006": RuleDefinition(
        rule_id="LH-API-006",
        title="Mass Assignment / excessive exposure (additionalProperties: true)",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.DATA_EXPOSURE,
        description=(
            "Request body or object schema explicitly allows additionalProperties: true or lacks "
            "strict property validation, allowing mass assignment and property injection."
        ),
        remediation=(
            "Explicitly configure additionalProperties: false on input schemas and define strict, "
            "whitelisted properties for request and response models."
        ),
        targets=[TargetType.OPENAPI, TargetType.GRAPHQL],
    ),
    "LH-API-007": RuleDefinition(
        rule_id="LH-API-007",
        title="Unbounded array or string susceptible to resource exhaustion",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.RESOURCE_MANAGEMENT,
        description=(
            "Array schema lacks maxItems constraint or string schema lacks maxLength constraint, "
            "leaving the API vulnerable to payload-based resource exhaustion and DoS."
        ),
        remediation=(
            "Specify explicit maxItems limits on array schemas and maxLength constraints or "
            "regex patterns on string inputs."
        ),
        targets=[TargetType.OPENAPI, TargetType.GRAPHQL],
    ),
    "LH-API-008": RuleDefinition(
        rule_id="LH-API-008",
        title="Server-Side Request Forgery (SSRF) vector in URL/callback parameter",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.SSRF_INJECTION,
        description=(
            "Request parameter or schema property accepts URL/webhook/callback values without "
            "strict domain allowlisting or regex pattern validation."
        ),
        remediation=(
            "Define strict regex pattern constraints allowlisting approved domains and protocols, "
            "and validate webhook destinations against internal network ranges."
        ),
        targets=[TargetType.OPENAPI, TargetType.GRAPHQL],
    ),
    "LH-API-009": RuleDefinition(
        rule_id="LH-API-009",
        title="Exposed administrative route or GraphQL introspection / cyclic query risk",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.EXPOSURE_RISK,
        description=(
            "API exposes administrative/debug routes (/admin, /debug, /actuator, /metrics) or "
            "GraphQL schema permits introspection and unbounded cyclic queries."
        ),
        remediation=(
            "Segregate administrative routes into private endpoints requiring administrative "
            "roles, and disable introspection and enforce query depth limits in GraphQL."
        ),
        targets=[TargetType.OPENAPI, TargetType.GRAPHQL],
    ),
    "LH-API-010": RuleDefinition(
        rule_id="LH-API-010",
        title="Hardcoded secrets, API tokens, or credentials in example/default values",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.SECRET_EXPOSURE,
        description=(
            "Live API key, JWT token, AWS credential, private key, or password discovered "
            "in OpenAPI example, examples, or default attribute fields."
        ),
        remediation=(
            "Remove real credentials from API specifications and replace them with standard "
            "dummy placeholders (e.g. 'YOUR_API_KEY', 'EXAMPLE_TOKEN')."
        ),
        targets=[TargetType.OPENAPI, TargetType.GRAPHQL],
    ),
}


def create_finding(
    rule_id: str,
    target: str,
    message: str,
    line_number: int | None = None,
    endpoint: str | None = None,
    method: str | None = None,
    resource: str | None = None,
    details: dict[str, Any] | None = None,
) -> Finding:
    """Construct a Finding instance using metadata from RULES_REGISTRY."""
    rule = RULES_REGISTRY[rule_id]
    ep = endpoint or resource
    res = resource or endpoint
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        category=rule.category,
        severity=rule.severity,
        target=target,
        message=message,
        line_number=line_number,
        endpoint=ep,
        method=method,
        resource=res,
        details=details or {},
    )
