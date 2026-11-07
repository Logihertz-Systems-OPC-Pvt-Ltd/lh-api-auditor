# ==============================================================================
# Product:       lh-api-auditor (lh-api)
# Module:        src.lh_api_auditor.__init__
# Role:          Package Initialization & Public API Declarations
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""lh-api-auditor: Enterprise OpenAPI and GraphQL security posture analyzer.

Audits OpenAPI v3, Swagger v2, and GraphQL schema definitions for OWASP API Security
Top 10 vulnerabilities, broken authentication, BOLA/IDOR patterns, mass assignment,
unbounded inputs, SSRF vectors, and exposed secrets.

Developed by Logihertz Systems (OPC) Private Limited.
"""

from __future__ import annotations

from lh_api_auditor.exporters import (
    OutputFormat,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_api_auditor.graphql_scanner import GraphQLScanner, scan_graphql
from lh_api_auditor.models import (
    RULES_REGISTRY,
    AuditReport,
    Finding,
    FindingCategory,
    FindingSeverity,
    RuleDefinition,
    ScanTargetResult,
    TargetType,
    create_finding,
)
from lh_api_auditor.openapi_scanner import OpenAPIScanner, scan_openapi

__version__ = "0.1.0"

__all__ = [
    "RULES_REGISTRY",
    "AuditReport",
    "Finding",
    "FindingCategory",
    "FindingSeverity",
    "GraphQLScanner",
    "OpenAPIScanner",
    "OutputFormat",
    "RuleDefinition",
    "ScanTargetResult",
    "TargetType",
    "__version__",
    "create_finding",
    "export_json",
    "export_sarif",
    "render_table_report",
    "scan_graphql",
    "scan_openapi",
]
