# ==============================================================================
# Product:       lh-api-auditor (lh-api)
# Module:        src.lh_api_auditor.openapi_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""OpenAPI v3 and Swagger v2 static analysis scanner for lh-api-auditor.

Audits OpenAPI and Swagger specifications in YAML and JSON formats for OWASP API Security
Top 10 risks: unauthenticated endpoints, BOLA/IDOR integer IDs, cleartext HTTP,
insecure auth schemes, missing rate limiting, mass assignment, unbounded inputs,
SSRF vectors, exposed admin endpoints, and leaked credentials in examples.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from lh_api_auditor.models import (
    Finding,
    ScanTargetResult,
    TargetType,
    create_finding,
)

SECRET_KEY_REGEX = re.compile(
    r"(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|credential)",
    re.IGNORECASE,
)
PLACEHOLDER_REGEX = re.compile(
    r"^(\*{3,}|x{3,}|<.*>|\$\{.*\}|\{\{.*\}\}|dummy|example|sample|test|changeme|your[-_]?.*)$",
    re.IGNORECASE,
)
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
AWS_KEY_REGEX = re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")
GITHUB_TOKEN_REGEX = re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{82})\b")
SLACK_TOKEN_REGEX = re.compile(r"\bxox[baprs]-[0-9]{10,13}-[a-zA-Z0-9-]+\b")
JWT_TOKEN_REGEX = re.compile(r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b")
SSRF_PARAM_REGEX = re.compile(
    r"^(url|uri|webhook|callback|redirect_url|target_url|image_url|endpoint)$",
    re.IGNORECASE,
)
ADMIN_ROUTE_REGEX = re.compile(
    r"^/(admin|debug|actuator|metrics|_internal|console|heapdump|trace|env)(/.*)?$",
    re.IGNORECASE,
)


class OpenAPIScanner:
    """Security auditor for OpenAPI v3 and Swagger v2 specifications."""

    def __init__(self, content: str, target_path: str = "openapi.yaml") -> None:
        self.content = content
        self.target_path = target_path
        self.lines = content.splitlines()

    def _find_line(self, pattern: str, start_line: int = 1) -> int:
        """Locate the 1-based line number matching regex pattern."""
        regex = re.compile(pattern, re.IGNORECASE)
        for idx in range(start_line - 1, len(self.lines)):
            if regex.search(self.lines[idx]):
                return idx + 1
        return start_line

    def scan(self) -> ScanTargetResult:
        """Analyze OpenAPI specification for security vulnerabilities."""
        try:
            if self.target_path.endswith(".json") or self.content.strip().startswith("{"):
                spec = json.loads(self.content)
            else:
                spec = yaml.safe_load(self.content)
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            return ScanTargetResult(
                target=self.target_path,
                target_type=TargetType.OPENAPI,
                findings=[],
                error_message=f"Specification parsing error: {e}",
            )

        if not isinstance(spec, dict):
            return ScanTargetResult(
                target=self.target_path,
                target_type=TargetType.OPENAPI,
                findings=[],
                error_message="Parsed specification is not a valid dictionary object.",
            )

        findings: list[Finding] = []

        self._check_transport_security(spec, findings)
        self._check_auth_schemes(spec, findings)
        self._check_paths(spec, findings)
        self._check_schemas_and_components(spec, findings)
        self._check_secrets_in_examples(spec, findings)

        return ScanTargetResult(
            target=self.target_path,
            target_type=TargetType.OPENAPI,
            findings=findings,
        )

    # --------------------------------------------------------------------------
    # --- Rule LH-API-003: Cleartext HTTP Transport Allowed (HIGH) ---
    # Evaluates security posture against cleartext http transport allowed.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_transport_security(self, spec: dict[str, Any], findings: list[Finding]) -> None:
        """Inspect server URLs and schemes for cleartext HTTP (LH-API-003)."""
        servers = spec.get("servers", [])
        if isinstance(servers, list):
            for s in servers:
                if isinstance(s, dict):
                    url = s.get("url", "")
                    if url.lower().startswith("http://") and not (
                        "localhost" in url or "127.0.0.1" in url
                    ):
                        line = self._find_line(re.escape(url))
                        findings.append(
                            create_finding(
                                rule_id="LH-API-003",
                                target=self.target_path,
                                line_number=line,
                                message=(f"Server URL '{url}' allows cleartext HTTP transport."),
                                details={"server_url": url},
                            )
                        )

        schemes = spec.get("schemes", [])
        if isinstance(schemes, list) and "http" in [str(x).lower() for x in schemes]:
            line = self._find_line(r"schemes\s*:")
            findings.append(
                create_finding(
                    rule_id="LH-API-003",
                    target=self.target_path,
                    line_number=line,
                    message="Swagger v2 schemes explicitly allow cleartext 'http' transport.",
                    details={"schemes": schemes},
                )
            )

    # --------------------------------------------------------------------------
    # --- Rule LH-API-004: Weak or Insecure Authentication Scheme (CRITICAL) ---
    # Evaluates security posture against weak or insecure authentication scheme.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_auth_schemes(self, spec: dict[str, Any], findings: list[Finding]) -> None:
        """Check for weak or insecure authentication mechanisms (LH-API-004)."""
        components = spec.get("components", {})
        sec_schemes: dict[str, Any] = {}
        if isinstance(components, dict):
            sec_schemes = components.get("securitySchemes", {}) or {}

        if not sec_schemes:
            sec_schemes = spec.get("securityDefinitions", {}) or {}

        if not isinstance(sec_schemes, dict):
            return

        for name, scheme in sec_schemes.items():
            if not isinstance(scheme, dict):
                continue

            scheme_type = str(scheme.get("type", "")).lower()

            if scheme_type == "apikey" and str(scheme.get("in", "")).lower() == "query":
                line = self._find_line(r"in\s*:\s*[\"']?query[\"']?")
                findings.append(
                    create_finding(
                        rule_id="LH-API-004",
                        target=self.target_path,
                        line_number=line,
                        message=(
                            f"API Key scheme '{name}' passes keys in URL query string (in: query)."
                        ),
                        details={"scheme": name, "in": "query"},
                    )
                )

            if scheme_type == "basic" or (
                scheme_type == "http" and str(scheme.get("scheme", "")).lower() == "basic"
            ):
                line = self._find_line(rf"[\"']?{re.escape(name)}[\"']?")
                findings.append(
                    create_finding(
                        rule_id="LH-API-004",
                        target=self.target_path,
                        line_number=line,
                        message=(f"Insecure HTTP Basic authentication scheme '{name}' configured."),
                        details={"scheme": name, "type": "basic"},
                    )
                )

            flow = str(scheme.get("flow", "")).lower()
            if flow in ("implicit", "password"):
                line = self._find_line(rf"flow\s*:\s*[\"']?{re.escape(flow)}[\"']?")
                findings.append(
                    create_finding(
                        rule_id="LH-API-004",
                        target=self.target_path,
                        line_number=line,
                        message=(f"OAuth2 scheme '{name}' uses deprecated/insecure '{flow}' flow."),
                        details={"scheme": name, "flow": flow},
                    )
                )

            flows = scheme.get("flows", {})
            if isinstance(flows, dict):
                for bad_flow in ("implicit", "password"):
                    if bad_flow in flows:
                        line = self._find_line(rf"[\"']?{bad_flow}[\"']?\s*:")
                        findings.append(
                            create_finding(
                                rule_id="LH-API-004",
                                target=self.target_path,
                                line_number=line,
                                message=(
                                    f"OAuth2 scheme '{name}' configures insecure '{bad_flow}' flow."
                                ),
                                details={"scheme": name, "flow": bad_flow},
                            )
                        )

    def _check_paths(self, spec: dict[str, Any], findings: list[Finding]) -> None:
        """Scan endpoint operations for auth, BOLA, rate limits, SSRF, and admin paths."""
        paths = spec.get("paths", {})
        if not isinstance(paths, dict):
            return

        global_security = spec.get("security")
        has_global_sec = isinstance(global_security, list) and len(global_security) > 0

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            if ADMIN_ROUTE_REGEX.match(path_str) or any(
                seg in path_str.lower().split("/") for seg in ("admin", "debug", "actuator")
            ):
                line = self._find_line(re.escape(path_str))
                findings.append(
                    create_finding(
                        rule_id="LH-API-009",
                        target=self.target_path,
                        line_number=line,
                        endpoint=path_str,
                        message=(
                            f"Potentially exposed administrative or debug route '{path_str}'."
                        ),
                        details={"path": path_str},
                    )
                )

            path_params = path_item.get("parameters", [])
            path_params_list = path_params if isinstance(path_params, list) else []

            for method in ("get", "post", "put", "delete", "patch", "options", "head"):
                op = path_item.get(method)
                if not isinstance(op, dict):
                    continue

                method_upper = method.upper()

                if method_upper in ("POST", "PUT", "DELETE", "PATCH"):
                    op_sec = op.get("security")
                    if op_sec is not None:
                        is_unauth = isinstance(op_sec, list) and len(op_sec) == 0
                    else:
                        is_unauth = not has_global_sec

                    if is_unauth:
                        line = self._find_line(rf"[\"']?{method}[\"']?\s*:")
                        findings.append(
                            create_finding(
                                rule_id="LH-API-001",
                                target=self.target_path,
                                line_number=line,
                                endpoint=path_str,
                                method=method_upper,
                                message=(
                                    f"State-changing {method_upper} {path_str} "
                                    "lacks authentication or declares empty security: []."
                                ),
                                details={"path": path_str, "method": method_upper},
                            )
                        )

                combined_params = list(path_params_list)
                op_params = op.get("parameters", [])
                if isinstance(op_params, list):
                    combined_params.extend(op_params)

                self._check_parameters(path_str, method_upper, combined_params, findings)

                if method_upper in ("POST", "PUT", "DELETE", "PATCH", "GET"):
                    self._check_rate_limiting(path_str, method_upper, op, findings)

                req_body = op.get("requestBody", {})
                if isinstance(req_body, dict):
                    self._check_request_body(path_str, method_upper, req_body, findings)

    def _check_parameters(
        self,
        path_str: str,
        method: str,
        parameters: list[Any],
        findings: list[Finding],
    ) -> None:
        """Analyze operation parameters for BOLA integer IDs, SSRF, and unbounded inputs."""
        for param in parameters:
            if not isinstance(param, dict):
                continue

            param_name = str(param.get("name", ""))
            param_in = str(param.get("in", "")).lower()

            schema = param.get("schema", {})
            param_type = (
                str(schema.get("type", "")).lower()
                if isinstance(schema, dict) and schema
                else str(param.get("type", "")).lower()
            )
            param_format = (
                str(schema.get("format", "")).lower()
                if isinstance(schema, dict) and schema
                else str(param.get("format", "")).lower()
            )
            has_pattern = (
                bool(schema.get("pattern"))
                if isinstance(schema, dict) and schema
                else bool(param.get("pattern"))
            )

            if param_in == "path":
                is_numeric = param_type in ("integer", "number")
                is_id_name = bool(
                    re.search(r"(?:^|_)id$|Id$", param_name)
                    or param_name in ("id", "user_id", "order_id", "account_id")
                )
                if (is_numeric or is_id_name) and param_format != "uuid" and not has_pattern:
                    line = self._find_line(rf"name\s*:\s*[\"']?{re.escape(param_name)}[\"']?")
                    findings.append(
                        create_finding(
                            rule_id="LH-API-002",
                            target=self.target_path,
                            line_number=line,
                            endpoint=path_str,
                            method=method,
                            message=(
                                f"Path parameter '{param_name}' in {path_str} uses sequential "
                                "integer or unvalidated ID susceptible to BOLA / IDOR."
                            ),
                            details={
                                "parameter": param_name,
                                "type": param_type,
                                "format": param_format,
                            },
                        )
                    )

            if SSRF_PARAM_REGEX.match(param_name):
                if not has_pattern:
                    line = self._find_line(rf"name\s*:\s*[\"']?{re.escape(param_name)}[\"']?")
                    findings.append(
                        create_finding(
                            rule_id="LH-API-008",
                            target=self.target_path,
                            line_number=line,
                            endpoint=path_str,
                            method=method,
                            message=(
                                f"Parameter '{param_name}' on {method} {path_str} accepts "
                                "URL/callback destination without regex pattern validation."
                            ),
                            details={"parameter": param_name},
                        )
                    )

            if param_type == "array":
                has_max_items = (
                    "maxItems" in schema if isinstance(schema, dict) else "maxItems" in param
                )
                if not has_max_items:
                    line = self._find_line(rf"name\s*:\s*[\"']?{re.escape(param_name)}[\"']?")
                    findings.append(
                        create_finding(
                            rule_id="LH-API-007",
                            target=self.target_path,
                            line_number=line,
                            endpoint=path_str,
                            method=method,
                            message=(
                                f"Array parameter '{param_name}' on {method} {path_str} lacks "
                                "maxItems constraint, risking payload resource exhaustion."
                            ),
                            details={"parameter": param_name},
                        )
                    )

            if param_type == "string":
                has_max_len = (
                    "maxLength" in schema if isinstance(schema, dict) else "maxLength" in param
                )
                has_enum = "enum" in schema if isinstance(schema, dict) else "enum" in param
                is_bounded = (
                    has_max_len
                    or has_pattern
                    or has_enum
                    or param_format in ("date", "date-time", "uuid", "binary", "byte")
                )
                if not is_bounded and param_in in ("query", "header", "formData"):
                    line = self._find_line(rf"name\s*:\s*[\"']?{re.escape(param_name)}[\"']?")
                    findings.append(
                        create_finding(
                            rule_id="LH-API-007",
                            target=self.target_path,
                            line_number=line,
                            endpoint=path_str,
                            method=method,
                            message=(
                                f"String parameter '{param_name}' on {method} {path_str} lacks "
                                "maxLength constraint, risking resource exhaustion."
                            ),
                            details={"parameter": param_name},
                        )
                    )

    def _check_rate_limiting(
        self,
        path_str: str,
        method: str,
        operation: dict[str, Any],
        findings: list[Finding],
    ) -> None:
        """Verify presence of rate limiting responses and headers (LH-API-005)."""
        responses = operation.get("responses", {})
        if not isinstance(responses, dict):
            return

        has_429 = "429" in responses or 429 in responses

        has_rate_headers = False
        for _status_code, resp_obj in responses.items():
            if isinstance(resp_obj, dict):
                headers = resp_obj.get("headers", {})
                if isinstance(headers, dict):
                    for h_name in headers:
                        h_lower = str(h_name).lower()
                        if "ratelimit" in h_lower or h_lower == "retry-after":
                            has_rate_headers = True
                            break

        if not has_429 and not has_rate_headers:
            line = self._find_line(rf"[\"']?{method.lower()}[\"']?\s*:")
            findings.append(
                create_finding(
                    rule_id="LH-API-005",
                    target=self.target_path,
                    line_number=line,
                    endpoint=path_str,
                    method=method,
                    message=(
                        f"Operation {method} {path_str} does not specify HTTP 429 response "
                        "or rate limiting headers (X-RateLimit-* / Retry-After)."
                    ),
                    details={"path": path_str, "method": method},
                )
            )

    def _check_request_body(
        self,
        path_str: str,
        method: str,
        req_body: dict[str, Any],
        findings: list[Finding],
    ) -> None:
        """Audit request body schema for Mass Assignment (LH-API-006) and SSRF (LH-API-008)."""
        content = req_body.get("content", {})
        if not isinstance(content, dict):
            return

        for _media_type, media_obj in content.items():
            if not isinstance(media_obj, dict):
                continue
            schema = media_obj.get("schema", {})
            if isinstance(schema, dict):
                self._audit_schema_object(path_str, method, schema, findings)

    def _audit_schema_object(
        self,
        path_str: str,
        method: str,
        schema: dict[str, Any],
        findings: list[Finding],
    ) -> None:
        """Recursively inspect request schema for mass assignment and SSRF properties."""
        if schema.get("additionalProperties") is True:
            line = self._find_line(r"additionalProperties\s*:\s*true")
            findings.append(
                create_finding(
                    rule_id="LH-API-006",
                    target=self.target_path,
                    line_number=line,
                    endpoint=path_str,
                    method=method,
                    message=(
                        f"Request schema on {method} {path_str} allows additionalProperties: true, "
                        "vulnerable to Mass Assignment."
                    ),
                    details={"endpoint": path_str, "method": method},
                )
            )

        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for prop_name, prop_schema in properties.items():
                if not isinstance(prop_schema, dict):
                    continue

                if SSRF_PARAM_REGEX.match(prop_name) and not prop_schema.get("pattern"):
                    line = self._find_line(rf"[\"']?{re.escape(prop_name)}[\"']?\s*:")
                    findings.append(
                        create_finding(
                            rule_id="LH-API-008",
                            target=self.target_path,
                            line_number=line,
                            endpoint=path_str,
                            method=method,
                            message=(
                                f"Body field '{prop_name}' on {method} {path_str} accepts "
                                "URL/callback without regex pattern validation."
                            ),
                            details={"field": prop_name},
                        )
                    )

                if prop_schema.get("type") == "array" and "maxItems" not in prop_schema:
                    line = self._find_line(rf"[\"']?{re.escape(prop_name)}[\"']?\s*:")
                    findings.append(
                        create_finding(
                            rule_id="LH-API-007",
                            target=self.target_path,
                            line_number=line,
                            endpoint=path_str,
                            method=method,
                            message=(
                                f"Array property '{prop_name}' on {method} {path_str} lacks "
                                "maxItems limit."
                            ),
                            details={"field": prop_name},
                        )
                    )

    def _check_schemas_and_components(self, spec: dict[str, Any], findings: list[Finding]) -> None:
        """Scan component/definition models for Mass Assignment and unconstrained bounds."""
        components = spec.get("components", {})
        schemas = (
            components.get("schemas", {})
            if isinstance(components, dict)
            else spec.get("definitions", {})
        )
        if not isinstance(schemas, dict):
            return

        for schema_name, schema_obj in schemas.items():
            if not isinstance(schema_obj, dict):
                continue

            if schema_obj.get("additionalProperties") is True:
                line = self._find_line(rf"[\"']?{re.escape(schema_name)}[\"']?\s*:")
                findings.append(
                    create_finding(
                        rule_id="LH-API-006",
                        target=self.target_path,
                        line_number=line,
                        message=(
                            f"Model schema '{schema_name}' permits additionalProperties: true, "
                            "enabling Mass Assignment."
                        ),
                        details={"schema": schema_name},
                    )
                )

    # --------------------------------------------------------------------------
    # --- Rule LH-API-010: Hardcoded Secret Leaked in Specification (CRITICAL) ---
    # Evaluates security posture against hardcoded secret leaked in specification.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_secrets_in_examples(self, spec: dict[str, Any], findings: list[Finding]) -> None:
        """Detect live secrets or tokens in examples or default fields (LH-API-010)."""
        for i, line in enumerate(self.lines):
            line_num = i + 1
            for regex, secret_name in (
                (PRIVATE_KEY_REGEX, "Private Key"),
                (AWS_KEY_REGEX, "AWS Access Key"),
                (GITHUB_TOKEN_REGEX, "GitHub Token"),
                (SLACK_TOKEN_REGEX, "Slack Token"),
                (JWT_TOKEN_REGEX, "JWT Bearer Token"),
            ):
                if regex.search(line):
                    findings.append(
                        create_finding(
                            rule_id="LH-API-010",
                            target=self.target_path,
                            line_number=line_num,
                            message=(f"Hardcoded {secret_name} pattern exposed in specification."),
                            details={"line": line.strip(), "secret_type": secret_name},
                        )
                    )
                    break

            match = re.search(
                r"[\"\'\s]?(example|default|examples)[\"\'\s]?\s*[:=]\s*[\"\']([^\"\']+)[\"\']",
                line,
                re.IGNORECASE,
            )
            if match:
                val = match.group(2).strip()
                if val and not PLACEHOLDER_REGEX.match(val):
                    key_match = re.search(r"([A-Za-z0-9_.-]+)\s*[:=]", line)
                    k = key_match.group(1) if key_match else ""
                    if SECRET_KEY_REGEX.search(k) or SECRET_KEY_REGEX.search(line):
                        findings.append(
                            create_finding(
                                rule_id="LH-API-010",
                                target=self.target_path,
                                line_number=line_num,
                                message=(
                                    f"Potential secret or password in '{match.group(1)}' field."
                                ),
                                details={"field": match.group(1), "value": val[:10] + "..."},
                            )
                        )


def scan_openapi(path: Path | str) -> ScanTargetResult:
    """Read and audit an OpenAPI or Swagger specification file.

    Args:
        path: Path to YAML or JSON specification.

    Returns:
        ScanTargetResult containing all detected findings.
    """
    file_path = Path(path)
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return ScanTargetResult(
            target=str(file_path),
            target_type=TargetType.OPENAPI,
            findings=[],
            error_message=f"Failed to read file: {e}",
        )

    scanner = OpenAPIScanner(content=content, target_path=str(file_path))
    return scanner.scan()
