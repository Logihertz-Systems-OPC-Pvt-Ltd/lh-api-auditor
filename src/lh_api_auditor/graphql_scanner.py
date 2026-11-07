# ==============================================================================
# Product:       lh-api-auditor (lh-api)
# Module:        src.lh_api_auditor.graphql_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""GraphQL Schema Definition Language (SDL) static analysis scanner for lh-api-auditor.

Audits GraphQL schemas (.graphql, .gql) for unauthenticated mutations (LH-API-001),
mass assignment dynamic scalars (LH-API-006), unbounded lists/strings (LH-API-007),
SSRF callback arguments (LH-API-008), cyclic queries and introspection risks (LH-API-009),
and hardcoded tokens or credentials in default values (LH-API-010).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from lh_api_auditor.models import (
    Finding,
    ScanTargetResult,
    TargetType,
    create_finding,
)

AUTH_DIRECTIVES = {
    "auth",
    "authenticated",
    "hasrole",
    "requireauth",
    "authorized",
    "protect",
    "private",
}

DYNAMIC_SCALARS = {"json", "jsonobject", "any", "map", "dynamic"}

ADMIN_FIELD_REGEX = re.compile(
    r"^(admin|debug|actuator|metrics|internal|system|purge|reset|console)",
    re.IGNORECASE,
)

SSRF_ARG_REGEX = re.compile(
    r"^(url|uri|webhook|callback|redirect_url|redirecturl|target_url|targeturl)$",
    re.IGNORECASE,
)

PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
AWS_KEY_REGEX = re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")
GITHUB_TOKEN_REGEX = re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{82})\b")
SLACK_TOKEN_REGEX = re.compile(r"\bxox[baprs]-[0-9]{10,13}-[a-zA-Z0-9-]+\b")
JWT_TOKEN_REGEX = re.compile(r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b")
SECRET_KEY_REGEX = re.compile(
    r"(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)",
    re.IGNORECASE,
)
PLACEHOLDER_REGEX = re.compile(
    r"^(\*{3,}|x{3,}|<.*>|\$\{.*\}|\{\{.*\}\}|dummy|example|sample|test|changeme)$",
    re.IGNORECASE,
)


class GraphQLScanner:
    """Security auditor for GraphQL Schema Definition Language (SDL) schemas."""

    def __init__(self, content: str, target_path: str = "schema.graphql") -> None:
        self.content = content
        self.target_path = target_path
        self.lines = content.splitlines()

    def _find_line(self, pattern: str, start_line: int = 1) -> int:
        """Find the 1-based line number matching regex pattern."""
        regex = re.compile(pattern, re.IGNORECASE)
        for idx in range(start_line - 1, len(self.lines)):
            if regex.search(self.lines[idx]):
                return idx + 1
        return start_line

    def scan(self) -> ScanTargetResult:
        """Scan the GraphQL schema for security vulnerabilities."""
        findings: list[Finding] = []

        types = self._extract_blocks(r"(?:type|input|interface)\s+([A-Za-z0-9_]+)")

        self._check_mutations(types, findings)
        self._check_mass_assignment_and_inputs(types, findings)
        self._check_unbounded_and_ssrf(types, findings)
        self._check_introspection_and_recursion(types, findings)
        self._check_hardcoded_secrets(findings)

        return ScanTargetResult(
            target=self.target_path,
            target_type=TargetType.GRAPHQL,
            findings=findings,
        )

    def _extract_blocks(self, pattern: str) -> list[dict[str, Any]]:
        """Extract GraphQL type and input blocks with balanced braces."""
        results: list[dict[str, Any]] = []
        for m in re.finditer(pattern, self.content):
            type_name = m.group(1)
            open_brace_idx = self.content.find("{", m.start())
            if open_brace_idx == -1:
                continue
            depth = 1
            idx = open_brace_idx + 1
            while idx < len(self.content) and depth > 0:
                char = self.content[idx]
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                idx += 1
            body = self.content[open_brace_idx + 1 : idx - 1]
            start_line = self.content[: m.start()].count("\n") + 1
            results.append(
                {
                    "name": type_name,
                    "body": body,
                    "start_line": start_line,
                    "raw": m.group(0),
                }
            )
        return results

    # --------------------------------------------------------------------------
    # --- Rule LH-API-001: Unauthenticated Endpoint (CRITICAL) ---
    # Evaluates security posture against unauthenticated endpoint.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_mutations(self, types: list[dict[str, Any]], findings: list[Finding]) -> None:
        """Audit Mutation type fields for authentication directives (LH-API-001)."""
        mutation_types = [t for t in types if t["name"] == "Mutation"]
        for m_type in mutation_types:
            body = m_type["body"]
            field_lines = [line.strip() for line in body.splitlines() if line.strip()]
            for f_line in field_lines:
                if f_line.startswith("#") or f_line.startswith('"""'):
                    continue
                match = re.match(r"^([A-Za-z0-9_]+)\s*(\([^)]*\))?\s*:\s*([^@\s#]+)(.*)$", f_line)
                if not match:
                    continue

                field_name = match.group(1)
                directives_part = match.group(4) or ""

                has_auth = any(f"@{d}" in directives_part.lower() for d in AUTH_DIRECTIVES)
                if not has_auth:
                    line = self._find_line(rf"\b{re.escape(field_name)}\b", m_type["start_line"])
                    findings.append(
                        create_finding(
                            rule_id="LH-API-001",
                            target=self.target_path,
                            line_number=line,
                            endpoint=f"Mutation.{field_name}",
                            method="MUTATION",
                            message=(
                                f"GraphQL mutation '{field_name}' lacks authentication "
                                "directive (@auth, @hasRole, @requireAuth)."
                            ),
                            details={"field": field_name, "type": "Mutation"},
                        )
                    )

    def _check_mass_assignment_and_inputs(
        self, types: list[dict[str, Any]], findings: list[Finding]
    ) -> None:
        """Inspect input types for dynamic/unvalidated scalars (LH-API-006)."""
        input_types = [t for t in types if "input " in t.get("raw", "").lower()]
        for inp in input_types:
            body = inp["body"]
            for line_str in body.splitlines():
                line_str = line_str.strip()
                if not line_str or line_str.startswith("#"):
                    continue

                match = re.match(r"^([A-Za-z0-9_]+)\s*:\s*([A-Za-z0-9_!\[\]]+)", line_str)
                if match:
                    field_name = match.group(1)
                    field_type = match.group(2).replace("!", "").replace("[", "").replace("]", "")
                    if field_type.lower() in DYNAMIC_SCALARS:
                        line = self._find_line(rf"\b{re.escape(field_name)}\b", inp["start_line"])
                        findings.append(
                            create_finding(
                                rule_id="LH-API-006",
                                target=self.target_path,
                                line_number=line,
                                endpoint=f"{inp['name']}.{field_name}",
                                message=(
                                    f"Input '{inp['name']}' uses dynamic scalar '{field_type}' "
                                    f"for '{field_name}', enabling Mass Assignment."
                                ),
                                details={"input": inp["name"], "field": field_name},
                            )
                        )

    def _check_unbounded_and_ssrf(
        self, types: list[dict[str, Any]], findings: list[Finding]
    ) -> None:
        """Audit field arguments for SSRF vectors and unbounded parameters (LH-API-007, 008)."""
        for t in types:
            body = t["body"]
            for m in re.finditer(r"([A-Za-z0-9_]+)\s*\(([^)]+)\)\s*:\s*([A-Za-z0-9_!\[\]]+)", body):
                field_name = m.group(1)
                args_str = m.group(2)
                args = [a.strip() for a in args_str.split(",") if a.strip()]
                for arg in args:
                    arg_match = re.match(r"^([A-Za-z0-9_]+)\s*:\s*([A-Za-z0-9_!\[\]]+)", arg)
                    if not arg_match:
                        continue
                    arg_name = arg_match.group(1)
                    arg_type = arg_match.group(2)

                    if SSRF_ARG_REGEX.match(arg_name):
                        if "@pattern" not in arg:
                            line = self._find_line(rf"\b{re.escape(arg_name)}\b", t["start_line"])
                            findings.append(
                                create_finding(
                                    rule_id="LH-API-008",
                                    target=self.target_path,
                                    line_number=line,
                                    endpoint=f"{t['name']}.{field_name}({arg_name})",
                                    message=(
                                        f"Argument '{arg_name}' on {t['name']}.{field_name} "
                                        "accepts URL/callback without pattern validation."
                                    ),
                                    details={"field": field_name, "argument": arg_name},
                                )
                            )

                    if arg_type.startswith("[") and arg_type.endswith("]"):
                        if "@limit" not in arg and "@maxItems" not in arg:
                            line = self._find_line(rf"\b{re.escape(arg_name)}\b", t["start_line"])
                            findings.append(
                                create_finding(
                                    rule_id="LH-API-007",
                                    target=self.target_path,
                                    line_number=line,
                                    endpoint=f"{t['name']}.{field_name}({arg_name})",
                                    message=(
                                        f"List argument '{arg_name}' on {t['name']}.{field_name} "
                                        "lacks size limit constraint."
                                    ),
                                    details={"argument": arg_name, "type": arg_type},
                                )
                            )

    def _check_introspection_and_recursion(
        self, types: list[dict[str, Any]], findings: list[Finding]
    ) -> None:
        """Detect exposed introspection or admin interfaces (LH-API-009)."""
        type_names = {t["name"] for t in types}

        for t in types:
            if t["name"] in ("Query", "Mutation"):
                body = t["body"]
                for line_str in body.splitlines():
                    match = re.match(r"^\s*([A-Za-z0-9_]+)", line_str)
                    if match:
                        f_name = match.group(1)
                        if f_name.startswith("__") or f_name in ("_service", "_entities"):
                            line = self._find_line(re.escape(f_name), t["start_line"])
                            findings.append(
                                create_finding(
                                    rule_id="LH-API-009",
                                    target=self.target_path,
                                    line_number=line,
                                    endpoint=f"{t['name']}.{f_name}",
                                    message=(
                                        f"GraphQL schema exposes internal/introspection "
                                        f"field '{f_name}' directly."
                                    ),
                                    details={"field": f_name},
                                )
                            )
                        elif ADMIN_FIELD_REGEX.match(f_name):
                            line = self._find_line(re.escape(f_name), t["start_line"])
                            findings.append(
                                create_finding(
                                    rule_id="LH-API-009",
                                    target=self.target_path,
                                    line_number=line,
                                    endpoint=f"{t['name']}.{f_name}",
                                    message=(
                                        f"Administrative/debug operation '{f_name}' exposed "
                                        f"on {t['name']}."
                                    ),
                                    details={"field": f_name},
                                )
                            )

        field_refs: dict[str, set[str]] = {}
        for t in types:
            body = t["body"]
            refs: set[str] = set()
            for m in re.finditer(r":\s*\[?([A-Za-z0-9_]+)\]?!?", body):
                target_type = m.group(1)
                if target_type in type_names and target_type != t["name"]:
                    refs.add(target_type)
            field_refs[t["name"]] = refs

        cyclic_pairs: set[tuple[str, str]] = set()
        for t_name, refs in field_refs.items():
            for ref in refs:
                if t_name in field_refs.get(ref, set()):
                    pair = tuple(sorted([t_name, ref]))
                    cyclic_pairs.add((pair[0], pair[1]))

        for t1, t2 in cyclic_pairs:
            line = self._find_line(rf"type\s+{t1}\b")
            findings.append(
                create_finding(
                    rule_id="LH-API-009",
                    target=self.target_path,
                    line_number=line,
                    endpoint=f"{t1} <-> {t2}",
                    message=(
                        f"Unbounded cyclic type relationship between '{t1}' and '{t2}' "
                        "vulnerable to deeply nested query DoS."
                    ),
                    details={"type_a": t1, "type_b": t2},
                )
            )

    # --------------------------------------------------------------------------
    # --- Rule LH-API-010: Hardcoded Secret Leaked in Specification (CRITICAL) ---
    # Evaluates security posture against hardcoded secret leaked in specification.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_hardcoded_secrets(self, findings: list[Finding]) -> None:
        """Scan schema lines for hardcoded credentials or API tokens (LH-API-010)."""
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
                            message=f"Hardcoded {secret_name} detected in GraphQL schema.",
                            details={"line": line.strip(), "secret_type": secret_name},
                        )
                    )
                    break

            match = re.search(
                r'([A-Za-z0-9_.-]+)\s*(?::\s*[^=:]+)?[:=]\s*["\']([^"\']+)["\']', line
            )
            if match:
                k = match.group(1)
                val = match.group(2).strip()
                if val and not PLACEHOLDER_REGEX.match(val):
                    if SECRET_KEY_REGEX.search(k) or SECRET_KEY_REGEX.search(line):
                        findings.append(
                            create_finding(
                                rule_id="LH-API-010",
                                target=self.target_path,
                                line_number=line_num,
                                message="Potential hardcoded credential in default value.",
                                details={"field": k, "value": val[:10] + "..."},
                            )
                        )


def scan_graphql(path: Path | str) -> ScanTargetResult:
    """Read and audit a GraphQL schema file.

    Args:
        path: Path to .graphql or .gql schema file.

    Returns:
        ScanTargetResult containing all detected findings.
    """
    file_path = Path(path)
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return ScanTargetResult(
            target=str(file_path),
            target_type=TargetType.GRAPHQL,
            findings=[],
            error_message=f"Failed to read file: {e}",
        )

    scanner = GraphQLScanner(content=content, target_path=str(file_path))
    return scanner.scan()
