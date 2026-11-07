# lh-api-auditor

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-api-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-api-auditor/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise api schema & graphql security developed by **Logihertz Systems (OPC) Private Limited**.

Scans OpenAPI v3, Swagger v2, and GraphQL schema specifications for OWASP API Security Top 10 risks including broken object-level authorization (BOLA), unauthenticated routes, mass assignment, and unbounded query depth.

---

## Key Features

- **Dual-Engine Schema Parsing**: Parses both OpenAPI RESTful specifications and GraphQL SDL schemas without external dependencies.
- **BOLA & IDOR Flaw Detection**: Analyzes path parameters and object references for missing authorization controls and insecure object retrieval.
- **Transport & Authentication Auditing**: Detects cleartext HTTP endpoints, query-string API keys, and unauthenticated administrative routes.
- **Mass Assignment & Over-Posting Auditing**: Flags unbounded object schemas and excessive data exposure in request/response schemas.
- **SSRF & Input Injection Vector Detection**: Flags URL and remote host parameters vulnerable to Server-Side Request Forgery.
- **Multi-Format Reporting**: Supports interactive terminal tables via `rich`, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-API-001` | `CRITICAL` | Unauthenticated Endpoint — missing global and operation-level security requirements on sensitive routes |
| `LH-API-002` | `HIGH` | Broken Object Level Authorization (BOLA/IDOR) Risk — path parameter reference lacking access control |
| `LH-API-003` | `HIGH` | Cleartext HTTP Transport Allowed — OpenAPI servers list declaring insecure http:// endpoints |
| `LH-API-004` | `CRITICAL` | Weak or Insecure Authentication Scheme — API keys passed via query parameters or basic auth over HTTP |
| `LH-API-005` | `MEDIUM` | Missing Rate-Limiting Specification — operation response schema lacks 429 Too Many Requests declaration |
| `LH-API-006` | `HIGH` | Mass Assignment / Excessive Data Exposure — object schema allows unbounded property mutation without readOnly guards |
| `LH-API-007` | `MEDIUM` | Unbounded Array or String Parameter — missing maxItems or maxLength constraints risking resource exhaustion |
| `LH-API-008` | `HIGH` | Server-Side Request Forgery (SSRF) Vector — request parameter accepting unvalidated target URLs |
| `LH-API-009` | `MEDIUM` | Exposed Administrative Route — administrative or internal paths (/admin, /debug) exposed on public APIs |
| `LH-API-010` | `CRITICAL` | Hardcoded Secret Leaked in Specification — live API keys, bearer tokens, or credentials in examples/descriptions |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-api-auditor.git
cd lh-api-auditor

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-api` (also accessible via `lh-api`, `lh-api-auditor`).

```bash
# Scan an OpenAPI 3.0/3.1 specification
lh-api scan openapi.yaml

# Scan a GraphQL SDL schema
lh-api scan schema.graphql --format json

# Export findings to OASIS SARIF format
lh-api scan openapi.json --format sarif --output api-results.sarif

# Filter by minimum severity threshold
lh-api scan ./apis/ --min-severity HIGH
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
