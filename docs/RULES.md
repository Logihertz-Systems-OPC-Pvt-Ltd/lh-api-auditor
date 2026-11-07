# Security Rules Reference: lh-api-auditor

An enterprise openapi & graphql security posture auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-api-auditor`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-API-001` | `CRITICAL` | Authentication | Unauthenticated Endpoint |
| `LH-API-002` | `HIGH` | Authorization | Broken Object Level Authorization (BOLA/IDOR) Risk |
| `LH-API-003` | `HIGH` | Transport Security | Cleartext HTTP Transport Allowed |
| `LH-API-004` | `CRITICAL` | Authentication | Weak or Insecure Authentication Scheme |
| `LH-API-005` | `MEDIUM` | Availability | Missing Rate-Limiting Specification |
| `LH-API-006` | `HIGH` | Data Governance | Mass Assignment / Excessive Data Exposure |
| `LH-API-007` | `MEDIUM` | Input Validation | Unbounded Array or String Parameter |
| `LH-API-008` | `HIGH` | Injection | Server-Side Request Forgery (SSRF) Vector |
| `LH-API-009` | `MEDIUM` | Access Control | Exposed Administrative Route |
| `LH-API-010` | `CRITICAL` | Secret Hygiene | Hardcoded Secret Leaked in Specification |

---

## Granular Rule Specifications

### `LH-API-001`: Unauthenticated Endpoint

- **Severity**: `CRITICAL`
- **Category**: `Authentication`
- **Description**: Endpoint missing global and operation-level security requirements.
- **Remediation**: Declare explicit security requirements (e.g. OAuth2, bearerAuth) on the operation.

---

### `LH-API-002`: Broken Object Level Authorization (BOLA/IDOR) Risk

- **Severity**: `HIGH`
- **Category**: `Authorization`
- **Description**: Path parameter reference vulnerable to IDOR without explicit authorization guardrails.
- **Remediation**: Implement object-level access control middleware validating user ownership before resolving entity.

---

### `LH-API-003`: Cleartext HTTP Transport Allowed

- **Severity**: `HIGH`
- **Category**: `Transport Security`
- **Description**: OpenAPI servers list declaring insecure http:// endpoints without mandatory TLS.
- **Remediation**: Enforce HTTPS schemes exclusively across all production and staging server declarations.

---

### `LH-API-004`: Weak or Insecure Authentication Scheme

- **Severity**: `CRITICAL`
- **Category**: `Authentication`
- **Description**: API keys passed via query parameters or basic auth transmitted over unencrypted transport.
- **Remediation**: Migrate API key transmission to HTTP Authorization headers or mTLS client certificates.

---

### `LH-API-005`: Missing Rate-Limiting Specification

- **Severity**: `MEDIUM`
- **Category**: `Availability`
- **Description**: Operation response schema lacks 429 Too Many Requests declaration or rate limiting metadata.
- **Remediation**: Define 429 response schemas and configure rate-limiting headers across public endpoints.

---

### `LH-API-006`: Mass Assignment / Excessive Data Exposure

- **Severity**: `HIGH`
- **Category**: `Data Governance`
- **Description**: Object schema allows unbounded property mutation without readOnly guards.
- **Remediation**: Explicitly mark internal fields (roles, id, permissions) as readOnly or use dedicated DTOs.

---

### `LH-API-007`: Unbounded Array or String Parameter

- **Severity**: `MEDIUM`
- **Category**: `Input Validation`
- **Description**: Missing maxItems or maxLength constraints risking buffer overruns or resource exhaustion.
- **Remediation**: Declare strict minLength/maxLength on strings and maxItems on request arrays.

---

### `LH-API-008`: Server-Side Request Forgery (SSRF) Vector

- **Severity**: `HIGH`
- **Category**: `Injection`
- **Description**: Request parameter accepts unvalidated target URLs for webhook or callback processing.
- **Remediation**: Validate destination URLs against strict domain allowlists and block internal IP addresses.

---

### `LH-API-009`: Exposed Administrative Route

- **Severity**: `MEDIUM`
- **Category**: `Access Control`
- **Description**: Administrative or internal paths (/admin, /debug) exposed on public external API surface.
- **Remediation**: Segregate administrative APIs to private subnets or dedicated management endpoints.

---

### `LH-API-010`: Hardcoded Secret Leaked in Specification

- **Severity**: `CRITICAL`
- **Category**: `Secret Hygiene`
- **Description**: Live API keys, bearer tokens, or database credentials leaked in specification examples.
- **Remediation**: Purge credentials from examples and replace with non-functional placeholder values.

---
