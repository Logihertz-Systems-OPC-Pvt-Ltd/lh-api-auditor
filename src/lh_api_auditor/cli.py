# ==============================================================================
# Product:       lh-api-auditor (lh-api)
# Module:        src.lh_api_auditor.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command-line interface for lh-api-auditor.

Implements CLI commands:
- lh-api scan <path> [--format table|json|sarif] [--output <path>]
                     [--min-severity <level>] [--fail-on <level>]
- lh-api rules
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from lh_api_auditor.exporters import (
    OutputFormat,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_api_auditor.graphql_scanner import scan_graphql
from lh_api_auditor.models import (
    RULES_REGISTRY,
    AuditReport,
    FindingSeverity,
    ScanTargetResult,
    TargetType,
)
from lh_api_auditor.openapi_scanner import scan_openapi

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-api",
    help=(
        "Enterprise OpenAPI and GraphQL security analyzer and vulnerability auditor.\n"
        "Developed by Logihertz Systems (OPC) Private Limited."
    ),
    no_args_is_help=True,
    rich_markup_mode=None,
)
console = Console()


def _is_graphql_file(path: Path) -> bool:
    """Check if file is a GraphQL schema definition."""
    name = path.name.lower()
    if name.endswith((".graphql", ".gql")):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:400]
        if "type Query" in head or "type Mutation" in head or "schema {" in head:
            return True
    except (OSError, UnicodeDecodeError):
        return False
    return False


def _is_openapi_file(path: Path) -> bool:
    """Check if file is an OpenAPI or Swagger specification."""
    name = path.name.lower()
    if name.endswith((".yaml", ".yml", ".json")):
        try:
            head = path.read_text(encoding="utf-8", errors="ignore")[:500]
            if "openapi:" in head or '"openapi"' in head:
                return True
            if "swagger:" in head or '"swagger"' in head:
                return True
        except (OSError, UnicodeDecodeError):
            return False
    return False


def _discover_and_scan(target_path: Path) -> list[ScanTargetResult]:
    """Scan target path (file or recursively in directory)."""
    results: list[ScanTargetResult] = []

    if target_path.is_file():
        if _is_graphql_file(target_path):
            results.append(scan_graphql(target_path))
        elif _is_openapi_file(target_path):
            results.append(scan_openapi(target_path))
        else:
            try:
                head = target_path.read_text(encoding="utf-8", errors="ignore")[:400]
                if "type " in head or "schema " in head:
                    results.append(scan_graphql(target_path))
                else:
                    results.append(scan_openapi(target_path))
            except (OSError, UnicodeDecodeError) as e:
                results.append(
                    ScanTargetResult(
                        target=str(target_path),
                        target_type=TargetType.UNKNOWN,
                        findings=[],
                        error_message=f"Could not read target file: {e}",
                    )
                )
        return results

    found_targets = False

    gql_files = list(target_path.rglob("*.graphql")) + list(target_path.rglob("*.gql"))
    for gf in sorted(set(gql_files)):
        if gf.is_file() and not any(part.startswith(".") for part in gf.parts):
            results.append(scan_graphql(gf))
            found_targets = True

    spec_files = (
        list(target_path.rglob("*.yaml"))
        + list(target_path.rglob("*.yml"))
        + list(target_path.rglob("*.json"))
    )
    for sf in sorted(set(spec_files)):
        if sf.is_file() and not any(part.startswith(".") for part in sf.parts):
            if _is_openapi_file(sf):
                results.append(scan_openapi(sf))
                found_targets = True

    if not found_targets:
        results.append(
            ScanTargetResult(
                target=str(target_path),
                target_type=TargetType.UNKNOWN,
                findings=[],
                error_message="No OpenAPI, Swagger, or GraphQL specifications discovered.",
            )
        )

    return results


def _output_report(
    report: AuditReport,
    fmt: OutputFormat,
    output_path: Path | None,
) -> None:
    """Format and write or print the audit report according to format and destination."""
    report.compute_summary()

    if fmt == OutputFormat.JSON:
        rendered = export_json(report)
    elif fmt == OutputFormat.SARIF:
        rendered = export_sarif(report)
    else:
        if output_path:
            file_console = Console(record=True, width=120, color_system=None)
            render_table_report(report, console=file_console)
            rendered = file_console.export_text()
        else:
            render_table_report(report, console=console)
            rendered = ""

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        console.print(f"[bold green]Report successfully written to {output_path}[/bold green]")
    elif rendered:
        print(rendered)


@app.command(name="scan")
def scan(
    path: Annotated[
        str,
        typer.Argument(help="Path to OpenAPI (.yaml/.json), GraphQL (.graphql), or directory."),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: table, json, or sarif."),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write output report file."),
    ] = None,
    min_severity: Annotated[
        FindingSeverity | None,
        typer.Option("--min-severity", "-s", help="Filter findings below this severity."),
    ] = None,
    fail_on: Annotated[
        FindingSeverity | None,
        typer.Option(
            "--fail-on",
            help="Severity threshold for failure exit (CRITICAL, HIGH, MEDIUM, LOW).",
        ),
    ] = FindingSeverity.HIGH,
) -> None:
    """Scan OpenAPI specifications and GraphQL schemas for security vulnerabilities."""
    target_path = Path(path)
    if not target_path.exists():
        console.print(f"[bold red]Error: Target path '{path}' does not exist.[/bold red]")
        raise typer.Exit(code=2)

    results = _discover_and_scan(target_path)

    report = AuditReport(
        report_type="api_security_audit",
        generated_at=datetime.now(UTC),
        parameters={
            "path": path,
            "format": format.value,
            "min_severity": min_severity.value if min_severity else None,
            "fail_on": fail_on.value if fail_on else None,
        },
        results=results,
    )

    if min_severity is not None:
        report.filter_min_severity(min_severity)

    _output_report(report, format, output)

    if report.has_failures(fail_on):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="rules")
def rules() -> None:
    """List all supported LH-API security posture detection rules."""
    table = Table(
        title="LH-API Security Detection Rules",
        border_style="blue",
    )
    table.add_column("Rule ID", style="bold magenta", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("Category", style="cyan")
    table.add_column("Rule Title", style="bold white")
    table.add_column("Targets")
    table.add_column("Description")

    sev_styles = {
        FindingSeverity.CRITICAL: "bold white on red",
        FindingSeverity.HIGH: "bold red",
        FindingSeverity.MEDIUM: "bold yellow",
        FindingSeverity.LOW: "bold cyan",
    }

    for rule_id, rule_def in sorted(RULES_REGISTRY.items()):
        badge = Text(rule_def.severity.value, style=sev_styles.get(rule_def.severity, "bold"))
        targets_str = ", ".join(t.value for t in rule_def.targets)
        table.add_row(
            rule_id,
            badge,
            rule_def.category.value,
            rule_def.title,
            targets_str,
            rule_def.description,
        )

    console.print(table)


if __name__ == "__main__":
    app()
