"""``redteam`` command line: scan, report, compare, list-attacks, validate."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from scanner.allowlist import TargetNotAllowedError, assert_allowed
from scanner.client import TargetClient, TargetError
from scanner.detectors.llm_judge import JudgeUnavailableError, anthropic_judge
from scanner.loader import ATTACKS_DIR, AttackLoadError, load_attacks
from scanner.models import CATEGORIES, AttackResult
from scanner.report import (
    ReportError,
    build_report,
    compare_reports,
    dump_report,
    load_report,
    render_comparison_markdown,
    render_html,
    render_markdown,
)
from scanner.runner import filter_attacks, run_scan

app = typer.Typer(help="Automated red-team scanner for the local NovaBank lab target.")

EXIT_FINDINGS = 1
EXIT_USAGE = 2

AttacksDir = typer.Option(ATTACKS_DIR, "--attacks-dir", help="Directory with attack YAML files.")
REPORT_FORMATS: tuple[str, ...] = ("md", "html", "json")


def _load(directory: Path):  # noqa: ANN202 - returns list[Attack]
    try:
        return load_attacks(directory)
    except AttackLoadError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc


@app.command()
def scan(
    target: str = typer.Option("http://localhost:8000", "--target", help="Localhost target URL."),
    categories: str = typer.Option("all", "--categories", help="Comma list (LLM01,LLM07) or all."),
    attacks_dir: Path = AttacksDir,
    timeout: float = typer.Option(10.0, "--timeout", help="Per-request timeout in seconds."),
    delay: float = typer.Option(0.0, "--delay", help="Seconds to wait before each request."),
    judge: bool = typer.Option(False, "--judge", help="Enable the optional LLM judge."),
    out: Annotated[Path | None, typer.Option("--out", help="Directory for report files.")] = None,
    fmt: Annotated[str, typer.Option("--format", help="Formats: md,html,json.")] = "md,html,json",
    name: Annotated[str, typer.Option("--name", help="Report file name, no extension.")] = "report",
) -> None:
    """Run attacks against a localhost target. Exits 1 if any finding, 2 on usage errors."""
    formats = _parse_formats(fmt)
    try:
        assert_allowed(target)  # before any network I/O
    except TargetNotAllowedError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    wanted = [c.strip().upper() for c in categories.split(",") if c.strip()]
    bad = [c for c in wanted if c != "ALL" and c not in CATEGORIES]
    if bad:
        typer.echo(f"error: unknown categories {bad}; choose from {list(CATEGORIES)}", err=True)
        raise typer.Exit(EXIT_USAGE)
    attacks = filter_attacks(_load(attacks_dir), wanted)
    judge_fn = None
    if judge:
        try:
            judge_fn = anthropic_judge()
        except JudgeUnavailableError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(EXIT_USAGE) from exc

    client = TargetClient(target, timeout=timeout, delay=delay)
    try:
        client.health()
        typer.echo(f"Scanning {client.base_url} with {len(attacks)} attacks")
        result = run_scan(client, attacks, judge=judge_fn, on_result=_print_result)
    except TargetError as exc:
        typer.echo(f"error: cannot reach target: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    finally:
        client.close()

    findings = result.findings
    typer.echo(f"\n{len(findings)} finding(s) out of {len(result.results)} attacks")
    if out is not None:
        _write_reports(build_report(result), out, name, formats)
    if findings:
        raise typer.Exit(EXIT_FINDINGS)


def _parse_formats(fmt: str) -> list[str]:
    formats = [f.strip().lower() for f in fmt.split(",") if f.strip()]
    bad = [f for f in formats if f not in REPORT_FORMATS]
    if bad or not formats:
        typer.echo(f"error: unknown format {bad}; choose from {list(REPORT_FORMATS)}", err=True)
        raise typer.Exit(EXIT_USAGE)
    return formats


def _write_reports(report: dict, out: Path, name: str, formats: list[str]) -> None:
    if Path(name).name != name or not name:
        typer.echo("error: --name must be a plain file name", err=True)
        raise typer.Exit(EXIT_USAGE)
    out.mkdir(parents=True, exist_ok=True)
    for f in formats:
        path = out / f"{name}.{f}"
        if f == "json":
            dump_report(report, path)
        else:
            text = render_markdown(report) if f == "md" else render_html(report)
            path.write_text(text, encoding="utf-8")
        typer.echo(f"wrote {path}")


def _load_report(path: Path) -> dict:
    try:
        return load_report(path)
    except ReportError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc


@app.command()
def report(
    results: Annotated[Path, typer.Argument(help="JSON results file written by `scan`.")],
    out: Annotated[Path, typer.Option("--out", help="Directory for report files.")] = Path(
        "results"
    ),
    fmt: Annotated[str, typer.Option("--format", help="Formats: md,html,json.")] = "md,html",
    name: Annotated[str | None, typer.Option("--name", help="File name, no extension.")] = None,
) -> None:
    """Render Markdown/HTML reports from a JSON results file (no network access)."""
    formats = _parse_formats(fmt)
    data = _load_report(results)
    _write_reports(data, out, name or results.stem, formats)


@app.command()
def compare(
    before: Annotated[Path, typer.Argument(help="JSON results from before the fix.")],
    after: Annotated[Path, typer.Argument(help="JSON results from after the fix.")],
    fmt: Annotated[str, typer.Option("--format", help="Output format: md or json.")] = "md",
    fail_on_regression: Annotated[
        bool,
        typer.Option(
            "--fail-on-regression", help="Exit 1 if an attack regressed or a new one is vulnerable."
        ),
    ] = False,
) -> None:
    """Compare two JSON results: fixed / still vulnerable / regressed / new / removed."""
    if fmt not in ("md", "json"):
        typer.echo("error: --format must be md or json", err=True)
        raise typer.Exit(EXIT_USAGE)
    comparison = compare_reports(_load_report(before), _load_report(after))
    if fmt == "json":
        typer.echo(json.dumps(comparison.to_dict(), indent=2))
    else:
        typer.echo(render_comparison_markdown(comparison), nl=False)
    if fail_on_regression and comparison.has_regression:
        raise typer.Exit(EXIT_FINDINGS)


def _print_result(r: AttackResult) -> None:
    label = {
        "vulnerable": "VULNERABLE",
        "not_vulnerable": "ok",
        "inconclusive": "inconclusive",
        "error": "ERROR",
    }[r.status]
    detail = r.evidence or r.error or ""
    typer.echo(f"[{label:>12}] {r.attack_id} ({r.severity.value}) {r.title}  {detail}".rstrip())


@app.command("list-attacks")
def list_attacks(
    attacks_dir: Path = AttacksDir,
    category: str | None = typer.Option(None, "--category", help="Only this category."),
) -> None:
    """List the attacks in the library."""
    attacks = filter_attacks(_load(attacks_dir), [category] if category else None)
    for a in attacks:
        typer.echo(f"{a.id}  {a.severity.value:<8} {a.detector.type:<12} {a.title}")
    typer.echo(f"{len(attacks)} attack(s)")


@app.command()
def validate(attacks_dir: Path = AttacksDir) -> None:
    """Validate the attack library (schema, ids, detectors). No network access."""
    attacks = _load(attacks_dir)
    typer.echo(f"OK: {len(attacks)} attacks valid")


if __name__ == "__main__":
    app()
