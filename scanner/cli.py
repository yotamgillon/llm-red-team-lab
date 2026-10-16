"""``redteam`` command line: scan, list-attacks, validate."""

from __future__ import annotations

from pathlib import Path

import typer

from scanner.allowlist import TargetNotAllowedError, assert_allowed
from scanner.client import TargetClient, TargetError
from scanner.detectors.llm_judge import JudgeUnavailableError, anthropic_judge
from scanner.loader import ATTACKS_DIR, AttackLoadError, load_attacks
from scanner.models import CATEGORIES, AttackResult
from scanner.runner import filter_attacks, run_scan

app = typer.Typer(help="Automated red-team scanner for the local NovaBank lab target.")

EXIT_FINDINGS = 1
EXIT_USAGE = 2

AttacksDir = typer.Option(ATTACKS_DIR, "--attacks-dir", help="Directory with attack YAML files.")


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
) -> None:
    """Run attacks against a localhost target. Exits 1 if any finding, 2 on usage errors."""
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
    if findings:
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
