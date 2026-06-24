"""コマンドラインインターフェース。

使い方:
    python -m wp_checker https://example.com
    python -m wp_checker https://example.com --checks exposed-files
    python -m wp_checker https://example.com --json report.json
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.table import Table

from . import __version__
from .checks import ALL_CHECKS
from .http import Client
from .report import Report, Severity

console = Console()

_SEV_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="wp_checker",
        description="WordPress コンテンツ層の脆弱性スキャナ（自己管理サイト向け）。",
    )
    p.add_argument("target", help="対象URL 例: https://example.com")
    p.add_argument(
        "--checks",
        help=f"実行するチェックをカンマ区切りで指定。既定は全部。選択肢: {', '.join(ALL_CHECKS)}",
    )
    p.add_argument("--json", metavar="FILE", help="結果をJSONで保存するファイルパス")
    p.add_argument("--timeout", type=float, default=10.0, help="リクエストタイムアウト秒 (既定10)")
    p.add_argument("--delay", type=float, default=0.3, help="リクエスト間隔秒 (既定0.3)")
    p.add_argument("--insecure", action="store_true", help="TLS証明書検証を無効化")
    p.add_argument(
        "--yes", action="store_true",
        help="対象サイトを自分が管理している確認をスキップ",
    )
    p.add_argument("--version", action="version", version=f"wp_checker {__version__}")
    return p.parse_args(argv)


def _confirm_authorization(target: str) -> bool:
    console.print(
        "[bold yellow]確認:[/] このツールは自分が管理する／検査の許可を得たサイトにのみ使用してください。",
    )
    console.print(f"対象: [bold]{target}[/]")
    try:
        ans = console.input("この対象を検査する権限がありますか？ [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans in ("y", "yes")


def _select_checks(spec: str | None) -> list[str]:
    if not spec:
        return list(ALL_CHECKS)
    requested = [c.strip() for c in spec.split(",") if c.strip()]
    unknown = [c for c in requested if c not in ALL_CHECKS]
    if unknown:
        console.print(f"[red]不明なチェック:[/] {', '.join(unknown)}")
        console.print(f"利用可能: {', '.join(ALL_CHECKS)}")
        raise SystemExit(2)
    return requested


def _render(report: Report) -> None:
    findings = report.sorted()
    if not findings:
        console.print("[green]検出された問題はありませんでした。[/]")
        return

    table = Table(title=f"スキャン結果: {report.target}", show_lines=False)
    table.add_column("深刻度", no_wrap=True)
    table.add_column("チェック", no_wrap=True)
    table.add_column("内容")
    table.add_column("URL", overflow="fold")

    for f in findings:
        style = _SEV_STYLE.get(f.severity.label, "")
        table.add_row(
            f"[{style}]{f.severity.label}[/]" if style else f.severity.label,
            f.check,
            f.title,
            f.url or "",
        )
    console.print(table)

    counts = report.counts()
    summary = "  ".join(
        f"[{_SEV_STYLE.get(s, '')}]{s}: {counts[s]}[/]"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        if s in counts
    )
    console.print(f"\n合計 {len(findings)} 件  —  {summary}")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        console.print("[red]target は http:// または https:// で始める必要があります。[/]")
        return 2

    if not args.yes and not _confirm_authorization(target):
        console.print("[red]中止しました。[/]")
        return 1

    check_ids = _select_checks(args.checks)
    report = Report(target=target)

    with Client(
        timeout=args.timeout,
        delay=args.delay,
        verify_tls=not args.insecure,
    ) as client:
        for cid in check_ids:
            check_cls = ALL_CHECKS[cid]
            check = check_cls(client, target)
            console.print(f"[dim]→ {cid}: {check.description}[/]")
            for finding in check.run():
                report.add(finding)

    console.print()
    _render(report)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(report.to_json())
        console.print(f"\n[green]JSONを保存しました:[/] {args.json}")

    # CRITICAL/HIGH があれば非ゼロ終了（CI連携用）。
    worst = max((f.severity for f in report.findings), default=Severity.INFO)
    return 1 if worst >= Severity.HIGH else 0


if __name__ == "__main__":
    raise SystemExit(main())
