"""露出ファイル検査。

外部から到達できる「あってはならない／情報を漏らす」ファイルやパスを探す。
WordPress は未知のパスに対してトップページや 200 のカスタム404を返すことが多いため、
ランダムな存在しないパスでベースライン（soft-404）を取り、それと区別して判定する。
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Iterator
from dataclasses import dataclass

from ..report import Finding, Severity
from .base import Check


@dataclass(frozen=True)
class Probe:
    """調べる1パスの定義。

    path       : base_url からの相対パス。
    title      : 見出し。
    severity   : 検出時の深刻度。
    detail     : なぜ問題か。
    remediation: 推奨対応。
    signature  : 本物だと確認するための本文の正規表現（任意）。
                 指定時、200 でも本文が一致しなければ誤検出として除外する。
    """

    path: str
    title: str
    severity: Severity
    detail: str
    remediation: str
    signature: str | None = None


# 危険度が高い順におおむね整理。網羅ではなく「効果の高い定番」を厳選。
PROBES: list[Probe] = [
    # --- 認証情報・設定の露出（最重要） ---
    Probe(
        "wp-config.php.bak", "wp-config のバックアップ露出", Severity.CRITICAL,
        "DB接続情報・認証キーを含む wp-config.php のバックアップが平文で取得できる可能性。",
        "公開ディレクトリから削除する。バックアップはドキュメントルート外へ。",
        signature=r"DB_PASSWORD|DB_NAME|AUTH_KEY",
    ),
    Probe(
        "wp-config.php~", "wp-config の一時バックアップ露出", Severity.CRITICAL,
        "エディタが残した ~ 付きバックアップ。DB認証情報が漏れる。",
        "削除し、編集はサーバ外で行う。",
        signature=r"DB_PASSWORD|DB_NAME|AUTH_KEY",
    ),
    Probe(
        "wp-config.php.save", "wp-config の保存バックアップ露出", Severity.CRITICAL,
        "DB認証情報を含む保存バックアップが取得できる可能性。",
        "削除する。", signature=r"DB_PASSWORD|DB_NAME",
    ),
    Probe(
        ".env", "環境変数ファイル(.env)露出", Severity.CRITICAL,
        "APIキー・DBパスワード等の機密が平文で漏れる。",
        "公開領域から削除し、ドキュメントルート外へ移す。",
        signature=r"(DB_|APP_KEY|SECRET|PASSWORD)",
    ),
    Probe(
        "wp-config-sample.php", "wp-config-sample.php の存在", Severity.LOW,
        "WordPress 同梱のサンプル設定。実害は小さいが導入の痕跡を露出。",
        "削除して問題ない。",
    ),
    # --- ソース管理・デプロイの痕跡 ---
    Probe(
        ".git/config", ".git ディレクトリ露出", Severity.HIGH,
        "リポジトリ全体（過去の認証情報・全ソース）を復元される恐れ。",
        ".git を公開領域から除外、またはWebサーバでアクセス拒否する。",
        signature=r"\[core\]|repositoryformatversion",
    ),
    Probe(
        ".git/HEAD", ".git/HEAD 露出", Severity.HIGH,
        ".git の露出。リポジトリをダンプされる恐れ。",
        ".git へのアクセスを拒否する。", signature=r"ref:\s+refs/",
    ),
    Probe(
        ".svn/entries", ".svn メタデータ露出", Severity.MEDIUM,
        "Subversion の管理情報。ソース構造が漏れる。",
        ".svn へのアクセスを拒否する。",
    ),
    Probe(
        "wp-content/debug.log", "debug.log 露出", Severity.HIGH,
        "WP_DEBUG_LOG の出力。パス・SQL・エラー詳細など内部情報が漏れる。",
        "WP_DEBUG_LOG を無効化、または debug.log を削除しアクセス拒否する。",
    ),
    # --- バックアップ・ダンプ ---
    Probe(
        "backup.sql", "SQLダンプ露出", Severity.CRITICAL,
        "データベースダンプが取得できる可能性。全データ漏洩。",
        "削除し、バックアップは公開領域に置かない。", signature=r"INSERT INTO|CREATE TABLE",
    ),
    Probe(
        "database.sql", "SQLダンプ露出", Severity.CRITICAL,
        "データベースダンプが取得できる可能性。",
        "削除する。", signature=r"INSERT INTO|CREATE TABLE",
    ),
    Probe(
        "backup.zip", "バックアップ書庫露出", Severity.HIGH,
        "サイト一式のバックアップが取得できる可能性。",
        "公開領域から削除する。",
    ),
    Probe(
        "installer.php", "Duplicator installer.php 残骸", Severity.HIGH,
        "移行ツールのインストーラ残骸。乗っ取り・DB再構築の入口になる。",
        "installer*.php と installer-backup を削除する。",
    ),
    # --- バージョン・情報露出 ---
    Probe(
        "readme.html", "readme.html によるバージョン露出", Severity.LOW,
        "WordPress コアの正確なバージョンが読める。既知脆弱性の標的選定を助ける。",
        "削除またはアクセス拒否する。", signature=r"WordPress",
    ),
    Probe(
        "license.txt", "license.txt の存在", Severity.INFO,
        "WordPress 導入の痕跡・おおまかなバージョン手掛かり。",
        "必須ではないが削除可能。", signature=r"WordPress",
    ),
    # --- 権限・攻撃の入口 ---
    Probe(
        "xmlrpc.php", "XML-RPC 有効", Severity.MEDIUM,
        "ブルートフォース増幅(system.multicall)やpingback悪用の入口になりうる。",
        "不要なら無効化、またはアクセス制限する。",
        signature=r"XML-RPC server accepts POST requests only",
    ),
    Probe(
        "wp-content/uploads/", "uploads ディレクトリリスティング", Severity.MEDIUM,
        "アップロード一覧が閲覧可能。非公開ファイルや内部情報が漏れる。",
        "Webサーバで自動インデックスを無効化する(Options -Indexes 等)。",
        signature=r"Index of /|<title>Index of",
    ),
    Probe(
        "wp-content/plugins/", "plugins ディレクトリリスティング", Severity.LOW,
        "導入プラグイン一覧が露出し、既知脆弱性の標的選定を助ける。",
        "自動インデックスを無効化する。",
        signature=r"Index of /|<title>Index of",
    ),
]


class ExposedFilesCheck(Check):
    id = "exposed-files"
    description = "外部から見える不適切なファイル・権限設定の入口を検査する"
    active = False

    # soft-404 判定で「同じ扱い」とみなすステータス群。
    _NOTFOUND_STATUSES = {404, 403, 410}

    def run(self) -> Iterator[Finding]:
        baseline = self._baseline()

        for probe in PROBES:
            res = self.client.get(self.url(probe.path))
            if not res.ok:
                continue
            if res.status not in (200, 206):
                continue

            # soft-404 判定: 存在しないパスと同じ本文サイズなら誤検出とみなす。
            if baseline is not None and self._looks_like_softnotfound(res.text, baseline):
                continue

            # シグネチャ指定があれば本文一致を必須にする。
            if probe.signature and not re.search(probe.signature, res.text, re.IGNORECASE):
                continue

            yield Finding(
                check=self.id,
                title=probe.title,
                severity=probe.severity,
                url=res.url,
                detail=probe.detail,
                evidence={
                    "status": res.status,
                    "content_type": res.headers.get("content-type", ""),
                    "bytes": len(res.text),
                },
                remediation=probe.remediation,
            )

    def _baseline(self) -> str | None:
        """存在しないはずのランダムパスを引いて soft-404 の本文を得る。"""
        rand = secrets.token_hex(8)
        res = self.client.get(self.url(f"wp-checker-not-here-{rand}"))
        if res.ok and res.status in (200, 206):
            return res.text
        return None

    @staticmethod
    def _looks_like_softnotfound(body: str, baseline: str) -> bool:
        """本文長がベースラインとほぼ同一なら soft-404 とみなす。"""
        if not baseline:
            return False
        a, b = len(body), len(baseline)
        if a == 0:
            return False
        # 長さの差が5%以内なら「同じカスタム404ページ」と判断。
        return abs(a - b) <= max(64, int(b * 0.05))
