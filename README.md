# wp_checker

WordPress の**コンテンツ層**の脆弱性をリモートからスキャンする CLI ツール（Python）。
サーバOSやミドルウェアの設定ではなく、WordPress サイトとして外部から見える穴を検査します。

> ⚠️ **自分が管理する、または検査の明示的な許可を得たサイトにのみ使用してください。**
> 無許可のスキャンは不正アクセス禁止法等に抵触する可能性があります。

## できること

| チェック (`--checks`) | 内容 | 種別 |
|---|---|---|
| `exposed-files` | 露出した設定/バックアップ/`.git`/`debug.log`/ディレクトリリスティング等の検査 | 受動 |
| `recon` | コアバージョン検出、REST API によるユーザー名列挙 | 受動 |

現状は**受動的（情報を見るだけ）**チェックのみ。今後の拡張予定は下記参照。

## インストール

[Poetry](https://python-poetry.org/) で環境を作ります。

```bash
poetry install
```

## 使い方

```bash
# 全チェック（実行前に権限の確認プロンプトが出る）
poetry run wp-checker https://example.com

# 露出ファイル検査だけ
poetry run wp-checker https://example.com --checks exposed-files

# 結果をJSONで保存、確認プロンプトを省略（自動化向け）
poetry run wp-checker https://example.com --json report.json --yes
```

`poetry run python -m wp_checker ...` でも同じく実行できます。

主なオプション: `--timeout`、`--delay`(リクエスト間隔)、`--insecure`(TLS検証無効)、`--yes`(確認スキップ)。
CRITICAL/HIGH を検出すると終了コード 1 を返すため CI でも使えます。

## 構成

```
wp_checker/
  http.py             レート制御付きHTTPクライアント
  report.py           Finding / Severity / Report（JSON出力）
  cli.py              CLI・確認プロンプト・表示
  checks/
    base.py           Check 基底クラス
    exposed_files.py  露出ファイル検査（PROBES に定義を追加して拡張）
    recon.py          偵察・列挙
```

新しいチェックは `checks/base.py:Check` を継承し、`checks/__init__.py:ALL_CHECKS` に登録するだけで CLI から使えます。

## 誤検出対策

WordPress は存在しないパスにトップページや 200 のカスタム404を返すことが多いため、
ランダムな非存在パスでベースライン（soft-404）を取り、本文長が近いものは除外します。
さらに各 probe に本文シグネチャ（例: `DB_PASSWORD`）を持たせ、本物のみを報告します。

## 今後の拡張（未実装）

- **既知脆弱性の突き合わせ**: 検出したコア/プラグイン/テーマのバージョンを WPScan API 等の脆弱性DBと照合。
- **能動テスト（SQLi/XSS）**: 自己管理サイト限定で、フォーム/パラメータへの安全なペイロード注入と差分検知。本格運用は sqlmap 連携を推奨。
- **プラグイン/テーマ列挙**: `wp-content/plugins/*/readme.txt` からバージョン特定。

## ライセンス

[MIT License](LICENSE) © 2026 Atsushi Shindo
