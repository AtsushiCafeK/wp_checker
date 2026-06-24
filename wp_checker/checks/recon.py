"""偵察・列挙チェック（受動的）。

外部攻撃の入口になりうる情報露出を確認する:
- WordPress コアのバージョン検出
- ユーザー名列挙（REST API）
- XML-RPC の有効性（exposed-files と重複するが、入口の観点で再掲）
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

from ..report import Finding, Severity
from .base import Check


class ReconCheck(Check):
    id = "recon"
    description = "バージョン検出・ユーザー列挙など外部攻撃の入口を偵察する"
    active = False

    def run(self) -> Iterator[Finding]:
        yield from self._wp_version()
        yield from self._user_enumeration()

    def _wp_version(self) -> Iterator[Finding]:
        """meta generator / feed / readme からバージョンを推定。"""
        version = None
        source = None

        # 1) トップページの meta generator
        home = self.client.get(self.base_url + "/")
        if home.ok:
            m = re.search(r'name="generator"\s+content="WordPress\s+([\d.]+)"', home.text)
            if m:
                version, source = m.group(1), "meta generator"

        # 2) RSS feed の <generator>
        if version is None:
            feed = self.client.get(self.url("feed/"))
            if feed.ok:
                m = re.search(r"<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>", feed.text)
                if m:
                    version, source = m.group(1), "RSS feed"

        if version:
            yield Finding(
                check=self.id,
                title=f"WordPress バージョン検出: {version}",
                severity=Severity.INFO,
                url=self.base_url + "/",
                detail=(
                    "コアの正確なバージョンが外部から判別できる。"
                    "既知脆弱性との突き合わせで攻撃対象になりやすい。"
                ),
                evidence={"version": version, "source": source},
                remediation="バージョン露出を抑止し、コアを常に最新へ更新する。",
            )

    def _user_enumeration(self) -> Iterator[Finding]:
        """REST API の users エンドポイントでログイン名が列挙できるか。"""
        res = self.client.get(self.url("wp-json/wp/v2/users"))
        if not res.ok or res.status != 200:
            return
        try:
            data = json.loads(res.text)
        except json.JSONDecodeError:
            return
        if not isinstance(data, list) or not data:
            return

        names = [u.get("slug") for u in data if isinstance(u, dict) and u.get("slug")]
        if names:
            yield Finding(
                check=self.id,
                title="ユーザー名列挙が可能 (REST API)",
                severity=Severity.MEDIUM,
                url=res.url,
                detail=(
                    "/wp-json/wp/v2/users からログインに使えるユーザー名(slug)が列挙できる。"
                    "ブルートフォースの前段に悪用される。"
                ),
                evidence={"users": names[:20], "count": len(names)},
                remediation=(
                    "REST API の users エンドポイントを制限するか、"
                    "セキュリティプラグイン等で列挙を遮断する。"
                ),
            )
