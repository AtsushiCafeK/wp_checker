"""検出結果（Finding）とレポートのデータモデル。"""

from __future__ import annotations

import dataclasses
import enum
import json
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """深刻度。値が大きいほど深刻。並べ替え・フィルタに使う。"""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Finding:
    """1件の検出結果。

    check    : 検出したチェックモジュールのID（例 "exposed-files"）。
    title    : 短い見出し。
    severity : 深刻度。
    url      : 該当URL（あれば）。
    detail   : 補足説明。なぜ問題か、何が見つかったか。
    evidence : 判定根拠（HTTPステータス、レスポンス抜粋など）。
    remediation : 推奨対応。
    """

    check: str
    title: str
    severity: Severity
    url: str | None = None
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.label
        return d


@dataclass
class Report:
    """1回のスキャン結果全体。"""

    target: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity, reverse=True)

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for f in self.findings:
            c[f.severity.label] = c.get(f.severity.label, 0) + 1
        return c

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "target": self.target,
                "summary": self.counts(),
                "findings": [f.to_dict() for f in self.sorted()],
            },
            ensure_ascii=False,
            indent=indent,
        )
