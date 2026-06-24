"""チェックモジュールの基底クラス。"""

from __future__ import annotations

import abc
from collections.abc import Iterator

from ..http import Client
from ..report import Finding


class Check(abc.ABC):
    """全チェックの共通インターフェース。

    各チェックは base_url（例 "https://example.com"、末尾スラッシュなし）を受け取り、
    Finding を yield する。HTTPアクセスは渡された Client を通して行う。
    """

    #: CLI / レポートで使う一意なID（kebab-case）。
    id: str = ""
    #: 人が読む説明。
    description: str = ""
    #: 能動的に攻撃リクエストを送るか（自己管理サイト限定の注意喚起に使う）。
    active: bool = False

    def __init__(self, client: Client, base_url: str) -> None:
        self.client = client
        self.base_url = base_url.rstrip("/")

    def url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    @abc.abstractmethod
    def run(self) -> Iterator[Finding]:
        """チェックを実行し Finding を逐次 yield する。"""
        raise NotImplementedError
