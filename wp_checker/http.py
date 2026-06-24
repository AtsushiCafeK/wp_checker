"""スキャン用の薄いHTTPクライアントラッパー。

- レート制御（リクエスト間隔）で対象サーバへの負荷を抑える。
- 共通のUser-Agent、タイムアウト、リダイレクト方針を一元化。
- 自己管理サイト向けのため verify(TLS) を任意で無効化できる。
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

DEFAULT_UA = "wp_checker/0.1 (+authorized self-assessment)"


@dataclass
class HttpResult:
    url: str
    status: int
    headers: httpx.Headers
    text: str
    elapsed_ms: int
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class Client:
    def __init__(
        self,
        *,
        timeout: float = 10.0,
        delay: float = 0.3,
        user_agent: str = DEFAULT_UA,
        verify_tls: bool = True,
        follow_redirects: bool = False,
        max_body: int = 200_000,
    ) -> None:
        self._delay = delay
        self._max_body = max_body
        self._last_request = 0.0
        self._client = httpx.Client(
            timeout=timeout,
            verify=verify_tls,
            follow_redirects=follow_redirects,
            headers={"User-Agent": user_agent},
        )

    def _throttle(self) -> None:
        wait = self._delay - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def request(self, method: str, url: str) -> HttpResult:
        self._throttle()
        start = time.monotonic()
        try:
            resp = self._client.request(method, url)
        except httpx.HTTPError as exc:
            return HttpResult(
                url=url,
                status=0,
                headers=httpx.Headers(),
                text="",
                elapsed_ms=int((time.monotonic() - start) * 1000),
                error=str(exc),
            )
        body = resp.text[: self._max_body]
        return HttpResult(
            url=str(resp.url),
            status=resp.status_code,
            headers=resp.headers,
            text=body,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )

    def get(self, url: str) -> HttpResult:
        return self.request("GET", url)

    def head(self, url: str) -> HttpResult:
        return self.request("HEAD", url)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
