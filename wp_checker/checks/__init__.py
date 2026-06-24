"""チェックモジュール群。

新しいチェックを追加するには base.Check を継承し、ALL_CHECKS に登録する。
"""

from __future__ import annotations

from .base import Check
from .exposed_files import ExposedFilesCheck
from .recon import ReconCheck

# CLI から名前で選べるように登録する。
ALL_CHECKS: dict[str, type[Check]] = {
    ExposedFilesCheck.id: ExposedFilesCheck,
    ReconCheck.id: ReconCheck,
}

__all__ = ["Check", "ALL_CHECKS", "ExposedFilesCheck", "ReconCheck"]
