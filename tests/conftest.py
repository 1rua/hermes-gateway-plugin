"""Resolve the Gateway contract before pytest collects anything.

Several modules compute the negotiated Schema digest at import time, so the
contract root has to be in the environment before collection starts — a
fixture would be too late. The digest is the real shipped one, never a
substitute: a test that negotiated against a fabricated contract would pass
while the phone could not connect.

Resolution order mirrors the plugin's own: an explicit environment override
first (what CI and offline deployments use), then this checkout's pinned
revision. If neither yields a contract the session refuses to start, because
silently skipping these tests would leave the digest gate unverified.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from open_android_intelligence_gateway.contract_assets import (  # noqa: E402
    CONTRACT_ROOT_ENV,
    resolve_contract_root,
)


def _bootstrap_contract_root() -> None:
    if os.environ.get(CONTRACT_ROOT_ENV):
        return
    resolution = resolve_contract_root(Path(__file__).resolve().parents[1])
    if resolution.root is None:
        raise RuntimeError(
            "测试需要真实的协议契约，但未能获取："
            f"{resolution.reason}\n"
            f"请设置 {CONTRACT_ROOT_ENV} 指向一个包含 gateway-contract 的目录，"
            "或在本插件目录放置 contract-pin.json 后重试。"
        )
    os.environ[CONTRACT_ROOT_ENV] = str(resolution.root)


_bootstrap_contract_root()