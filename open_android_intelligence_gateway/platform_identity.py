"""Hermes 平台身份与兼容入口的共同定义。"""

from __future__ import annotations

import logging
from typing import Any

GATEWAY_PLATFORM_ID = "open-android-intelligence-gateway"
LEGACY_PLATFORM_IDS = ("open_android", "open_android_intelligence")
GATEWAY_PLATFORM_IDS = (GATEWAY_PLATFORM_ID, *LEGACY_PLATFORM_IDS)

logger = logging.getLogger(__name__)


def _platform_sections() -> list[tuple[str, dict]] | None:
    """使用宿主标准配置读取与优先级，保留显式开关的原始信息。"""
    try:
        from gateway import config_loader
        from hermes_constants import get_hermes_home
    except ImportError:
        return None
    home = get_hermes_home()
    data = config_loader.load_legacy_gateway_json(home)
    yaml = config_loader.read_yaml_layers(home)
    nested = yaml.get("gateway", {})
    blocks = config_loader.merge_platform_sections(yaml, nested, data)
    sections = []
    for name in GATEWAY_PLATFORM_IDS:
        section, _ = config_loader.platform_section(yaml, name, blocks)
        if isinstance(section, dict):
            sections.append((name, section))
    return sections


def gateway_enabled() -> bool:
    """尊重整个部署的显式停用，旧名不能绕过用户的停用设置。"""
    sections = _platform_sections()
    if sections is None:
        return True
    from gateway.config import PlatformConfig
    explicit = [PlatformConfig.from_dict(section).enabled for _, section in sections if "enabled" in section]
    return any(explicit) if explicit else True


def listener_config(fallback: Any) -> Any:
    """按宿主已解析的配置选择一个监听器，不写回旧配置。"""
    try:
        from gateway.config import Platform, load_gateway_config
    except ImportError:
        return fallback

    settings = load_gateway_config()
    # 宿主会在返回已解析配置前清除 _enabled_explicit，因此显式名称由
    # 同一套只读配置层提取，监听设置仍使用宿主完成解析后的 PlatformConfig。
    explicit = [(name, settings.platforms.get(Platform(name))) for name, _ in (_platform_sections() or [])]
    explicit = [(name, config) for name, config in explicit if config is not None and config.enabled]
    if not explicit:
        return fallback
    if len(explicit) > 1:
        logger.warning(
            "多个 Gateway 平台名已启用：%s；共享一个监听器，采用 %s 的配置",
            ", ".join(name for name, _ in explicit), explicit[0][0],
        )
    return explicit[0][1]
