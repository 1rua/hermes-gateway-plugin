#!/usr/bin/env python3
"""Hermes Gateway 本地账号管理 CLI。

在没有 Hermes 宿主的机器上（离线准备、部署前预置账号）直接管理网关账号：
创建、删除、查看状态，以及生成受限主密钥文件（ADR 0023）。

已经安装插件的宿主应优先使用 `hermes open-android-intelligence account ...`
与 `hermes open-android-intelligence contract ...`；本脚本与它们共用同一套
管理服务和主密钥来源，因此两条路径创建的账号完全等价。
"""

import os
import sys
from pathlib import Path

# 插件仓根：本文件位于 <plugin_root>/tools/，包位于 <plugin_root>/。
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from open_android_intelligence_gateway.account_paths import default_hermes_gateway_root
from open_android_intelligence_gateway.admin import (
    HostApiCompatibility,
    create_admin_service,
    run_admin_command,
)
from open_android_intelligence_gateway.contract_assets import resolve_contract_root
from open_android_intelligence_gateway.core import create_gateway_core
from open_android_intelligence_gateway.local_keys import (
    MASTER_KEY_FILE_ENV,
    MASTER_KEY_FILE_ENV_ALIAS,
    MasterKeyUnavailable,
    create_master_key_file,
    resolve_local_master_key_store,
)

SCRIPT = "./tools/hermes-account.py"


def _usage() -> None:
    print("用法:")
    print(f"  {SCRIPT} create <用户名>      # 注册新账号")
    print(f"  {SCRIPT} delete <用户名>      # 删除账号")
    print(f"  {SCRIPT} status              # 查看网关管理状态")
    print(f"  {SCRIPT} init-key [路径]     # 生成 0600 受限主密钥文件（ADR 0023）")
    print(f"  {SCRIPT} contract            # 查看协议契约是否就绪")
    print("\n示例:")
    print(f"  {SCRIPT} create djbd")
    sys.exit(1)


def main() -> None:
    if len(sys.argv) < 2:
        _usage()

    cmd = sys.argv[1]

    if cmd in ("init-key", "init_key", "key"):
        # ADR 0023：宿主没有 Secret Store 时必须由部署者提供受限密钥文件。
        # 该文件不能与数据库、备份或普通配置放在一起，所以默认写在项目外部。
        default_path = Path.home() / ".open-android-intelligence" / "gateway-master-key"
        target = Path(sys.argv[2]).expanduser() if len(sys.argv) > 2 else default_path
        try:
            created = create_master_key_file(target)
        except FileExistsError:
            print(f"❌ 密钥文件已存在，未覆盖: {target}")
            sys.exit(1)
        except OSError as exc:
            print(f"❌ 无法创建密钥文件 {target}: {exc}")
            sys.exit(1)
        print(f"✅ 已生成受限主密钥文件: {created}")
        print("请在 ~/.hermes/.env 中配置：")
        print(f"  {MASTER_KEY_FILE_ENV}={created}")
        print(f"（兼容别名也接受：{MASTER_KEY_FILE_ENV_ALIAS}）")
        print("配置后重启网关；缺少主密钥时网关会拒绝启动。")
        return

    # 协议契约与插件运行时取同一份，保证这里创建账号的宿主与手机端协商一致。
    resolution = resolve_contract_root(PLUGIN_ROOT)
    if resolution.root is None:
        print(f"❌ 协议契约未就绪：{resolution.reason}")
        sys.exit(1)

    # 默认存储目录：与 Hermes 插件运行时的 default_hermes_gateway_root() 保持严格对齐
    storage_root = os.environ.get("HERMES_STORAGE_ROOT") or str(default_hermes_gateway_root())

    # 命令行必须与插件使用同一个主密钥来源，否则这里创建的账号会缺少主密钥，
    # 表现为"登录成功但所有业务请求 400"。
    try:
        secret_store = resolve_local_master_key_store()
    except MasterKeyUnavailable as exc:
        print(f"❌ 主密钥不可用: {exc}")
        print(f"   可执行 {SCRIPT} init-key 生成受限密钥文件后重试。")
        sys.exit(1)

    core = create_gateway_core(
        storage_root=storage_root,
        secret_store=secret_store,
        contract_root=resolution.root,
    )
    admin = create_admin_service(
        core=core,
        host_version="2.0.0",
        host_api=HostApiCompatibility("1.0.0", "3.0.0", "0" * 40),
    )

    if cmd == "contract":
        # The resolution above is the single source of truth for this report;
        # it must not be re-derived by the admin service.
        print(f"📄 协议契约状态: {resolution.source} @ {resolution.pinned_ref or '(由宿主指定)'}")
        print(f"  • 契约目录: {resolution.root}")
        return
    if cmd in ("create", "add"):
        if len(sys.argv) < 3:
            print(f"错误: 请提供要创建的用户名，例如: {SCRIPT} create djbd")
            sys.exit(1)
        account_id = sys.argv[2]
        remaining = sys.argv[3:]
        password = None
        if "--password" in remaining:
            idx = remaining.index("--password")
            if idx + 1 < len(remaining):
                password = remaining[idx + 1]
        if not password:
            for arg in remaining:
                if not arg.startswith("--"):
                    password = arg
                    break
        if not password:
            password = os.environ.get("OPEN_ANDROID_PASSWORD", "GatewaySecretPass2026!")

        result = run_admin_command(
            ["account", "create", account_id, "--password", password, "--confirm-local"], admin,
        )
    elif cmd in ("delete", "remove", "rm"):
        if len(sys.argv) < 3:
            print(f"错误: 请提供要删除的用户名，例如: {SCRIPT} delete djbd")
            sys.exit(1)
        account_id = sys.argv[2]
        result = run_admin_command(["account", "delete", account_id, "--confirm-local"], admin)
    elif cmd == "status":
        result = run_admin_command(["status"], admin)
    else:
        result = run_admin_command(sys.argv[1:] + ["--confirm-local"], admin)

    if result.get("ok"):
        print(f"✅ 操作成功: {result}")
    else:
        print(f"❌ 操作失败: {result}")
        sys.exit(1)


if __name__ == "__main__":
    main()