# Hermes 平台身份与旧会话兼容修复

日期：2026-10-09。插件基线：`7fc91869e0494316b78ef254e2560ff4556fb658`，版本 `2.1.0`。真实宿主：Hermes `0.21.3`，源码提交 `75b083e9399115b12513385252811f09c3503c90`，Python `3.11.15`。

## 已确认的故障

`plugin.py` 注册 `open-android-intelligence-gateway`，但 `adapter.py` 构造 `Platform("open_android")`。Hermes 的 `Platform._missing_` 只接受内置或已注册的平台，旧名未注册时构造失败。旧实现捕获所有异常并改用 `LOCAL`，因此插件看似能够启动，消息实际带着错误的宿主来源身份。

Hermes 的 `SessionSource.from_dict` 同样用 `Platform` 解析持久化的来源。未注册的 `open_android` 和 `open_android_intelligence` 会被拒绝，`SessionStore` 随后跳过相应的 SQLite 路由及旧 `sessions.json` 记录。单独把适配器改成新名仍会留下这部分问题。

真实宿主的隔离红灯复现得到五个失败：适配器身份为 `local`、两种旧来源无法读取、两种旧路由被跳过。隔离副本与数据库均在临时目录；没有读取、重置或删除真实用户账号。

这证明了 Hermes 平台身份与历史加载故障。本报告不把它解释为手机认证失败的充分原因；密码认证、Android 本地初始化和事件流各阶段仍须分别验证。

## 修复和兼容策略

- `platform_identity.py` 统一主平台 ID，并明确保留 `open_android`、`open_android_intelligence` 两个兼容入口。
- `plugin.py` 使用 Hermes 标准 `register_platform` 注册三个名字。平台注册失败直接交给宿主报告，不再被捕获后静默忽略。
- 兼容入口保留各自的 `Platform.value`，不会把旧来源强制改写成新来源。Hermes 会话键包含平台原值，这能保持旧会话键的字节不变。
- 三个工厂共享同一适配器实例。适配器只使用主平台 ID；连接与断开以异步锁串行化并保持幂等，所以只创建一个 HTTP 监听器、一个事件投递回调和一个维护任务。
- 监听配置采用 Hermes 自身的配置读取和解析流程，优先选择显式新配置，其次是 `open_android`，最后是 `open_android_intelligence`。多个名字同时配置时，只告警平台名和所选名字，不输出配置内容。没有写回配置文件，也没有原地迁移数据库。
- 显式停用不会被兼容入口绕过。已声明的平台名仍可解析，以保持历史可读；服务是否启动继续服从配置。
- `_ensure_agent_session` 先核对当前账号与对话自己的持久绑定，并查找原始会话键。来源平台、账号、对话、会话 ID 和原始键必须一致，才能继续使用原来的 Agent 会话。
- 来源缓存按 `(account_id, conversation_id)` 隔离。旧来源继续通过 Hermes 的原生来源构造、profile 路由和会话键生成函数工作，并保留接收适配器引用，供宿主进行授权及回送。
- `LOCAL`、未知来源、缺失会话键、失配绑定和存在多条候选路线的历史不会被猜测性认领。它们保留在原始存储中，兼容流程明确报告 `HOST_INCOMPATIBLE` 和固定原因；不会创建替代 Agent 会话或覆盖绑定。
- 后台会话绑定使用已有的任务观察函数，兼容拒绝不会变成无人读取的异步异常。新增诊断只包含阶段、错误类型或固定错误码，不输出密码、令牌、完整响应正文或签名材料。

涉及的文件：`open_android_intelligence_gateway/plugin.py`、`adapter.py`、新增的 `platform_identity.py`、`tests/test_platform_identity.py`、`scripts/check_hermes_platform.py` 和本报告。没有修改 Gateway Protocol Schema、账号数据库结构或刷新凭据规则。

## 验证证据

普通回归使用单独创建的 Python 3.11 临时环境，测试依赖与 Hermes 安装环境分开。新增测试在旧版本副本能复现缺少旧平台注册、静默回退和吞掉注册失败；修复后通过。

普通完整套件：`324 passed, 1 skipped`。跳过项为需要真实 `hermes_state` 的既有原生历史测试；另外使用真实 Hermes 环境单独执行 `tests/test_native_history_complete.py`，结果为 `1 passed`。插件清单与入口检查通过，协议为 `2.1.0`，契约固定版本没有改变。

真实宿主验证脚本使用真实 `PluginManager`、`load_gateway_config`、完整 `GatewayRunner`、`SessionDB`、`SessionStore` 和 `aiohttp`。所有状态存放在脚本创建的临时 Hermes home，保留供人工复核，不操作当前服务。验证了：

1. 三个注册入口可以加载；主适配器身份始终为 `open-android-intelligence-gateway`。
2. SQLite 与旧 `sessions.json` 中的两种旧来源均可读，原始会话键和 Agent 会话 ID 不变，历史哨兵文本仍在原会话中。
3. 三个入口同时连接只创建一个真实 HTTP site；`/health` 返回 HTTP 200 与 `ok`，事件回调与维护任务各一个。
4. Hermes 反复注入消息处理、会话存储与致命错误处理回调后，旧来源的 `_transport_owner`、`_delivery_adapter_for`、`_is_user_authorized` 均通过。
5. 已有 Gateway 绑定指向旧平台时，新的主适配器继续路由到原 Agent 会话；宿主生成的键与原始键逐字节相等，Gateway 绑定完整保留。
6. 同一对话标识在另一个账号下不会复用来源缓存。
7. 三个入口同时断开后，监听器、维护任务及事件回调均停止。人为占用监听端口后连接返回失败，运行标志不会显示为成功。
8. `LOCAL` 历史绑定被明确拒绝自动认领，原历史文本和宿主会话总数保持不变。
9. 新旧配置同时存在、只存在任一旧配置、显式停用四种配置场景均通过。旧配置的监听端口得到保留；配置文件字节未被插件改写。

可从插件仓库根目录复查真实宿主验证：

```bash
"$HERMES_ROOT/venv/bin/python" scripts/check_hermes_platform.py \
  --host-root "$HERMES_ROOT" \
  --contract-root ../open-android-intelligence/gateway-contract \
  --config-mode mixed
```

把 `--config-mode` 分别设为 `legacy`、`legacy-alternate` 和 `disabled` 可以复查其余三个场景。脚本不会连接手机，不调用 Agent 模型，也不会使用真实账号凭据。

## 部署与未验证边界

本修复保留旧配置和历史，不需要重建账号、重置密码、清除手机数据或注销已有访问会话。最小部署动作是把已验证的修复提交同步到正在运行的插件目录，然后重启一次 Hermes Gateway，让旧平台名在宿主加载历史之前注册。重启会断开当前传输连接，但本修复不撤销已保存的访问会话、刷新凭据或设备公钥。

本次隔离验证没有重启当前 Gateway、没有更新手机上的 App，也没有把账号数据写入真实部署。多 profile 路由的全面测试、运行中更改平台配置的热重载和真实手机对话闭环不属于上述通过证据。已存在但缺少可靠归属的 `LOCAL` 或无键绑定需要操作员核查，不能自动迁到手机账号。
