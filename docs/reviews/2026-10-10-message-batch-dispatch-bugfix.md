# Hermes 批次消息无法回复修复与验证记录

日期：2026-10-10。

修复基线：`a41e692dc640d6ef94b8083bf220f260936234dd`。

本报告记录插件源码、隔离 HTTP/SSE 与 Hermes 原生平台回合的实测结果。Android 的本地消息镜像、侧边栏退出和附件 Keystore 修复由应用仓库负责。本轮没有操作生产账号、线上服务、配对密钥或部署目录；提交、CI、部署和两处手机验收仍须在交付流程中另行记录。

## 1. 根因与修复

### 完整请求入口拒绝批次

`GatewayCore.handle()` 外层已经取得请求时间 `now`，其内部 `work()` 中的重命名分支却又给局部 `now` 赋值。Python 因此把 `work()` 内所有 `now` 解释为未初始化的局部变量。普通文本批次受理、生成取消和同步快照均可返回 `INTERNAL_ERROR`，HTTP 层表现为 400。

将重命名分支时间改为 `rename_now`，同时用于标题更新和标题事件；其余分支继续读取外层请求时间。没有改变时钟来源、认证校验、幂等事务或重命名行为。

### 已受理批次没有交给 Agent

HTTP 层为 `message-batches` 成功响应安排了宿主投递，但 `_conversation_id_of()` 只接受会话本身与 `messages`。投递入口因此得不到会话 ID 并直接返回，批次停留在排队状态。

让路径提取同时接受 `messages` 与 `message-batches`。两者使用既有消息 outbox、一次性 claim、会话生成锁和事件回传。`generations`、`attachments` 等子资源继续不构成打开会话或投递消息的入口。

### 宿主完成回调的异步契约不一致

Hermes 原生 `BasePlatformAdapter` 通过 `await hook(...)` 调用 `on_processing_complete`。插件原先是同步函数，执行状态写入后返回 `None`，宿主随后抛出 `TypeError: object NoneType can't be used in 'await' expression`。

将完成回调改为 `async def`，保持现有状态结算和媒体清理语义；原有测试调用点也使用 `await` 或 `asyncio.run()`。

生产变更仅位于 `open_android_intelligence_gateway/core.py` 和 `open_android_intelligence_gateway/adapter.py`。新增回归位于 `tests/test_batch_request_boundary.py` 与 `tests/test_batch_http_dispatch.py`；既有 outbox 和流式附件测试同步改为异步完成调用。

## 2. 先失败、再修复的证据

新增测试通过完整公开边界观察行为，没有替换 `Core.handle()`、HTTP 路由、验签、宿主消息入口或 SSE 发送实现。

| 阶段 | 实测结果 |
| --- | --- |
| 原始基线运行完整 Core 批次回归 | `INTERNAL_ERROR`，`1 failed`。 |
| 仅修复 `rename_now` 后运行签名 HTTP/SSE 回归 | HTTP 返回 accepted，但等不到宿主处理入口，5 秒后超时。 |
| 再修复批次路径后运行完成回调回归 | 原同步回调不能 await，得到上述 `TypeError`。 |
| 原始基线统一复核新增 Core 与完成回调回归 | 批次、取消和同步快照均为 `INTERNAL_ERROR`，完成回调为 `TypeError`，合计 `4 failed in 0.29s`。 |
| 三项修复后运行同一回归 | 完整 Core 与签名 HTTP/SSE 共 `6 passed in 2.47s`。 |

独立基线副本只复制新增测试，没有复制任何生产修复。失败与通过运行均使用主仓真实 `gateway-contract`，没有替换 Schema 摘要。

## 3. 实际验证结果

使用 Python `3.11.15`，显式提供 `OPEN_ANDROID_GATEWAY_CONTRACT_ROOT`。

| 检查 | 结果与边界 |
| --- | --- |
| 插件完整 `pytest tests` | `332 passed, 1 skipped in 103.32s`。唯一跳过项要求可导入 `hermes_state`，独立插件环境没有该宿主模块。 |
| 实际 Hermes 平台回合与原生历史测试 | `4 passed in 3.22s`；前述唯一跳过项在此实际执行通过。 |
| 插件 manifest、入口与协议一致性检查 | 通过，插件 `2.1.0`，协议 `2.1.0`，契约 pin `95f2e1702a6e`。 |
| 共享固定向量 | `66 / 66` 通过。 |
| 差异空白检查 | `git diff --check` 通过。 |

原生验证使用 Hermes checkout `75b083e9399115b12513385252811f09c3503c90`，加载的基类确认为 `gateway.platforms.base.BasePlatformAdapter`，并强制设置 `OAI_REQUIRE_NATIVE_HERMES=1`；若只加载独立测试 fallback，该运行会失败。`HERMES_HOME` 和宿主数据库均指向隔离测试目录。

签名 HTTP 回归独立按协议十个字段组装 Ed25519 签名预像，并通过真实本机 HTTP 监听器提交。测试验证：

- 两个批次成员获得不同远端消息 ID；宿主收到一次、按 `newline-v1` 原样合并的输入。
- 生成期间和完成后以同一请求身份重放，都返回同一回执；宿主回合只执行一次。
- 每个成员在 SSE 中依次收到 `queued → delivered → completed`，修订号为 `0 → 1 → 2`。
- SSE 收到所属会话的唯一回复，普通消息路径也保持同样投递与完成行为。
- 原生完成 hook 可被 await，过程中没有宿主 hook 失败或插件投递失败告警。

完整套件还执行了既有的 50 MiB 原始 HTTP 附件上传、丢失回执恢复、重传、摘要校验、宿主媒体读取与异步完成清理。该证据证明插件附件链路，没有替代手机端 Android Keystore 验证。

## 4. 可复现命令

在独立插件仓库根目录执行，`OPEN_ANDROID_GATEWAY_CONTRACT_ROOT` 应由调用环境设置为应用仓库真实 `gateway-contract` 目录；`python` 应为安装了 `pytest`、`jsonschema`、`aiohttp`、`cryptography` 和 `pyyaml` 的 Python 3.11。

```bash
python -m pytest -q -ra tests
python -m pytest -q tests/test_batch_request_boundary.py tests/test_batch_http_dispatch.py
python scripts/check_plugin_manifest.py
git diff --check
```

原生验证额外把真实 Hermes checkout 和其 Python 依赖目录放入 `PYTHONPATH`，并把 `HERMES_HOME`、`HERMES_TEST_ISOLATION` 指向独立测试目录，再执行：

```bash
OAI_REQUIRE_NATIVE_HERMES=1 python -m pytest -q tests/test_batch_http_dispatch.py tests/test_native_history_complete.py
```

HTTP/SSE 测试使用确定性 Agent 回答，实际执行原生宿主的后台回合、最终发送与完成回调。它没有调用生产模型服务，也没有证明两处部署的真实 LLM、手机界面或公网链路已完成验收。

## 5. 兼容与部署边界

没有修改核心 Schema、协议次版本、SQLite 格式、账号目录或主密钥；本轮使用的真实核心摘要是 `sha256:99309b87dec79f9c737b7d875a6e949ceffb6bb18b468d7ce98ca37d77dd3d50`。更新程序不要求重建账号、重新配对或清理现有历史。

Android 侧独立发送记录与稳定身份的保存由应用仓库实现。本插件恢复实际受理、宿主投递和状态回传后，两端仍须以修复后的确切提交进行无缓存互通验证。

完成源码验证后，后续步骤是提交与独立审查、CI、保留配置和数据的插件更新，以及本机 Gateway 和服务器 `47.251.8.196` 的手动手机验收。这里的隔离测试结果不能据此标记两处部署或三项手机问题全部闭环。

## 6. 2026-10-11 追加 Android 可启动回复夹具

为使应用仓的生产 `GatewayAuthClient`、`ConversationClient` 与事件流客户端覆盖实际批次回复，`tests/android_gateway_fixture.py` 新增可选 `--echo-agent`。不传该参数时，保留原有 ThreadingHTTPServer、账号、密码、签名路由与有限 heartbeat 响应。

echo 模式具有以下固定协议：

- stdout 首行始终是随机端口的 `http://127.0.0.1:<port>`；其余夹具诊断只写 stderr。
- 在导入 Hermes 之前创建隔离环境，强制设置临时 `HERMES_HOME`、`HERMES_TEST_ISOLATION` 与三个主密钥环境路径；账号数据使用单独临时 Gateway 目录，密钥使用真实 AES-GCM、0600 专用文件。继承的监听端口、账号和主密钥位置不参与此模式。
- 启动生产 `OpenAndroidPlatformAdapter`，使用真实协商、密码账号存储、Ed25519 验签、批次投递、事件存储和 SSE。
- 每个宿主回合经生产 `adapter.send()` 返回 `fixture-agent-reply:\n` 加实际收到的原样输入。实际 Hermes 可导入时执行原生后台回合与完成 hook；独立环境由现有测试 fallback 明确调用异步完成。
- stderr 以 JSON 标注 `fixtureMode=echo-agent` 和 `host=native|standalone`；每次确定性 Agent 执行只记录一条 `fixtureEvent=agent-turn` 及会话/消息身份，不记录输入正文或任何凭据。
- 支持 SIGTERM/SIGINT 结束、取消后台工作和关闭监听器；不清理或删除用户数据。

新增 `tests/test_android_echo_fixture.py` 以真实子进程启动上述 CLI，先验证新增参数在原实现上失败，再验证默认与 echo 两种模式。测试先协商、密码登录并创建会话；echo 模式签名连接真实 SSE，发送 `/sync/snapshot` 并等到 `gateway.notice` 后再提交双成员批次，检查唯一回复、成员完成、回执重放及后续普通消息。诊断记录证明批次仅执行一次，普通消息再执行一次。故意注入不存在的继承主密钥路径、其他监听主机、端口 11451 与其他账号，echo 模式仍在隔离环境正常运行。

本追加变更在此前 332 项完整套件之后进行了新的定向验证：

| 运行环境 | 执行文件 | 结果 |
| --- | --- | --- |
| 独立 Python 3.11 | CLI 默认/echo、Core 边界、签名 HTTP/SSE | `10 passed in 3.26s`。 |
| 实际 Hermes 基类 | CLI 默认/echo、签名 HTTP/SSE、原生历史 | `8 passed in 4.52s`。 |
| 差异空白检查 | `git diff --check` | 通过。 |

这些新增结果覆盖夹具变更，并未把之前的 332 项执行记录改写成变更后的全量执行记录。

从插件仓根目录可使用以下命令，契约环境变量由调用环境显式提供：

```bash
python tests/android_gateway_fixture.py --echo-agent --contract-root "$OPEN_ANDROID_GATEWAY_CONTRACT_ROOT"
python -m pytest -q tests/test_android_echo_fixture.py tests/test_batch_http_dispatch.py tests/test_batch_request_boundary.py
```

要强制实际 Hermes 验证，先设置隔离宿主环境和实际 Hermes 的 `PYTHONPATH`，再运行：

```bash
OAI_REQUIRE_NATIVE_HERMES=1 python -m pytest -q tests/test_android_echo_fixture.py tests/test_batch_http_dispatch.py tests/test_native_history_complete.py
```

该夹具只替换 Agent 系统边界的模型回答，不会访问真实模型或代替两处手机验收。应用仓的 JVM 客户端互通结果由应用仓报告负责记录。

## 最新完整套件复核

包含新增 echo 夹具后的完整套件重新执行，实际结果为 `336 passed, 1 skipped in 57.25s`。原始输出保存在 `evidence/2026-10-10-message-batch/pytest-final.txt`。唯一跳过项仍为独立环境缺少 `hermes_state` 的宿主历史用例，已在实际 Hermes 的定向 8 项运行中覆盖。该结果不包含生产账号或真实模型验收。
