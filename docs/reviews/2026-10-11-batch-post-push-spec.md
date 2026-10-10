# 批次消息修复推送后独立审查：规格轴

日期：2026-10-11。独立审查范围为 `a41e692dc640d6ef94b8083bf220f260936234dd..9f6878b42e8ef73a6a6d8f0e9a41d48a8230c514`，基线确认为两者的共同祖先。未修改生产代码、提交或部署服务。

## 结论

本次规格轴发现 **0 项**需要修改的问题；未发现该差异新增的要求缺失、越界改动或实现错误。审查以用户批准的三项缺陷修复计划及应用仓以下权威文件为准：`docs/superpowers/plans/2026-10-10-conversation-bugfix.md`、模块化插件架构规格、Gateway Protocol 2.1 契约 §6.5/§7、`CONTEXT.md` 的发送单元与消息合并批次定义、ADR 0045。

## 逐项核对

- `open_android_intelligence_gateway/core.py:5442` 使用 `rename_now`，消除了内部 `work()` 对请求时间的局部遮蔽，标题更新和标题事件继续使用同一时间来源；批次、取消、同步快照入口保持既有事务与幂等边界。
- `open_android_intelligence_gateway/adapter.py:713` 明确接受 `message-batches`，使成功 HTTP 受理进入既有 outbox、claim 和会话生成锁；附件、生成和其他深层子资源仍被排除。
- `adapter.py:2088` 的完成回调可被原生宿主 `await`，原生宿主实际调用链与插件签名一致。成员状态继续由原有共享生成映射推进。
- `tests/test_batch_http_dispatch.py:140` 起通过完整签名 HTTP/SSE 验证两个不同远端成员身份、原样有序聚合、唯一回复、成员修订 `0→1→2`；生成期间及结束后重放返回同一回执且宿主只执行一次。
- 新增 echo 模式仅用于隔离互通夹具，生产模型接口没有变更。差异未修改核心 Schema、协议版本、持久化格式、账号路径、密钥来源或宿主会话绑定格式。

## 审查者实际复核

在插件根目录显式使用应用仓的真实 `gateway-contract`，Python 3.11 执行：

```bash
python -m pytest -q tests/test_batch_request_boundary.py tests/test_batch_http_dispatch.py tests/test_android_echo_fixture.py
```

结果：`10 passed in 3.30s`。随后以独立 `HERMES_HOME`、`HERMES_TEST_ISOLATION`、真实 Hermes 的 `PYTHONPATH` 和 `OAI_REQUIRE_NATIVE_HERMES=1` 执行：

```bash
python -m pytest -q tests/test_batch_http_dispatch.py tests/test_native_history_complete.py tests/test_android_echo_fixture.py
```

结果：`8 passed in 4.33s`；真实 Hermes checkout 确认为 `75b083e9399115b12513385252811f09c3503c90`。另独立调用路径提取函数，3 个允许路径及 6 个附件/生成/深层路径断言全部通过；`git diff --check` 通过。

## 验证边界

这是独立插件规格审查与隔离 HTTP/原生宿主验证，不是仓库全量安全审计。确定性回答证明协议及宿主回合链路，不证明生产模型、两处运行服务、Android 界面或手机真实 Keystore。账号保留的结论来自程序差异与兼容边界核对；本机及服务器的数据保留、真实回复和附件接收仍须部署后验证。Android 持久化、退出按钮和附件加密由应用仓独立审查；本报告不把这些待验收范围标记为完成。
