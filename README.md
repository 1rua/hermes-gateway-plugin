# Open Android Intelligence Gateway for Hermes

原生 Gateway Protocol v2.1 平台插件：把 Open Android Intelligence 手机端接入
Hermes Agent 宿主，通过一条经过认证的本地通道承载对话、通知、短信、设备请求与
附件传输。

## 安装

```bash
hermes plugins install 1rua/hermes-gateway-plugin --enable
```

安装完成后，插件注册平台、管理入口、HTTP 路由与原生命令。首次使用前先获取协议契约
（见下文「协议契约」，需要联网且耗时约半分钟）：

```bash
hermes open-android-intelligence contract sync
hermes gateway setup          # 向导式创建手机连接账号
hermes open-android-intelligence status
```

插件**加载时不会联网**：宿主启动只检查契约是否已在本地，不会替你下载，因此首次安装后
需要显式执行一次 `contract sync`。

## 更新

```bash
hermes plugins update open-android-intelligence-gateway
hermes gateway restart        # 更新后需重启进程才会加载新代码
```

未指定 `--ref` 时安装的是仓库当前分支的最新提交。需要锁定到某个不可变版本时：

```bash
hermes plugins install 1rua/hermes-gateway-plugin --ref <40位提交SHA>
```

## 协议契约

手机端与宿主协商时会比对协议 Schema 摘要，因此宿主必须持有与手机端**同一份**契约
文件。本仓库**不携带**契约副本，只在 `contract-pin.json` 中锁定它在应用仓库中的
地址与提交：

```json
{
  "repository": "https://github.com/1rua/open-android-intelligence.git",
  "revision": "95f2e1702a6e360b6779c6c69667d36a0e96d683"
}
```

插件在加载时按该提交把 `gateway-contract/` 取到本插件目录下（只检出这一棵子树，
不会拉取整个应用仓库）。这样契约只有一份真源，既不会与手机端漂移，也不必手工
同步副本。

随时可查看与修复：

```bash
hermes open-android-intelligence contract status
hermes open-android-intelligence contract sync
```

契约的完整性以 `core-dispatched-schemas.json`、`schemas/envelope.schema.json` 与
`vectors/vector-set-1.0.0.schema.json` 三者为准：缺任何一个都会被判定为未就绪，而不会让
网关在协商时才暴露问题。

`status` 会如实报告契约来源（`pin` / `cached` / `env`）、锁定提交与目录；未就绪时
给出可操作的中文原因，不会静默降级。

### 离线与内网部署

已经持有契约的部署者可以直接指定目录，跳过拉取：

```bash
export OPEN_ANDROID_GATEWAY_CONTRACT_ROOT=/secure/path/gateway-contract
```

内网镜像可用 `OPEN_ANDROID_GATEWAY_CONTRACT_REPOSITORY` 覆盖仓库地址（提交号仍
由 pin 决定）。显式传入的契约目录优先级最高，其次是该环境变量，最后才是向上查找。

## 配置

在 `~/.hermes/.env` 中配置：

```bash
OPEN_ANDROID_GATEWAY_HOST=0.0.0.0     # 监听地址
OPEN_ANDROID_GATEWAY_PORT=8045        # 监听端口
# Hermes 不向插件暴露 Secret Store，主密钥文件位置可显式指定
OPEN_ANDROID_INTELLIGENCE_GATEWAY_MASTER_KEY_FILE=/secure/path/gateway-master-key
```

主密钥文件为 32 字节随机数、权限固定 `0600`，默认位于
`~/.open-android-intelligence/gateway-master-key`，在 Hermes 数据目录之外，不会随
数据库、备份或诊断一起导出。文件缺失、是符号链接、不属于当前用户或组/其他用户
可读时，网关**拒绝启动**并打印原因。

也可在 `~/.hermes/config.yaml` 中配置：

```yaml
gateway:
  platforms:
    open_android:
      enabled: true
      extra:
        port: 8085
        host: "0.0.0.0"
```

## 账号管理

宿主内使用原生命令：

```bash
hermes open-android-intelligence account list
hermes open-android-intelligence account create -u phone1 -p <密码> --confirm-local
hermes open-android-intelligence account delete phone1 --confirm-local
```

没有 Hermes 宿主时（例如离线预置），可用仓库内的等价 CLI，它与上面共用同一套管理
服务与主密钥来源：

```bash
python3 tools/hermes-account.py create phone1 --password <密码>
python3 tools/hermes-account.py status
python3 tools/hermes-account.py contract
```

## 开发与测试

```bash
python3 -m venv .venv && .venv/bin/pip install pytest jsonschema aiohttp cryptography
```

测试需要真实协议契约（协商测试计算的是真实 Schema 摘要，不使用替身）。二选一：

```bash
# 指向已有的契约目录
OPEN_ANDROID_GATEWAY_CONTRACT_ROOT=/path/to/gateway-contract .venv/bin/python -m pytest tests

# 或让插件按 pin 自动获取
.venv/bin/python -m pytest tests
```

提交前建议跑一次官方校验：

```bash
hermes plugins validate .
```

## 与应用仓库的版本关系

本仓库与应用仓库独立发版。以下两件事必须同步，否则手机端会在协商阶段收到
`PROTOCOL_INCOMPATIBLE`：

1. **`gateway-contract/schemas/*.schema.json` 变更** → 核心 Schema 摘要随之变化，
   必须把插件与手机端一起升级到同一版本。
2. **插件协议版本升级** → `contract-pin.json` 的 `revision` 必须指向包含该契约的
   提交。

插件在加载时会校验清单声明的协议版本与核心实现是否一致，不一致直接拒绝加载并
说明差异，因此跨仓升版不会静默漂移到协商阶段才暴露。

## 许可

MIT，与应用仓库一致。
