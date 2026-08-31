# key-account-bind

CLIProxyAPI 原生插件：把下游 API key 绑定到指定上游凭证（auth 文件/channel 账号），实现**按密钥隔离账号**。

## 为什么有它

官方商店的 `cpa-key-policy` 依赖宿主把 frontend-auth metadata 转发进 scheduler options——CLIProxyAPI v7.2.146（含 7.2.107~146 及 main）没有这条链路，其账号隔离静默失效（调度退回全池）。本插件不依赖任何宿主转发：scheduler.pick 时直接从宿主传来的**原始下游请求头**（`Options.Headers`）自解析 key，闭环完成隔离。

## 工作原理

```
下游请求 ──> CPA 原生 api-keys 认证（不变）
              │
              ▼
        scheduler.pick(Options.Headers=原始请求头, Candidates=本provider候选)
              │
              ▼
   提取下游 key → 查绑定表 → 候选过滤(allow glob)
              │
     ┌────────┴─────────┐
     ▼                  ▼
  有匹配候选         无匹配候选
  选优先级最高      返回错误 → 宿主硬失败
  （不会泄漏到       （绝不回落到别的账号）
   未授权账号）
```

- 绑定的 key：只落在 allow 列表匹配的 auth ID 上；没有可用候选时请求**硬失败**（`auth_not_bound`），不降级、不回退。
- 未绑定的 key（含管理员自己的）：按 `unbound` 策略，`passthrough` 交给宿主原生调度（默认），或 `deny` 一律拒绝。
- 失败重试、冷却、多 provider 混合路由均兼容：每次重选都会再次过插件过滤。

## 配置（plugins.configs.key-account-bind）

```yaml
plugins:
  enabled: true
  dir: /plugins
  configs:
    key-account-bind:
      enabled: true
      bindings:                       # 紧凑格式（CPAMC 面板可直接编辑）
        - "sk-tenant-a=openai-compatible:chan-a:*"   # key=允许的authID glob，逗号分隔
        - "sk-tenant-b=codex-bob*.json,claude-main*.json"
      unbound: passthrough            # passthrough | deny
```

也支持完整对象格式（两种可混用，效果相同）：

```yaml
      bindings:
        - key: sk-tenant-a            # 必须同时存在于原生 api-keys
          allow:
            - "openai-compatible:chan-a:*"
```

- `allow` 用 `path.Match` glob 匹配候选的 auth ID：OAuth 账号 = auth 文件名；openai-compatibility = `openai-compatibility:<channel>:<hash>`（channel 名可通配）。
- 绑定的 key 认证走 header（`Authorization: Bearer` / `X-Api-Key` / `x-goog-api-key` 等）。**query 参数传 key 的客户端（`?key=`）调度器看不到**，会按未绑定处理——这类客户端请用 `passthrough` 或改用 header。
- 修改配置即热生效（宿主 config watcher 触发 plugin.reconfigure）。

## 在管理面板里改配置

插件在 CPAMC「插件启停与配置」页声明了可视化字段（v0.2.0+）：`bindings` 数组（紧凑字符串格式，面板里直接增删行）和 `unbound` 下拉框。保存即写回 config.yaml 并热生效。旧版本（v0.1.0）未声明字段，面板显示为空，需手工编辑 yaml。

## 注意事项

1. **绑定 key 不得依赖 query 传参认证**（见上）。
2. **与其他 scheduler 类插件互斥**：宿主只把第一个注册的 scheduler 插件接入调度链。先卸载 cpa-key-policy 之类再启用本插件。
3. 绑定 key 仍必须存在于原生 `api-keys`——本插件不负责认证，只负责调度隔离。两层正交，原生认证失败照样 401。
4. 兼容 CLIProxyAPI v7.2.x（在 v7.2.146 实测）。

## 构建

```sh
CGO_ENABLED=1 go build -buildmode=c-shared -o key-account-bind.so .
# 产物放入 CPA 的 plugins 目录（linux/amd64）
```

## 验收记录（2026-08-31，v7.2.146 实测）

- key-a 绑定 chan-a ×5 请求 → 上游全部 `upstream-a-SECRET`
- key-b 绑定 chan-b ×5 请求 → 上游全部 `upstream-b-SECRET`
- 绑定指向不存在 ID → 硬失败 `key-account-bind: no eligible credential`，未泄漏到另一账号；其他 key 不受影响
- `X-Api-Key`、小写 `bearer`、大写 key 值等 header 形态均正确识别
- 未绑定 key passthrough 正常走原生调度
- 配置热重载（改 yaml 免重启生效）
