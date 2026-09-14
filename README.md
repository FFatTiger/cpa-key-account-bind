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
- 允许集内支持 CPA 同名策略：`round-robin`（默认）、`weighted-round-robin`、`fill-first`；优先级、ID 排序、平滑加权和候选缩小时的游标恢复按 CPA 原生算法实现。

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
      strategy: round-robin           # round-robin | weighted-round-robin | fill-first
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

插件在 CPAMC「插件启停与配置」页声明了可视化字段：`bindings` 数组（紧凑字符串格式，面板里直接增删行）、`unbound` 下拉框，以及 v0.3.0+ 的 `strategy` 下拉框。保存即写回 config.yaml 并热生效。

## 注意事项

1. **绑定 key 不得依赖 query 传参认证**（见上）。
2. **与其他 scheduler 类插件互斥**：宿主只把第一个注册的 scheduler 插件接入调度链。先卸载 cpa-key-policy 之类再启用本插件。
3. 绑定 key 仍必须存在于原生 `api-keys`——本插件不负责认证，只负责调度隔离。两层正交，原生认证失败照样 401。
4. 当前 CPA 插件 ABI 不能把“过滤后的候选集”交回原生调度器，因此 `strategy` 由插件独立配置；请与全局 `routing.strategy` 保持一致。省略时默认 `round-robin`。
5. 兼容 CLIProxyAPI v7.2.x（在 v7.2.146 实测）。

## 安装

GitHub Releases 按官方商店规范发布 zip：`key-account-bind_<version>_<goos>_<goarch>.zip`，解压后把动态库放进 CPA 的 `plugins/` 目录：

- Linux: `key-account-bind.so`
- macOS: `key-account-bind.dylib`
- Windows: `key-account-bind.dll`

从源码构建：

```sh
CGO_ENABLED=1 go build -buildmode=c-shared -o key-account-bind.so .
```

## 验收记录（2026-08-31，v7.2.146 实测）

- key-a 绑定 chan-a ×5 请求 → 上游全部 `upstream-a-SECRET`
- key-b 绑定 chan-b ×5 请求 → 上游全部 `upstream-b-SECRET`
- 绑定指向不存在 ID → 硬失败 `key-account-bind: no eligible credential`，未泄漏到另一账号；其他 key 不受影响
- `X-Api-Key`、小写 `bearer`、大写 key 值等 header 形态均正确识别
- 未绑定 key passthrough 正常走原生调度
- 配置热重载（改 yaml 免重启生效）

## Account-tree isolation

This is a **standalone native CPA plugin**. It runs on the standard core; no core
patch, custom core build, or replacement update channel is required. Normal
EasyCLIProxy core updates can keep the plugin library, configuration and state.
As with other plugins, future CPA versions must retain a compatible plugin API.

Isolation is optional and disabled by default. When enabled, it composes existing
API-key bindings, exact credential classification, the selected provenance route,
and persistent tree scope. See [the example](examples/account-isolation.yaml) and
[deployment guidance](docs/DEPLOYMENT.md).

### Routing and identity

Classify each scheduler candidate by exact `id`, `provider`, `scope` and `source`.
Scope names use lowercase ASCII letters, digits and hyphens, start with a letter
or digit, and contain at most 64 bytes.
OAuth files, API-key credentials and OpenAI-compatible channels use the same
mechanism. Unknown credentials are excluded. Update the classification if CPA
changes a synthesized credential ID after a key, prefix or endpoint change.

Use CPA's native prefix plus model aliases to expose
`<scope>/<source>/<canonical-model>`, with `force-model-prefix: true`. For example,
set prefix `work` and alias `litellm/glm-5.3-flash`. Native `display-name` fields
provide configurable friendly labels; full route IDs also distinguish duplicate
models. The plugin verifies the candidate's configured classification against
the route, rather than trusting the route text alone.

The plugin reads CPA's existing `canonical_session_id` and `parent_session_id`
scheduler metadata, including identities extracted by CPA from Claude request
bodies. For Codex, explicit thread/parent headers take precedence over a name-based
agent identity, so nested children use stable thread IDs. UUID normalization is
stable across protocol prefixes and plugin restarts. No private host
metadata or additional request hooks are needed.

A root establishes its scope through a classified route. Children inherit the
persisted parent's scope. Changing models or sources within that scope is allowed;
changing the tree's scope or parent is rejected. Retry selections repeat the
candidate filtering. Original key-binding behavior is unchanged when isolation
is disabled.

`require-scope-bound-key` optionally requires a downstream binding whose classified
allow-list belongs to a single scope; it defaults to true. Set it to false to let otherwise permitted unbound keys
establish scope through a provenance route. These client identities are protocol
metadata, not cryptographic proof of ancestry.

### State

State stores hashed session IDs, scope, parent linkage and a checksum, with no
credentials or prompts. Private atomic writes and a lock serialize concurrent
updates. The configured capacity defaults to 100,000 sessions, without automatic
eviction. Missing/corrupt state or a stale crash lock requires recovery from a
verified backup. Do not reset an existing store to fix a resumed session.

Initialize a **new** store only with:

```sh
python3 scripts/init-scope-state.py /absolute/path/to/account-scope-state.json
```

### Operation and updates

Build on the runtime platform:

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=1 go build -buildmode=c-shared -o key-account-bind.dylib .
```

Use the platform's library extension, and install into the existing CPA plugin
directory. Keep this plugin enabled as the active scheduler. Standard CPA may
use its builtin scheduler if a plugin is disabled, unavailable or fails to load;
this version intentionally does not patch the host to prevent that behavior.
Home dispatch and special execution paths outside the standard scheduler are not
covered. The discovered Codex/Claude/LiteLLM routes use the standard scheduler.

After a core update, verify that the plugin is registered and active, and test both
an allowed and a denied scoped request before resuming work. Back up configuration,
the library and persistent state together. Scheduler rejection currently surfaces
as an HTTP 500 in CPA; this plugin does not control that HTTP mapping.

The optional launcher requires an explicit model and key directory:

```sh
python3 scripts/codex-scope.py --model personal/source/model --key-dir /private/keys personal -- exec "task"
```

The key is inherited through the environment rather than passed in process arguments.
The launcher does not change the Codex configuration file.
