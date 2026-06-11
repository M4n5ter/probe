# sssa-probe 进程级流量探针设计文档

## 1. 背景与目标

`sssa-probe` 的目标不是做一个传统抓包工具，而是做一个面向 Linux 主机的进程级流量探针。它需要在支持 eBPF 的机器上优先使用 eBPF 获取强进程归因和高性能采集能力；在 eBPF 不可用或能力不足时，自动降级到 libpcap/procfs 等 fallback 路径，并明确标注能力降级。

本系统的长期方向包括四类能力：

- 进程级流量观测：识别进程、服务、容器、连接和协议语义。
- 加密流量 best effort 明文探测：优先通过非 MITM 路线获取 TLS 明文或会话材料。
- 可扩展协议解析：首要支持 HTTP/1.x 和 SSE，后续自然扩展 WebSocket、HTTP/2、HTTP/3 等协议。
- 策略驱动的检测与防护：V1 先支持观测、告警和 dry-run verdict，后续接入真实拦截执行。

本文档是架构事实源，同时记录当前实现状态。当前仓库已经进入 V0/V1 骨架实现阶段：已建立 Rust workspace，完成 replay 驱动的 HTTP/1.x + SSE parser、LuaJIT policy runtime、Fjall ingress journal/export queue、protobuf batch envelope、pluggable compression codec 和 HTTP webhook exporter。已定义 capture provider、procfs process attribution、runtime config 和 runtime planning 的第一版边界。尚未实现真实 live capture backend、libpcap fallback、eBPF 主路径、TLS uprobe provider 和真实 enforcement。

## 2. 核心 thesis

这个项目不应该被设计成“抓包工具 + 若干 parser”。更干净的终局模型是四个平面分离：

- 采集平面：负责连接、进程、socket、payload chunk 和能力来源。
- 语义解析平面：负责协议识别、流重组后的解析、协议事件输出。
- 策略平面：负责 selector 命中后的检测、转换、告警和 typed verdict。
- 动作平面：负责 export、dry-run audit、未来 enforce/block/reset/quarantine。

这四个平面必须解耦。采集可以默认全机，但深度内容解析、完整 payload、TLS 明文和未来拦截只能对 selector 命中的目标启用。这样可以同时满足：

- 全机可见性。
- 对受管进程/应用的深度观测。
- 对未来“只拦截某些应用”的能力预留。
- 对性能、隐私、资源预算和故障半径的控制。

一个必须避免的坏味道是把“采集过滤”“深度解析目标”“防护目标”做成三套互相漂移的规则语言。它们应该共享一套 typed selector 语义，再由策略或配置声明 observe、detect、enforce 等不同意图。

## 3. 不可妥协原则

- 不静默伪造完整性：任何 payload 缺口、能力缺失、缓冲溢出或 fallback 都必须以 `degraded`、`gap`、`capability` 等字段显式表达。
- 不把 PID 当稳定身份：进程归因必须使用复合身份，避免 PID 复用和长时间运行环境中的误归因。
- 不把证书误称为通用解密能力：现代 TLS 下证书/私钥通常不能解密 ECDHE/TLS 1.3 流量，必须区分 trust material 和 decrypt material。
- 不让策略语言承担热路径预过滤：selector 必须可编译、可索引、可解释；Lua 用于语义检测和 verdict，不用于替代 selector。
- 不为跨平台抽象牺牲 Linux 主线：V1 只承诺 Linux，充分利用 procfs、cgroup、systemd、eBPF、capabilities。
- 不为了追求“灵活”暴露内部生命周期：Lua 策略可信，但只能访问受控领域 API，不暴露任意 Rust 内部对象、系统动态库或 FFI。
- 不承诺现实中无法同时满足的三元组：有限资源下不能同时保证无限流量不丢、不截断、不影响业务。V1 采用有界无损与显式降级。

## 4. V1 范围

V1 的硬目标是完成观测闭环：

1. Host Agent 在 Linux 上运行。
2. 通过 selector 命中目标进程或服务。
3. eBPF/socket-first 路径采集连接和明文 HTTP/1.x 字节流。
4. HTTP/1.x parser 输出 request、response、body chunk、SSE 语义事件。
5. Lua 策略消费标准化事件，产生 alert 或 dry-run typed verdict。
6. 事件进入 Fjall-backed durable spool。
7. HTTP(S) webhook batch exporter 将事件发送到测试 receiver。
8. agent 暴露 capability matrix、metrics、health、degraded/gap counters。

V1 的额外证明点：

- 单 libssl TLS demo：对一个 OpenSSL/libssl 测试进程，通过 `SSL_read`、`SSL_write`、`SSL_read_ex`、`SSL_write_ex` uprobe 获取明文并接入同一 HTTP parser。
- libpcap fallback demo：eBPF 禁用或不可用时，使用 libpcap 捕获本机明文 HTTP/1.x，procfs best effort 归因，并标记 degraded capability。
- enforcement dry-run demo：Lua 策略返回 `deny`、`reset`、`quarantine` 等 typed verdict，agent 记录 desired action、capability mismatch 和 audit event，但不执行真实阻断。

V1 明确不做：

- 不默认 MITM。
- 不实现真实连接阻断。
- 不承诺 Go `crypto/tls`、rustls、Java TLS 的明文覆盖。
- 不完整解析 WebSocket frame/message。
- 不支持 HTTP/2、HTTP/3/QUIC 的完整解析。
- 不实现远程控制面下发，只预留抽象。
- 不长期保存全量原始流量。

当前实现状态：

- 已实现 replay CLI，用单向输入文件驱动 capture provider、ingress journal、parser、policy、export queue 和可选 webhook exporter。
- 已实现 `capture` crate 的 `CaptureProvider` 抽象和 `ReplayProvider`，真实 eBPF/libpcap/plaintext provider 尚未实现。
- 已实现 `attribution` crate 的 `ProcfsAttributor`，可从 `/proc/<pid>` 读取进程身份、cmdline hash、starttime、uid/gid、cgroup、systemd service 与 container hint；replay flow 默认使用 synthetic replay identity、保留 PID/TGID `0` 和 0 confidence，避免把文件输入误归因到 agent 进程。
- 已实现 `probe-config` crate 的 TOML runtime config schema，覆盖 capture selection、live capture fallback order、storage、exporter、TLS material、policy 和 enforcement mode 的第一版结构；配置解析拒绝未知字段，基础字段校验不理解 runtime capability。
- 已实现 `runtime` crate 的 provider descriptor `ProviderRegistry` 与 `RuntimePlan`，由 registry 生成 capability matrix，并基于配置解析 capture backend selection；`auto` 使用有序 live fallback 列表，显式 backend 表示 required backend，不自动回退；runtime validation 对未实现的安全敏感能力 fail closed；`agent` 不再手写 capability matrix。
- 已实现 `pipeline` crate 的 `CapturePipeline`，负责 capture event -> ingress journal -> parser -> policy -> export queue 的 replay/shared processing；`agent` binary 只负责 CLI wiring、配置读取和 exporter 命令。
- 已实现 capability matrix；`procfs_attribution` 按本机 `/proc` 探测结果标记 degraded/unavailable，真实 live capture 相关能力仍必须标记 unavailable；policy/webhook 目前只在 replay pipeline 中可用。默认 `auto` capture 在当前 build 中会生成 `unavailable` live capture plan，不会静默选择 replay 作为 live provider；`run` 在无 live capture provider 时 fail closed，`check` 用于查看 resolved plan。
- 已实现 selector AST 的基础形态：`match`、`all`、`any`、`not`、`ref`，命名 selector 通过 registry 编译解析。
- 当前 `FjallSpool` 存储的是带 schema 的 `SpoolPayload`；ingress lane 当前写入 JSON framed `CapturedBytes`，export lane 当前写入 JSON framed `EventEnvelope`。protobuf batch envelope 通过显式 payload schema 标记该格式。这是过渡契约，不等同于最终 protobuf event envelope。当前 replay 不把文件输入归因到 agent 自身，而使用 synthetic replay identity、保留 PID/TGID `0` 和 0 confidence。

## 5. 部署与平台

部署模型为 Linux Host Agent。agent 默认面向真实主机运行，而不是应用内嵌 SDK，也不是第一阶段的 Kubernetes DaemonSet 专用实现。

平台范围：

- V1 只承诺 Linux。
- 主支持面为 RHEL8+/Ubuntu20+ 级别环境。
- RHEL7/CentOS7 这类旧环境允许自动降级到 libpcap/procfs，不把 eBPF 主路径作为硬承诺。
- CPU 架构支持 `x86_64` 和 `aarch64`。

权限模型：

- 现实部署通常会以 root 运行。
- 设计上仍要做 capability discovery，并把长期目标设为最小 capabilities。
- 可能涉及的能力包括 `CAP_BPF`、`CAP_PERFMON`、`CAP_NET_ADMIN`、`CAP_NET_RAW` 等，具体按 runtime capability matrix 判定。
- 不应因为 root 运行就让内部代码随意访问系统能力；高风险能力必须集中在少数边界模块。

## 6. 能力矩阵与降级

启动时 agent 必须生成 capability matrix。它应覆盖：

- 采集能力：eBPF syscall/tracepoint、libpcap fallback、procfs attribution。
- TLS 明文能力：libssl uprobe、keylog/session secret、future MITM provider。
- 协议能力：HTTP/1.x、SSE、WebSocket upgrade detection、opaque stream。
- 策略能力：LuaJIT、JIT 状态、policy state API、hot reload。
- 动作能力：dry-run verdict、future connection-level eBPF enforcement。
- 外发能力：spool-backed exporter、best-effort sink、codec 支持、mTLS。

配置和策略可以声明：

- `required_capabilities`：缺失时策略不启用，或 agent 按配置 fail fast。
- `preferred_capabilities`：缺失时策略降级运行，并产生 degraded 状态。

不允许静默降级。任何能力缺失必须出现在 health、metrics、admin API 和相关事件 envelope 中。

## 7. Selector 模型

采集默认全机，但深度观测、完整 payload、TLS 明文 provider 和未来拦截只对 selector 命中的目标启用。

selector 使用 typed DSL，不使用 Lua 直接判断热路径目标。原因：

- selector 需要可索引、可预编译，避免每个事件都进入脚本运行时。
- selector 是能力启用边界，不只是业务策略判断。
- selector 需要可审计、可解释、可在配置检查阶段验证。

selector 应支持：

- PID/TGID。
- 进程名。
- 可执行路径 glob。
- cmdline regex/hash。
- systemd service。
- 监听端口、本地端口、远端地址、方向、协议族。
- cgroup、container id、namespace 等基础容器信息。
- 命名 selector 复用。
- `any`、`all`、`not` 组合。

当前实现采用 AST 形态，而不是把 public model 固化成扁平 AND：

- `match`：叶子 selector，包含 process selector 和 traffic selector。
- `all`：所有子 selector 命中。
- `any`：任一子 selector 命中。
- `not`：对子 selector 取反。
- `ref`：引用 registry 中的命名 selector，编译阶段检测未知引用和循环引用。

selector 热更新语义：

- 新连接按新 selector。
- 已有 flow 在下一个事件阶段重新评估 capability。
- 不回溯补采历史 payload。
- 事件必须携带 `config_version`。

## 8. 进程、连接与时间身份

### ProcessIdentity

进程身份使用复合模型，不以 PID 单独作为稳定主键。

建议字段：

- `pid`、`tgid`。
- `start_time`。
- `boot_id`。
- `exe_path`。
- `cmdline_hash`。
- `uid`、`gid`。
- `cgroup`。
- `systemd_service`。
- `container_id`、`runtime_hint`、`namespace`。

这样可以避免 PID 复用、短生命周期进程和服务级归因混乱。

### FlowIdentity

flow id 也不能只用五元组。

建议使用 composite stable id：

- `boot_id`。
- `process_identity` 摘要。
- socket cookie 或 socket inode。
- 5-tuple。
- start monotonic timestamp。
- agent 内 monotonic sequence。

eBPF 下优先使用 socket cookie；fallback 拿不到时降级为可用字段组合，并标注 confidence。

### 时间模型

事件使用 dual timestamp：

- `monotonic_ns`：用于内部排序、时延、流内顺序。
- `wall_time`：用于外部查询、日志关联、审计展示。

batch/envelope 还应携带 agent `boot_id` 和 clock source 信息。

## 9. eBPF 采集路径

eBPF 技术栈选择 Aya。理由：

- Rust 项目内 eBPF 程序、用户态 agent、共享事件类型可以放在同一个 workspace。
- 更容易保持 Rust 侧类型和构建体验一致。
- 避免 V1 同时维护 C eBPF、clang/bpftool、Rust FFI 的双语言复杂度。

主采集策略为 socket/syscall-first，而不是 packet-first 或 proxy-first。

原因：

- 目标是进程级探针，进程、FD、socket、flow 关系必须是一等信息。
- packet-first 更容易拿到网络包，但进程归因和 TLS 明文都更弱。
- proxy-first 可以强化 L7 和拦截，但侵入性高，并且与非 MITM 默认路线冲突。

V1 首批 eBPF attach 点：

- connect/accept/close。
- send/recv/read/write 相关 syscall 或 tracepoint。
- FD、socket、process、flow 关联。
- 暂不把 TC/XDP 作为 V1 数据面主线。

BTF 或 eBPF 主程序不可用时：

- capability matrix 标记 eBPF unavailable。
- 自动进入 libpcap/procfs fallback。
- required/preferred capability 规则决定策略启用或降级。

## 10. libpcap fallback

fallback 使用 Rust `pcap` crate + 系统 libpcap。

理由：

- 企业 Linux 环境容易理解和排查。
- 不需要 V1 自研 AF_PACKET/TPACKET 捕获栈。
- 不引入 vendored libpcap 的构建、授权和 CVE 更新成本。

fallback 能力边界：

- 支持明文 HTTP/1.x 捕获和解析。
- 进程归因通过 procfs/netlink 快照 best effort。
- TLS 明文不承诺 uprobe 等同能力；只依赖可用的 keylog/session material 或其它 PlaintextProvider。
- 所有事件必须标记 degraded/capability source。

## 11. TLS 与明文来源

### PlaintextProvider

TLS/应用层明文来源抽象为 `PlaintextProvider`，而不是 `TLSDecryptor`。

原因：

- 目标不是只做 TLS 解密，而是获取 parser 可以消费的 bidirectional byte chunks。
- 来源可能是 uprobe、keylog/session decrypt、future MITM proxy、SDK feed。
- provider 应输出带 `source`、`confidence`、`capability` 的有序字节 chunk。

### V1 TLS 覆盖

V1 优先支持 libssl/OpenSSL/BoringSSL/LibreSSL 风格路径：

- `SSL_read`。
- `SSL_write`。
- `SSL_read_ex`。
- `SSL_write_ex`。

挂载方式为 process-scoped dynamic attach：

- 根据 selector 命中的进程读取 `/proc/<pid>/maps`。
- 发现 libssl/boringssl 路径和符号。
- 对命中进程动态挂载/卸载 uprobe。
- 降低全机无关开销。

Go `crypto/tls`、rustls、Java TLS 不进入 V1 正式覆盖，只作为后续 provider。

### TLS material

TLS 材料分为两类：

- identity/trust materials：CA、client cert、private key，用于 exporter mTLS、控制面连接、TLS 元数据验证。
- decrypt materials：SSLKEYLOGFILE、session secrets、有限私钥场景，用于明文恢复尝试。

必须明确：导入证书不等于能解密现代 TLS。TLS 1.2 ECDHE 和 TLS 1.3 具备前向保密时，单纯导入服务端证书或私钥通常无法解密流量。

未来 MITM 应作为新的 PlaintextProvider 或 EnforcementProvider 接入，不能污染证书材料概念。

## 12. 协议解析抽象

协议 parser 使用双向流状态机模型。

输入：

- 有序 byte chunk。
- direction。
- timestamp。
- flow context。
- process context。
- capability/source/confidence。
- sequence/gap 信息。

输出：

- 标准化 protocol events。
- parser state transition。
- protocol error/degraded marker。
- optional handoff request。

不采用包级 parser，因为 packet/frame 会把重组、方向和 TLS 明文差异泄漏给每个协议实现。

协议识别使用 Detector + Handoff：

- detector registry 管理多个 detector。
- 输入包括端口、ALPN、SNI、首包 magic、selector hint、policy hint。
- parser 可在 HTTP Upgrade、CONNECT 等场景 handoff 给下一个 parser。

未知协议行为：

- 输出 opaque stream metadata。
- 可以保留 limited first-bytes fingerprint。
- 不强行猜测 HTTP。
- payload 是否保留由 selector/配置决定。

## 13. HTTP/1.x、SSE 与 WebSocket

V1 以 HTTP/1.x 为主。

实现路线：

- 使用 `httparse` 解析 request/response line 和 headers。
- 自有状态机处理 content-length、chunked transfer、body chunks、SSE、handoff。
- 使用 `http` crate 承载标准 HTTP 类型。
- 不复用 hyper parser 作为被动探针核心，因为 hyper 面向 endpoint，不自然适配半包、双向被动流和外部 flow context。

HTTP body 事件粒度：

- headers/metadata 单独成事件。
- body 以有序 chunk 事件进入 spool/export/policy。
- 不等待完整 request/response 聚合后再处理。

SSE 是 V1 一等语义：

- parser 识别 `text/event-stream`。
- 保留原始 body chunks。
- 额外输出 `sse_event` 或 `sse_chunk` 语义事件。
- 这是为了覆盖 LLM streaming response 等长响应场景。

WebSocket 范围：

- V1 识别 HTTP Upgrade。
- 记录协议切换。
- 定义 WebSocket parser 插件接口和 handoff 契约。
- 不在 V1 完整解析 frame/message。

HTTP/2 和 HTTP/3：

- V1 只做检测和元数据预留。
- 不实现完整 frame/multiplexed stream/QUIC 解密。

## 14. Payload、完整性与过载语义

默认完整 payload 只适用于 selector 命中的目标，不适用于全机所有流量。

理由：

- 全机默认完整 payload 会放大隐私、数据量、故障半径和外发成本。
- selector 命中范围才是用户明确声明的深度观测对象。
- 这也为未来只对部分应用拦截提供一致边界。

payload 使用 header + chunk 流模型：

- headers event。
- body chunk event。
- SSE event。
- future WebSocket frame event。
- gap marker。

完整性模型：

- 每个 flow direction 独立 sequence。
- chunk 带 offset、len、hash。
- 缺口输出 gap marker。
- flow/event 可以标记 degraded。

过载语义：

- 在配置的内存/磁盘预算内追求无损。
- 当 eBPF ring/perf buffer、用户态队列、spool 或 exporter 长期跟不上时，不静默丢弃。
- 对受影响 flow 输出 `capture_gap` 或 `degraded`。
- 可以停止该 flow 的深度 payload 捕获或降为元数据。
- 默认不阻塞业务进程。

内存模型：

- 用户态 pipeline 使用 `bytes::Bytes`、`BytesMut` 或 Arc-backed slice 传递 chunk。
- 避免每阶段重复复制大 payload。
- chunk size 可配置，并通过 benchmark 调优。
- 不在 V1 自研 arena/ring，除非 benchmark 证明必要。

## 15. 策略运行时

策略语言选择 Lua，通过 `mlua` 嵌入 LuaJIT。

选择 LuaJIT 的理由：

- 策略是可信的，灵活度比纯声明式策略更重要。
- Lua 生态和表达能力适合复杂检测逻辑快速迭代。
- 相比 OPA/Rego，Lua 更适合嵌入 agent 热路径中的自定义逻辑。
- 相比 WASM，Lua 在 V1 的 ABI、构建链、调试和策略发布成本更低。
- 相比 Rhai，Lua 生态和表达力更适合复杂策略。

LuaJIT 运行策略：

- 默认使用 LuaJIT。
- 启动时检测 JIT 状态。
- JIT 不可用时允许解释模式降级，并在 capability/health 中标记。
- 需要额外验证 aarch64 和企业发行版环境，因为 JIT 可能受可执行内存策略、seccomp、SELinux、老 glibc 或容器限制影响。

LuaJIT FFI：

- 默认禁用。
- 策略只能通过受控领域 API 调用 agent 能力。
- 不允许默认访问系统动态库或任意 native 函数。

当前实现状态：

- 使用 `mlua` + LuaJIT。
- 只加载受限标准库：table、string、math、bit。
- 显式移除 `ffi`、`io`、`os`、`package`、`debug`、`jit`、`dofile`、`loadfile`、`load`、`collectgarbage`。
- `require` 被替换为固定错误函数，不允许访问系统 Lua 路径。
- runtime 同时设置 instruction budget 和 memory limit；instruction budget 防死循环，memory limit 防少量指令的大分配 OOM。
- 当前 replay CLI 允许加载裸 Lua 文件作为调试入口，但这只是 `ReplayPolicyLoader` 语义，不能等同于长期 policy bundle 格式。

## 16. Policy Bundle

策略以 policy bundle 分发，而不是裸 Lua 文件。

bundle 形态：

- `manifest.toml`。
- `main.lua`。
- `lib/` 目录，允许 bundle-local modules。
- 可选 checksum/signature 字段。

manifest 应声明：

- policy id。
- version。
- hooks。
- selector。
- required/preferred capabilities。
- state budget。
- resource limits。
- delivery or alert metadata。

加载流程：

1. 读取 bundle。
2. 校验 manifest。
3. 校验 checksum/signature，如果配置启用。
4. 在独立 Lua VM 中 dry-run。
5. 通过后原子切换。
6. 失败时保留旧策略。

不允许从系统 Lua 路径 require 模块。这样可以保证策略可复现、可审计、可回滚。

## 17. Lua API 与状态

Lua 策略不直接消费 ringbuf 原始事件，而是消费 agent 标准化后的领域事件。

典型事件包括：

- `connection_opened`。
- `connection_closed`。
- `tls_metadata`。
- `http_request_headers`。
- `http_request_body_chunk`。
- `http_response_headers`。
- `http_response_body_chunk`。
- `sse_event`。
- `opaque_stream`。
- `protocol_error`。
- `capture_gap`。
- `policy_alert`。

Lua API 采用受控领域 API：

- `probe.emit_alert`。
- `probe.tag`。
- `probe.verdict`。
- `probe.metric`。
- state API。

不暴露任意文件、网络、系统调用或 Rust 内部对象。

策略执行采用分阶段 Hook，而不是每个底层事件都无差别同步调用 Lua。

执行流程：

1. Rust selector 先做热路径预过滤，决定该 flow 是否进入深度观测、策略或未来 enforcement。
2. agent 将采集和 parser 输出转换为稳定领域事件。
3. Lua policy bundle 根据 manifest 注册 hook，例如 `on_connection`、`on_http_request_headers`、`on_http_request_body_chunk`、`on_http_response_headers`、`on_http_response_body_chunk`、`on_sse_event`。
4. 只有声明支持同步动作的阶段才等待 typed verdict。
5. 观测、告警、tag、metric 等非阻断结果可以异步进入后续 pipeline。
6. 不支持当前 enforcement capability 的 verdict 记录为 desired action 和 capability mismatch。

这样可以同时保留未来拦截能力，又避免把所有观测事件都压进同步阻塞路径。

并发模型：

- 每个 policy worker 持有独立 Lua VM。
- 事件按 `flow_id` 分片，保证同一 flow 有序。
- 跨 worker 共享状态只能通过有界 state API。

热更新模型：

- 新 policy bundle 在独立 Lua VM 中加载和校验。
- 校验通过后原子切换到新 VM。
- 显式 state store 按 policy id/version 规则保留或迁移。
- Lua 全局变量、闭包和 VM 内隐式状态不迁移。
- 新版本加载失败时继续使用旧版本，并输出 policy load error。

状态模型：

- 支持 per-policy KV。
- 支持 counters。
- 支持 TTL。
- 支持 sliding windows。
- 支持 key scope。
- 必须声明内存预算。

跨 worker state 使用 eventually consistent counters/windows。

优点：

- 热路径不会被全局锁或同步 IO 卡住。
- 适合高吞吐检测。
- 足够表达窗口内异常请求量、错误率、敏感路径访问等策略。

缺点：

- 不适合金融账本式强一致判断。
- 短时间窗口内可能有轻微延迟和分片误差。
- 如果未来某类阻断策略需要强一致，应作为单独 enforcement/control-plane 状态，而不是污染通用 policy hot path。

## 18. Verdict 与防护抽象

V1 先观测告警，不真实阻断，但必须把拦截抽象做好。

防护抽象使用 `EnforcementProvider + stage capabilities`。

provider 声明自己支持哪些阶段：

- connection。
- http headers。
- http body chunk。
- response。
- future websocket frame。

provider 声明自己支持哪些动作：

- allow。
- observe。
- alert。
- deny。
- reset。
- quarantine。
- tag。

Lua 策略返回 typed verdict：

- action。
- reason。
- confidence。
- ttl。
- scope。
- metadata。

V1 执行语义：

- `observe` 和 `alert` 可以实际执行。
- `deny`、`reset`、`quarantine` 记录为 desired action。
- 如果当前 provider 不具备执行能力，记录 capability mismatch。
- 输出 audit event。

未来第一类真实 enforcement backend 优先做 socket/连接级 eBPF：

- 对 selector 命中的进程。
- 在 connect/accept/send 等阶段做 allow/deny/reset。
- 不先把透明代理/MITM 作为核心拦截路径。

## 19. 配置系统

配置形态：

- 主配置使用 TOML。
- 支持目录化拆分，例如 `policies.d`、`exporters.d`、`selectors.d`。
- 文件变更触发 validate-then-swap。
- 新配置失败时保留旧配置。

配置源抽象：

- V1 实现 filesystem config source。
- 预留 `RemoteConfigSource` trait。
- 后续控制面下发进入同一 validation/swap pipeline。

当前 capture 配置语义：

- `capture.selection = "auto"` 是默认生产入口，按 `capture.fallback_backends` 的顺序选择第一个可用 live provider；默认顺序为 `ebpf` 后 `libpcap`。
- `capture.selection = "ebpf"`、`"libpcap"` 或 `"replay"` 表示 required backend；显式 backend 不自动使用 `fallback_backends`。这是为了让 operator 能表达“缺少该能力就 fail fast”，避免把强能力需求静默降级。
- `capture.fallback_backends` 只允许 live backend，不包含 replay。replay 是可重复验证入口，不是 live agent 的自动 fallback。
- `RuntimePlan` 是配置解析后的事实源，必须输出候选 provider、选中的 provider、capability matrix 和不可用原因；`run` 使用 plan 启动，`check` 输出 plan 供部署前审计。

配置/策略签名：

- V1 预留 verifier trait。
- manifest 支持 optional checksum/signature。
- filesystem source 可先校验 checksum。
- 不强制签名，避免初期运维复杂度过高。

## 20. Secret 与 TLS materials 管理

V1 使用 filesystem + 权限 + 抽象。

默认行为：

- root-owned 文件。
- `0600` 权限。
- 路径白名单。
- 热加载校验。

同时定义 `SecretStore` trait，为后续接入 Vault、KMS、TPM 预留。

敏感材料包括：

- exporter mTLS CA。
- client cert。
- private key。
- TLS decrypt materials。
- policy bundle signature keys。
- at-rest encryption keys。

不把敏感路径字符串散落到各模块。

## 21. Spool 与本地持久化

可靠性模型采用双层 spool：

- ingress journal：持久化捕获/解析所需的原始有序 chunk 或标准化输入。
- export queue：持久化 policy/parser 后的外发事件。

选择双层 spool 的理由：

- 目标态下，agent 在解析或策略前崩溃时可以恢复。
- 支持短期 replay/debug。
- 支持策略变更后的离线验证。
- 支持脱敏前后数据的明确边界。

默认 embedded storage backend 选择 Fjall。

理由：

- log-structured pure Rust KV，贴近高写入 agent 场景。
- 避免 RocksDB 的 C++、bindgen、native dependency 运维面。
- 相比 redb，更适合 append/ack/scan 型高吞吐队列。
- SlateDB 更偏 object-storage native，适合未来远端/云端 durable queue，不作为 V1 本机热路径默认。

storage 设计仍要通过 trait 隔离具体 backend，避免 Fjall API 泄漏到核心契约。

当前实现状态：

- 已实现 `DurableSpool` trait，agent 的写入、读取和 ack 边界依赖 trait。
- 已实现 Fjall adapter 作为默认 backend。
- 已实现 ingress journal 和 export queue 两条 lane，并为两者维护独立 sequence 与 cursor。
- 当前 replay pipeline 先将 `CapturedBytes` 写入 ingress journal，再解析成 `EventEnvelope` 写入 export queue。
- 当前尚未实现从 ingress journal 恢复 parser 状态或重放未 ack chunk，因此 `ingress_journal` 和整体 `durable_spool` capability 只能标记 degraded。
- 当前落盘 payload 是带 schema 的 `SpoolPayload`。V0 内容包括 JSON framed `CapturedBytes` 和 JSON framed `EventEnvelope`，用于 replay/debug/export 闭环。该格式必须通过 `payload_schema` 明示，不能伪装成最终 protobuf event schema。

redb 是可接受的备选，但不是 V1 默认。它的事务语义清晰、依赖轻，适合可靠本地状态；但 V1 spool 更偏 append、ack、scan 和高写入事件队列，LSM/log-structured 模型更自然。

spool retention：

- raw ingress journal 默认在下游确认后尽快清理。
- 支持短期 replay/debug 窗口。
- 可按 selector/policy 配置保留时间和容量。
- export queue 按 per-sink cursor 和 retention policy 清理。

落盘加密：

- 预留 at-rest encryption 接口。
- V1 可选本地 key 文件加密。
- 默认先依赖文件权限，避免 key management 抢占主线。

## 22. Exporter 与外发协议

外发 transport 必须可扩展，后续支持常见方式，例如 HTTP、gRPC、Kafka、OTLP 等。

V1 正式可靠路径：

- exporter 从 export queue pull batch。
- 发送成功后 ack。
- 每个可靠 sink 有独立 cursor。
- 所有必需 sink ack 后才能清理相关事件。

混合 exporter 模型：

- 可靠 exporter：spool-backed，at-least-once。
- realtime push sink：best-effort，只用于低延迟本地消费、debug 或非关键告警。

不允许 best-effort sink 伪装成可靠投递。

多 exporter：

- 每个可靠 sink 维护独立 cursor/ack。
- 某个 sink 慢或失败时按 per-sink quota/retention deadline 标记 failed/degraded。
- 不让单个坏 sink 拖垮采集和其它 exporter。

投递语义：

- at-least-once + 幂等。
- event 有稳定 `event_id`。
- batch 有稳定 `batch_id`。
- 接收端按 id 去重。
- 不承诺 exactly-once。

## 23. HTTP webhook batch

V1 的 HTTP(S) exporter 是 webhook 风格，但必须定义协议语义。

请求：

- URL 可配置。
- method 使用 POST。
- body 为 protobuf batch envelope。
- 支持 mTLS、自定义 CA、headers。
- 支持 codec。
- 支持 idempotency key。
- 支持 retry/backoff。

响应：

- 使用 JSON structured ack。
- 2xx 不一定自动代表整批成功，除非配置允许 empty 2xx full ack。
- ack body 包含 accepted `batch_id`。
- ack body 可以包含 acked event ids 或 contiguous cursor。
- ack body 可以表达 retryable failures。
- 非 2xx 按状态码语义决定重试、降级或失败。

当前实现要求：

- ack `batch_id` 必须与请求 batch 一致。
- `acked_event_ids` 和 `retryable_event_ids` 必须属于当前 batch。
- `acked_cursor` 如果存在，必须落在当前 batch 的 sequence 范围内。
- 如果 ack 只返回 event ids，agent 只在这些 ids 构成当前 batch 的连续前缀时推进 cursor，避免跳过未确认事件。

状态码建议：

- 2xx：请求被理解，按 ack body 判定已确认范围。
- 400：不可重试的请求格式或 schema 错误。
- 401/403：认证授权失败，sink 进入 failed/degraded。
- 404：endpoint 配置错误，sink 进入 failed/degraded。
- 409：幂等冲突或 cursor 冲突，需要按响应体处理。
- 413：batch 过大，exporter 降低 batch size 后重试。
- 429：限流，按 backoff 重试。
- 5xx：接收端临时失败，按 backoff 重试。

## 24. 编码与压缩

事件主编码使用 protobuf envelope。

理由：

- 适合跨语言接收端。
- schema 演进清晰。
- 二进制 batch 对大 payload 更友好。
- spool 和 exporter 可以复用同一 envelope 契约。

当前实现状态：

- 已实现 protobuf `BatchEnvelope`。
- `BatchEnvelope` 包含 `schema_version`。
- `EventRecord` 包含 `payload_format` 和 `payload_schema`。
- V0 payload schema 为 JSON serialized `EventEnvelope`，用于 replay/export 闭环；这是显式过渡格式，不是长期目标中的最终 protobuf event envelope。

压缩采用 pluggable codec：

- 定义 `CompressionCodec` trait。
- wire envelope 声明 codec enum。
- 默认 codec 为 zstd。
- V1 可选 gzip/deflate。
- endpoint 配置或能力不匹配时 fail fast。

关于 `zlib-rs`：

- `zlib-rs` 是 zlib/deflate 方向，不是 zstd 实现。
- 如果支持 gzip/deflate，可考虑 `zlib-rs` 作为底层候选。
- zstd 方向使用当前稳定 `zstd` crate 或等价 zstd 实现。

## 25. 脱敏与数据转换

即使命中 selector 的目标默认导出完整 payload，也需要策略层转换能力。

脱敏模型：

- Lua policy 可以对 headers/body chunks 产出 redacted view。
- policy 可以添加 tags、alerts、metadata。
- exporter 默认发送 policy 后事件。
- 原始载荷是否保留由 selector/配置显式决定。

不把脱敏放到 exporter 私有逻辑中。

原因：

- 不同 exporter 自行脱敏会导致同一事件到不同目标语义漂移。
- 策略层更了解业务语义。
- 转换必须可审计、可测试、可 replay。

## 26. 管理 API 与自观测

本地管理接口使用 root-owned Unix socket。

能力：

- health。
- capabilities。
- reload。
- debug dump。
- metrics snapshot。
- policy status。
- spool status。
- exporter status。

默认不监听 TCP，降低攻击面。Prometheus metrics 可以通过可选 localhost listener 或 admin socket adapter 导出。

日志与追踪：

- 使用 `tracing`。
- 结构化 span 覆盖 pipeline、policy、exporter、eBPF lifecycle。
- 普通事件流不打日志。

metrics 必须覆盖：

- capture events。
- parser events。
- policy execution count/error/latency。
- spool write/read/ack。
- exporter retry/ack/failure。
- degraded/gap count。
- per capability status。
- per sink cursor lag。
- LuaJIT JIT status。

## 27. Workspace 与工程结构

仓库采用 Rust edition 2024 和当前稳定工具链。

后续 workspace 使用短名 crate，建议边界：

- `agent`：主二进制、生命周期、配置加载、CLI/admin API wiring。
- `attribution`：procfs process attribution、future netlink/socket attribution adapter。
- `capture`：capture provider trait、replay provider、未来 eBPF/libpcap/plaintext provider adapter。
- `config`：TOML runtime config schema、validation、future config source abstraction。
- `core`：领域类型、selector、flow/process identity、pipeline traits。
- `ebpf`：Aya eBPF 程序和用户态 loader glue。
- `proto`：protobuf schema、generated types、wire envelope。
- `parsers`：协议 detector、HTTP/1.x、SSE、handoff。
- `pipeline`：capture event 到 ingress journal、parser、policy、export queue 的 shared processing stages。
- `policy`：mlua/LuaJIT runtime、policy bundle、state API、verdict。
- `runtime`：provider registry、capability matrix、config validation orchestration、runtime plan。
- `storage`：Fjall-backed spool、storage traits、retention。
- `exporter`：HTTP webhook exporter、codec、sink traits。
- `xtask`：eBPF 构建、代码生成、CI 辅助任务。

trait async/sync 边界：

- 热路径同步：parser、selector、policy hot hooks。
- IO 异步：exporter、config source、admin API。
- storage 使用专用 writer handle 或批量同步写入，不让 arbitrary async 污染热路径。

运行时模型采用 Tokio + 专用热路径线程：

- Tokio 负责控制面、admin API、HTTP exporter、文件监听、定时任务等 IO 型工作。
- 采集、流重组、parser、policy hot hooks、spool writer 使用专用 worker 或线程池。
- 热路径通过有界队列和明确 backpressure/degraded 语义连接。
- 不把高吞吐字节流解析全部放进 Tokio task/channel，避免调度和尾延迟污染核心路径。

eBPF 构建：

- 使用 `xtask` 统一构建 eBPF target、校验 artifacts、再构建用户态。
- 不把复杂构建逻辑藏进 `build.rs`。

依赖策略：

- 引入 crates 时使用 crates.io 当前稳定版本。
- 不限制 0.x crate。
- 但不稳定生态依赖必须包在项目 trait/adapter 后面，不能泄漏到 protobuf wire contract 或核心公共契约。
- 许可无硬约束，但应记录 license/NOTICE，避免分发阶段补债。

## 28. 错误处理

错误必须隔离，不应让单个 flow 或 policy 错误拖垮 agent。

parser 错误：

- 当前 flow 标记 `protocol_error` 或 `degraded`。
- 停止该 flow 的深度解析。
- 保留必要 metadata 和 gap/error event。

policy 错误：

- 限定到该 policy 或该事件处理。
- 达到阈值时禁用该 policy。
- agent 继续运行。
- 输出 policy error metric 和 audit event。

exporter 错误：

- 按 sink 隔离。
- 重试、backoff、retention deadline。
- 超过预算后该 sink degraded/failed。
- 不影响其它 sink 和采集主线。

## 29. 性能策略

性能目标不先拍固定数字，而是建立 benchmark harness。

benchmark 参数：

- 连接数。
- RPS。
- payload size。
- SSE chunk rate。
- exporter 延迟。
- spool latency。
- policy complexity。
- TLS provider on/off。
- eBPF vs libpcap。

观测指标：

- CPU 使用率。
- memory footprint。
- p50/p95/p99 pipeline latency。
- spool write latency。
- exporter lag。
- degraded rate。
- gap rate。
- policy latency。

默认 profile 为 Safe Production：

- 全机连接元数据。
- selector 命中目标完整 HTTP payload。
- 启用 durable spool。
- 启用 metrics/health/capability matrix。
- 资源预算保守但可调。

## 30. CLI

V1 CLI 至少提供：

- `run`：启动 agent。
- `check`：校验配置和 policy bundle。
- `replay`：用 pcap/spool 样本跑 parser/policy/exporter。
- `capabilities`：输出 capability matrix。

`replay` 是关键能力，因为 parser、Lua 策略和 exporter schema 都需要可重复验证。

## 31. 测试与验收

测试分三层：

- 纯 Rust 单元/属性测试：selector、parser state machine、policy state、spool cursor、codec。
- pcap/replay 集成测试：HTTP/1.x、SSE、unknown protocol、gap marker、policy verdict、export ack。
- 特权 eBPF smoke/e2e：Linux 环境下验证 syscall/tracepoint、libssl uprobe、pcap fallback。

V1 端到端验收：

1. 启动本机 HTTP/SSE 测试服务。
2. 配置 selector 命中该进程。
3. agent 捕获 HTTP/1.x request/response。
4. agent 识别 SSE streaming response。
5. Lua 策略产出 alert。
6. 事件写入 Fjall spool。
7. HTTP webhook batch exporter 发送 protobuf batch。
8. 测试 receiver 返回 JSON structured ack。
9. exporter cursor 前进。
10. metrics 中无静默 gap；如人为制造过载，则出现明确 degraded/gap。

TLS 验收：

1. 启动使用 OpenSSL/libssl 的测试进程。
2. selector 命中该进程。
3. 动态 attach `SSL_read/write` family uprobes。
4. 捕获明文字节。
5. 明文字节进入 HTTP parser。
6. 事件标注 plaintext source 和 confidence。

fallback 验收：

1. 禁用 eBPF 或在不支持环境启动。
2. capability matrix 显示 eBPF unavailable。
3. libpcap 捕获明文 HTTP/1.x。
4. procfs best effort 归因。
5. 事件标注 degraded capability。

enforcement 抽象验收：

1. Lua 策略返回 `deny` 或 `reset` typed verdict。
2. agent 不真实阻断。
3. 记录 desired action。
4. 记录 capability mismatch。
5. 输出 audit event。

## 32. 被拒绝或推迟的方案

| 方案 | 结论 | 理由 |
| --- | --- | --- |
| 默认透明 MITM | 推迟 | 侵入性、安全边界、证书注入和兼容性复杂；与非 MITM 默认路线冲突。 |
| 全机默认完整 payload | 拒绝 | 数据量、隐私、资源和故障半径过大；完整 payload 只对 selector 命中目标启用。 |
| 纯声明式策略或 CEL | 拒绝 | 灵活度不足，复杂检测会演变成难维护的伪语言。 |
| OPA/Rego 作为 V1 策略 | 推迟 | 能力强但嵌入、性能、数据输入边界和运维复杂度更高。 |
| WASM 策略作为 V1 默认 | 推迟 | 沙箱强但 ABI、构建链、调试和版本兼容成本高。 |
| selector 用 Lua 实现 | 拒绝 | 热路径预过滤必须可编译、可索引、可审计。 |
| 自研 segment log | 拒绝 | V1 会被拖进存储系统细节；Fjall 更务实。 |
| RocksDB 默认 spool | 拒绝 | 成熟但 C++/bindgen/native dependency 运维面大。 |
| SlateDB 默认本机 spool | 推迟 | 更适合 object-storage native 场景，不是本机 agent 热路径默认。 |
| packet-first 采集 | 拒绝 | 进程归因和 TLS 明文弱，不适合进程级探针主线。 |
| proxy-first 采集 | 拒绝 | 侵入性高，过早引入 MITM/透明代理复杂度。 |
| 全 Tokio 热路径 | 拒绝 | 高吞吐字节流和 parser/policy 热路径不应被 async 调度污染。 |
| 真实连接级阻断进入 V1 | 推迟 | 会抢占观测闭环、TLS demo 和 fallback 交付主线。 |
| exactly-once export | 拒绝 | 跨本地 spool、HTTP 和接收端存储需要复杂分布式事务，不符合实际收益。 |
| 任意 2xx 视为 webhook 全成功 | 拒绝 | 无法表达部分失败、幂等状态和 cursor。 |
| zlib-rs 作为 zstd 实现 | 拒绝 | `zlib-rs` 是 zlib/deflate，不是 zstd。 |

## 33. 后续阶段建议

### Phase 1：文档与骨架

- 完成本文档 review。
- 搭建 workspace。
- 定义核心 traits 和 protobuf envelope。
- 建立 `xtask` 构建入口。

### Phase 2：观测闭环

- 实现 selector。
- 实现 process/flow identity。
- 实现 eBPF syscall/tracepoint 主路径。
- 实现 HTTP/1.x + SSE parser。
- 实现 Lua policy runtime。
- 实现 Fjall spool。
- 实现 HTTP webhook exporter。

### Phase 3：证明性能力

- libssl uprobe plaintext provider。
- libpcap fallback。
- dry-run enforcement verdict。
- replay CLI。
- 本机 E2E demo。

### Phase 4：扩展

- WebSocket frame parser。
- HTTP/2 parser。
- Go/rustls/Java plaintext providers。
- connection-level eBPF enforcement。
- remote config source。
- stronger at-rest encryption。
- additional exporters such as gRPC, Kafka, OTLP。

## 34. 当前明确假设

- 当前仓库从零开始，没有需要兼容的公开 API。
- 当前已进入实现阶段，workspace 和核心 crate 已建立；文档必须同时记录目标设计和当前实现状态。
- 策略是可信的，但仍需要资源限制、错误隔离和受控 API。
- 完整 payload 默认只针对 selector 命中目标。
- 可靠外发必须通过 spool-backed exporter。
- realtime sink 是 best-effort。
- Linux 是唯一 V1 平台。
- root 运行是现实默认，但不是内部滥用权限的理由。
- 任何降级、gap、能力缺失都必须可观测。

## 35. 本轮决策覆盖清单

| 决策主题 | 已采纳结论 | 文档位置 |
| --- | --- | --- |
| 总体模型 | 采集、解析、策略、动作四个平面分离 | 第 2 节 |
| V1 目标 | 先完成观测闭环，不直接实现真实阻断 | 第 4 节 |
| 部署模型 | Linux Host Agent | 第 5 节 |
| 采集范围 | 全机采集 + selector 深度过滤 | 第 7 节 |
| selector 维度 | PID、进程名、路径、service、端口、地址、容器基础元数据 | 第 7 节 |
| 进程身份 | PID 不能单独作为稳定身份，使用复合身份 | 第 8 节 |
| flow identity | 使用 composite stable id | 第 8 节 |
| eBPF 技术栈 | Aya | 第 9 节 |
| 采集主路径 | socket/syscall-first | 第 9 节 |
| 企业旧内核 | RHEL8+/Ubuntu20+ 主支持，RHEL7/CentOS7 fallback | 第 5、9、10 节 |
| fallback | libpcap + procfs best effort，并标记 degraded | 第 10 节 |
| TLS 路线 | 非 MITM 优先，V1 libssl uprobe demo | 第 11、31 节 |
| 证书语义 | 区分 identity/trust materials 与 decrypt materials | 第 11、20 节 |
| MITM 预留 | 作为未来 PlaintextProvider 或 EnforcementProvider | 第 11、18 节 |
| HTTP 范围 | V1 HTTP/1.x 优先 | 第 13 节 |
| SSE | V1 一等识别 | 第 13、31 节 |
| WebSocket | V1 识别 Upgrade 并定义 handoff，不完整解析 frame | 第 13 节 |
| payload 默认 | selector 命中目标默认完整 payload，不是全机完整 payload | 第 14 节 |
| 过载语义 | 有界无损 + 显式 degraded/gap | 第 14 节 |
| 策略语言 | mlua + LuaJIT | 第 15 节 |
| LuaJIT 降级 | JIT 不可用时解释模式降级并标记 health/capability | 第 15 节 |
| LuaJIT FFI | 默认禁用 | 第 15 节 |
| Policy Bundle | manifest + main.lua + bundle-local modules | 第 16 节 |
| 策略 Hook | 分阶段 Hook，selector 先预过滤 | 第 17 节 |
| policy state | 有界状态 API，跨 worker eventually consistent | 第 17 节 |
| 热更新 | 新 VM 校验后原子切换，Lua 隐式状态不迁移 | 第 17 节 |
| 拦截抽象 | EnforcementProvider + stage capabilities | 第 18 节 |
| V1 拦截验收 | dry-run typed verdict | 第 18、31 节 |
| 配置 | TOML + 目录热加载，预留 RemoteConfigSource | 第 19 节 |
| runtime plan | provider descriptor `ProviderRegistry` 生成 capability matrix，`RuntimePlan` 解析 capture backend selection；`auto` 使用有序 live fallback，显式 backend 是 required backend；默认 auto 在无 live provider 时显式 unavailable，`run` fail closed | 第 19、27 节 |
| SecretStore | filesystem 默认，预留 Vault/KMS/TPM | 第 20 节 |
| durable spool 目标 | ingress journal + export queue 双层 spool | 第 21 节 |
| durable spool 当前实现 | Fjall ingress journal + export queue + `DurableSpool` trait + schema-aware `SpoolPayload`；两条 lane 独立 sequence/cursor；parser recovery 未实现因此 capability degraded | 第 21 节 |
| storage backend | Fjall 默认，redb/RocksDB/SlateDB 非默认 | 第 21、32 节 |
| exporter | 可靠路径 pull from spool，realtime sink best-effort | 第 22 节 |
| 多 exporter | per-sink cursor 和 retention | 第 22 节 |
| webhook | 可配置 URL，但有状态码和 JSON structured ack 契约 | 第 23 节 |
| 编码目标 | protobuf envelope | 第 24 节 |
| 编码当前实现 | protobuf batch envelope + JSON `EventEnvelope` payload schema 过渡格式 | 第 24 节 |
| 压缩 | pluggable codec，默认 zstd，可选 gzip/deflate | 第 24 节 |
| zlib-rs | 用于 deflate/gzip 方向候选，不是 zstd 实现 | 第 24、32 节 |
| 脱敏 | policy transform，不放到 exporter 私有逻辑 | 第 25 节 |
| admin API | root-owned Unix socket | 第 26 节 |
| 自观测 | metrics、health、tracing、capability/degraded/gap counters | 第 26 节 |
| workspace | 短名 crate，使用 xtask 管 eBPF 构建 | 第 27 节 |
| runtime | 热路径同步，IO 异步，Tokio + 专用热路径线程 | 第 27 节 |
| 依赖 | 使用当前稳定 crate，不限制 0.x，但通过 trait/adapter 隔离 | 第 27 节 |
| CLI | run/check/replay/capabilities | 第 30 节 |
| 验收 | HTTP/SSE demo、libssl TLS demo、pcap fallback、dry-run enforcement | 第 31 节 |
