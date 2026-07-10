# 仓库执行约束

## 事实源

- Clean-slate rebuild goal 进行期间，修改代码前先读取 goal 和本地
  `.agents/plans/probe-clean-slate-rebuild/index.md` 知识包。始终读取相关 tracked
  文档、Git history 和 worktree。若本地计划不存在或重构已经完成，`docs/` 是产品事实源。
- Clean-slate rebuild 只使用一个 goal；里程碑和审查检查点不是子 goal。
- Goal 进行期间，其记录的 plan digest 保持冻结。规范变更必须先在 canonical plan 外形成
  exact patch，由 objective-anchored approval key/issuer 验证用户批准，写入
  `.agents/goals/probe-clean-slate/runtime/amendments/<ID>.toml`，再由 bootstrap verifier
  materialize；计划包中的 `amendments.md` 只供导航。不得先修改规范再请求追认。
- 未经用户明确批准不得创建 ADR。`decisions/clean-slate-rebuild.md` 是本次重构唯一预先
  批准的 ADR。

## 产品方向

- 只支持 Linux。项目尚未发布，不承担向后兼容负担。
- 直接删除过时 schema、配置路径、存储格式、feature flag 和 production path，不保留
  shim。
- 交付完整的 production vertical path。Trait、placeholder、mock、replay source 或 test
  feed 不能满足 production requirement。
- 保持 raw evidence、显式 gap、provenance、稳定 workload identity、有界资源、最小权限和
  passive no-backpressure 语义。

## Rust

- 使用 stable Rust、edition 2024 和最新稳定 crate。添加 crate 前运行
  `cargo search --registry crates-io <crate>`，再使用 `cargo add`。
- 默认使用 `mod.rs` 作为模块入口。除非存在更强的结构性理由，`mod.rs`、`lib.rs` 和
  `main.rs` 只负责导出与组装。
- 可行时把 unit test 放在相关实现文件末尾。`tests/` 只放通过 public API 验证行为的
  integration test。
- 不创建通用 `test_support` 模块或低价值 smoke test。共享 fixture 必须有明确领域 owner。
- 不按行数机械拆分内聚的 Rust 文件。文件超过约 1,000 行时审视真实 ownership boundary；
  组织清晰且单元测试合理内聚时允许超过该规模。
- 修改代码后运行 `cargo fmt --check`、`cargo clippy` 和相关测试；仓库 `xtask` gate 建立后
  使用对应入口。

## 文档

- 使用本地 `maintain-okf-docs` skill 维护简体中文 OKF 知识树。`README.md` 使用 English，
  `README_ZH.md` 使用简体中文。
- 按读者意图、领域契约、不变量、工作流、失败模式、运维和验证组织文档。设计与参考文档
  不得写成实现流水账。
- 重组文档时保留有效决定、理由、约束、风险和验证证据。

## 验证与审查

- Required validation 遇到 `skipped`、`not_run`、`missing`、`unknown`、mock provenance、
  replay provenance 或 candidate artifact 不匹配时必须失败。
- Goal-specific contract、case、schema 与 verifier 只位于 ignored
  `.agents/goals/probe-clean-slate/`；`base/` 在 objective 锚定后不可修改，`runtime/` 只承载
  signed amendments、runner enrollment 与 evidence。不得加入 workspace、产品 binary 或
  `xtask`。可重放 final evidence 归档后删除该临时目录。
- 不得为了通过 gate 删除、弱化、缩小或绕过测试与 requirement；不得降低阈值、扩大
  inferred attribution、重标 loss 或拼接不同 candidate 的证据。
- 每个高风险 proof/边界完成后、每个里程碑提交前和 final acceptance 前运行 `$gejv` 与
  `$thermos`。
- `$thermos` 使用两个独立只读 reviewer，均为 Sol high：一个加载
  `thermo-nuclear-review`，另一个加载 `thermo-nuclear-code-quality-review`。修复后尽可能
  交回原 reviewer 复核。
- 解决全部阻断 finding 并获得 reviewer 确认后再提交。每个可独立审查的里程碑使用 English
  commit message 提交。

## 安全

- 不回退用户改动。存在 dirty worktree 时协同处理，并把无关改动与当前任务分开。
- 未经用户明确批准，不对共享主机、网络策略、信任库、用户 evidence 或外部服务执行
  destructive operation。
- 分开记录实际观察到的验证结果与推断。Required runner 不可用时继续推进独立工作，并保持
  goal active。
