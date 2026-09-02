# Project reviews

这里记录跨前端（UI 视觉/交互/组件架构）、后端、Helm 和运行时数据链路的项目级评审，作为后续修复和重构的依据。

| 日期 | 基线 | 文档 | 重点内容 |
| --- | --- | --- | --- |
| 2026-09-02 | `main...working tree` | [测试覆盖与模块化评审](./2026-09-02-test-coverage-and-architecture.md) | v0.0.5 覆盖率基线、功能场景矩阵、跨站 Cookie/授权趋势修复、E2E 缺口与 API/前端渐进拆分方案 |
| 2026-08-20 | `87b7848` | [前后端架构、UI/UX 交互与数据正确性综合评审](./2026-08-20-project-review.md) | 多集群身份与 ACL、缓存正确性、前端 UI 配色/抽屉/Fixable 过滤/组件规范 (15个Lint问题) 及性能容量评估 |
| 2026-08-20 | working tree | [Detail Cache 决策修订](./2026-08-20-cache-decision.md) | 恢复独立 Detail Snapshot，明确 stale、容量、权限和数据生命周期 |
| 2026-08-20 | working tree | [缓存与前端渲染性能跟进](./2026-08-20-performance-followup.md) | Query Cache、Summary 快照、首屏懒加载和后续基准计划 |
| 2026-08-20 | working tree | [算法与数据结构优化建议](./2026-08-20-data-structures.md) | LRU、原子 generation、ReportRef 索引、游标分页和 Scope 编译 |
| 2026-08-20 | working tree | [认证交互与审计日志](./2026-08-20-auth-observability.md) | 登录态恢复、401/403/503 交互、用户和来源 IP 结构化日志 |
| 2026-08-20 | `6c92bf3` | [多集群切换性能与渲染优化](./2026-08-20-cluster-switch-perf.md) | 切换竞态防护与局部刷新、元数据 SWR 缓存、首屏并行化、overview memo/singleflight，多 agent review 与修复验证 |

文档中的优先级约定：

- P1：合并或生产验证前应解决，可能破坏核心功能、租户边界、数据正确性或触发致命 React 规范错误。
- P2：应进入近期迭代，通常影响可靠性、性能、可维护性、视觉一致性或用户体验。
- P3：清理和长期演进项。
