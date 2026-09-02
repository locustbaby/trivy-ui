# 多集群切换性能与渲染优化

基线：`6c92bf3`（working tree）。聚焦前端集群切换链路的性能/渲染，以及上一轮 review 确认的两个后端修复点。

## 设计与落地

| # | 改动 | 层 | 说明 |
| --- | --- | --- | --- |
| D1 | `fetchData` generation + AbortController | FE | 消除快速切换集群时乱序响应覆盖新状态的竞态（ReportsList/ReportDetails 早有此模式，Dashboard 缺失） |
| D2 | 切换不再全屏 loading | FE | 仅首屏全屏；切换保持应用壳不动，元数据缓存命中即时水合侧边栏 |
| D3 | ReportsList 首屏并行化 | FE | reports 第 1 页与 namespaces 并行拉取；ns 校验有差异才补偿性重取一次；顺带修复 HEAD 上即存在的 `prevFiltersRef` 不同步导致的重复 fetch |
| D4 | `apiCache.ts` 元数据 TTL 缓存 | FE | 20s TTL（< 30s 轮询周期，轮询始终真实回源）；登出时清空 |
| D5 | GlobalHub / OverviewDashboard 错误态 | FE | 补齐 Retry UI，消除失败白屏；Dashboard 头部新增"元数据可能过期"降级提示条 |
| D6 | React.memo × 3 + `sameMetadata` | FE | clusters/reportTypes 身份稳定化，15s/30s 轮询不再整树重渲 |
| D7 | detail singleflight panic-safe | BE | defer close + recover + 堆栈；修复 panic 后 flight entry 永久阻塞等待者的问题 |
| D8 | overview memo | BE | `(cluster, scopeFingerprint, repositoryVersion)` 键、3s TTL、per-key singleflight、64 条上限、unknown-cluster 短路（不进缓存）、TOCTOU 版本快照校验 |

## 多 agent Review 结论

三个隔离视角（正确性/竞态、性能/架构、安全/降级）独立审查后确认并已修复：

1. **P2**：切换到从未访问的集群且请求失败时，B 集群 header 与 A 集群类型列表无限期共存且无任何陈旧信号 → 现在清空类型列表并显示可点击的过期提示。
2. **P2**：overview memo 可被垃圾 cluster 参数撑爆；插入时全局锁内全表扫描；无 singleflight → unknown-cluster 直接返回空结果不进缓存；64 条上限（先淘汰过期再整体重置）；singleflight 收敛并发 miss。
3. **P2**：`clusters/reportTypes` 每次 poll 换新数组身份打穿 React.memo → `sameMetadata` 浅比较保持引用稳定。
4. **P2**：init/corrective 更新 URL 后 `prevFiltersRef` 未同步 → filters watcher 触发多余请求（HEAD 上已有）→ `syncPrevFilters` 同步写入。
5. **P3**：首次加载未完成时 silent poll 会 abort 初始加载并吞错造成白屏窗口 → `effectiveSilent = silent && !initialLoad` 升级处理。
6. **P3**：登出不清理前端元数据缓存 → App logout 接入 `invalidateCached()`。
7. **P3**：panic recover 丢失堆栈 / apiCache 死代码 → 已修/已删。

复核 agent 对全部修复逐项验证：7/7 OK，无新增 P1/P2。

安全结论：overview memo key 含 SHA-256 双 fingerprint（user scope + data source scope），不存在跨用户泄漏路径；auth 模式启动即固化，policy 变更产生新 fingerprint；localStorage 命名空间注入无害（服务端 scope 独立校验，参数仅进 URL query 且服务端只做 split/trim）。

## 已知取舍（backlog）

- overview 仍是全量扫描 + memo；长期方案是从现有 atomic counters（total/withVuln per cluster/ns/type）增量推导，避免 O(N) 重扫。
- overviewMemo 无 post-validation（query cache 有 generation 复验），依赖"所有 summary 变更必经 Cache.Set/Delete"这一隐式契约，已在代码注释中钉明。
- singleflight waiter 的 3s 兜底会在 leader 迟迟未完成时本地重复计算；持续慢的场景下每个 waiter 都付全价。TTL 设计下可接受。
- 列表虚拟化、GlobalHub sparkline 手写 SVG：收益/成本比低，暂缓。
