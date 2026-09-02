# 缓存与前端渲染性能跟进

## 本轮已落地

### 后端缓存

- Query Cache 不再在每次 Report 更新时执行全量 `DeletePrefix` 扫描；使用 type generation 让旧 Key 自然失效，再由 TTL/LRU 回收。
- Overview 和 Report Count 优先消费 `ReportSummaries()` 快照，不再复制整个缓存 map，也不再对每条记录访问 Ristretto。
- Summary、Detail、Query Cache 仍保持独立容量和生命周期；Summary 不允许被普通 Ristretto 淘汰静默删除。

### 前端

- Sidebar 的 Report Count 从“每个 Report Type 一个请求”改为一次 Cluster Overview 聚合。
- Overview、GlobalHub、ReportDetails 改为按需懒加载。
- Overview/GlobalHub 在 Cluster 切换或卸载时取消旧请求，避免无效响应继续触发渲染。

构建结果：首屏主 JS 从约 683KiB 降到约 298KiB；Recharts 单独进入约 345KiB 的按需 Chunk。总下载量没有消失，但首屏不再承担图表和详情代码。

## 仍有优化空间

### P1：建立基准后处理

1. `ReportSummaries()` 和 Overview 仍是 `O(reportCount)`；10 万摘要下需要测量 P95。若超过目标，引入按 Cluster/Namespace/Type 的增量聚合索引，不能直接复用未授权的全局统计。
2. `GetReports` Query Miss 仍需要过滤和排序；后续应让 Query Cache 保存 `ReportRef` 而不是完整 `Report`，并评估按排序键的索引和游标分页。
3. Trend 文件目前仍是整文件读写；按小时 7 天、按日 90 天压缩后再评估是否迁移到专用时序存储。

### P2：按使用规模处理

1. GlobalHub 当前每个 Cluster 请求一份 mini trend，10 个 Cluster 是约 10 个并行请求；可增加批量趋势接口。
2. Detail 中漏洞或 Checks 超过 500 条且实测卡顿时，再引入虚拟列表。
3. 只有在 Overview 频繁访问成为热点后，才增加带 Scope Fingerprint 的有界 Overview Cache。
4. 继续监控浏览器长任务、Recharts 渲染耗时、API P95、RSS 和 Ristretto 命中率，不根据 bundle 大小单独判断性能。

## 验证限制

本地已通过前端 lint/build，但当前环境没有 Go、Helm 和 Docker，尚未完成 10 万摘要规模的后端基准、race 测试和镜像构建验证。
