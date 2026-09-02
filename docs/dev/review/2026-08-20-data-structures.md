# 算法与数据结构优化建议

## 已落地

- Query Cache 淘汰从扫描全部 entry 找最老项改为 `container/list + map` 的 LRU，写入和淘汰从 `O(C)` 降为 `O(1)`。
- type generation 从 `sync.Map Load/Store` 改为 `atomic.Uint64`，避免高并发 informer 更新时丢失版本递增。
- Overview/Count 读取增加 Summary 快照入口，绕过整张缓存 map 和 Ristretto 热缓存查询。
- 前端 Sidebar 报告类型排序、GlobalHub Cluster 健康索引和趋势转换改为 memoized 派生数据；列表使用稳定业务 Key。

## 当前数据结构的主要瓶颈

### 1. Summary 主索引仍是字符串 Key

当前 `report:cluster:namespace:type:name` 需要频繁 `Split`，并且业务身份分散在字符串、`Report` 和多个计数器中。下一步应引入：

```go
type ReportRef struct {
    Cluster, Namespace, Type, Name string
}

type ReportSummaryStore struct {
    byRef       map[ReportRef]ReportSummary
    byType      map[string]map[ReportRef]struct{}
    byCluster   map[string]map[ReportRef]struct{}
    byNamespace map[ClusterNamespace]map[ReportRef]struct{}
}
```

字符串 Key 只保留在持久化兼容层。这样可以减少拆分、降低碰撞风险，也为 Cluster/Namespace 游标分页提供索引基础。

### 2. Query 仍是全量过滤和排序

现在 Query Miss 需要扫描匹配 Type 的报告，再做过滤、搜索、排序和分页。短期对 10 万摘要可接受，但长期应：

- 搜索字段建立规范化索引，或使用倒排索引；
- 固定排序使用复合排序键；
- 从 offset pagination 改为 cursor pagination；
- Query Cache 只保存 `ReportRef`，不复制完整 Summary。

不要直接给每个查询建立独立全量索引，否则内存会按查询数增长。

### 3. Scope Matcher 可以编译成常数级查找

当前 ACL 规则数量通常很小，逐条匹配已经足够。未来规则量增大时，可编译为：

```text
exact cluster -> exact namespace set
exact cluster -> namespaced wildcard
all clusters  -> exact namespace set
all clusters  -> namespaced wildcard
cluster-scoped `_` 单独处理
```

匹配从 `O(ruleCount)` 降到接近 `O(1)`，同时保留 `*` 不匹配 `_` 的语义。

### 4. 聚合应从全量扫描转为增量索引

Overview 和 Trends 在高频访问时仍会按 Summary 重新聚合。正确的演进方式是以 `ReportRef` 为粒度维护增量 severity 聚合，并按 partition generation 失效；权限查询仍必须在授权数据集合上重新聚合，不能直接复用无权限全局结果。

## 暂不建议

- 不建议马上引入数据库或搜索引擎；当前规模先用进程内分区索引和版本化 Snapshot。
- 不建议为每个 Namespace 建独立 goroutine 或缓存副本；会放大多租户资源消耗。
- 不建议现在全面虚拟化列表；服务端分页已经控制了 Report 列表规模，只有 Detail 超过 500 条且基准证明需要时再做。
