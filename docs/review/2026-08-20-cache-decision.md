# Detail Cache 决策修订

## 结论

完整 Report Detail 不取消落盘，但不再和 Summary 共用 Snapshot 文件。当前实现采用两个持久化边界：

```text
cache.json         Report Summary、列表索引依赖的数据
detail-cache.json  有界、可过期的完整 Detail
```

Query Cache 不落盘。

## 为什么保留 Detail 落盘

- Pod 重启后可以继续查看最近打开过的详情。
- Cluster 短暂不可用时仍能查看历史详情。
- 降低重复打开详情对 Kubernetes API Server 的压力。
- Summary 只负责列表、统计和权限过滤，Detail 不参与 Summary 的完整性判断。

## 正确性与安全边界

- Detail key 仍按 `cluster + namespace + type + name` 隔离；Report 包含 `resourceVersion`，用于识别详情版本。
- informer Update/Delete 会淘汰对应 Detail，不能继续使用已确认过期的详情。
- 详情读取先执行用户权限和数据源权限校验，再访问内存或磁盘缓存。
- Detail Snapshot 使用 schema version、临时文件、`fsync`、原子 rename 和 `0600` 权限。
- 重启加载但已经超过 Detail TTL 的条目标记为 `stale`，最多保留 24 小时；API 返回 `stale: true`，不伪装成实时数据。
- Detail 有独立最大容量，超过容量按最早过期项淘汰；不能影响 Summary 的完整性。

## 当前配置

```yaml
cache:
  detail:
    persist: true
    maxSize: 256Mi
    ttl: 10m
    staleRetention: 24h
```

Detail 配置通过 Deployment 环境变量传入后端。若 `persist=false`，服务仍使用有界内存 Detail Cache，但不会读取或写入 `detail-cache.json`。

## 后续 TODO

1. 在 Go 测试中覆盖 Detail Snapshot 重启恢复、过期 stale、容量淘汰、原子写入失败和 `0600` 权限。
2. 将 `resourceVersion` 纳入详情命中校验：如果当前 Summary 版本与缓存版本不同，必须回源或返回 stale。
3. 为 Summary 和 Detail 增加命中率、淘汰数、stale 命中数和 Snapshot 大小指标。
4. 生产环境如果 Detail 含有更严格的敏感字段，再评估加密存储；不能依赖文件权限替代 Kubernetes volume 和 Pod 权限控制。
