# 测试覆盖与模块化评审

## 基线与结论

- 日期：2026-09-02
- 基线：`main...working tree`，包含 v0.0.5 的全局采集、Dashboard scope、Cluster-scoped CR 和文档改动
- 验证：`go test ./...`、`go test -race ./...`、`go vet ./...`、`go test -tags e2e -c ./test/e2e`、`npm run lint`、`npm run build`、`helm lint`、`helm template` 均通过

当前分层是清楚的：`auth` 负责 Dashboard 用户身份与 scope，`dataaccess` 负责采集来源边界，`kubernetes` 负责 Kubernetes 访问，`config` 负责 CRD 能力发现，`api` 负责 HTTP 编排。v0.0.5 的功能正确性有 Unit、race 和 kwok E2E 保护；主要后续投入应放在浏览器 E2E、真实 RBAC 失败路径、多集群集成，以及拆分过大的 API 文件。

## CI 与交付边界

- kwok 创建完成不代表 Kubernetes API 的 post-start hook 已 ready。E2E 创建两个 cluster，分别使用 KWOK v0.7.0 提供的 Kubernetes `v1.30.10` 和 `v1.31.6`，逐个轮询 `/readyz` 后才应用 CRD，避免 API server 初始化竞态。
- Helm 渲染检查覆盖默认 RBAC、关闭 chart RBAC、关闭受限缓存卷以及自定义缓存挂载路径。`DATA_PATH` 由 Chart 统一推导，避免环境变量与 volume mount 不一致。
- amd64 镜像在漏洞扫描后以只读根文件系统运行 `hash-password` smoke test，验证最终镜像中的服务二进制可执行。
- OCI Chart 仅发布到 Docker Hub，并且只在 GitHub Release 发布后（或手动 dispatch）运行，不会在普通 `main` push 时绕过测试流水线。

## 本轮修复与回归保护

### 跨站认证 Cookie

`CORS_ALLOWED_ORIGINS` 配置精确来源时，服务会允许携带凭证的 CORS 请求，并在未显式设置 `AUTH_COOKIE_SAME_SITE` 时将 session Cookie 派生为 `SameSite=None`。该模式强制 `AUTH_COOKIE_SECURE=true`；`none + insecure` 和未知 SameSite 值会在启动时失败。

可通过 Helm 的 `auth.session.cookieSameSite`（`lax`、`strict`、`none`）显式覆盖派生策略。默认同源部署仍保持 `lax`。

对应测试：

- CORS 来源解析与凭证开关；
- CORS 到 Cookie policy 的派生与显式覆盖；
- Cookie 的 `SameSite=None; Secure` 输出；
- 非安全 `SameSite=None` 与非法 policy 的拒绝。

### 受限用户趋势

趋势历史现在为每个 Cluster 记录 Namespaced scope 和 Cluster-scoped scope（`_`）的独立计数。受限用户请求趋势时，后端只聚合其可见 scope：

- 全局请求返回一个 fleet aggregate 和每个可见 Cluster 的 aggregate；
- 单 Cluster 请求只返回该 Cluster 的 aggregate；
- 原始全局和 Cluster aggregate 不参与受限用户聚合，避免计入不可见报告。

前端 fleet 图只消费 `cluster=""` 的 aggregate，Cluster 卡片消费对应 Cluster 的 aggregate，避免多 Cluster 场景中同一时间 bucket 重复绘制。

对应测试覆盖同一用户同时拥有 `team-a` 与 `_` scope、被拒绝的 `team-b` scope、全局聚合及单 Cluster 聚合。

### Cluster-scoped CR 详情

kwok E2E 会种入 40 个 `ClusterVulnerabilityReport`，并验证：

```text
/api/v1/reports/{cluster}/clustervulnerabilityreports/_/{name}
```

能从真实 Kubernetes API server 读取详情内容。另有 Kubernetes fake-client Unit 测试，确保 cluster-scoped 详情不会调用 namespaced resource 路径。

## 覆盖率基线

以下是 `go test -cover ./...` 的 package 级 statement coverage；它不等同于端到端功能覆盖，也不应被简单汇总为单一百分比。

| 模块 | 覆盖率 | 现状 |
| --- | ---: | --- |
| `dataaccess` | 87.1% | scope 解析、交集和旧 Namespace-mode 配置迁移覆盖较完整 |
| `auth` | 61.7% | 文件用户、scope、登录、Cookie 与会话签名均有测试 |
| `api` | 38.0% | 查询、分页、鉴权流、错误协议、缓存重点路径已覆盖，但分支最多 |
| `kubernetes` | 31.1% | Client 和 informer 有 Unit 测试；真实权限错误路径不足 |
| `config` | 19.4% | CRD discovery 与异常配置路径需要补强 |
| `utils` | 0.0% | 目前无直接 Unit 测试 |
| 前端 | 无测试 runner | 目前由 ESLint、TypeScript 与 production build 覆盖静态质量 |

## 功能场景矩阵

| 场景 | Unit / Integration | kwok E2E | 状态 |
| --- | --- | --- | --- |
| 未登录、错误密码、登录、退出 | 有 | 无 | 已覆盖服务端流程 |
| 用户 namespace scope 与 `_` cluster scope | 有 | 无 | 已覆盖列表及权限模型 |
| Cluster-scoped list / detail | 有 | 有 | 已覆盖 `_` 详情路径 |
| 列表分页、排序、搜索、namespace、漏洞过滤 | 有 | 有 | 已覆盖 |
| Overview 与受限趋势聚合 | 有 | 无 | 已覆盖关键授权聚合 |
| Informer create/delete 实时同步 | 部分 | 有 | 已覆盖 |
| 缓存容量、持久化、stale 读取、目录缺失 | 有 | 无 | 关键 Unit 已有，恢复兼容场景仍少 |
| Helm RBAC、认证/CORS、缓存挂载与渲染 | Render check | 无 | 已覆盖默认和主要配置组合 |
| 多 Cluster 来源、隔离与合并统计 | 有 | 有 | 已覆盖两个不同版本的 KWOK cluster |
| Kubernetes RBAC 拒绝 `list/watch/get` | 无 | 无 | 待补 |
| 跨站浏览器登录与 Cookie 发送 | Cookie Unit | 无 | 待补真实浏览器验证 |
| Dashboard 交互（筛选、详情、切换、错误页） | 无 | 无 | 待建立前端测试基础设施 |

## 后续测试优先级

### P1：发布前或引入相关功能时必须覆盖

1. 浏览器 E2E：不同 site 的 frontend 与 API，验证登录响应能写入 Cookie、后续请求携带 Cookie、logout 能删除 Cookie。Go 的 `httptest` 不能代表浏览器 SameSite 行为。
2. Kubernetes RBAC E2E：分别缺少 `list/watch/get` 权限，验证 readiness、sync state、API 错误码和 UI 错误页行为。

### P2：近期迭代

1. local auth 下详情 API 的允许与拒绝路径，特别是缺少 `_` scope 的 Cluster-scoped detail。
2. 缓存快照升级、损坏文件、磁盘写满和旧 fingerprint 清理。
3. 建立前端测试 runner，优先覆盖登录恢复、全局/Cluster 切换、ReportsList 的筛选与详情跳转。

## 模块化与抽象评估

### 已有的合理边界

- `auth` 的 identity provider、policy provider 与 session manager 是独立抽象；Kubernetes RBAC 与 Dashboard RBAC 不混在一起。
- `dataaccess.Policy` 表达采集来源边界，最终权限由 `auth.AccessSnapshot` 计算交集。
- `kubernetes.Client` 与 informer 将动态 CRD 操作从 HTTP handler 隔离。
- `CacheService` 与 `QueryService` 使列表查询、权限过滤可以脱离真实缓存测试。

### 主要结构债务

| 优先级 | 位置 | 问题 | 渐进拆分目标 |
| --- | --- | --- |
| P2 | `go-server/api/cache.go`（约 2300 行） | summary、detail、磁盘 snapshot、趋势、容量和 query cache 共存 | `summary_store`、`detail_store`、`trend_history`、`query_cache` |
| P2 | `go-server/api/handlers.go`（约 1350 行） | HTTP 协议、鉴权、报告详情、overview 聚合集中 | `reports_handler`、`overview_handler`、`clusters_handler` 与 application services |
| P2 | `trivy-dashboard/src/components/ReportsList.tsx` | 请求状态、筛选状态与呈现耦合 | `features/reports` 下的 query hook、状态模型与展示组件 |
| P3 | `trivy-dashboard/src/components/Dashboard.tsx` | 页面导航、筛选同步与视图编排集中 | feature router / dashboard state hook |
| P3 | `go-server/api/router.go` | 新旧 API 路由的 method/path 分支重复 | 声明式 route table；保留兼容路由但共用 handler adapter |

推荐先拆 `api/cache.go` 的趋势历史和详情缓存：两者有独立的数据生命周期、持久化格式和测试边界，且不需要改变 HTTP API。之后把 `handlers.go` 的 overview 和 report-detail 编排移动到 application service，由轻量 HTTP handler 调用。不要为抽象而引入泛化 repository；以 Report summary、Report detail、Trend history 三个明确生命周期作为边界。
