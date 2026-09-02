# 认证交互与审计日志

## 已实现

- `auth.mode` 是总开关：`none` 保持匿名访问且不挂载认证 Secret；`local` 才启用登录、Session 和 API 鉴权。
- Local auth 启动时调用 `/api/auth/me`，未认证显示登录页；登录成功后等待会话再次确认，再进入 Dashboard。
- Dashboard 内任意受保护 API 返回 `401` 时卸载当前页面状态并回到登录页。原 URL 保留，重新登录后可以恢复筛选和详情入口。
- `403` 显示无权限，`503` 显示服务不可用，不把它们误报为密码错误。
- 退出会清除服务端 Cookie 并卸载 Dashboard。
- 访问日志统一包含 `src_ip`、`user`、method、path、status、size 和耗时；保留 `ip` 字段兼容已有日志消费者。
- 登录成功、登录失败、退出、Session 创建失败和权限解析失败有独立结构化事件日志，不记录密码和 Cookie。

## 日志示例字段

```json
{
  "message": "request",
  "fields": {
    "src_ip": "10.0.0.8",
    "user": "alice",
    "method": "GET",
    "path": "/api/v1/reports",
    "status": 200
  }
}
```

## 部署注意事项

当前 `X-Forwarded-For` 和 `X-Real-IP` 需要由可信 Ingress/反向代理覆盖。若服务端口直接暴露给不可信客户端，应增加可信代理网段配置，避免客户端伪造来源 IP 写入日志。
