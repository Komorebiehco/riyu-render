# Kate Mu 森林主题可视化工作台

这是一个由当前 Python 项目直接托管的管理仪表盘，使用原生 HTML、CSS 和 JavaScript，无需安装 Node.js 或其他依赖。

## 预览

在项目根目录启动统一服务：

```powershell
start.cmd dashboard
```

然后访问 `http://127.0.0.1:8766`。

## 已包含

- 响应式侧边栏和移动端布局
- 浅色 / 深色主题
- 核心指标卡片
- 原生 Canvas 趋势图
- 任务状态环图
- 8 步流程健康度
- 异常分类统计
- 任务搜索和状态筛选
- 单条任务删除（处理中任务除外）
- 脱敏任务列表
- 来自 SQLite 的脱敏任务与实时活动
- 服务健康状态与手动刷新

## 对接建议

当前页面使用 Python 服务提供的以下主要接口：

```text
GET /api/dashboard/summary
GET /api/dashboard/trend?range=week
GET /api/dashboard/steps
GET /api/dashboard/failures
GET /api/tasks?status=&query=&page=
DELETE /api/tasks/{account_id}
GET /api/events
GET /api/health
```

服务端不返回密码、TOTP 密钥、Cookie、备用码、恢复信息或代理地址；账号邮箱始终由后端脱敏后再返回。删除操作只会删除选中的任务数据库记录，正在处理的任务不能删除。
