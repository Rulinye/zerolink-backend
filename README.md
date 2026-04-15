# zerolink-backend

> 0-0link 项目控制面后端
> Phase 0: 仅有 `/ping` 和 `/version` 两个端点
> 维护人: @rulinye

---

## 这是什么

部署在控制机(春川)上的 HTTP 服务,负责:

- **当前 (Phase 0)**: 仅 `/ping` 健康检查 + `/version` 版本查询,验证部署链路
- **未来 (Phase 1+)**: 用户/邀请码/节点下发/订阅链接/流量统计/管理 API

按 0-0link 项目计划书 §2.4,本服务的节点列表事实来源是 `0-0link-infra` 仓库的 Ansible inventory。本仓库不在数据库里直接存节点。

---

## 技术栈

- Go 1.25+
- `github.com/go-chi/chi/v5` 路由
- `log/slog` 结构化日志(stdlib)
- 无其他外部依赖

选型理由见项目计划书 §6.3。

---

## 本地开发

### 前置

- Go 1.25 或更新版本

### 跑起来

```bash
make run
# 或直接:
go run . -listen 127.0.0.1:8080
```

然后:

```bash
$ curl -s http://127.0.0.1:8080/ping | jq
{
  "ok": true,
  "service": "zerolink-backend",
  "time": "2026-04-15T12:34:56Z"
}

$ curl -s http://127.0.0.1:8080/version | jq
{
  "version": "dev-a1b2c3d"
}
```

### 测试

```bash
make test
```

### 跨平台编译(Linux/amd64,部署目标)

```bash
make linux
# 产物: build/zerolink-backend-linux-amd64
```

---

## 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-listen` | `127.0.0.1:8080` | 监听地址。Phase 0 默认仅本机访问,通过 SSH 隧道暴露 |
| `-log-json` | `false` | 输出 JSON 日志(给 systemd/journal 用) |

---

## 部署

部署由 `0-0link-infra` 仓库的 `roles/backend` 完成。简略流程:

1. 推送 tag `vX.Y.Z` 到本仓库
2. GitHub Actions 自动编译并发布二进制到 GitHub Release
3. 在 `0-0link-infra` 的 `inventory/group_vars/all.yml` 改 `backend_version`
4. 跑 `ansible-playbook playbooks/deploy-control.yml`
5. 验证: 在管理机本地开 SSH 隧道访问

```bash
# 在管理机本地执行:
ssh -N -L 8080:127.0.0.1:8080 ubuntu@168.107.55.126 &
curl -s http://127.0.0.1:8080/ping
```

---

## 路线图

- [x] **Phase 0**: `/ping` + `/version`,可部署到春川,SSH 隧道访问 OK
- [ ] **Phase 1**: SQLite + 用户注册/登录/JWT/邀请码/节点下发/订阅链接
- [ ] **Phase 4**: 流量统计、限速、管理员 Web 界面

详见项目计划书 §4.4。

---

## 仓库结构

```
zerolink-backend/
├── main.go              ← HTTP 服务入口、所有 handler、graceful shutdown
├── main_test.go         ← /ping /version 烟测
├── go.mod
├── Makefile
├── README.md
├── .gitignore
└── .github/workflows/
    └── build.yml        ← test + linux/amd64 build + tag → release
```

Phase 1 起会拆出 `internal/{auth,nodes,subscription,storage}` 等子包。

---

## 安全注意

- ⚠️ Phase 0 的 `/ping` **没有认证**,所以坚决只听 `127.0.0.1`,不开公网。
- Phase 1 加 JWT 中间件后,`/api/v1/*` 才会要求 token,但 `/ping` 仍然保持无认证(用于探活)。
- 任何敏感配置(JWT secret, admin 密码 hash) 走 Ansible Vault,不进本仓库。
