# 🚀 Google 账号极速换绑与防盗系统 v1.0 使用指南

本系统是一套面向大体量买家的高并发、秒级响应 Google 账号极速换绑与防盗切割系统。系统在收到账号凭证后，自动通过真实 Chrome 引擎完成 8 步全链路防盗切割操作，彻底剪断卡网所有后台控制通道，杜绝盗回。

---

## 🛠️ 1. 环境准备与依赖安装

### Windows 本地独立环境（推荐）

项目不依赖系统 Python，也不会修改全局 `PATH`。双击 `setup.cmd`，脚本会把以下内容全部安装在当前项目的 `.runtime` 目录：

- Python 3.12 便携版
- `requirements.txt` 中的 Python 依赖
- 自动检测已安装的 Chrome 或 Microsoft Edge（不重复安装）

首次安装需要联网，以后可直接使用 `start.cmd`。如需完全删除运行环境，只需删除项目内的 `.runtime` 目录。

```cmd
setup.cmd
start.cmd status
```

双击 `start.cmd` 会显示可用命令和示例。也可在 CMD 中传入原有 CLI 参数：

```cmd
start.cmd sanitize --input accounts.txt --workers 3
start.cmd sanitize-single --gmail 账号邮箱@gmail.com --password 原始密码 --2fa 原始2FA密钥
start.cmd export --output clean_accounts.json
```

### 使用已安装的 Python（可选）

如果不使用项目自带的 CMD 脚本，需要 Python 3.10 或更高版本，然后执行：

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

---

## ⚙️ 2. 全局配置说明 (`.env`)

项目根目录下的 `.env` 文件包含系统运行的关键配置：

```ini
# 1. 换绑接码域名设置
BUYER_DOMAIN=your-buyer-domain.com
MAIL_CALLBACK_URL=http://127.0.0.1:8765/code
CODE_WAIT_TIMEOUT=30

# 2. 代理 IP 设置 (批量并发时建议配置动态住宅代理)
PROXY_MODE=none  # 可选: none / socks5 / http

# 3. 密码生成规则
PASSWORD_LENGTH=18

# 4. 冷库加密存储
DB_TYPE=sqlite
SQLITE_PATH=data/accounts.db
ENCRYPTION_KEY=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef

# 5. 浏览器运行模式
HEADLESS=false  # false: 弹出无痕 Chrome/Edge 窗口；true: 无头静默运行
# 可选：通常无需填写。程序会自动读取 .runtime/browser.path 并检测 Chrome/Edge
# CHROMIUM_PATH=C:\Program Files\Google\Chrome\Application\chrome.exe
```

程序不再依赖 `start.cmd` 传递浏览器路径。即使直接执行
`python -m src.main dashboard`，也会自动发现项目记录的浏览器或本机
Chrome/Edge。`GET /api/health` 会返回浏览器就绪状态；浏览器不可用时，
面板会拒绝提交清洗任务，并给出明确的修复提示。

浏览器始终使用无痕参数和独立的非持久化 Context，不会复用日常浏览器
Cookie、扩展或用户资料；任务结束后该临时会话会自动销毁。

---

## 🚀 3. CLI 快速运行指令

主入口为 `src/main.py`，提供了丰富的命令行工具：

### 🔹 (1) 单号清洗与验证 (`sanitize-single`) — 推荐测试使用
对单个账号执行完整 8 步切割与新凭证登录校验：

```bash
python src/main.py sanitize-single -g 账号邮箱@gmail.com -p 原始密码 -t 原始2FA密钥
```
> *注：若账号未开启 2FA，可省略 `-t` 参数。*

### 🔹 (2) 批量并发清洗 (`sanitize`)
导入凭证文本文件（格式如：`gmail----password----2fa_secret`，每行一个账号）：

```bash
python src/main.py sanitize -i accounts.txt -w 3
```
> `-w 3` 表示启动 3 个并发线程同时清洗。

### 🔹 (3) 查看账号冷库状态统计 (`status`)
随时查看数据库中各种状态账号数量：

```bash
python src/main.py status
```

### 🔹 (4) 导出已验证成功的干净账号 (`export`)
将所有状态为 `VERIFIED` 的清洗成功账号解密导出为 JSON 文件：

```bash
python src/main.py export -o clean_accounts.json
```

### 🔹 (5) 重试失败账号 (`retry-failed`)
一键重试死信队列中状态为 `FAILED` 的账号：

```bash
python src/main.py retry-failed
```

---

## 🔒 4. 核心 8 步全链路防盗切割原理

```text
Step 1: 账号预检 (Pre-Validation)        ── 过滤 Disabled/死号，节省代理资源
Step 2: 改辅助邮箱 (Recovery Email)       ── 替换为买家接码邮箱，掐断 Catch-All 找回
Step 3: 移除辅助手机号 (Recovery Phone)    ── 删卡网手机号，掐断短信找回
Step 4: 删除所有 Passkey                  ── 删除 WebAuthn/Passkey 硬件私钥后门
Step 5: 重置 2FA TOTP                    ── 重新提取 Base32 密钥并实时填码激活
Step 6: 改主密码 + 全设备强制下线          ── 提交新强密码，作废卡网所有旧 Session Cookie
Step 7: 撤销 OAuth 授权                    ── 清理第三方应用 API 授权后门
Step 8: 新凭证二次登录验证                ── 用新密码+新 2FA 重新登录验证，加密存库
```

---

## 📁 5. 项目目录结构

```text
gmail/
├── .env                          # 全局配置文件
├── requirements.txt              # 项目 Python 依赖清单
├── README.md                     # 使用指南
├── src/
│   ├── main.py                   # CLI 主入口
│   ├── config.py                 # 配置加载中心
│   ├── mail_worker/              # 邮件接码 Worker 模块
│   ├── sanitizer/
│   │   ├── drission_engine.py    # 8 步全链路 DrissionPage 引擎
│   │   └── selectors.json        # Google 页面选择器映射
│   ├── storage/
│   │   ├── db_manager.py         # AES-256 加密冷库存储
│   │   └── models.py             # 数据模型定义
│   └── monitor/
│       └── logger.py             # 日志与统计采集
├── data/                         # 冷库数据库目录 (加密)
└── logs/                         # 运行日志目录
```
