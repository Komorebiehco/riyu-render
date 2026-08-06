# ============================================================
# main.py — CLI 主入口
# 提供 sanitize / sanitize-single / status / retry-failed / export 子命令
# ============================================================

from __future__ import annotations

import asyncio
import csv
import json
import os
import sys

import click
from rich.console import Console
from rich.table import Table

# 将项目根目录加入 sys.path（方便直接 python src/main.py 运行）
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import __version__
from src.config import config
from src.storage.db_manager import get_db
from src.storage.models import AccountStatus, RawCredential, SanitizeTask
from src.monitor.logger import get_logger, get_stats, MonitorPanel

# Windows 终端 UTF-8 兼容性设置
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console()
log = get_logger("CLI")


# ══════════════════════════════════════════════════════════════
# 辅助函数
# ══════════════════════════════════════════════════════════════

def _load_credentials_from_file(filepath: str) -> list[RawCredential]:
    """
    从 CSV / TXT / JSON 文件加载原始凭证。

    支持的格式：
      CSV  : gmail,password,totp_secret (表头可选)
      JSON : [{"gmail":"...","password":"...","totp_secret":"..."}, ...]
      TXT  : gmail----password----totp_secret  (四横线分隔)
    """
    ext = os.path.splitext(filepath)[1].lower()
    credentials = []

    if ext == ".json":
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        for item in data:
            credentials.append(RawCredential(**item))

    elif ext == ".csv":
        with open(filepath, encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            # 兼容无表头的 CSV（尝试手动赋列名）
            if reader.fieldnames and "gmail" not in reader.fieldnames:
                f.seek(0)
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2:
                        credentials.append(RawCredential(
                            gmail=row[0].strip(),
                            password=row[1].strip(),
                            totp_secret=row[2].strip() if len(row) > 2 else None,
                            old_recovery_email=row[3].strip() if len(row) > 3 and "@" in row[3] else None,
                        ))
            else:
                for row in reader:
                    credentials.append(RawCredential(
                        gmail=row.get("gmail", "").strip(),
                        password=row.get("password", "").strip(),
                        totp_secret=row.get("totp_secret", "").strip() or None,
                        old_recovery_email=row.get("old_recovery_email", "").strip() or None,
                        cookies=row.get("cookies", "").strip() or None,
                        source=row.get("source", "").strip() or None,
                    ))

    elif ext == ".txt":
        with open(filepath, encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                # 优先按 '----' 分隔，其次自动检测 ':' 或 '|'
                if "----" in line:
                    parts = [p.strip() for p in line.split("----")]
                elif "|" in line:
                    parts = [p.strip() for p in line.split("|")]
                elif ":" in line and "@" in line:
                    parts = [p.strip() for p in line.split(":")]
                else:
                    parts = [p.strip() for p in line.split()]

                if len(parts) >= 2:
                    gmail = parts[0]
                    password = parts[1]
                    totp_secret = parts[2] if len(parts) > 2 and parts[2] else None
                    
                    # 如果有第 4 段，判断是 Cookie 还是旧辅助邮箱
                    cookies = None
                    old_recovery_email = None
                    if len(parts) > 3 and parts[3]:
                        p3 = parts[3]
                        if p3.startswith("[") or p3.startswith("{"):
                            cookies = p3
                        elif "@" in p3:
                            old_recovery_email = p3
                    
                    credentials.append(RawCredential(
                        gmail=gmail,
                        password=password,
                        totp_secret=totp_secret,
                        old_recovery_email=old_recovery_email,
                        cookies=cookies,
                    ))
    else:
        raise ValueError(f"不支持的文件格式: {ext}，请使用 .csv / .json / .txt")

    return credentials


# ══════════════════════════════════════════════════════════════
# CLI 命令组
# ══════════════════════════════════════════════════════════════

@click.group()
@click.version_option(__version__, prog_name="Google 账号极速换绑防盗系统")
def cli():
    """
    \b
    ╔══════════════════════════════════════════╗
    ║  🚀 Google 账号极速换绑与防盗系统 v1.1  ║
    ╚══════════════════════════════════════════╝
    大体量买家专用 | 8步全链路切割 | 防卡网盗回
    """
    pass


# ── 只读可视化控制台 ─────────────────────────────────────────
@cli.command("dashboard")
@click.option("--host", default=lambda: os.getenv("HOST", "0.0.0.0"), show_default=True, help="监听地址")
@click.option("--port", default=lambda: int(os.getenv("PORT", "8766")), show_default=True, type=click.IntRange(1, 65535), help="监听端口")
def cmd_dashboard(host: str, port: int):
    """启动只读 API 与可视化控制台（不提供账号操作接口）"""
    from src.dashboard.server import run

    console.print(f"[green]RIYU 只读控制台已启动: http://{host}:{port}[/]")
    if config.browser.executable_available():
        console.print(f"[dim]浏览器已就绪: {config.browser.CHROMIUM_PATH}[/]")
    else:
        console.print("[yellow]警告：未找到可用的 Chrome/Edge，清洗任务将被拒绝。[/]")
    console.print("[dim]API 仅返回脱敏运行元数据，不返回凭证或恢复信息。[/]")
    run(host=host, port=port)


# ── 批量清洗 ────────────────────────────────────────────────
@cli.command("sanitize")
@click.option(
    "--input", "-i", "input_file",
    required=True,
    type=click.Path(exists=True),
    help="账号凭证文件路径（支持 .csv / .json / .txt）",
)
@click.option(
    "--workers", "-w",
    default=config.queue.MAX_WORKERS,
    show_default=True,
    help="并发 Worker 数量",
)
@click.option(
    "--no-monitor",
    is_flag=True,
    default=False,
    help="禁用实时监控面板（适合日志重定向场景）",
)
def cmd_sanitize(input_file: str, workers: int, no_monitor: bool):
    """批量导入账号凭证并启动并发清洗任务"""
    console.rule("[bold blue]📥 加载凭证文件")

    try:
        credentials = _load_credentials_from_file(input_file)
    except Exception as e:
        console.print(f"[red]❌ 加载失败: {e}[/]")
        sys.exit(1)

    console.print(f"[green]✅ 成功加载 {len(credentials)} 个账号凭证[/]")
    console.print(f"[blue]⚙️  并发 Worker 数: {workers}[/]")

    # 延迟导入，避免在没有安装 playwright 时 CLI 启动报错
    from src.queues.task_queue import TaskQueue

    async def _run():
        db = get_db()
        await db.init()

        queue = TaskQueue(max_workers=workers)
        tasks = [SanitizeTask.from_credential(c) for c in credentials]

        get_stats().total = len(tasks)
        get_stats().in_queue = len(tasks)

        if not no_monitor:
            import threading
            panel = MonitorPanel()
            t = threading.Thread(target=panel.start, daemon=True)
            t.start()

        await queue.run(tasks)

        if not no_monitor:
            panel.print_final_report()

    asyncio.run(_run())


# ── 单号测试 ─────────────────────────────────────────────────
@cli.command("sanitize-single")
@click.option("--gmail",   "-g", required=True, help="Gmail 账号")
@click.option("--password","-p", required=True, help="当前密码")
@click.option("--2fa",     "-t", "totp_secret", default="", help="当前 2FA Base32 密钥（如有）")
@click.option("--cookies", "-c", default="", help="Cookie JSON 字符串（如有）")
def cmd_sanitize_single(gmail: str, password: str, totp_secret: str, cookies: str):
    """对单个账号执行完整 8 步清洗（DrissionPage 真实 Chrome 引擎）"""
    from src.sanitizer.drission_engine import DrissionEngine

    cred = RawCredential(
        gmail=gmail,
        password=password,
        totp_secret=totp_secret or None,
        cookies=cookies or None,
    )
    task = SanitizeTask.from_credential(cred)

    console.rule(f"[bold blue]🔧 单号清洗: {gmail}")

    async def _init_db():
        db = get_db()
        await db.init()
        return db

    db = asyncio.run(_init_db())
    engine = DrissionEngine(db=db)
    result = engine.run_sync(task)

    if result.status == AccountStatus.VERIFIED:
        console.print(f"[green]✅ 清洗成功！全链路防盗防盗回完全切割完成！[/]")
    elif result.status == AccountStatus.DEAD:
        console.print(f"[yellow]☠ 死号：账号不存在或已封禁[/]")
    else:
        console.print(f"[red]❌ 清洗未能完全通关: {result.fail_reason} — {result.fail_detail}[/]")

    console.rule("[bold cyan]🔑 账号最新切割凭证汇总面板")
    console.print(f"  账号 Gmail:  [bold white]{gmail}[/]")
    console.print(f"  新修改密码:  [bold green]{result.new_password or '未修改 (保持原密码)'}[/]")
    console.print(f"  新辅助邮箱:  [bold green]{result.buyer_recovery_email or '未修改'}[/]")
    console.print(f"  新 2FA 密钥:  [bold green]{result.new_totp_secret or '未重置 (保持原 2FA Key)'}[/]")
    console.rule()


# ── 状态查看 ─────────────────────────────────────────────────
@cli.command("status")
def cmd_status():
    """查看当前数据库中各状态的账号统计"""
    async def _run():
        db = get_db()
        await db.init()
        counts = await db.count_by_status()

        table = Table(title="📊 账号状态统计", show_header=True, header_style="bold blue")
        table.add_column("状态", style="cyan")
        table.add_column("数量", justify="right", style="green")

        total = sum(counts.values())
        for status, count in sorted(counts.items()):
            table.add_row(status, str(count))
        table.add_row("[bold]合计[/]", f"[bold]{total}[/]")

        console.print(table)

    asyncio.run(_run())


# ── 重试死信队列 ─────────────────────────────────────────────
@cli.command("retry-failed")
@click.option("--workers", "-w", default=10, show_default=True, help="并发 Worker 数量")
def cmd_retry_failed(workers: int):
    """重试死信队列中所有状态为 FAILED 的账号"""
    from src.queues.task_queue import TaskQueue
    from src.queues.dead_letter import DeadLetterQueue

    async def _run():
        db = get_db()
        await db.init()
        dlq = DeadLetterQueue(db=db)
        failed_accounts = await dlq.get_retryable()

        if not failed_accounts:
            console.print("[yellow]⚠️  死信队列为空，没有需要重试的账号[/]")
            return

        console.print(f"[blue]🔄 准备重试 {len(failed_accounts)} 个失败账号[/]")
        tasks = [SanitizeTask.from_credential(
            RawCredential(gmail=acc.gmail, password="__RETRY__")  # 从 DB 读取旧凭证
        ) for acc in failed_accounts]

        queue = TaskQueue(max_workers=workers)
        await queue.run(tasks)

    asyncio.run(_run())


# ── 导出干净资产 ─────────────────────────────────────────────
@cli.command("export")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["json", "csv"]),
              default="json", show_default=True,
              help="导出格式")
@click.option("--output", "-o", default="clean_accounts.json", show_default=True,
              help="输出文件路径")
def cmd_export(fmt: str, output: str):
    """导出所有清洗成功（VERIFIED）的账号凭证"""
    async def _run():
        db = get_db()
        await db.init()
        records = await db.export_verified()

        if not records:
            console.print("[yellow]⚠️  暂无已验证的账号可导出[/]")
            return

        if fmt == "json":
            with open(output, "w", encoding="utf-8") as f:
                json.dump(records, f, ensure_ascii=False, indent=2)
        elif fmt == "csv":
            if records:
                with open(output, "w", encoding="utf-8", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=records[0].keys())
                    writer.writeheader()
                    writer.writerows(records)

        console.print(f"[green]✅ 已导出 {len(records)} 个账号 → {output}[/]")

    asyncio.run(_run())


# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    cli()
