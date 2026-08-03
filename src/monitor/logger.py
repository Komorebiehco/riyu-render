# ============================================================
# logger.py — 结构化日志 + 实时终端监控面板
# 基于 loguru + rich
# ============================================================

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

from loguru import logger
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.config import config

# ── 初始化 loguru ────────────────────────────────────────────

import os
os.makedirs(config.log.LOG_DIR, exist_ok=True)

# 移除默认 handler
logger.remove()

# 终端输出（彩色）
if config.log.CONSOLE_OUTPUT:
    logger.add(
        sys.stderr,
        level=config.log.LEVEL,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{extra[tag]}</cyan> | {message}",
        colorize=True,
    )

# 文件输出（按日期滚动，JSON 格式）
logger.add(
    os.path.join(config.log.LOG_DIR, "sanitizer_{time:YYYY-MM-DD}.log"),
    level="DEBUG",
    rotation="00:00",        # 每天午夜滚动
    retention="30 days",
    compression="zip",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {extra[tag]} | {message}",
    serialize=True,           # JSON 格式
)

def get_logger(tag: str):
    """返回带有 tag 标识的 logger 实例（用于区分不同 Worker）"""
    return logger.bind(tag=tag)


# ── 实时统计数据类 ───────────────────────────────────────────

@dataclass
class Stats:
    """全局实时统计（线程安全）"""
    total:      int = 0
    success:    int = 0
    failed:     int = 0
    dead:       int = 0     # 死号（预检不通过）
    in_queue:   int = 0
    processing: int = 0

    # 失败细分
    captcha_blocked: int = 0
    account_disabled: int = 0
    step_timeout:    int = 0
    proxy_error:     int = 0
    browser_error:   int = 0
    other_fail:      int = 0

    # 耗时统计
    total_elapsed_seconds: float = 0.0
    _lock: Lock = field(default_factory=Lock, compare=False, repr=False)

    def increment(self, field_name: str, delta: int = 1) -> None:
        with self._lock:
            current = getattr(self, field_name, 0)
            setattr(self, field_name, current + delta)

    @property
    def success_rate(self) -> float:
        done = self.success + self.failed + self.dead
        return (self.success / done * 100) if done > 0 else 0.0

    @property
    def avg_elapsed(self) -> float:
        return (self.total_elapsed_seconds / self.success) if self.success > 0 else 0.0


# ── 全局统计单例 ─────────────────────────────────────────────
_stats = Stats()

def get_stats() -> Stats:
    return _stats


# ── 实时监控面板（Rich Live）────────────────────────────────

class MonitorPanel:
    """在终端中渲染实时刷新的统计面板"""

    def __init__(self, refresh_interval: float = 1.0):
        self._console = Console()
        self._interval = refresh_interval
        self._start_time = time.time()
        self._live: Optional[Live] = None

    def _build_table(self) -> Panel:
        s = _stats
        elapsed = time.time() - self._start_time

        # 主统计行
        grid = Table.grid(expand=True)
        grid.add_column(style="bold cyan", justify="right")
        grid.add_column(justify="left")
        grid.add_column(style="bold cyan", justify="right")
        grid.add_column(justify="left")

        grid.add_row(
            "总任务:", f"[white]{s.total}[/]",
            "处理中:", f"[yellow]{s.processing}[/]",
        )
        grid.add_row(
            "✅ 成功:", f"[green]{s.success}[/]",
            "队列中:", f"[blue]{s.in_queue}[/]",
        )
        grid.add_row(
            "❌ 失败:", f"[red]{s.failed}[/]",
            "☠ 死号:", f"[dim]{s.dead}[/]",
        )
        grid.add_row(
            "成功率:", f"[{'green' if s.success_rate >= 90 else 'yellow'}]{s.success_rate:.1f}%[/]",
            "平均耗时:", f"[white]{s.avg_elapsed:.1f}s/号[/]",
        )
        grid.add_row(
            "总耗时:", f"[white]{elapsed/60:.1f}min[/]",
            "", "",
        )

        # 死信细分
        if s.failed > 0:
            fail_text = Text()
            fail_text.append("  死信分类 → ", style="dim")
            fail_text.append(f"打码:{s.captcha_blocked} ", style="red")
            fail_text.append(f"死号:{s.account_disabled} ", style="dim red")
            fail_text.append(f"超时:{s.step_timeout} ", style="yellow")
            fail_text.append(f"代理:{s.proxy_error} ", style="magenta")
            fail_text.append(f"浏览器:{s.browser_error} ", style="bright_red")
            fail_text.append(f"其他:{s.other_fail}", style="dim")
        else:
            fail_text = Text("  暂无失败记录", style="dim green")

        from rich.columns import Columns
        content = Columns([grid])

        return Panel(
            grid,
            title="[bold blue]🚀 账号清洗引擎 · 实时监控[/]",
            subtitle=fail_text,
            border_style="blue",
            padding=(0, 1),
        )

    def start(self) -> None:
        """启动实时刷新面板（阻塞，建议在单独线程运行）"""
        with Live(
            self._build_table(),
            console=self._console,
            refresh_per_second=int(1 / self._interval),
            screen=False,
        ) as live:
            self._live = live
            while True:
                live.update(self._build_table())
                time.sleep(self._interval)

    def print_final_report(self) -> None:
        """任务全部完成后打印最终报告"""
        s = _stats
        self._console.rule("[bold blue]清洗任务完成报告")
        self._console.print(f"  ✅ 清洗成功:  [green]{s.success}[/] 个账号")
        self._console.print(f"  ❌ 清洗失败:  [red]{s.failed}[/] 个账号")
        self._console.print(f"  ☠  死号过滤:  [dim]{s.dead}[/] 个账号")
        self._console.print(f"  📊 成功率:    [{'green' if s.success_rate>=90 else 'yellow'}]{s.success_rate:.1f}%[/]")
        self._console.print(f"  ⏱  平均耗时:  [white]{s.avg_elapsed:.1f}s / 号[/]")
        self._console.rule()
