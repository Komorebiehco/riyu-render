# ============================================================
# task_queue.py — 异步任务队列与调度器
# 基于 asyncio.Queue，支持高并发 Worker + 超时保护
# ============================================================

from __future__ import annotations

import asyncio
import time
from typing import List

from src.config import config
from src.monitor.logger import get_logger, get_stats
from src.sanitizer.drission_engine import DrissionEngine
from src.storage.db_manager import get_db
from src.storage.models import AccountStatus, FailReason, SanitizeTask

log = get_logger("QUEUE")


class TaskQueue:
    """
    异步并发任务调度器。
    - 使用 asyncio.Queue 作为任务缓冲区
    - 固定数量的 Worker 协程从队列中消费任务
    - 每个任务有全局超时保护
    """

    def __init__(self, max_workers: int = None):
        self._max_workers = max_workers or config.queue.MAX_WORKERS
        self._queue: asyncio.Queue[SanitizeTask] = asyncio.Queue()
        self._db = get_db()

    async def run(self, tasks: List[SanitizeTask]) -> None:
        """
        将所有任务放入队列并启动并发 Worker 处理。
        直到所有任务完成才返回。
        """
        # 初始化数据库
        await self._db.init()

        # 将任务全部入队
        for task in tasks:
            await self._queue.put(task)

        log.info(f"任务队列就绪: {len(tasks)} 个任务，{self._max_workers} 个 Worker")

        # 启动 Worker 协程池
        workers = [
            asyncio.create_task(self._worker(worker_id=i))
            for i in range(self._max_workers)
        ]

        # 等待队列被完全消费
        await self._queue.join()

        # 停止所有 Worker
        for _ in workers:
            await self._queue.put(None)  # 发送停止信号

        await asyncio.gather(*workers, return_exceptions=True)
        log.info("所有任务已完成")

    async def _worker(self, worker_id: int) -> None:
        """Worker 协程：持续从队列取任务并执行"""
        engine = DrissionEngine(db=self._db)
        log.debug(f"Worker-{worker_id} 启动")

        while True:
            task = await self._queue.get()

            # None 是停止信号
            if task is None:
                self._queue.task_done()
                break

            # 更新统计
            get_stats().increment("processing")
            get_stats().increment("in_queue", -1)

            log.info(f"[W{worker_id}] 开始: {task.credential.gmail}")
            start = time.time()

            try:
                # 全局超时保护
                account = await asyncio.wait_for(
                    asyncio.to_thread(engine.run_sync, task),
                    timeout=config.queue.TASK_TOTAL_TIMEOUT,
                )
                # Persist every terminal result, including failures. The engine
                # checkpoints progress, but a worker exception can skip its final save.
                await self._db.upsert(account)

                elapsed = time.time() - start

                if account.status == AccountStatus.VERIFIED:
                    log.info(f"[W{worker_id}] ✅ {task.credential.gmail} 耗时 {elapsed:.1f}s")
                elif account.status == AccountStatus.DEAD:
                    get_stats().increment("dead")
                    log.warning(f"[W{worker_id}] ☠ 死号: {task.credential.gmail}")
                else:
                    get_stats().increment("failed")
                    _update_fail_stats(account.fail_reason)
                    log.error(
                        f"[W{worker_id}] ❌ {task.credential.gmail} "
                        f"失败原因: {account.fail_reason}"
                    )

            except asyncio.TimeoutError:
                elapsed = time.time() - start
                log.error(
                    f"[W{worker_id}] ⏱ 超时 {elapsed:.1f}s: {task.credential.gmail}"
                )
                task.account.mark_failed(
                    FailReason.STEP_TIMEOUT,
                    f"总超时 {config.queue.TASK_TOTAL_TIMEOUT}s"
                )
                get_stats().increment("failed")
                get_stats().increment("step_timeout")
                await self._db.upsert(task.account)

            except Exception as e:
                log.exception(f"[W{worker_id}] 未处理异常: {e}")
                task.account.mark_failed(FailReason.UNKNOWN, str(e))
                try:
                    await self._db.upsert(task.account)
                except Exception:
                    log.exception(f"[W{worker_id}] 失败任务持久化异常: {task.credential.gmail}")
                get_stats().increment("failed")
                get_stats().increment("other_fail")

            finally:
                get_stats().increment("processing", -1)
                self._queue.task_done()

        log.debug(f"Worker-{worker_id} 退出")


def _update_fail_stats(fail_reason: FailReason) -> None:
    """根据失败原因更新死信细分统计"""
    s = get_stats()
    if fail_reason == FailReason.CAPTCHA_BLOCKED:
        s.increment("captcha_blocked")
    elif fail_reason == FailReason.ACCOUNT_DISABLED:
        s.increment("account_disabled")
    elif fail_reason == FailReason.STEP_TIMEOUT:
        s.increment("step_timeout")
    elif fail_reason == FailReason.PROXY_ERROR:
        s.increment("proxy_error")
    elif fail_reason == FailReason.BROWSER_ERROR:
        s.increment("browser_error")
    else:
        s.increment("other_fail")
