# ============================================================
# dead_letter.py — 死信队列与失败重试管理器
# 管理所有清洗失败的账号，支持按原因分类查询和指数退避重试
# ============================================================

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List

from tenacity import retry, stop_after_attempt, wait_exponential, before_sleep_log
import logging

from src.config import config
from src.monitor.logger import get_logger
from src.storage.db_manager import DBManager
from src.storage.models import AccountStatus, CleanAccount, FailReason

log = get_logger("DLQ")

# 不可重试的失败原因（这些账号需要人工处理）
_NON_RETRYABLE = {
    FailReason.ACCOUNT_DISABLED,  # 死号，重试无意义
    FailReason.WRONG_PASSWORD,    # 密码错误，需人工确认
    FailReason.MISSING_2FA,       # 缺少旧 2FA，需补充凭证
    FailReason.WRONG_2FA,         # 2FA 错误，需人工确认
}


class DeadLetterQueue:
    """
    死信队列管理器：
    - 收集所有清洗失败的账号
    - 按失败原因过滤可重试 vs 不可重试
    - 提供带指数退避的自动重试
    - 提供人工介入队列查看
    """

    def __init__(self, db: DBManager):
        self._db = db

    # ── 查询 ────────────────────────────────────────────────

    async def get_all_failed(self) -> List[CleanAccount]:
        """获取所有失败的账号"""
        return await self._db.list_by_status(AccountStatus.FAILED)

    async def get_retryable(self) -> List[CleanAccount]:
        """获取可重试的失败账号（排除不可重试原因）"""
        all_failed = await self.get_all_failed()
        retryable = [
            acc for acc in all_failed
            if acc.fail_reason not in _NON_RETRYABLE
            and acc.retry_count < config.queue.MAX_RETRIES
        ]
        log.info(
            f"死信队列: 总计 {len(all_failed)} 个失败账号，"
            f"可重试 {len(retryable)} 个，"
            f"不可重试 {len(all_failed) - len(retryable)} 个"
        )
        return retryable

    async def get_manual_review(self) -> List[CleanAccount]:
        """获取需要人工介入的账号（不可重试 / 已超过最大重试次数）"""
        all_failed = await self.get_all_failed()
        return [
            acc for acc in all_failed
            if acc.fail_reason in _NON_RETRYABLE
            or acc.retry_count >= config.queue.MAX_RETRIES
        ]

    async def summary(self) -> dict:
        """返回死信队列分类统计"""
        all_failed = await self.get_all_failed()
        breakdown: dict = {}
        for acc in all_failed:
            reason = acc.fail_reason.value if acc.fail_reason else "UNKNOWN"
            breakdown[reason] = breakdown.get(reason, 0) + 1
        return {
            "total":   len(all_failed),
            "detail":  breakdown,
            "retryable": len(await self.get_retryable()),
            "manual":  len(await self.get_manual_review()),
        }

    # ── 重试 ────────────────────────────────────────────────

    async def retry_one(
        self,
        account: CleanAccount,
        engine,   # SanitizerEngine（避免循环导入，用 Any 类型）
    ) -> CleanAccount:
        """
        对单个失败账号执行带指数退避的重试。
        重试前递增 retry_count，超过上限则标记为不可重试。
        """
        if account.retry_count >= config.queue.MAX_RETRIES:
            log.warning(
                f"账号 {account.gmail} 已达最大重试次数 "
                f"({config.queue.MAX_RETRIES})，转入人工审核"
            )
            return account

        # 计算退避延迟：base * 2^(retry_count)
        delay = config.queue.RETRY_BASE_DELAY * (2 ** account.retry_count)
        log.info(
            f"重试 [{account.gmail}] "
            f"第 {account.retry_count + 1}/{config.queue.MAX_RETRIES} 次，"
            f"等待 {delay:.1f}s"
        )
        await asyncio.sleep(delay)

        account.retry_count += 1
        account.status = AccountStatus.SANITIZING
        account.fail_reason = None
        account.fail_detail = None
        await self._db.upsert(account)

        from src.storage.models import RawCredential, SanitizeTask
        # 注意：重试时原始密码可能已经改变（Step6 已改密）
        # 通过断点续跑机制跳过已完成的步骤
        cred = RawCredential(
            gmail    = account.gmail,
            password = account.new_password or "RETRY_PLACEHOLDER",
        )
        task = SanitizeTask(credential=cred, account=account)
        result = await engine.run(task)
        return result

    async def retry_all(self, engine) -> dict:
        """
        批量重试所有可重试的失败账号。
        返回统计结果 {'success': N, 'still_failed': N, 'skipped': N}
        """
        retryable = await self.get_retryable()
        if not retryable:
            log.info("没有可重试的账号")
            return {"success": 0, "still_failed": 0, "skipped": 0}

        results = {"success": 0, "still_failed": 0, "skipped": 0}

        # 并发重试，但限制并发数
        semaphore = asyncio.Semaphore(min(10, config.queue.MAX_WORKERS))

        async def _retry_with_sem(acc: CleanAccount) -> None:
            async with semaphore:
                result = await self.retry_one(acc, engine)
                if result.status == AccountStatus.VERIFIED:
                    results["success"] += 1
                elif result.retry_count >= config.queue.MAX_RETRIES:
                    results["skipped"] += 1
                else:
                    results["still_failed"] += 1

        await asyncio.gather(*[_retry_with_sem(acc) for acc in retryable])

        log.info(
            f"重试完成: 成功 {results['success']}，"
            f"仍失败 {results['still_failed']}，"
            f"已放弃 {results['skipped']}"
        )
        return results

    # ── 报告 ────────────────────────────────────────────────

    async def print_report(self) -> None:
        """打印死信队列详细报告"""
        summary = await self.summary()
        log.info("=" * 50)
        log.info(f"📋 死信队列报告")
        log.info(f"  总计失败: {summary['total']}")
        log.info(f"  可重试:   {summary['retryable']}")
        log.info(f"  需人工:   {summary['manual']}")
        log.info(f"  失败分类:")
        for reason, count in summary.get("detail", {}).items():
            log.info(f"    {reason}: {count}")
        log.info("=" * 50)
