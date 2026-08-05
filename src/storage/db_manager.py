# ============================================================
# db_manager.py — 加密冷库存储管理器
# 支持 SQLite（开发）/ PostgreSQL（生产）
# 敏感字段全部 AES-256-GCM 加密存储
# ============================================================

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import List, Optional

import aiosqlite
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.config import config
from src.storage.models import AccountStatus, CleanAccount, FailReason, StepProgress


# ── AES-256-GCM 加密工具 ────────────────────────────────────

class _Cipher:
    """轻量 AES-256-GCM 对称加密工具（内部使用）"""

    def __init__(self, hex_key: str):
        raw = bytes.fromhex(hex_key)
        if len(raw) != 32:
            raise ValueError("ENCRYPTION_KEY 必须为 64 位十六进制字符串（32 字节）")
        self._aesgcm = AESGCM(raw)

    def encrypt(self, plaintext: str) -> str:
        """加密明文字符串，返回 hex(nonce + ciphertext)"""
        if not plaintext:
            return ""
        nonce = os.urandom(12)  # 96-bit nonce
        ct = self._aesgcm.encrypt(nonce, plaintext.encode(), None)
        return (nonce + ct).hex()

    def decrypt(self, token: str) -> str:
        """解密 hex 令牌，返回明文字符串"""
        if not token:
            return ""
        raw = bytes.fromhex(token)
        nonce, ct = raw[:12], raw[12:]
        return self._aesgcm.decrypt(nonce, ct, None).decode()


# ── 全局 Cipher 实例 ────────────────────────────────────────
_cipher = _Cipher(config.db.ENCRYPTION_KEY)


# ── 建表 SQL ─────────────────────────────────────────────────
_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id            TEXT PRIMARY KEY,
    gmail                 TEXT NOT NULL UNIQUE,

    -- 清洗后新凭证（AES-256-GCM 加密存储）
    new_password_enc      TEXT,
    buyer_recovery_email  TEXT,
    new_totp_secret_enc   TEXT,
    backup_codes_enc      TEXT,
    new_cookies_enc       TEXT,

    -- 状态
    status                TEXT NOT NULL DEFAULT 'PENDING',
    fail_reason           TEXT,
    fail_detail           TEXT,
    retry_count           INTEGER NOT NULL DEFAULT 0,
    proxy_used            TEXT,

    -- 8步进度（JSON 存储）
    step_progress         TEXT NOT NULL DEFAULT '{}',

    -- 时间戳
    created_at            TEXT NOT NULL,
    sanitized_at          TEXT,
    verified_at           TEXT,
    exported_at           TEXT
);

CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_accounts_gmail  ON accounts(gmail);
"""


# ── DBManager ────────────────────────────────────────────────

class DBManager:
    """异步 SQLite 数据库管理器（生产环境可替换为 asyncpg/PostgreSQL）"""

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path or config.db.SQLITE_PATH
        # 确保数据目录存在
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)

    async def init(self) -> None:
        """初始化数据库，建表（幂等）"""
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(_CREATE_TABLE_SQL)
            await db.commit()

    # ── 写入 ────────────────────────────────────────────────

    async def upsert(self, account: CleanAccount) -> None:
        """创建或更新一条账号记录"""
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("""
                INSERT INTO accounts (
                    account_id, gmail,
                    new_password_enc, buyer_recovery_email,
                    new_totp_secret_enc, backup_codes_enc, new_cookies_enc,
                    status, fail_reason, fail_detail,
                    retry_count, proxy_used, step_progress,
                    created_at, sanitized_at, verified_at, exported_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(gmail) DO UPDATE SET
                    account_id            = excluded.account_id,
                    new_password_enc      = excluded.new_password_enc,
                    buyer_recovery_email  = excluded.buyer_recovery_email,
                    new_totp_secret_enc   = excluded.new_totp_secret_enc,
                    backup_codes_enc      = excluded.backup_codes_enc,
                    new_cookies_enc       = excluded.new_cookies_enc,
                    status                = excluded.status,
                    fail_reason           = excluded.fail_reason,
                    fail_detail           = excluded.fail_detail,
                    retry_count           = excluded.retry_count,
                    proxy_used            = excluded.proxy_used,
                    step_progress         = excluded.step_progress,
                    created_at            = excluded.created_at,
                    sanitized_at          = excluded.sanitized_at,
                    verified_at           = excluded.verified_at,
                    exported_at           = excluded.exported_at
            """, (
                account.account_id,
                account.gmail,
                _cipher.encrypt(account.new_password or ""),
                account.buyer_recovery_email,
                _cipher.encrypt(account.new_totp_secret or ""),
                _cipher.encrypt(json.dumps(account.backup_codes or [])),
                _cipher.encrypt(account.new_cookies or ""),
                account.status.value,
                account.fail_reason.value if account.fail_reason else None,
                account.fail_detail,
                account.retry_count,
                account.proxy_used,
                account.step_progress.model_dump_json(),
                account.created_at.isoformat(),
                account.sanitized_at.isoformat() if account.sanitized_at else None,
                account.verified_at.isoformat()  if account.verified_at  else None,
                account.exported_at.isoformat()  if account.exported_at  else None,
            ))
            await db.commit()

    # ── 查询 ────────────────────────────────────────────────

    async def upsert_many(self, accounts: List[CleanAccount]) -> None:
        """Persist a batch of accounts in one transaction."""
        if not accounts:
            return
        values = []
        for account in accounts:
            values.append((
                account.account_id,
                account.gmail,
                _cipher.encrypt(account.new_password or ""),
                account.buyer_recovery_email,
                _cipher.encrypt(account.new_totp_secret or ""),
                _cipher.encrypt(json.dumps(account.backup_codes or [])),
                _cipher.encrypt(account.new_cookies or ""),
                account.status.value,
                account.fail_reason.value if account.fail_reason else None,
                account.fail_detail,
                account.retry_count,
                account.proxy_used,
                account.step_progress.model_dump_json(),
                account.created_at.isoformat(),
                account.sanitized_at.isoformat() if account.sanitized_at else None,
                account.verified_at.isoformat() if account.verified_at else None,
                account.exported_at.isoformat() if account.exported_at else None,
            ))
        async with aiosqlite.connect(self._db_path) as db:
            await db.executemany("""
                INSERT INTO accounts (
                    account_id, gmail,
                    new_password_enc, buyer_recovery_email,
                    new_totp_secret_enc, backup_codes_enc, new_cookies_enc,
                    status, fail_reason, fail_detail,
                    retry_count, proxy_used, step_progress,
                    created_at, sanitized_at, verified_at, exported_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(gmail) DO UPDATE SET
                    account_id            = excluded.account_id,
                    new_password_enc      = excluded.new_password_enc,
                    buyer_recovery_email  = excluded.buyer_recovery_email,
                    new_totp_secret_enc   = excluded.new_totp_secret_enc,
                    backup_codes_enc      = excluded.backup_codes_enc,
                    new_cookies_enc       = excluded.new_cookies_enc,
                    status                = excluded.status,
                    fail_reason           = excluded.fail_reason,
                    fail_detail           = excluded.fail_detail,
                    retry_count           = excluded.retry_count,
                    proxy_used            = excluded.proxy_used,
                    step_progress         = excluded.step_progress,
                    created_at            = excluded.created_at,
                    sanitized_at          = excluded.sanitized_at,
                    verified_at           = excluded.verified_at,
                    exported_at           = excluded.exported_at
            """, values)
            await db.commit()

    async def get_by_gmail(self, gmail: str) -> Optional[CleanAccount]:
        """根据 Gmail 查询一条记录"""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM accounts WHERE gmail = ?", (gmail,)
            ) as cursor:
                row = await cursor.fetchone()
        return _row_to_account(row) if row else None

    async def list_by_status(self, status: AccountStatus) -> List[CleanAccount]:
        """根据状态批量查询账号"""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM accounts WHERE status = ? ORDER BY created_at DESC",
                (status.value,)
            ) as cursor:
                rows = await cursor.fetchall()
        return [_row_to_account(r) for r in rows]

    async def count_by_status(self) -> dict:
        """返回各状态的账号数量统计"""
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT status, COUNT(*) as cnt FROM accounts GROUP BY status"
            ) as cursor:
                rows = await cursor.fetchall()
        return {row[0]: row[1] for row in rows}

    # ── 导出 ────────────────────────────────────────────────

    async def export_verified(self) -> List[dict]:
        """导出所有验证成功的账号（解密后明文）"""
        accounts = await self.list_by_status(AccountStatus.VERIFIED)
        result = []
        for acc in accounts:
            d = acc.to_export_dict()
            result.append(d)

            # 标记为已导出
            acc.exported_at = datetime.now(timezone.utc)
            acc.status = AccountStatus.EXPORTED
            await self.upsert(acc)
        return result


# ── 内部：Row → CleanAccount ────────────────────────────────

def _row_to_account(row: aiosqlite.Row) -> CleanAccount:
    """将数据库行反序列化为 CleanAccount 对象（自动解密敏感字段）"""
    step_data = json.loads(row["step_progress"] or "{}")

    return CleanAccount(
        account_id           = row["account_id"],
        gmail                = row["gmail"],
        new_password         = _cipher.decrypt(row["new_password_enc"] or "") or None,
        buyer_recovery_email = row["buyer_recovery_email"],
        new_totp_secret      = _cipher.decrypt(row["new_totp_secret_enc"] or "") or None,
        backup_codes         = json.loads(
                                   _cipher.decrypt(row["backup_codes_enc"] or "") or "[]"
                               ) or None,
        new_cookies          = _cipher.decrypt(row["new_cookies_enc"] or "") or None,
        status               = AccountStatus(row["status"]),
        fail_reason          = FailReason(row["fail_reason"]) if row["fail_reason"] else None,
        fail_detail          = row["fail_detail"],
        retry_count          = row["retry_count"],
        proxy_used           = row["proxy_used"],
        step_progress        = StepProgress(**step_data),
        created_at           = datetime.fromisoformat(row["created_at"]),
        sanitized_at         = datetime.fromisoformat(row["sanitized_at"]) if row["sanitized_at"] else None,
        verified_at          = datetime.fromisoformat(row["verified_at"])  if row["verified_at"]  else None,
        exported_at          = datetime.fromisoformat(row["exported_at"])  if row["exported_at"]  else None,
    )


# ── 全局单例（懒初始化）────────────────────────────────────
_db: Optional[DBManager] = None

def get_db() -> DBManager:
    global _db
    if _db is None:
        _db = DBManager()
    return _db
