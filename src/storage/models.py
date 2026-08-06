# ============================================================
# models.py — 数据模型定义
# 使用 Pydantic v2 进行严格的字段类型验证
# ============================================================

from __future__ import annotations

import secrets
import string
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


# ── 账号状态枚举 ─────────────────────────────────────────────
class AccountStatus(str, Enum):
    """账号在整个生命周期中的状态"""
    PENDING      = "PENDING"        # 待清洗（刚从卡网拿到凭证）
    VALIDATING   = "VALIDATING"     # 预检中
    DEAD         = "DEAD"           # 死号（Disabled / 无法登录）
    SANITIZING   = "SANITIZING"     # 清洗中
    PARTIAL      = "PARTIAL"        # 部分完成（中途中断）
    VERIFIED     = "VERIFIED"       # 清洗 + 验证全部成功
    FAILED       = "FAILED"         # 清洗失败，进入死信队列
    EXPORTED     = "EXPORTED"       # 已导出


# ── 失败原因枚举 ─────────────────────────────────────────────
class FailReason(str, Enum):
    """清洗失败的分类原因"""
    CAPTCHA_BLOCKED   = "CAPTCHA_BLOCKED"   # Google 风控 / 打码失败
    ACCOUNT_DISABLED  = "ACCOUNT_DISABLED"  # 账号被封禁
    WRONG_PASSWORD    = "WRONG_PASSWORD"    # 旧密码不正确
    MISSING_2FA       = "MISSING_2FA"        # 账号要求 2FA，但输入未提供密钥
    WRONG_2FA         = "WRONG_2FA"         # 旧 2FA 密钥错误
    PROXY_ERROR       = "PROXY_ERROR"       # 代理 IP 连接失败
    BROWSER_ERROR     = "BROWSER_ERROR"     # 浏览器缺失、损坏或无法启动
    MAIL_TIMEOUT      = "MAIL_TIMEOUT"      # 接码超时
    STEP_TIMEOUT      = "STEP_TIMEOUT"      # 某步操作超时
    UNKNOWN           = "UNKNOWN"           # 未知错误


# ── 清洗步骤进度记录 ─────────────────────────────────────────
class StepProgress(BaseModel):
    """记录 8 步清洗链路中每步的完成状态（用于断点续跑）"""
    current_step:          int = Field(default=0, ge=0, le=8)
    current_step_name: Optional[str] = None
    updated_at: Optional[datetime] = None
    step1_validated:       bool = False  # 预检通过
    step2_email_changed:   bool = False  # 辅助邮箱已替换
    step3_phone_removed:   bool = False  # 辅助手机号已移除
    step4_passkeys_deleted:bool = False  # Passkey 已全部删除
    step5_2fa_reset:       bool = False  # 2FA 已重置
    step5_backup_codes:    bool = False  # 备用验证码已重新生成
    step6_password_changed:bool = False  # 主密码已修改
    step6_all_signed_out:  bool = False  # 所有设备已强制下线
    step7_oauth_revoked:   bool = False  # OAuth 授权已撤销
    step8_verified:        bool = False  # 新凭证登录验证成功

    @property
    def last_completed_step(self) -> int:
        """返回最后成功完成的步骤编号（用于断点续跑定位）"""
        if self.step8_verified:       return 8
        if self.step7_oauth_revoked:  return 7
        if self.step6_all_signed_out: return 6
        if self.step5_backup_codes:   return 5
        if self.step4_passkeys_deleted:return 4
        if self.step3_phone_removed:  return 3
        if self.step2_email_changed:  return 2
        if self.step1_validated:      return 1
        return 0


# ── 原始凭证（从卡网拿到的输入）────────────────────────────
class RawCredential(BaseModel):
    """从卡网采购到的原始账号凭证（清洗前）"""
    gmail:      str = Field(..., description="Google 账号邮箱")
    password:   str = Field(..., description="原始密码")
    totp_secret: Optional[str] = Field(None, description="原始 2FA Base32 密钥（如有）")
    old_recovery_email: Optional[str] = Field(None, description="原始辅助邮箱（用于登录安全验证，如有）")
    cookies:    Optional[str]  = Field(None, description="原始 Cookie 字符串（JSON 格式，如有）")
    source:     Optional[str]  = Field(None, description="来源卡网名称或批次标识")

    @field_validator("gmail")
    @classmethod
    def validate_gmail(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v:
            raise ValueError(f"无效的 Gmail 地址: {v}")
        return v

    @field_validator("totp_secret", mode="before")
    @classmethod
    def normalize_totp_secret(cls, v: object) -> Optional[str]:
        """Accept compact or whitespace-grouped 2FA secrets of any length."""
        if v is None:
            return None
        normalized = "".join(str(v).split())
        return normalized or None


# ── 清洗后干净资产（写入冷库的输出）────────────────────────
class CleanAccount(BaseModel):
    """清洗成功后的干净账号凭证（写入加密冷库）"""
    # 标识
    account_id:           str = Field(default_factory=lambda: secrets.token_hex(8).upper())
    gmail:                str

    # 清洗后新凭证
    new_password:         Optional[str]       = None
    buyer_recovery_email: Optional[str]       = None  # 买家自建接码邮箱
    new_totp_secret:      Optional[str]       = None  # 新 2FA Base32 密钥
    backup_codes:         Optional[List[str]] = None  # 新备用验证码列表
    new_cookies:          Optional[str]       = None  # 清洗后刷新的 Cookie

    # 运行元数据
    status:         AccountStatus = AccountStatus.PENDING
    fail_reason:    Optional[FailReason] = None
    fail_detail:    Optional[str]        = None
    step_progress:  StepProgress         = Field(default_factory=StepProgress)
    retry_count:    int                  = 0
    proxy_used:     Optional[str]        = None  # 实际使用的代理 IP

    # 时间戳
    created_at:    datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sanitized_at:  Optional[datetime] = None
    verified_at:   Optional[datetime] = None
    exported_at:   Optional[datetime] = None

    def begin_step(self, step: int, name: str) -> None:
        """Mark a step as active so the dashboard can display live progress."""
        self.status = AccountStatus.SANITIZING
        self.fail_reason = None
        self.fail_detail = None
        self.step_progress.current_step = step
        self.step_progress.current_step_name = name
        self.step_progress.updated_at = datetime.now(timezone.utc)

    def mark_step(self, field: str) -> None:
        """标记某个步骤完成"""
        setattr(self.step_progress, field, True)
        self.step_progress.updated_at = datetime.now(timezone.utc)

    def mark_failed(self, reason: FailReason, detail: str = "") -> None:
        """标记清洗失败"""
        self.status = AccountStatus.FAILED
        self.fail_reason = reason
        self.fail_detail = detail
        self.step_progress.updated_at = datetime.now(timezone.utc)

    def mark_sanitized(self) -> None:
        """标记清洗成功"""
        self.status = AccountStatus.VERIFIED
        self.sanitized_at = datetime.now(timezone.utc)
        self.step_progress.current_step = 8
        self.step_progress.current_step_name = "结果验证"
        self.step_progress.updated_at = self.sanitized_at

    def to_export_dict(self) -> dict:
        """导出为明文 dict（用于 JSON / CSV 导出，仅在有权限时调用）"""
        return {
            "account_id":           self.account_id,
            "gmail":                self.gmail,
            "new_password":         self.new_password,
            "buyer_recovery_email": self.buyer_recovery_email,
            "new_totp_secret":      self.new_totp_secret,
            "backup_codes":         ",".join(self.backup_codes) if self.backup_codes else "",
            "status":               self.status.value,
            "sanitized_at":         self.sanitized_at.isoformat() if self.sanitized_at else "",
        }


# ── 任务包装（供任务队列使用）──────────────────────────────
class SanitizeTask(BaseModel):
    """封装到任务队列中的工作单元"""
    task_id:    str = Field(default_factory=lambda: secrets.token_hex(6))
    credential: RawCredential
    account:    CleanAccount
    enqueued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_credential(cls, cred: RawCredential) -> "SanitizeTask":
        """从原始凭证创建任务"""
        account = CleanAccount(gmail=cred.gmail)
        return cls(credential=cred, account=account)
