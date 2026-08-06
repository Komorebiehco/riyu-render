"""TXT 导入解析与清洗结果导出工具。"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from src.storage.models import RawCredential


def parse_txt_content(content: str) -> tuple[list[RawCredential], list[str]]:
    """解析 `邮箱----密码----2FA` 或 `邮箱|密码|2FA` 行格式。"""
    credentials: list[RawCredential] = []
    invalid: list[str] = []

    for line_no, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "----" in line:
            separator = "----"
        elif "|" in line:
            separator = "|"
        else:
            invalid.append(f"第 {line_no} 行缺少 ---- 或 | 分隔符")
            continue

        parts = [part.strip() for part in line.split(separator)]
        if len(parts) < 2 or not parts[1]:
            invalid.append(f"第 {line_no} 行密码为空")
            continue

        gmail = parts[0].lower()
        password = parts[1]
        third = parts[2].strip() if len(parts) > 2 else ""
        fourth = parts[3].strip() if len(parts) > 3 else ""
        totp_secret = third or None
        old_recovery_email = None
        cookies = None
        if "@" in third:
            old_recovery_email = third
            totp_secret = fourth or None
            if fourth.startswith("[") or fourth.startswith("{"):
                cookies = fourth
                totp_secret = None
        elif fourth:
            if fourth.startswith("[") or fourth.startswith("{"):
                cookies = fourth
            elif "@" in fourth:
                old_recovery_email = fourth

        if "@" not in gmail or "." not in gmail.split("@", 1)[1]:
            invalid.append(f"第 {line_no} 行邮箱格式无效: {parts[0]}")
            continue

        credentials.append(
            RawCredential(
                gmail=gmail,
                password=password,
                totp_secret=totp_secret,
                old_recovery_email=old_recovery_email,
                cookies=cookies,
            )
        )

    return credentials, invalid


def write_txt_export(records: Iterable[dict[str, Any]], path: Path) -> int:
    """将清洗后的账号写入 `邮箱----新密码----新2FA` 格式的 TXT。"""
    lines = []
    for record in records:
        gmail = (record.get("gmail") or "").strip()
        password = record.get("new_password") or ""
        totp_secret = record.get("new_totp_secret") or ""
        lines.append(f"{gmail}----{password}----{totp_secret}")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(lines)
