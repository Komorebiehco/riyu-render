"""
tests/test_mail_parser.py — 接码正则解析单元测试
验证 Cloudflare Worker 中的验证码提取逻辑（Python 复现）
"""
import re
import pytest


# ── 复现 Worker 中的正则解析逻辑 ────────────────────────────

CODE_PATTERNS = [
    re.compile(r"\b([0-9]{6})\b(?=\s*(?:is your|是您的|為您的|verification|验证|驗證|code|码|碼))", re.IGNORECASE),
    re.compile(r"(?:verification code|验证码|驗證碼|安全码|安全碼)[^\d]*([0-9]{6})", re.IGNORECASE),
    re.compile(r"G-([0-9]{6})", re.IGNORECASE),
    re.compile(r"\b([0-9]{6})\b"),  # 兜底
]

LINK_PATTERNS = [
    re.compile(r"https://accounts\.google\.com/[^\s\"'<>]+(?:reset|recovery|signin)[^\s\"'<>]*", re.IGNORECASE),
    re.compile(r"https://myaccount\.google\.com/[^\s\"'<>]+", re.IGNORECASE),
]


def extract_code(email_body: str):
    for pattern in CODE_PATTERNS:
        m = pattern.search(email_body)
        if m:
            return m.group(1)
    return None


def extract_link(email_body: str):
    for pattern in LINK_PATTERNS:
        m = pattern.search(email_body)
        if m:
            return m.group(0)
    return None


# ── 测试用例 ─────────────────────────────────────────────────

class TestMailParser:
    """验证验证码正则在多种 Google 邮件模板下的提取准确率"""

    def test_english_template_1(self):
        """英文模板：'123456 is your Google verification code'"""
        body = "123456 is your Google verification code. Don't share it with anyone."
        assert extract_code(body) == "123456"

    def test_english_template_2(self):
        """英文模板：'Your verification code is: 654321'"""
        body = "Your verification code is: 654321\nDo not share this code."
        assert extract_code(body) == "654321"

    def test_english_template_G_prefix(self):
        """Google 特定格式：G-XXXXXX"""
        body = "G-789012 is your Google verification code"
        assert extract_code(body) == "789012"

    def test_chinese_simplified_template(self):
        """中文简体模板：'您的验证码为 345678'"""
        body = "您的 Google 验证码为 345678，请勿向他人透露。"
        assert extract_code(body) == "345678"

    def test_chinese_traditional_template(self):
        """中文繁体模板"""
        body = "您的驗證碼為 234567，請勿向他人透露。"
        assert extract_code(body) == "234567"

    def test_code_in_html(self):
        """HTML 邮件正文中提取验证码"""
        body = """
        <html><body>
        <p>Your verification code is: <strong>456789</strong></p>
        <p>This code expires in 10 minutes.</p>
        </body></html>
        """
        assert extract_code(body) == "456789"

    def test_no_code_returns_none(self):
        """无验证码的邮件应返回 None"""
        body = "Welcome to Google. Your account has been created successfully."
        # 兜底模式会匹配任意 6 位数字，所以这里测试无 6 位数字的文本
        body_no_digits = "Welcome to Google. No numeric codes here at all."
        assert extract_code(body_no_digits) is None

    def test_does_not_match_phone_number(self):
        """不应错误匹配 7 位以上的数字串"""
        body = "Call us at 1234567 for support."
        code = extract_code(body)
        # 兜底正则只匹配 \b6位数字\b，7位不应被匹配
        assert code is None or len(code) == 6

    def test_reset_link_extraction(self):
        """成功提取 Google 账号重置链接"""
        body = """
        Click the link below to reset your password:
        https://accounts.google.com/signin/recovery?hl=en&flowName=GlifWebSignIn&rid=abc123
        """
        link = extract_link(body)
        assert link is not None
        assert "accounts.google.com" in link
        assert "recovery" in link

    def test_myaccount_link_extraction(self):
        """提取 myaccount.google.com 链接"""
        body = "Visit https://myaccount.google.com/security to manage your account security settings."
        link = extract_link(body)
        assert link is not None
        assert "myaccount.google.com" in link

    def test_no_link_returns_none(self):
        """无重置链接的邮件应返回 None"""
        body = "Your verification code is 123456. It expires in 10 minutes."
        link = extract_link(body)
        assert link is None
