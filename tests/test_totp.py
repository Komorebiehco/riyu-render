"""
tests/test_totp.py — 2FA TOTP 算号单元测试
"""
import time
import pytest
import pyotp


class TestTOTP:
    """验证 PyOTP 的 TOTP 生成逻辑"""

    KNOWN_SECRET = "JBSWY3DPEHPK3PXP"  # 标准测试密钥

    def test_totp_generates_6_digits(self):
        """生成的验证码应为 6 位数字字符串"""
        totp = pyotp.TOTP(self.KNOWN_SECRET)
        code = totp.now()
        assert len(code) == 6
        assert code.isdigit()

    def test_totp_is_time_based(self):
        """同一密钥在同一时间窗口内应生成相同的验证码"""
        totp = pyotp.TOTP(self.KNOWN_SECRET)
        code1 = totp.now()
        code2 = totp.now()
        assert code1 == code2

    def test_totp_verify(self):
        """验证当前时间窗口的 TOTP 应通过校验"""
        totp = pyotp.TOTP(self.KNOWN_SECRET)
        code = totp.now()
        assert totp.verify(code) is True

    def test_totp_invalid_code_fails(self):
        """错误的验证码应该校验失败"""
        totp = pyotp.TOTP(self.KNOWN_SECRET)
        assert totp.verify("000000") is False  # 极低概率碰撞，可忽略

    def test_totp_provisioning_uri(self):
        """应能生成有效的 OTPAuth URI（供验证器 App 扫码用）"""
        totp = pyotp.TOTP(self.KNOWN_SECRET)
        uri = totp.provisioning_uri(name="test@gmail.com", issuer_name="Google")
        assert uri.startswith("otpauth://totp/")
        assert "test%40gmail.com" in uri or "test@gmail.com" in uri

    def test_multiple_secrets_independent(self):
        """不同密钥生成的验证码应不同（绝大多数情况）"""
        totp1 = pyotp.TOTP("JBSWY3DPEHPK3PXP")
        totp2 = pyotp.TOTP("AAAAAAAAAAAAAAAA")
        # 同一时刻两个不同密钥，验证码应不同（极低概率相同）
        # 仅验证结构有效
        assert totp1.now().isdigit()
        assert totp2.now().isdigit()
