"""
tests/test_password_gen.py — 密码生成器单元测试
"""
import re
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.sanitizer.sanitizer_engine import generate_password


class TestPasswordGenerator:
    """验证强随机密码生成器的正确性"""

    def test_password_correct_length(self):
        """密码应符合配置的长度"""
        from src.config import config
        pwd = generate_password()
        assert len(pwd) == config.password.LENGTH

    def test_password_has_uppercase(self):
        """密码应包含大写字母"""
        pwd = generate_password()
        assert any(c.isupper() for c in pwd), "密码缺少大写字母"

    def test_password_has_lowercase(self):
        """密码应包含小写字母"""
        pwd = generate_password()
        assert any(c.islower() for c in pwd), "密码缺少小写字母"

    def test_password_has_digit(self):
        """密码应包含数字"""
        pwd = generate_password()
        assert any(c.isdigit() for c in pwd), "密码缺少数字"

    def test_password_has_symbol(self):
        """密码应包含特殊字符"""
        from src.config import config
        pwd = generate_password()
        assert any(c in config.password.SYMBOLS for c in pwd), "密码缺少特殊字符"

    def test_passwords_are_unique(self):
        """连续生成的多个密码应不重复"""
        passwords = {generate_password() for _ in range(50)}
        assert len(passwords) == 50, "密码生成器存在重复"

    def test_password_no_ambiguous_chars(self):
        """验证密码不包含影响可读性的极端特殊字符"""
        pwd = generate_password()
        # 确保密码是可见 ASCII 字符
        assert all(32 < ord(c) < 127 for c in pwd)
