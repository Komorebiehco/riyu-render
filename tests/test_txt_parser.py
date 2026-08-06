"""
tests/test_txt_parser.py — TXT 凭证文件解析测试
"""
import tempfile
import os
import pytest
from src.dashboard.txt_io import parse_txt_content
from src.main import _load_credentials_from_file
from src.storage.models import RawCredential


class TestTxtParser:

    @pytest.mark.parametrize(
        ("raw_secret", "expected"),
        [
            ("avcdefg", "avcdefg"),
            ("abcd abcd abcd", "abcdabcdabcd"),
            ("a", "a"),
            ("ab cd\tef\ngh", "abcdefgh"),
        ],
    )
    def test_totp_secret_accepts_compact_or_grouped_any_length(self, raw_secret, expected):
        cred = RawCredential(
            gmail="user@example.com",
            password="password",
            totp_secret=raw_secret,
        )

        assert cred.totp_secret == expected

    def test_gui_txt_parser_normalizes_grouped_totp_secret(self):
        credentials, invalid = parse_txt_content(
            "user@example.com----password----abcd abcd abcd\n"
        )

        assert invalid == []
        assert len(credentials) == 1
        assert credentials[0].totp_secret == "abcdabcdabcd"

    def test_parsers_preserve_old_recovery_email_in_fourth_field(self):
        content = "user@example.com----password----SECRET----old@example.net\n"
        credentials, invalid = parse_txt_content(content)

        assert invalid == []
        assert credentials[0].old_recovery_email == "old@example.net"

        with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp_path = f.name
        try:
            loaded = _load_credentials_from_file(tmp_path)
            assert loaded[0].old_recovery_email == "old@example.net"
        finally:
            os.remove(tmp_path)

    def test_parsers_support_pipe_delimited_credentials(self):
        content = "user@example.com|password|SECRET|old@example.net\n"
        credentials, invalid = parse_txt_content(content)

        assert invalid == []
        assert credentials[0].gmail == "user@example.com"
        assert credentials[0].password == "password"
        assert credentials[0].totp_secret == "SECRET"
        assert credentials[0].old_recovery_email == "old@example.net"

        with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp_path = f.name
        try:
            loaded = _load_credentials_from_file(tmp_path)
            assert loaded[0].old_recovery_email == "old@example.net"
        finally:
            os.remove(tmp_path)

    @pytest.mark.parametrize("separator", ["----", "|"])
    def test_parsers_support_swapped_totp_and_recovery_email(self, separator):
        content = f"user@example.com{separator}password{separator}old@example.net{separator}SECRET\n"

        credentials, invalid = parse_txt_content(content)

        assert invalid == []
        assert credentials[0].totp_secret == "SECRET"
        assert credentials[0].old_recovery_email == "old@example.net"

        with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp_path = f.name
        try:
            loaded = _load_credentials_from_file(tmp_path)
            assert loaded[0].totp_secret == "SECRET"
            assert loaded[0].old_recovery_email == "old@example.net"
        finally:
            os.remove(tmp_path)

    def test_parse_four_hyphens_format(self):
        """测试用户给出的 n62931142afca@gmail.com----Phanh48458----y7eax4iocyia3tapqokjnzk5piqqitub 格式"""
        content = "n62931142afca@gmail.com----Phanh48458----y7eax4iocyia3tapqokjnzk5piqqitub\n"
        with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp_path = f.name

        try:
            creds = _load_credentials_from_file(tmp_path)
            assert len(creds) == 1
            assert creds[0].gmail == "n62931142afca@gmail.com"
            assert creds[0].password == "Phanh48458"
            assert creds[0].totp_secret == "y7eax4iocyia3tapqokjnzk5piqqitub"
        finally:
            os.remove(tmp_path)

    def test_parse_batch_txt(self):
        """测试多行批量凭证格式"""
        content = (
            "user1@gmail.com----Pass111----SECRET111\n"
            "user2@gmail.com----Pass222----SECRET222\n"
            "# 这是一行注释\n"
            "\n"
            "user3@gmail.com----Pass333\n"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp_path = f.name

        try:
            creds = _load_credentials_from_file(tmp_path)
            assert len(creds) == 3
            assert creds[0].gmail == "user1@gmail.com"
            assert creds[1].totp_secret == "SECRET222"
            assert creds[2].totp_secret is None
        finally:
            os.remove(tmp_path)
