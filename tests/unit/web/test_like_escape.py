"""
Tests for SQL LIKE escape utility (P0-W3).
"""

from web.app.api import escape_like


class TestEscapeLike:
    """escape_like() must neutralize SQL LIKE wildcards."""

    def test_escape_percent(self):
        assert escape_like("100%") == "100\\%"

    def test_escape_underscore(self):
        assert escape_like("file_name") == "file\\_name"

    def test_escape_backslash(self):
        assert escape_like("path\\to") == "path\\\\to"

    def test_normal_unchanged(self):
        assert escape_like("hello world") == "hello world"

    def test_combined(self):
        assert escape_like("50%_off\\deal") == "50\\%\\_off\\\\deal"

    def test_empty_string(self):
        assert escape_like("") == ""
