"""Tests for DB URL rewriting helpers."""

from llmpuffin.db import _to_async_url, _to_sync_url


class TestToAsyncUrl:
    def test_plain_postgresql(self):
        url = "postgresql://user:pass@host:5432/db"
        assert _to_async_url(url) == "postgresql+asyncpg://user:pass@host:5432/db"

    def test_already_asyncpg(self):
        url = "postgresql+asyncpg://user:pass@host:5432/db"
        assert _to_async_url(url) == url

    def test_preserves_all_parts(self):
        url = "postgresql://admin:s3cret@db.example.com:5433/mydb"
        result = _to_async_url(url)
        assert "admin:s3cret@" in result
        assert "db.example.com:5433" in result
        assert "/mydb" in result


class TestToSyncUrl:
    def test_plain_postgresql(self):
        url = "postgresql://user:pass@host:5432/db"
        assert _to_sync_url(url) == "postgresql+psycopg://user:pass@host:5432/db"

    def test_already_psycopg(self):
        url = "postgresql+psycopg://user:pass@host:5432/db"
        assert _to_sync_url(url) == url

    def test_preserves_all_parts(self):
        url = "postgresql://admin:s3cret@db.example.com:5433/mydb"
        result = _to_sync_url(url)
        assert "admin:s3cret@" in result
        assert "db.example.com:5433" in result
        assert "/mydb" in result
