"""Integration tests for FastAPI routes.

Requires a PostgreSQL instance. Set LLMPUFFIN_TEST_DB_URL to enable these tests.
Example: LLMPUFFIN_TEST_DB_URL=postgresql://localhost:5555/llmpuffin_test

The test database is created automatically and dropped after the session.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

import pytest

_TEST_DB_URL = os.environ.get("LLMPUFFIN_TEST_DB_URL", "")

pytestmark = pytest.mark.skipif(
    not _TEST_DB_URL,
    reason="Set LLMPUFFIN_TEST_DB_URL to enable API integration tests",
)


def _base_url():
    """Extract base URL (without db name) from the test DB URL."""
    return _TEST_DB_URL.rsplit("/", 1)[0]


def _db_name():
    return _TEST_DB_URL.rsplit("/", 1)[1]


def _check_and_create_db():
    """Create the test database if it doesn't exist."""
    import psycopg

    base = _base_url()
    db_name = _db_name()
    conn = psycopg.connect(f"{base}/postgres", autocommit=True)
    conn.execute(f"DROP DATABASE IF EXISTS {db_name}")
    conn.execute(f"CREATE DATABASE {db_name}")
    conn.close()


def _drop_db():
    import psycopg

    base = _base_url()
    db_name = _db_name()
    conn = psycopg.connect(f"{base}/postgres", autocommit=True)
    conn.execute(
        f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
        f"WHERE datname = '{db_name}' AND pid <> pg_backend_pid()"
    )
    conn.execute(f"DROP DATABASE IF EXISTS {db_name}")
    conn.close()


@pytest.fixture(scope="session", autouse=True)
def _setup_test_database():
    """Session-scoped: create test DB and tables, drop at end."""
    if not _TEST_DB_URL:
        yield
        return

    from sqlalchemy import create_engine

    from llmpuffin.models import Base

    _check_and_create_db()

    sync_url = _TEST_DB_URL.replace("postgresql://", "postgresql+psycopg://")
    engine = create_engine(sync_url)
    Base.metadata.create_all(engine)
    engine.dispose()

    yield

    _drop_db()


@pytest.fixture
def client():
    """Per-test: create a fresh DB, app, and TestClient."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, text

    from llmpuffin.config import Config, PostgresConfig
    from llmpuffin.db import DB
    from llmpuffin.agent.harness import Harness
    from llmpuffin.models import Base
    from llmpuffin_fastapi.deps import set_github_client
    from llmpuffin_fastapi.routes import findings, profiles, runs, skills, threat_models

    config = Config()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield

    app = FastAPI(lifespan=lifespan)
    db = DB(PostgresConfig(url=_TEST_DB_URL))
    app.state.config = config
    app.state.db = db
    app.state.harness = Harness(global_config=config)

    app.include_router(profiles.router)
    app.include_router(runs.router)
    app.include_router(findings.router)
    app.include_router(skills.router)
    app.include_router(threat_models.router)
    set_github_client(None)

    with TestClient(app, follow_redirects=False) as tc:
        yield tc

    db._sync_engine.dispose()


@pytest.fixture(autouse=True)
def _clean_tables():
    """Truncate all tables between tests."""
    if not _TEST_DB_URL:
        yield
        return

    yield

    from sqlalchemy import create_engine, text

    from llmpuffin.models import Base

    sync_url = _TEST_DB_URL.replace("postgresql://", "postgresql+psycopg://")
    engine = create_engine(sync_url)
    with engine.connect() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(text(f"TRUNCATE {table.name} CASCADE"))
        conn.commit()
    engine.dispose()


def _insert(model_cls, **kwargs):
    """Insert a model row via a standalone sync session. Returns the id."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    sync_url = _TEST_DB_URL.replace("postgresql://", "postgresql+psycopg://")
    engine = create_engine(sync_url)
    with Session(engine) as s:
        obj = model_cls(**kwargs)
        s.add(obj)
        s.commit()
        obj_id = obj.id
    engine.dispose()
    return obj_id


# -- Profile tests --


class TestProfiles:
    def test_list_empty(self, client):
        resp = client.get("/profiles/")
        assert resp.status_code == 200

    def test_create_profile(self, client):
        resp = client.post(
            "/profiles/create/",
            data={
                "name": "test-profile",
                "profile_toml": '[audit]\nname = "test"\nimage = "img:v1"\nthreat_model = "tm/"',
            },
        )
        assert resp.status_code in (204, 303)

        resp = client.get("/profiles/")
        assert resp.status_code == 200
        assert "test-profile" in resp.text

    def test_create_profile_invalid_toml(self, client):
        resp = client.post(
            "/profiles/create/",
            data={"name": "bad", "profile_toml": "not valid toml {{{"},
        )
        assert resp.status_code in (204, 303)

    def test_create_profile_empty_name(self, client):
        resp = client.post(
            "/profiles/create/",
            data={"name": "", "profile_toml": "[audit]"},
        )
        assert resp.status_code in (204, 303)

    def test_profile_detail(self, client):
        from llmpuffin.models import AuditProfile

        pid = _insert(
            AuditProfile,
            name="detail-test",
            profile_toml='[audit]\nname = "x"\nimage = "i"\nthreat_model = "t"',
        )
        resp = client.get(f"/profiles/{pid}/")
        assert resp.status_code == 200
        assert "detail-test" in resp.text

    def test_profile_detail_404(self, client):
        resp = client.get("/profiles/99999/")
        assert resp.status_code == 404

    def test_update_profile(self, client):
        from llmpuffin.models import AuditProfile

        pid = _insert(
            AuditProfile,
            name="update-me",
            profile_toml='[audit]\nname = "x"\nimage = "i"\nthreat_model = "t"',
        )
        resp = client.post(
            f"/profiles/{pid}/",
            data={
                "name": "updated-name",
                "profile_toml": '[audit]\nname = "y"\nimage = "i2"\nthreat_model = "t"',
            },
        )
        assert resp.status_code in (204, 303)


# -- Runs tests --


class TestRuns:
    def test_list_empty(self, client):
        resp = client.get("/runs/")
        assert resp.status_code == 200

    def test_run_detail_404(self, client):
        resp = client.get("/runs/99999/")
        assert resp.status_code == 404


# -- Skills tests --


class TestSkills:
    def test_list_empty(self, client):
        resp = client.get("/skills/")
        assert resp.status_code == 200

    def test_create_skill(self, client):
        resp = client.post(
            "/skills/create/",
            data={"name": "test-skill", "description": "A test skill"},
        )
        assert resp.status_code in (204, 303)

        resp = client.get("/skills/")
        assert resp.status_code == 200
        assert "test-skill" in resp.text

    def test_create_duplicate_skill(self, client):
        from llmpuffin.models import Skill

        _insert(Skill, name="dup-skill")
        resp = client.post(
            "/skills/create/",
            data={"name": "dup-skill", "description": ""},
        )
        assert resp.status_code in (204, 303)

    def test_skill_detail(self, client):
        from llmpuffin.models import Skill

        sid = _insert(Skill, name="detail-skill")
        resp = client.get(f"/skills/{sid}/")
        assert resp.status_code == 200
        assert "detail-skill" in resp.text

    def test_skill_detail_404(self, client):
        resp = client.get("/skills/99999/")
        assert resp.status_code == 404

    def test_upload_file(self, client):
        from llmpuffin.models import Skill

        sid = _insert(Skill, name="upload-skill")
        resp = client.post(
            f"/skills/{sid}/upload/",
            data={"path": "guide.md", "content": "# Guide\nHello"},
        )
        assert resp.status_code in (204, 303)

    def test_delete_skill(self, client):
        from llmpuffin.models import Skill

        sid = _insert(Skill, name="delete-me")
        resp = client.post(f"/skills/{sid}/delete/")
        assert resp.status_code in (204, 303)


# -- Threat model tests --


class TestThreatModels:
    def test_list_empty(self, client):
        resp = client.get("/threat-models/")
        assert resp.status_code == 200

    def test_create_threat_model(self, client):
        resp = client.post(
            "/threat-models/create/",
            data={"name": "test-tm", "description": "A test threat model"},
        )
        assert resp.status_code in (204, 303)

        resp = client.get("/threat-models/")
        assert resp.status_code == 200
        assert "test-tm" in resp.text

    def test_create_duplicate(self, client):
        from llmpuffin.models import ThreatModelDB

        _insert(ThreatModelDB, name="dup-tm")
        resp = client.post(
            "/threat-models/create/",
            data={"name": "dup-tm", "description": ""},
        )
        assert resp.status_code in (204, 303)

    def test_detail(self, client):
        from llmpuffin.models import ThreatModelDB

        tid = _insert(ThreatModelDB, name="detail-tm")
        resp = client.get(f"/threat-models/{tid}/")
        assert resp.status_code == 200
        assert "detail-tm" in resp.text

    def test_detail_404(self, client):
        resp = client.get("/threat-models/99999/")
        assert resp.status_code == 404

    def test_upload_file(self, client):
        from llmpuffin.models import ThreatModelDB

        tid = _insert(ThreatModelDB, name="upload-tm")
        resp = client.post(
            f"/threat-models/{tid}/upload/",
            data={"path": "components.toml", "content": "[[components]]"},
        )
        assert resp.status_code in (204, 303)

    def test_delete(self, client):
        from llmpuffin.models import ThreatModelDB

        tid = _insert(ThreatModelDB, name="delete-tm")
        resp = client.post(f"/threat-models/{tid}/delete/")
        assert resp.status_code in (204, 303)


# -- Findings tests --


class TestFindings:
    def test_list_empty(self, client):
        resp = client.get("/findings/")
        assert resp.status_code == 200

    def test_finding_detail_404(self, client):
        resp = client.get("/findings/99999/")
        assert resp.status_code == 404
