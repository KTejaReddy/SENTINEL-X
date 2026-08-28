"""Migration discipline tests.

1. A fresh database upgrades cleanly from empty to head via Alembic.
2. The migrated schema can be seeded (the production bootstrap path).
3. The migration tree's resulting schema matches the SQLAlchemy models
   (table/column/type/nullability level) — catching model/migration drift
   that would otherwise surface as runtime bugs.
"""
from __future__ import annotations

import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from sentinelx.config import settings
from sentinelx.db import Base

API_DIR = Path(__file__).resolve().parents[1] / "apps" / "api"
ALEMBIC_INI = API_DIR / "alembic.ini"


@contextmanager
def _temp_db_dir():
    """mkdtemp + lenient cleanup: alembic's engine is not returned to us, and on
    Windows an open SQLite handle makes rmtree raise — ignore cleanup errors."""
    tmp = tempfile.mkdtemp(prefix="sentinelx-mig-")
    try:
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(API_DIR / "alembic"))
    settings.DATABASE_URL = db_url  # env.py reads settings.DATABASE_URL
    return cfg


def _upgrade_to_head(db_url: str) -> None:
    command.upgrade(_alembic_config(db_url), "head")


def _model_tables() -> dict[str, dict]:
    """{table: {column: (str(type), nullable, is_pk)}} from SQLAlchemy models."""
    result: dict[str, dict] = {}
    for table in Base.metadata.sorted_tables:
        cols = {}
        for c in table.columns:
            cols[c.name] = (str(c.type), c.nullable, c.primary_key)
        result[table.name] = cols
    return result


def _migrated_tables(db_url: str) -> dict[str, dict]:
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    insp = inspect(engine)
    result: dict[str, dict] = {}
    for name in insp.get_table_names():
        pk_cols = insp.get_pk_constraint(name).get("constrained_columns", [])
        cols = {}
        for col in insp.get_columns(name):
            cols[col["name"]] = (str(col["type"]), col["nullable"], col["name"] in pk_cols)
        result[name] = cols
    engine.dispose()
    return result


def test_fresh_database_upgrades_to_head():
    with _temp_db_dir() as tmp:
        db_path = Path(tmp) / "fresh.db"
        db_url = f"sqlite:///{db_path.as_posix()}"
        _upgrade_to_head(db_url)

        assert db_path.exists()
        engine = create_engine(db_url, connect_args={"check_same_thread": False})
        insp = inspect(engine)
        names = set(insp.get_table_names())
        assert "users" in names
        assert "login_attempts" in names  # from the login-hardening migration
        assert "alembic_version" in names
        engine.dispose()


def test_migrated_schema_can_be_seeded():
    """Seeding must work against an Alembic-migrated (not create_all) schema."""
    import sentinelx.seed as seedmod

    with _temp_db_dir() as tmp:
        db_path = Path(tmp) / "seeded.db"
        db_url = f"sqlite:///{db_path.as_posix()}"
        _upgrade_to_head(db_url)

        engine = create_engine(db_url, connect_args={"check_same_thread": False})

        @contextmanager
        def _tmp_session():
            from sqlalchemy.orm import Session

            db = Session(bind=engine)
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

        original = seedmod.session_scope
        seedmod.session_scope = _tmp_session
        try:
            result = seed_all_quiet()
            assert result and len(result) >= 1
            for org_id, res in result.items():
                seeded_counts = res.get("seeded", {})
                assert seeded_counts.get("assets", 0) > 0, f"org {org_id} got no assets: {res}"
        finally:
            seedmod.session_scope = original
            engine.dispose()


def seed_all_quiet():
    import sentinelx.seed as seedmod

    # seed_all prints progress; call the real function
    return seedmod.seed_all()


def test_migration_schema_matches_models():
    """The upgrade-to-head schema must equal the model metadata (drift check)."""
    with _temp_db_dir() as tmp:
        db_path = Path(tmp) / "drift.db"
        db_url = f"sqlite:///{db_path.as_posix()}"
        _upgrade_to_head(db_url)

        model = _model_tables()
        migrated = _migrated_tables(db_url)

        # alembic_version is Alembic's own bookkeeping table, not a model
        migrated.pop("alembic_version", None)

        model_names, migrated_names = set(model), set(migrated)
        assert model_names == migrated_names, (
            f"TABLE DRIFT: only in models={sorted(model_names - migrated_names)}, "
            f"only in migrations={sorted(migrated_names - model_names)}"
        )

        diffs = []
        for table in sorted(model_names):
            mcols, dcols = model[table], migrated[table]
            if set(mcols) != set(dcols):
                diffs.append(f"{table}: column set mismatch model={sorted(mcols)} migrated={sorted(dcols)}")
                continue
            for col in sorted(mcols):
                mtype, mnull, mpk = mcols[col]
                dtype, dnull, dpk = dcols[col]
                if mtype != dtype or mnull != dnull or mpk != dpk:
                    diffs.append(f"{table}.{col}: model=({mtype},{mnull},{mpk}) migrated=({dtype},{dnull},{dpk})")
        assert not diffs, "MODEL/MIGRATION DRIFT:\n" + "\n".join(diffs[:40])
