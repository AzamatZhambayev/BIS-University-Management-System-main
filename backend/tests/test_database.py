"""Database check: 10 tests of the PostgreSQL schema produced by the Alembic migrations.

They need TEST_DATABASE_URL (a migrated, disposable *_test database), like the other
integration tests, and cover schema structure, constraints, cascades and FK protection.
"""

from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.modules.auth import service as auth_service
from app.modules.registrations.service import enroll
from tests.conftest import PASSWORD, PASSWORD_HASH

BACKEND = Path(__file__).resolve().parents[1]


async def scalar(db_factory, sql, **params):
    async with db_factory() as db:
        return await db.scalar(text(sql), params)


async def rejected(db_factory, sql, **params):
    """Run one statement in its own transaction and expect PostgreSQL to refuse it."""
    with pytest.raises(IntegrityError):
        async with db_factory() as db, db.begin():
            await db.execute(text(sql), params)


# 1
async def test_all_tables_exist(db_factory):
    async with db_factory() as db:
        rows = await db.scalars(
            text("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
        )
        tables = set(rows)
    assert {
        "users",
        "students",
        "courses",
        "semesters",
        "course_sections",
        "section_meetings",
        "registrations",
        "auth_sessions",
        "refresh_tokens",
        "login_failures",
    } <= tables


# 2
async def test_database_is_at_latest_migration(db_factory):
    config = Config()
    config.set_main_option("script_location", str(BACKEND / "alembic"))
    head = ScriptDirectory.from_config(config).get_current_head()
    assert await scalar(db_factory, "SELECT version_num FROM alembic_version") == head


# 3
async def test_query_indexes_exist(db_factory):
    async with db_factory() as db:
        names = set(
            await db.scalars(text("SELECT indexname FROM pg_indexes WHERE schemaname='public'"))
        )
    assert {
        "ix_registration_schedule",
        "ix_registration_seats",
        "ix_registrations_student_id",
        "ix_course_sections_semester_id",
        "ix_section_meetings_section_id",
        "ix_login_failures_email",
    } <= names


# 4
async def test_email_must_be_lowercase(db_factory):
    await rejected(
        db_factory,
        "INSERT INTO users (email,password_hash,role) VALUES ('Mixed@Example.edu',:h,'STUDENT')",
        h=PASSWORD_HASH,
    )


# 5
async def test_role_must_be_known(db_factory):
    await rejected(
        db_factory,
        "INSERT INTO users (email,password_hash,role) VALUES ('guest@example.edu',:h,'GUEST')",
        h=PASSWORD_HASH,
    )


# 6
async def test_course_credits_boundaries(data, db_factory):
    insert = "INSERT INTO courses (course_code,course_title,credits) VALUES (:c,'Title',:n)"
    for code, credits in [("LOW", 0), ("HIGH", 31)]:
        await rejected(db_factory, insert, c=code, n=credits)
    for code, credits in [("MIN", 1), ("MAX", 30)]:
        async with db_factory() as db, db.begin():
            await db.execute(text(insert), {"c": code, "n": credits})
    assert await scalar(db_factory, "SELECT count(*) FROM courses") == 3


# 7
async def test_course_code_and_semester_name_are_unique(data, db_factory):
    await rejected(
        db_factory,
        "INSERT INTO courses (course_code,course_title,credits) VALUES ('CS101','Copy',3)",
    )
    await rejected(
        db_factory,
        "INSERT INTO semesters (name,start_date,end_date) "
        "VALUES ('Semester 0','2040-01-01','2040-06-01')",
    )


# 8
async def test_section_number_is_unique_within_course_and_semester(data, db_factory):
    insert = (
        "INSERT INTO course_sections (course_id,semester_id,section_number,capacity) "
        "VALUES (:course,:semester,:number,10)"
    )
    await rejected(db_factory, insert, course=data.course, semester=data.semesters[0], number="A")
    async with db_factory() as db, db.begin():  # same number in another semester is fine
        await db.execute(
            text(insert), {"course": data.course, "semester": data.semesters[1], "number": "A"}
        )


# 9
async def test_cascades_remove_meetings_and_refresh_tokens(data, db_factory):
    section = data.sections[5]  # MULTI: two weekly meetings
    count_meetings = "SELECT count(*) FROM section_meetings WHERE section_id=:s"
    assert await scalar(db_factory, count_meetings, s=section) == 2
    async with db_factory() as db, db.begin():
        await db.execute(text("DELETE FROM course_sections WHERE section_id=:s"), {"s": section})
    assert await scalar(db_factory, count_meetings, s=section) == 0

    await auth_service.login(data.actors[0].email, PASSWORD)
    assert await scalar(db_factory, "SELECT count(*) FROM refresh_tokens") == 1
    async with db_factory() as db, db.begin():
        await db.execute(text("DELETE FROM auth_sessions"))
    assert await scalar(db_factory, "SELECT count(*) FROM refresh_tokens") == 0


# 10
async def test_referenced_rows_cannot_be_deleted(data, db_factory):
    await enroll(data.actors[0], data.sections[0], data.semesters[0])
    await rejected(db_factory, "DELETE FROM courses WHERE course_id=:i", i=data.course)
    await rejected(db_factory, "DELETE FROM semesters WHERE semester_id=:i", i=data.semesters[0])
    await rejected(db_factory, "DELETE FROM students WHERE student_id=:i", i=data.students[0])
    await rejected(db_factory, "DELETE FROM users WHERE id=:i", i=data.teacher.id)
    assert await scalar(db_factory, "SELECT count(*) FROM registrations") == 1
