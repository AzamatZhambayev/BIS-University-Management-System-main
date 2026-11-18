"""Twenty additional checks: security helpers, settings, schemas and HTTP contracts.

Tests 1-9 need no database. Tests 10-20 use the same migrated `*_test` PostgreSQL database
as the rest of the integration suite (see conftest.py).
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.common.schemas import Password
from app.core.config import Settings
from app.core.exceptions import AppError
from app.core.security import (
    decode_token,
    hash_password,
    issue_token,
    token_digest,
    verify_password,
)
from app.modules.courses.schemas import CourseCreate
from app.modules.semesters.schemas import SemesterCreate

API = "/api/v1"


def future(minutes: int = 5) -> datetime:
    return datetime.now(UTC) + timedelta(minutes=minutes)


# --------------------------------------------------------------------------- no database


# 1
def test_password_hash_roundtrip():
    """Пароль хешируется (хеш != пароль), и verify_password подтверждает верный пароль."""
    hashed = hash_password("a-long-enough-secret")
    assert hashed != "a-long-enough-secret"
    assert verify_password("a-long-enough-secret", hashed)


# 2
def test_wrong_password_and_garbage_hash_are_rejected():
    """Неверный пароль и битый хеш дают False, а не ошибку."""
    hashed = hash_password("a-long-enough-secret")
    assert not verify_password("another-secret-value", hashed)
    assert not verify_password("a-long-enough-secret", "not-a-real-hash")


# 3
def test_password_hashes_are_salted():
    """Один и тот же пароль даёт разные хеши (используется соль)."""
    assert hash_password("same-password-123") != hash_password("same-password-123")


# 4
def test_token_digest_is_stable_sha256_hex():
    """token_digest стабилен, различает токены и возвращает 64-символьный SHA-256."""
    digest = token_digest("token")
    assert digest == token_digest("token")
    assert digest != token_digest("token2")
    assert len(digest) == 64 and int(digest, 16) >= 0


# 5
def test_access_token_roundtrip_and_type_check():
    """Access-токен выпускается и читается обратно; как refresh-токен он отвергается (401)."""
    session_id = uuid4()
    token = issue_token(42, session_id, "access", future())
    claims = decode_token(token, "access")
    assert claims["sub"] == "42" and claims["sid"] == str(session_id)
    with pytest.raises(AppError) as error:
        decode_token(token, "refresh")  # an access token must not pass as a refresh token
    assert error.value.status == 401


# 6
def test_tampered_or_garbage_token_is_rejected():
    """Подделанный, мусорный и пустой токены отвергаются с кодом INVALID_TOKEN."""
    token = issue_token(1, uuid4(), "access", future())
    for bad in (token[:-2] + ("AA" if not token.endswith("AA") else "BB"), "garbage", ""):
        with pytest.raises(AppError) as error:
            decode_token(bad, "access")
        assert error.value.code == "INVALID_TOKEN"


# 7
def test_settings_reject_bad_configuration():
    """Настройки отвергают не-PostgreSQL URL, слабый JWT-секрет и неверные сроки токенов."""
    good = {"database_url": "postgresql+asyncpg://u:p@localhost/db", "jwt_secret": "x" * 40}
    assert Settings(_env_file=None, **good).database_url.startswith("postgresql+asyncpg://")
    for override in (
        {"database_url": "sqlite:///file.db"},
        {"jwt_secret": "too-short"},
        {"jwt_secret": "replace-" + "x" * 40},
        {"access_token_minutes": 0},
        {"refresh_token_days": 91},
    ):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, **{**good, **override})


# 8
def test_course_schema_limits_and_extra_fields():
    """Схема курса отклоняет кредиты вне 1-30, ECTS > 60, пустой код и лишние поля."""
    base = {"course_code": "CS1", "course_title": "Intro", "credits": 3}
    assert CourseCreate(**base).ects is None
    for override in (
        {"credits": 0},
        {"credits": 31},
        {"ects": 61},
        {"course_code": ""},
        {"unknown": 1},
    ):
        with pytest.raises(ValidationError):
            CourseCreate(**{**base, **override})


# 9
def test_semester_schema_and_password_length():
    """Семестр: дата начала должна быть раньше конца; пароль: длина от 12 до 128 символов."""
    ok = {"name": "Fall", "start_date": "2030-09-01", "end_date": "2030-12-20"}
    assert SemesterCreate(**ok).is_active is True
    for dates in (
        {"start_date": "2030-12-20", "end_date": "2030-09-01"},
        {"start_date": "2030-09-01", "end_date": "2030-09-01"},
    ):
        with pytest.raises(ValidationError):
            SemesterCreate(**{**ok, **dates})
    from pydantic import TypeAdapter

    adapter = TypeAdapter(Password)
    assert adapter.validate_python("x" * 12) == "x" * 12
    for bad in ("x" * 11, "x" * 129):
        with pytest.raises(ValidationError):
            adapter.validate_python(bad)


# ------------------------------------------------------------------------------- HTTP API


# 10
async def test_health_endpoints_and_request_id(client, db_factory):
    """/health и /ready отвечают 200, и каждый ответ получает уникальный X-Request-ID."""
    for path in ("/health", "/ready"):
        response = await client.get(path)
        assert response.status_code == 200
        assert response.headers["x-request-id"]
    first = (await client.get("/health")).headers["x-request-id"]
    assert first != (await client.get("/health")).headers["x-request-id"]


# 11
async def test_protected_routes_require_a_token(client, data):
    """Защищённые маршруты без токена возвращают 401 с телом ошибки."""
    for path in ("/students", "/courses", "/registrations/me", "/schedules/me", "/auth/me"):
        response = await client.get(API + path)
        assert response.status_code == 401, path
        assert response.json()["error"]["code"]


# 12
async def test_me_does_not_leak_password_hash(client, data, headers):
    """/auth/me возвращает email и роль студента, но не содержит полей с паролем."""
    response = await client.get(f"{API}/auth/me", headers=await headers(data.actors[0]))
    body = response.json()
    assert response.status_code == 200
    assert body["email"] == "student0@example.edu" and body["role"] == "STUDENT"
    assert not any("password" in key for key in body)


# 13
async def test_unknown_course_returns_404_error_envelope(client, data, headers):
    """Несуществующий курс даёт 404 в едином формате {"error": ...}."""
    response = await client.get(f"{API}/courses/999999", headers=await headers(data.admin))
    assert response.status_code == 404
    assert set(response.json()) == {"error"}


# 14
async def test_course_list_is_paginated(client, data, headers):
    """Список курсов возвращает items/total/offset/limit и корректно делится на страницы."""
    admin = await headers(data.admin)
    for code in ("PG1", "PG2"):
        created = await client.post(
            f"{API}/courses",
            headers=admin,
            json={"course_code": code, "course_title": code, "credits": 2},
        )
        assert created.status_code == 201
    page = (await client.get(f"{API}/courses?limit=2&offset=0", headers=admin)).json()
    assert set(page) == {"items", "total", "offset", "limit"}
    assert page["total"] == 3 and len(page["items"]) == 2 and page["limit"] == 2
    rest = (await client.get(f"{API}/courses?limit=2&offset=2", headers=admin)).json()
    assert len(rest["items"]) == 1


# 15
async def test_pagination_rejects_out_of_range_values(client, data, headers):
    """limit=0, offset=-1 и слишком большой limit дают 422."""
    admin = await headers(data.admin)
    for query in ("limit=0", "offset=-1", "limit=100000"):
        response = await client.get(f"{API}/courses?{query}", headers=admin)
        assert response.status_code == 422, query


# 16
async def test_student_cannot_manage_courses_or_list_students(client, data, headers):
    """Студент не может создавать и удалять курсы и смотреть список студентов (403)."""
    student = await headers(data.actors[0])
    payload = {"course_code": "NOPE", "course_title": "Nope", "credits": 3}
    assert (await client.post(f"{API}/courses", headers=student, json=payload)).status_code == 403
    assert (await client.delete(f"{API}/courses/{data.course}", headers=student)).status_code == 403
    assert (await client.get(f"{API}/students", headers=student)).status_code == 403


# 17
async def test_admin_course_create_duplicate_and_validation(client, data, headers):
    """Админ создаёт курс (201); дубликат кода даёт 409; кредиты 0 дают 422 с деталями."""
    admin = await headers(data.admin)
    payload = {"course_code": "NEW1", "course_title": "New", "credits": 4, "ects": 6}
    created = await client.post(f"{API}/courses", headers=admin, json=payload)
    assert created.status_code == 201
    assert created.json()["ects"] == 6
    duplicate = await client.post(f"{API}/courses", headers=admin, json=payload)
    assert duplicate.status_code == 409
    invalid = await client.post(f"{API}/courses", headers=admin, json={**payload, "credits": 0})
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "VALIDATION_ERROR"
    assert invalid.json()["error"]["details"]


# 18
async def test_admin_semester_create_and_interval_validation(client, data, headers):
    """Админ создаёт семестр; обратный интервал дат даёт 422; повторное имя даёт 409."""
    admin = await headers(data.admin)
    good = {"name": "Spring 2040", "start_date": "2040-02-01", "end_date": "2040-06-01"}
    created = await client.post(f"{API}/semesters", headers=admin, json=good)
    assert created.status_code == 201 and created.json()["is_active"] is True
    reversed_dates = {
        **good,
        "name": "Backwards",
        "start_date": "2040-06-01",
        "end_date": "2040-02-01",
    }
    assert (
        await client.post(f"{API}/semesters", headers=admin, json=reversed_dates)
    ).status_code == 422
    assert (await client.post(f"{API}/semesters", headers=admin, json=good)).status_code == 409


# 19
async def test_student_enrolls_and_cancels_through_http(client, data, headers):
    """Студент записывается на секцию (201), повтор даёт 409, регистрация видна и отменяется."""
    student = await headers(data.actors[0])
    body = {"section_id": data.sections[0], "semester_id": data.semesters[0]}
    enrolled = await client.post(f"{API}/registrations", headers=student, json=body)
    assert enrolled.status_code == 201 and enrolled.json()["status"] == "Enrolled"
    duplicate = await client.post(f"{API}/registrations", headers=student, json=body)
    assert duplicate.status_code == 409
    mine = (await client.get(f"{API}/registrations/me", headers=student)).json()
    assert mine["total"] == 1
    registration_id = enrolled.json()["registration_id"]
    cancelled = await client.delete(f"{API}/registrations/{registration_id}", headers=student)
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "Cancelled"


# 20
async def test_student_cannot_cancel_someone_elses_registration(client, data, headers):
    """Студент не может отменить чужую регистрацию (403/404), чужая запись остаётся Enrolled."""
    owner, other = await headers(data.actors[0]), await headers(data.actors[1])
    body = {"section_id": data.sections[0], "semester_id": data.semesters[0]}
    registration = (await client.post(f"{API}/registrations", headers=owner, json=body)).json()
    stolen = await client.delete(
        f"{API}/registrations/{registration['registration_id']}", headers=other
    )
    assert stolen.status_code in (403, 404)
    mine = (await client.get(f"{API}/registrations/me", headers=owner)).json()
    assert mine["items"][0]["status"] == "Enrolled"
