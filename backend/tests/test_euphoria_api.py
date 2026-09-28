import os

import pytest
import requests


BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
ADMIN_EMAIL = "admin@euphoria.local"
ADMIN_PASSWORD = "EuphoriaAdmin!2026"


@pytest.fixture(scope="module")
def api():
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    return session


@pytest.fixture(scope="module")
def token(api):
    response = api.post(f"{BASE_URL}/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["token"]


@pytest.fixture(scope="module")
def auth(api, token):
    api.headers.update({"Authorization": f"Bearer {token}"})
    return api


def test_health(api):
    response = api.get(f"{BASE_URL}/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_login_and_me(api, token):
    response = api.get(f"{BASE_URL}/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["email"] == ADMIN_EMAIL
    assert response.json()["role"] == "ADMIN"


def test_invalid_login_and_missing_auth(api):
    bad = api.post(f"{BASE_URL}/api/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong-password"})
    assert bad.status_code == 401
    missing = api.get(f"{BASE_URL}/api/dashboard/stats")
    assert missing.status_code == 401


def test_dashboard_and_registration_search(auth):
    stats = auth.get(f"{BASE_URL}/api/dashboard/stats")
    assert stats.status_code == 200
    assert {"total_registrations", "total_entered", "entry_percentage"}.issubset(stats.json())
    rows = auth.get(f"{BASE_URL}/api/registrations", params={"search": "TEST", "page_size": 50})
    assert rows.status_code == 200
    assert isinstance(rows.json()["items"], list)


def test_invalid_qr_is_recorded(auth):
    response = auth.post(f"{BASE_URL}/api/scanner/verify", json={"token": "invalid-token-value"})
    assert response.status_code == 200
    assert response.json()["status"] == "INVALID_QR"
    assert response.json()["success"] is False