import os
import uuid

import pytest
import requests


BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
ADMIN_EMAIL = "admin@euphoria.local"
ADMIN_PASSWORD = "EuphoriaAdmin!2026"


@pytest.fixture(scope="module")
def auth_session():
    session = requests.Session()
    login = session.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    assert login.status_code == 200, login.text
    session.headers.update({"Authorization": f"Bearer {login.json()['token']}"})
    return session


def test_generated_token_entry_is_atomic_and_invalid_qr_is_reported(auth_session):
    # Scanner verification: create a pass, allow one entry, reject duplicates and invalid tokens.
    registration = {
        "registration_number": f"TEST_SCAN_{uuid.uuid4().hex[:10]}",
        "participant_full_name": "TEST Scanner Participant",
        "email": f"test-scan-{uuid.uuid4().hex[:8]}@example.com",
        "phone": "9876543210",
        "event_name": "EUPHORIA 2026",
        "event_category": "GENERAL",
    }
    created = auth_session.post(f"{BASE_URL}/api/registrations", json=registration)
    assert created.status_code == 200, created.text
    registration_id = created.json()["id"]

    generated = auth_session.post(f"{BASE_URL}/api/passes/{registration_id}/generate")
    assert generated.status_code == 200, generated.text
    token = generated.json()["pass"]["qr_token"]

    first = auth_session.post(f"{BASE_URL}/api/scanner/verify", json={"token": token})
    assert first.status_code == 200
    assert first.json()["status"] == "ENTRY_ALLOWED"
    assert first.json()["participant"]["registration_number"] == registration["registration_number"]

    second = auth_session.post(f"{BASE_URL}/api/scanner/verify", json={"token": token})
    assert second.status_code == 200
    assert second.json()["status"] == "ALREADY_SCANNED"

    invalid = auth_session.post(
        f"{BASE_URL}/api/scanner/verify", json={"token": "invalid-token-value"}
    )
    assert invalid.status_code == 200
    assert invalid.json()["status"] == "INVALID_QR"