"""Scanner-specific regression: create scanner user via admin, decode the raw
QR token from the returned qr_image (since qr_token is stripped from the API
response), and validate ENTRY_ALLOWED -> ALREADY_SCANNED -> INVALID_QR flow."""
import base64
import io
import os
import uuid
from pathlib import Path

import pytest
import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]


def _login(email, password):
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    r = s.post(f"{BASE_URL}/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    s.headers.update({"Authorization": f"Bearer {r.json()['token']}"})
    return s, r.json()["user"]


@pytest.fixture(scope="module")
def admin():
    session, _ = _login(ADMIN_EMAIL, ADMIN_PASSWORD)
    return session


@pytest.fixture(scope="module")
def scanner(admin):
    username = f"regscan{uuid.uuid4().hex[:6]}"
    password = "ScanTest!2026"
    r = admin.post(f"{BASE_URL}/api/scanner-users", json={
        "username": username, "display_name": "TEST Reg Scanner", "password": password,
    })
    assert r.status_code == 200, r.text
    session, user = _login(username, password)
    assert user["role"] == "SCANNER"
    return session


def _decode_qr_token(qr_image_data_url):
    assert qr_image_data_url.startswith("data:image/png;base64,")
    png = base64.b64decode(qr_image_data_url.split(",", 1)[1])
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode  # type: ignore
    except ImportError:
        pytest.skip("pyzbar not installed on runner; skipping raw-token decode test")
    decoded = decode(Image.open(io.BytesIO(png)))
    assert decoded, "QR image could not be decoded"
    return decoded[0].data.decode()


def test_generated_token_entry_is_atomic_and_invalid_qr_is_reported(admin, scanner):
    registration = {
        "registration_number": f"TEST_SCAN_{uuid.uuid4().hex[:10]}",
        "participant_full_name": "TEST Scanner Participant",
        "email": f"test-scan-{uuid.uuid4().hex[:8]}@example.com",
        "phone": "9876543210",
        "event_name": "EUPHORIA 2026",
        "event_category": "GENERAL",
    }
    created = admin.post(f"{BASE_URL}/api/registrations", json=registration)
    assert created.status_code == 200, created.text
    registration_id = created.json()["id"]

    generated = admin.post(f"{BASE_URL}/api/passes/{registration_id}/generate")
    assert generated.status_code == 200, generated.text
    token = _decode_qr_token(generated.json()["qr_image"])

    first = scanner.post(f"{BASE_URL}/api/scanner/verify", json={"token": token})
    assert first.status_code == 200
    assert first.json()["status"] == "ENTRY_ALLOWED"
    assert first.json()["participant"]["registration_number"] == registration["registration_number"]

    second = scanner.post(f"{BASE_URL}/api/scanner/verify", json={"token": token})
    assert second.status_code == 200
    assert second.json()["status"] == "ALREADY_SCANNED"

    invalid = scanner.post(f"{BASE_URL}/api/scanner/verify", json={"token": "invalid-token-value"})
    assert invalid.status_code == 200
    assert invalid.json()["status"] == "INVALID_QR"
