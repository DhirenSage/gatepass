from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path(__file__).parent / ".env")

import base64
import csv
import hashlib
import io
import logging
import os
import secrets
import smtplib
import ssl
import uuid
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr
from typing import Optional

import bcrypt
import jwt
import qrcode
from fastapi import APIRouter, Depends, FastAPI, File, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from pymongo.errors import DuplicateKeyError
from PIL import Image, ImageDraw
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

ROOT_DIR = Path(__file__).parent
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]
app = FastAPI(title="EUPHORIA Event Entry System")
api = APIRouter(prefix="/api")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
log = logging.getLogger("euphoria")

class LoginRequest(BaseModel):
    email: str
    password: str

class EventInput(BaseModel):
    name: str = Field(min_length=2)
    description: str = ""
    start_date: str
    end_date: str
    entry_start_time: str
    entry_end_time: str
    timezone: str = "UTC"
    status: str = "ACTIVE"

class RegistrationInput(BaseModel):
    registration_number: str = Field(min_length=2)
    participant_full_name: str = Field(min_length=2)
    email: EmailStr
    phone: str = Field(min_length=7)
    event_name: str = Field(min_length=2)
    event_category: str = Field(min_length=2)
    event_id: Optional[str] = None

class ScanInput(BaseModel):
    token: str = Field(min_length=8, max_length=512)

class ScannerUserInput(BaseModel):
    username: str = Field(min_length=3)
    display_name: str = Field(min_length=2)
    password: str = Field(min_length=8)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def public(doc: dict):
    result = dict(doc)
    result.pop("_id", None)
    result.pop("password_hash", None)
    result.pop("qr_token", None)
    result.pop("qr_token_encrypted", None)
    return result

def hash_password(value: str) -> str:
    return bcrypt.hashpw(value.encode(), bcrypt.gensalt()).decode()

def verify_password(value: str, hashed: str) -> bool:
    return bcrypt.checkpw(value.encode(), hashed.encode())

def token_for(user: dict) -> str:
    return jwt.encode({"sub": user["id"], "role": user["role"], "exp": datetime.now(timezone.utc).timestamp() + 28800}, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def current_user(request: Request, authorization: Optional[str] = Header(default=None)):
    authorization = authorization or (f"Bearer {request.cookies.get('access_token')}" if request.cookies.get("access_token") else None)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    try:
        payload = jwt.decode(authorization[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"id": payload["sub"], "is_active": True}, {"_id": 0})
    except (jwt.InvalidTokenError, KeyError):
        raise HTTPException(401, "Invalid or expired session")
    if not user:
        raise HTTPException(401, "User is inactive or missing")
    return user

async def admin_user(user=Depends(current_user)):
    if user["role"] != "ADMIN":
        raise HTTPException(403, "Admin access required")
    return user

async def scanner_user(user=Depends(current_user)):
    if user["role"] not in ("ADMIN", "SCANNER"):
        raise HTTPException(403, "Scanner access required")
    return user

async def audit(user, action, target_type="system", target_id=None, metadata=None):
    await db.audit_logs.insert_one({"id": str(uuid.uuid4()), "actor_user_id": user["id"], "action": action, "target_type": target_type, "target_id": target_id, "metadata": metadata or {}, "created_at": now_iso()})

async def ensure_indexes():
    await db.users.create_index("email", unique=True)
    await db.users.create_index("username", unique=True)
    await db.registrations.create_index([("registration_number", 1), ("event_id", 1)], unique=True)
    await db.registrations.create_index([("participant_full_name", 1)])
    await db.registrations.create_index([("email", 1)])
    await db.event_passes.create_index("qr_token_hash", unique=True)
    await db.event_passes.create_index([("registration_id", 1), ("event_id", 1)], unique=True)
    await db.entries.create_index([("pass_id", 1), ("event_id", 1)], unique=True)
    await db.scan_attempts.create_index([("attempted_at", -1)])

async def seed_defaults():
    admin_email = os.environ["ADMIN_EMAIL"].lower()
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one({"id": str(uuid.uuid4()), "username": "admin", "email": admin_email, "display_name": "EUPHORIA Admin", "password_hash": hash_password(os.environ["ADMIN_PASSWORD"]), "role": "ADMIN", "is_active": True, "created_at": now_iso(), "updated_at": now_iso()})
    elif not verify_password(os.environ["ADMIN_PASSWORD"], existing["password_hash"]):
        await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_password(os.environ["ADMIN_PASSWORD"]), "updated_at": now_iso()}})
    event = await db.events.find_one({"status": {"$in": ["ACTIVE", "DRAFT"]}})
    if not event:
        await db.events.insert_one({"id": str(uuid.uuid4()), "name": "EUPHORIA 2026", "description": "Event entry configuration", "start_date": "2026-01-01", "end_date": "2026-12-31", "entry_start_time": "00:00", "entry_end_time": "23:59", "timezone": "UTC", "status": "ACTIVE", "created_at": now_iso(), "updated_at": now_iso()})

@app.on_event("startup")
async def startup():
    await ensure_indexes()
    await seed_defaults()

@api.get("/health")
async def health():
    await db.command("ping")
    return {"status": "ok", "service": "euphoria-entry"}

@api.post("/auth/login")
async def login(body: LoginRequest, response: Response):
    user = await db.users.find_one({"$or": [{"email": body.email.lower()}, {"username": body.email.lower()}]}, {"_id": 0})
    if not user or not user.get("is_active") or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    await db.users.update_one({"id": user["id"]}, {"$set": {"last_login_at": now_iso()}})
    response.set_cookie("access_token", token_for(user), httponly=True, secure=True, samesite="lax", max_age=28800)
    return {"token": token_for(user), "user": public(user)}

@api.get("/auth/me")
async def me(user=Depends(current_user)):
    return public(user)

@api.post("/auth/logout")
async def logout(response: Response, user=Depends(current_user)):
    await audit(user, "LOGOUT")
    response.delete_cookie("access_token")
    return {"success": True}

@api.get("/events")
async def events(user=Depends(current_user)):
    return [public(x) async for x in db.events.find({}, {"_id": 0}).sort("created_at", -1)]

@api.get("/events/current")
async def current_event(user=Depends(current_user)):
    event = await db.events.find_one({"status": {"$in": ["ACTIVE", "DRAFT"]}}, {"_id": 0})
    if not event:
        raise HTTPException(404, "No event configured")
    return public(event)

@api.put("/events/{event_id}")
async def update_event(event_id: str, body: EventInput, user=Depends(admin_user)):
    data = body.model_dump(); data["updated_at"] = now_iso()
    await db.events.update_one({"id": event_id}, {"$set": data}, upsert=True)
    await audit(user, "EVENT_SETTINGS_UPDATED", "event", event_id)
    return public(await db.events.find_one({"id": event_id}, {"_id": 0}))

@api.get("/registrations")
async def registrations(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100), search: str = "", user=Depends(admin_user)):
    query = {"is_active": True}
    if search:
        query["$or"] = [{"registration_number": {"$regex": search, "$options": "i"}}, {"participant_full_name": {"$regex": search, "$options": "i"}}, {"email": {"$regex": search, "$options": "i"}}, {"phone": {"$regex": search, "$options": "i"}}]
    total = await db.registrations.count_documents(query)
    rows = await db.registrations.find(query, {"_id": 0}).sort("created_at", -1).skip((page - 1) * page_size).limit(page_size).to_list(page_size)
    for row in rows:
        p = await db.event_passes.find_one({"registration_id": row["id"]}, {"_id": 0})
        entry = await db.entries.find_one({"registration_id": row["id"]}, {"_id": 0})
        row["pass_status"] = p.get("pass_status", "NOT_GENERATED") if p else "NOT_GENERATED"
        row["pass_id"] = p.get("id") if p else None
        row["entry_status"] = "ENTERED" if entry else "NOT_ENTERED"
        row["entry_time"] = entry.get("scanned_at") if entry else None
    return {"items": rows, "total": total, "page": page, "page_size": page_size}

@api.post("/registrations")
async def create_registration(body: RegistrationInput, user=Depends(admin_user)):
    data = body.model_dump(); data["id"] = str(uuid.uuid4()); data["email"] = str(data["email"]).lower(); data["is_active"] = True; data["created_at"] = now_iso(); data["updated_at"] = now_iso()
    try:
        await db.registrations.insert_one(data)
    except DuplicateKeyError:
        raise HTTPException(409, "Registration number already exists for this event")
    await audit(user, "REGISTRATION_CREATED", "registration", data["id"])
    return public(data)

@api.put("/registrations/{registration_id}")
async def edit_registration(registration_id: str, body: RegistrationInput, user=Depends(admin_user)):
    data = body.model_dump(); data.pop("event_id", None); data["email"] = str(data["email"]).lower(); data["updated_at"] = now_iso()
    await db.registrations.update_one({"id": registration_id}, {"$set": data})
    await audit(user, "REGISTRATION_UPDATED", "registration", registration_id)
    return public(await db.registrations.find_one({"id": registration_id}, {"_id": 0}))

@api.post("/registrations/{registration_id}/deactivate")
async def deactivate_registration(registration_id: str, user=Depends(admin_user)):
    await db.registrations.update_one({"id": registration_id}, {"$set": {"is_active": False, "updated_at": now_iso()}})
    await audit(user, "REGISTRATION_DEACTIVATED", "registration", registration_id)
    return {"success": True}

def validate_row(row: dict, row_number: int):
    required = ["Registration Number", "Participant Full Name", "Email", "Phone", "Event Name", "Event Category"]
    errors = [f"Missing {key}" for key in required if not str(row.get(key, "")).strip()]
    if row.get("Email") and ("@" not in row["Email"] or "." not in row["Email"].split("@")[-1]): errors.append("Invalid email")
    if row.get("Phone") and len("".join(ch for ch in row["Phone"] if ch.isdigit())) < 7: errors.append("Invalid phone")
    return errors

@api.post("/imports/preview")
async def import_preview(file: UploadFile = File(...), user=Depends(admin_user)):
    raw = await file.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    rows = list(csv.DictReader(io.StringIO(text)))
    expected = ["Registration Number", "Participant Full Name", "Email", "Phone", "Event Name", "Event Category"]
    if (list(rows[0].keys()) if rows else []) != expected:
        headers = list(rows[0].keys()) if rows else []
        if set(headers) != set(expected): raise HTTPException(422, {"message": "CSV columns do not match the required template", "expected": expected, "received": headers})
    seen = set(); preview = []; valid = invalid = duplicate = 0
    for index, row in enumerate(rows, start=2):
        errors = validate_row(row, index); status = "VALID"
        reg = row.get("Registration Number", "").strip()
        if reg in seen or await db.registrations.find_one({"registration_number": reg}, {"_id": 0}):
            errors.append("Duplicate registration number"); status = "DUPLICATE"; duplicate += 1
        elif errors: status = "INVALID"; invalid += 1
        else: valid += 1
        seen.add(reg); preview.append({"row_number": index, "data": row, "errors": errors, "status": status})
    import_id = str(uuid.uuid4())
    await db.import_logs.insert_one({"id": import_id, "filename": file.filename, "rows": preview, "total_rows": len(rows), "valid_rows": valid, "invalid_rows": invalid, "duplicate_rows": duplicate, "created_by": user["id"], "status": "PREVIEWED", "created_at": now_iso()})
    return {"import_id": import_id, "filename": file.filename, "summary": {"total": len(rows), "valid": valid, "invalid": invalid, "duplicates": duplicate}, "rows": preview}

@api.post("/imports/{import_id}/confirm")
async def confirm_import(import_id: str, user=Depends(admin_user)):
    batch = await db.import_logs.find_one({"id": import_id}, {"_id": 0})
    if not batch or batch["status"] != "PREVIEWED": raise HTTPException(404, "Import preview not found")
    imported = 0
    for item in batch["rows"]:
        if item["status"] != "VALID": continue
        row = item["data"]; doc = {"id": str(uuid.uuid4()), "registration_number": row["Registration Number"].strip(), "participant_full_name": row["Participant Full Name"].strip(), "email": row["Email"].strip().lower(), "phone": row["Phone"].strip(), "event_name": row["Event Name"].strip(), "event_category": row["Event Category"].strip(), "event_id": None, "is_active": True, "created_at": now_iso(), "updated_at": now_iso()}
        try:
            await db.registrations.insert_one(doc); imported += 1
        except DuplicateKeyError: pass
    await db.import_logs.update_one({"id": import_id}, {"$set": {"status": "CONFIRMED", "imported_rows": imported, "completed_at": now_iso()}})
    await audit(user, "CSV_IMPORTED", "import", import_id, {"imported": imported})
    return {"success": True, "imported": imported, "skipped": batch["total_rows"] - imported}

def qr_data(token: str):
    image = qrcode.make(token); output = io.BytesIO(); image.save(output, format="PNG")
    return "data:image/png;base64," + base64.b64encode(output.getvalue()).decode()

@api.post("/passes/{registration_id}/generate")
async def generate_pass(registration_id: str, user=Depends(admin_user)):
    registration = await db.registrations.find_one({"id": registration_id}, {"_id": 0})
    if not registration: raise HTTPException(404, "Registration not found")
    existing = await db.event_passes.find_one({"registration_id": registration_id}, {"_id": 0})
    if existing:
        return {"pass": public(existing), "message": "Pass already exists; QR was not regenerated."}
    raw = secrets.token_urlsafe(32); doc = {"id": str(uuid.uuid4()), "registration_id": registration_id, "event_id": registration.get("event_id"), "qr_token_encrypted": raw, "qr_token_hash": hashlib.sha256(raw.encode()).hexdigest(), "qr_token_last4": raw[-4:], "pass_status": "ACTIVE", "generated_at": now_iso(), "created_at": now_iso(), "updated_at": now_iso()}
    await db.event_passes.insert_one(doc); await audit(user, "PASS_GENERATED", "pass", doc["id"])
    return {"pass": public(doc), "qr_image": qr_data(raw), "message": "Pass generated. Download the PDF or send it by email."}

FESTIVAL_STOPS = [(0.0, (28, 12, 60)), (0.28, (110, 24, 118)), (0.5, (204, 46, 118)), (0.72, (238, 108, 96)), (0.88, (248, 176, 96)), (1.0, (254, 226, 148))]

def _festival_gradient(width=595, height=842):
    img = Image.new("RGB", (width, height)); draw = ImageDraw.Draw(img)
    for y in range(height):
        t = y / (height - 1); color = FESTIVAL_STOPS[-1][1]
        for i in range(len(FESTIVAL_STOPS) - 1):
            a, b = FESTIVAL_STOPS[i], FESTIVAL_STOPS[i + 1]
            if a[0] <= t <= b[0]:
                p = (t - a[0]) / max(b[0] - a[0], 1e-9); color = tuple(int(a[1][k] + (b[1][k] - a[1][k]) * p) for k in range(3)); break
        draw.line([(0, y), (width, y)], fill=color)
    for _ in range(120):
        import random; x, y = random.randint(0, width), random.randint(0, height); r = random.randint(1, 3); draw.ellipse([x, y, x + r, y + r], fill=(255, 255, 255, 200))
    return img

@api.get("/passes/{pass_id}/pdf")
async def pass_pdf(pass_id: str, user=Depends(admin_user)):
    pass_doc = await db.event_passes.find_one({"id": pass_id}, {"_id": 0})
    if not pass_doc or pass_doc.get("pass_status") != "ACTIVE":
        raise HTTPException(404, "Active pass not found")
    registration = await db.registrations.find_one({"id": pass_doc["registration_id"]}, {"_id": 0})
    raw = pass_doc.get("qr_token_encrypted") or pass_doc.get("qr_token")
    qr = qrcode.make(raw); qr_buffer = io.BytesIO(); qr.save(qr_buffer, format="PNG"); qr_buffer.seek(0)
    bg = _festival_gradient(); bg_buffer = io.BytesIO(); bg.save(bg_buffer, format="PNG"); bg_buffer.seek(0)
    output = io.BytesIO(); pdf = canvas.Canvas(output, pagesize=A4); pdf.setTitle("EUPHORIA Mega Event Pass")
    W, H = A4
    pdf.drawImage(ImageReader(bg_buffer), 0, 0, width=W, height=H)
    pdf.setFillColorRGB(0.03, 0.02, 0.08); pdf.setFillAlpha(0.55); pdf.rect(0, H - 108, W, 108, fill=1, stroke=0); pdf.setFillAlpha(1)
    pdf.setFillColorRGB(1, 1, 1); pdf.setFont("Helvetica-Bold", 36); pdf.drawString(42, H - 60, "EUPHORIA")
    pdf.setFillColorRGB(1, 0.86, 0.42); pdf.setFont("Helvetica-Bold", 10); pdf.drawString(44, H - 78, "MEGA EVENT  ·  OFFICIAL ENTRY PASS  ·  2026")
    pdf.setFillColorRGB(1, 1, 1); pdf.setFont("Helvetica-Bold", 11); pdf.drawRightString(W - 42, H - 58, registration["registration_number"])
    pdf.setFillColorRGB(1, 0.9, 0.7); pdf.setFont("Helvetica", 8); pdf.drawRightString(W - 42, H - 74, "REGISTRATION ID")
    pdf.setFillColorRGB(1, 1, 1); pdf.setFillAlpha(0.85); pdf.setFont("Helvetica", 9); pdf.drawString(42, H - 150, "PARTICIPANT"); pdf.setFillAlpha(1)
    pdf.setFillColorRGB(1, 1, 1); pdf.setFont("Helvetica-Bold", 30); pdf.drawString(42, H - 185, registration["participant_full_name"][:34])
    pdf.setFillColorRGB(1, 1, 1); pdf.setFillAlpha(0.85); pdf.setFont("Helvetica", 9); pdf.drawString(42, H - 235, "EVENT"); pdf.setFillAlpha(1)
    pdf.setFillColorRGB(1, 1, 1); pdf.setFont("Helvetica-Bold", 17); pdf.drawString(42, H - 258, registration["event_name"][:42])
    pdf.setFillColorRGB(1, 1, 1); pdf.setFillAlpha(0.85); pdf.setFont("Helvetica", 9); pdf.drawString(42, H - 290, "CATEGORY"); pdf.setFillAlpha(1)
    pdf.setFillColorRGB(0.05, 0.03, 0.12); pdf.setFillAlpha(0.35); pdf.roundRect(42, H - 322, 160, 26, 4, fill=1, stroke=0); pdf.setFillAlpha(1)
    pdf.setFillColorRGB(1, 0.88, 0.48); pdf.setFont("Helvetica-Bold", 12); pdf.drawString(52, H - 315, registration["event_category"][:24])
    pdf.setFillColorRGB(1, 1, 1); pdf.roundRect(42, 175, W - 84, 335, 16, fill=1, stroke=0)
    pdf.setFillColorRGB(0.06, 0.03, 0.14); pdf.setFont("Helvetica-Bold", 15); pdf.drawCentredString(W / 2, 470, "SCAN AT ENTRY GATE")
    pdf.setFillColorRGB(0.48, 0.22, 0.58); pdf.setFont("Helvetica", 9); pdf.drawCentredString(W / 2, 452, "PRESENT THIS QR TO ANY EUPHORIA SCANNER OPERATOR")
    pdf.drawImage(ImageReader(qr_buffer), (W - 220) / 2, 224, width=220, height=220)
    pdf.setFillColorRGB(0.32, 0.14, 0.44); pdf.setFont("Helvetica", 8); pdf.drawCentredString(W / 2, 205, "One scan only  ·  Do not share this pass  ·  Server-verified")
    pdf.setFillColorRGB(0.03, 0.02, 0.08); pdf.setFillAlpha(0.5); pdf.rect(0, 0, W, 148, fill=1, stroke=0); pdf.setFillAlpha(1)
    pdf.setFillColorRGB(1, 0.88, 0.48); pdf.setFont("Helvetica-Bold", 10); pdf.drawString(42, 118, "ENTRY INSTRUCTIONS")
    pdf.setFillColorRGB(1, 0.96, 0.86); pdf.setFont("Helvetica", 9)
    for i, line in enumerate(["Arrive at the EUPHORIA entry gate with this pass ready on your device or printed.", "Present the QR code to any scanner operator — verification is instant and server-side.", "This QR is valid for a single entry only. Sharing invalidates the pass automatically.", "Doors close at the announced start time. No re-entry without staff approval."]):
        pdf.drawString(42, 96 - i * 14, "•  " + line)
    pdf.setFillColorRGB(1, 1, 1); pdf.setFillAlpha(0.55); pdf.setFont("Helvetica", 8); pdf.drawString(42, 22, "EUPHORIA 2026  ·  mega event operations"); pdf.drawRightString(W - 42, 22, "euphoria-entry.system"); pdf.setFillAlpha(1)
    pdf.showPage(); pdf.save(); output.seek(0)
    await audit(user, "PASS_PDF_DOWNLOADED", "pass", pass_id)
    return Response(content=output.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="euphoria-{registration["registration_number"]}.pdf"'})

@api.post("/passes/{pass_id}/send")
async def send_pass(pass_id: str, user=Depends(admin_user)):
    pass_doc = await db.event_passes.find_one({"id": pass_id}, {"_id": 0}); registration = await db.registrations.find_one({"id": pass_doc["registration_id"]}, {"_id": 0}) if pass_doc else None
    if not pass_doc or not registration: raise HTTPException(404, "Pass not found")
    log_doc = {"id": str(uuid.uuid4()), "registration_id": registration["id"], "recipient_email": registration["email"], "email_type": "PASS_SENT", "status": "FAILED", "created_at": now_iso()}
    smtp_ready = all(os.environ.get(key) for key in ["SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM_EMAIL", "SMTP_FROM_NAME"])
    if not smtp_ready:
        log_doc["error_message"] = "SMTP is not configured on the backend"
        await db.email_logs.insert_one(log_doc)
        raise HTTPException(503, "SMTP is not configured. Add backend SMTP settings before sending passes.")
    raw = pass_doc.get("qr_token_encrypted") or pass_doc.get("qr_token"); pdf_response = await pass_pdf(pass_id, user); message = EmailMessage(); message["From"] = formataddr((os.environ["SMTP_FROM_NAME"], os.environ["SMTP_FROM_EMAIL"])); message["To"] = registration["email"]; message["Subject"] = "Your EUPHORIA Event Entry Pass"; message.set_content(f"Hello {registration['participant_full_name']},\n\nYour EUPHORIA event entry pass is attached. Please bring it to the event.")
    message.add_attachment(pdf_response.body, maintype="application", subtype="pdf", filename="euphoria-entry-pass.pdf")
    try:
        port = int(os.environ["SMTP_PORT"]); context = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(os.environ["SMTP_HOST"], port, context=context, timeout=20) as smtp: smtp.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"]); smtp.send_message(message)
        else:
            with smtplib.SMTP(os.environ["SMTP_HOST"], port, timeout=20) as smtp: smtp.ehlo(); smtp.starttls(context=context); smtp.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"]); smtp.send_message(message)
        log_doc["status"] = "SENT"; log_doc["sent_at"] = now_iso(); await db.event_passes.update_one({"id": pass_id}, {"$set": {"last_sent_at": now_iso()}})
    except Exception as exc:
        log_doc["error_message"] = type(exc).__name__; await db.email_logs.insert_one(log_doc); raise HTTPException(502, "Email delivery failed; the pass was not marked as sent.")
    await db.email_logs.insert_one(log_doc); await audit(user, "PASS_SENT", "pass", pass_id); return {"success": True, "status": "SENT"}

@api.get("/scanner-users")
async def scanner_users(user=Depends(admin_user)):
    return [public(x) async for x in db.users.find({"role": "SCANNER"}, {"_id": 0}).sort("created_at", -1)]

@api.post("/scanner-users")
async def create_scanner_user(body: ScannerUserInput, user=Depends(admin_user)):
    doc = {"id": str(uuid.uuid4()), "username": body.username.lower(), "email": f"{body.username.lower()}@scanner.euphoria.local", "display_name": body.display_name, "password_hash": hash_password(body.password), "role": "SCANNER", "is_active": True, "created_at": now_iso(), "updated_at": now_iso()}
    try: await db.users.insert_one(doc)
    except DuplicateKeyError: raise HTTPException(409, "Scanner username already exists")
    await audit(user, "SCANNER_USER_CREATED", "user", doc["id"]); return public(doc)

@api.get("/dashboard/stats")
async def dashboard(user=Depends(admin_user)):
    total = await db.registrations.count_documents({"is_active": True}); entered = await db.entries.count_documents({})
    return {"total_registrations": total, "total_entered": entered, "not_entered": max(0, total - entered), "entry_percentage": round((entered / total * 100), 2) if total else 0, "passes_generated": await db.event_passes.count_documents({"pass_status": "ACTIVE"}), "entries_today": await db.entries.count_documents({"server_date": datetime.now(timezone.utc).date().isoformat()}), "duplicate_attempts": await db.scan_attempts.count_documents({"status": "ALREADY_SCANNED"}), "invalid_attempts": await db.scan_attempts.count_documents({"status": "INVALID_QR"})}

@api.get("/dashboard/recent-scans")
async def recent_scans(user=Depends(admin_user)):
    return await db.scan_attempts.find({}, {"_id": 0}).sort("attempted_at", -1).limit(12).to_list(12)

@api.post("/scanner/verify")
async def verify_scan(body: ScanInput, user=Depends(scanner_user)):
    fingerprint = hashlib.sha256(body.token.encode()).hexdigest()[:16]; attempt = {"id": str(uuid.uuid4()), "scanner_user_id": user["id"], "token_fingerprint": fingerprint, "attempted_at": now_iso()}
    hashed = hashlib.sha256(body.token.encode()).hexdigest(); pass_doc = await db.event_passes.find_one({"qr_token_hash": hashed}, {"_id": 0})
    if not pass_doc: attempt.update(status="INVALID_QR", message="Invalid QR code"); await db.scan_attempts.insert_one(attempt); return {"success": False, "status": "INVALID_QR", "message": "This QR code is not registered in the EUPHORIA Entry System."}
    registration = await db.registrations.find_one({"id": pass_doc["registration_id"]}, {"_id": 0}); attempt.update(pass_id=pass_doc["id"], registration_id=registration["id"])
    if pass_doc.get("pass_status") != "ACTIVE" or not registration.get("is_active"):
        attempt.update(status="PASS_INACTIVE", message="Pass inactive"); await db.scan_attempts.insert_one(attempt); return {"success": False, "status": "PASS_INACTIVE", "message": "PASS INACTIVE — ENTRY DENIED"}
    event = await db.events.find_one({"status": "ACTIVE"}, {"_id": 0})
    if event and not (event["start_date"] <= datetime.now(timezone.utc).date().isoformat() <= event["end_date"]):
        attempt.update(status="EVENT_CLOSED", message="Entry closed"); await db.scan_attempts.insert_one(attempt); return {"success": False, "status": "EVENT_CLOSED", "message": "ENTRY CLOSED"}
    entry = {"id": str(uuid.uuid4()), "pass_id": pass_doc["id"], "registration_id": registration["id"], "event_id": pass_doc.get("event_id"), "scanner_user_id": user["id"], "scanned_at": now_iso(), "server_date": datetime.now(timezone.utc).date().isoformat(), "server_time": datetime.now(timezone.utc).strftime("%H:%M:%S"), "created_at": now_iso()}
    try:
        await db.entries.insert_one(entry)
        attempt.update(status="ENTRY_ALLOWED", message="Entry allowed"); await db.scan_attempts.insert_one(attempt); await audit(user, "ENTRY_ALLOWED", "entry", entry["id"])
        return {"success": True, "status": "ENTRY_ALLOWED", "message": "Entry allowed", "participant": {"name": registration["participant_full_name"], "registration_number": registration["registration_number"], "event": registration["event_name"], "category": registration["event_category"]}, "entry_time": entry["scanned_at"]}
    except DuplicateKeyError:
        previous = await db.entries.find_one({"pass_id": pass_doc["id"], "event_id": pass_doc.get("event_id")}, {"_id": 0})
        attempt.update(status="ALREADY_SCANNED", message="This pass has already been scanned"); await db.scan_attempts.insert_one(attempt)
        return {"success": False, "status": "ALREADY_SCANNED", "message": "This pass has already been scanned", "entry_time": previous.get("scanned_at") if previous else None, "participant": {"name": registration["participant_full_name"], "registration_number": registration["registration_number"]}}

@api.get("/scanner/today-count")
async def today_count(user=Depends(scanner_user)):
    return {"count": await db.entries.count_documents({"server_date": datetime.now(timezone.utc).date().isoformat()})}

@api.get("/audit-logs")
async def audit_logs(user=Depends(admin_user)):
    return await db.audit_logs.find({}, {"_id": 0}).sort("created_at", -1).limit(100).to_list(100)

app.include_router(api)
app.add_middleware(CORSMiddleware, allow_credentials=False, allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","), allow_methods=["*"], allow_headers=["*"])

@app.on_event("shutdown")
async def shutdown():
    client.close()