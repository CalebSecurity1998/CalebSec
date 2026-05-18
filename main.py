from fastapi import (
    FastAPI,
    Request,
    Form,
    Depends,
    HTTPException,
    status,
    BackgroundTasks,
    UploadFile,
    File
)
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
import json
import csv
import io
import os
import secrets
import math
import time
from collections import Counter, defaultdict, deque

from detection import run_all_detections
from database import (
    init_db,
    insert_log,
    insert_alert,
    get_logs,
    get_alerts,
    update_alert,
    delete_alert,
    clear_db,
    create_case,
    get_cases,
    update_case,
    delete_case,
    log_audit_event,
    get_audit_events
)
from macos_ingest import collect_macos_logs

app = FastAPI()
templates = Jinja2Templates(directory="templates")
security = HTTPBasic()

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"
ENABLE_MACOS_INGEST = os.getenv("ENABLE_MACOS_INGEST", "true").lower() == "true"

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "caleb")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-this-password")

ALERTS_PER_PAGE = 25
LOGS_PER_PAGE = 25
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_UPLOAD_RECORDS = 1000

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_ACTIONS = 20
rate_limit_buckets = defaultdict(deque)

init_db()


def get_client_ip(request: Request):
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def enforce_rate_limit(request: Request):
    now = time.time()
    ip = get_client_ip(request)
    bucket = rate_limit_buckets[ip]

    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
        bucket.popleft()

    if len(bucket) >= RATE_LIMIT_MAX_ACTIONS:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please wait before trying again."
        )

    bucket.append(now)


def require_admin(credentials: HTTPBasicCredentials = Depends(security)):
    username_ok = secrets.compare_digest(
        credentials.username.encode("utf-8"),
        ADMIN_USERNAME.encode("utf-8")
    )

    password_ok = secrets.compare_digest(
        credentials.password.encode("utf-8"),
        ADMIN_PASSWORD.encode("utf-8")
    )

    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username


def protected_admin_action(
    request: Request,
    admin: str = Depends(require_admin)
):
    enforce_rate_limit(request)
    return admin


def seed_demo_data_if_needed():
    if DEMO_MODE and len(get_logs()) == 0:
        with open("sample_logs/auth_logs.json", "r") as f:
            logs = json.load(f)

        alerts = run_all_detections(logs)

        for log in logs:
            insert_log(log)

        for alert in alerts:
            insert_alert(alert)

        log_audit_event(
            "system",
            "demo_seed",
            f"Seeded {len(logs)} demo logs and {len(alerts)} alerts."
        )


def paginate(items, page, page_size):
    total_items = len(items)
    total_pages = max(1, math.ceil(total_items / page_size))

    page = max(1, min(page, total_pages))

    start = (page - 1) * page_size
    end = start + page_size

    return items[start:end], page, total_pages


def redirect_with_notice(message: str):
    return RedirectResponse(
        url=f"/?notice={message}",
        status_code=303
    )


def process_log_batch(logs, actor, source_label):
    alerts = run_all_detections(logs)

    for log in logs:
        insert_log(log)

    for alert in alerts:
        insert_alert(alert)

    log_audit_event(
        actor,
        "ingest_complete",
        f"{source_label}: inserted {len(logs)} logs and generated {len(alerts)} alerts."
    )


def process_macos_batch(actor):
    logs = collect_macos_logs()
    process_log_batch(logs, actor, "macOS logs")


seed_demo_data_if_needed()


@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(
    request: Request,
    exc: StarletteHTTPException
):
    status_code = exc.status_code

    if status_code == 404:
        title = "Page Not Found"
        message = "The CalebSec page you requested does not exist."
    elif status_code == 401:
        title = "Admin Login Required"
        message = "This action requires valid CalebSec administrator credentials."
    elif status_code == 429:
        title = "Rate Limit Reached"
        message = "Too many protected actions were attempted too quickly. Please wait a moment."
    else:
        title = f"Request Error {status_code}"
        message = str(exc.detail) if exc.detail else "CalebSec could not complete that request."

    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={
            "status_code": status_code,
            "title": title,
            "message": message
        },
        status_code=status_code
    )


@app.exception_handler(Exception)
async def custom_server_error_handler(
    request: Request,
    exc: Exception
):
    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={
            "status_code": 500,
            "title": "Something Went Wrong",
            "message": "CalebSec ran into an unexpected issue. Please try again shortly."
        },
        status_code=500
    )


@app.get("/health")
async def health():
    return {"status": "ok", "app": "CalebSec"}


@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    q: str = "",
    severity: str = "",
    status: str = "",
    case_status: str = "",
    alert_page: int = 1,
    log_page: int = 1,
    notice: str = ""
):
    all_logs = get_logs()
    all_alerts = get_alerts()
    all_cases = get_cases()
    audit_events = get_audit_events(100)

    logs = all_logs
    alerts = all_alerts
    cases = all_cases

    if q:
        q_lower = q.lower()
        logs = [
            log for log in logs
            if q_lower in log.get("timestamp", "").lower()
            or q_lower in log.get("event_type", "").lower()
            or q_lower in log.get("username", "").lower()
            or q_lower in log.get("src_ip", "").lower()
            or q_lower in log.get("message", "").lower()
        ]

    if severity:
        alerts = [
            alert for alert in alerts
            if alert.get("severity", "").lower() == severity.lower()
        ]

    if status:
        alerts = [
            alert for alert in alerts
            if alert.get("status", "").lower() == status.lower()
        ]

    if case_status:
        cases = [
            case for case in cases
            if case.get("status", "").lower() == case_status.lower()
        ]

    paginated_alerts, alert_page, total_alert_pages = paginate(
        alerts,
        alert_page,
        ALERTS_PER_PAGE
    )

    paginated_logs, log_page, total_log_pages = paginate(
        logs,
        log_page,
        LOGS_PER_PAGE
    )

    severity_counts = dict(Counter(alert["severity"] for alert in all_alerts))
    event_counts = dict(Counter(log["event_type"] for log in all_logs))

    critical_alert_count = sum(
        1 for alert in all_alerts
        if alert.get("severity") == "Critical"
    )

    high_alert_count = sum(
        1 for alert in all_alerts
        if alert.get("severity") == "High"
    )

    open_alert_count = sum(
        1 for alert in all_alerts
        if alert.get("status") == "Open"
    )

    investigating_case_count = sum(
        1 for case in all_cases
        if case.get("status") == "Investigating"
    )

    total_alerts_for_chart = max(1, len(all_alerts))

    critical_percent = round(
        severity_counts.get("Critical", 0) / total_alerts_for_chart * 100,
        1
    )

    high_percent = round(
        severity_counts.get("High", 0) / total_alerts_for_chart * 100,
        1
    )

    medium_percent = round(
        severity_counts.get("Medium", 0) / total_alerts_for_chart * 100,
        1
    )

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "alerts": paginated_alerts,
            "logs": paginated_logs,
            "cases": cases,
            "audit_events": audit_events,
            "alert_count": len(alerts),
            "log_count": len(logs),
            "case_count": len(cases),
            "q": q,
            "severity": severity,
            "status": status,
            "case_status": case_status,
            "severity_counts": severity_counts,
            "event_counts": event_counts,
            "macos_ingest_enabled": ENABLE_MACOS_INGEST,
            "demo_mode": DEMO_MODE,
            "alert_page": alert_page,
            "log_page": log_page,
            "total_alert_pages": total_alert_pages,
            "total_log_pages": total_log_pages,
            "notice": notice,
            "critical_alert_count": critical_alert_count,
            "high_alert_count": high_alert_count,
            "open_alert_count": open_alert_count,
            "investigating_case_count": investigating_case_count,
            "critical_percent": critical_percent,
            "high_percent": high_percent,
            "medium_percent": medium_percent
        }
    )


@app.post("/ingest")
async def ingest_sample_logs(
    background_tasks: BackgroundTasks,
    admin: str = Depends(protected_admin_action)
):
    with open("sample_logs/auth_logs.json", "r") as f:
        logs = json.load(f)

    background_tasks.add_task(
        process_log_batch,
        logs,
        admin,
        "Sample logs"
    )

    log_audit_event(
        admin,
        "ingest_queued",
        f"Queued {len(logs)} sample logs for background processing."
    )

    return redirect_with_notice("Sample log ingestion queued")


@app.post("/ingest-macos")
async def ingest_macos_logs(
    background_tasks: BackgroundTasks,
    admin: str = Depends(protected_admin_action)
):
    if not ENABLE_MACOS_INGEST:
        return redirect_with_notice("macOS ingestion is disabled in hosted demo mode")

    background_tasks.add_task(process_macos_batch, admin)

    log_audit_event(
        admin,
        "macos_ingest_queued",
        "Queued macOS log collection for background processing."
    )

    return redirect_with_notice("macOS log ingestion queued")


@app.post("/upload-logs")
async def upload_logs(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    admin: str = Depends(protected_admin_action)
):
    raw = await file.read()

    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is too large. Maximum size is 2 MB."
        )

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file must be valid JSON."
        )

    if not isinstance(parsed, list):
        raise HTTPException(
            status_code=400,
            detail="Uploaded JSON must be a list of log objects."
        )

    if len(parsed) > MAX_UPLOAD_RECORDS:
        raise HTTPException(
            status_code=400,
            detail="Uploaded JSON has too many records. Maximum is 1000."
        )

    for record in parsed:
        if not isinstance(record, dict):
            raise HTTPException(
                status_code=400,
                detail="Every uploaded log entry must be a JSON object."
            )

    background_tasks.add_task(
        process_log_batch,
        parsed,
        admin,
        f"Uploaded file {file.filename}"
    )

    log_audit_event(
        admin,
        "upload_queued",
        f"Queued uploaded file {file.filename} with {len(parsed)} records."
    )

    return redirect_with_notice("Uploaded logs queued for analysis")


@app.post("/alert/{alert_id}/update")
async def alert_update(
    alert_id: int,
    status: str = Form(...),
    notes: str = Form(""),
    admin: str = Depends(protected_admin_action)
):
    update_alert(alert_id, status, notes)

    log_audit_event(
        admin,
        "alert_updated",
        f"Alert #{alert_id} updated to status {status}."
    )

    return redirect_with_notice("Alert updated")


@app.post("/alert/{alert_id}/delete")
async def alert_delete(
    alert_id: int,
    admin: str = Depends(protected_admin_action)
):
    delete_alert(alert_id)

    log_audit_event(
        admin,
        "alert_deleted",
        f"Deleted alert #{alert_id} and any linked cases."
    )

    return redirect_with_notice("Alert deleted")


@app.post("/alert/{alert_id}/case")
async def create_case_route(
    alert_id: int,
    title: str = Form(...),
    notes: str = Form(""),
    admin: str = Depends(protected_admin_action)
):
    create_case(alert_id, title, notes)

    log_audit_event(
        admin,
        "case_created",
        f"Created case from alert #{alert_id}: {title}"
    )

    return redirect_with_notice("Case created")


@app.post("/case/{case_id}/update")
async def case_update(
    case_id: int,
    status: str = Form(...),
    notes: str = Form(""),
    admin: str = Depends(protected_admin_action)
):
    update_case(case_id, status, notes)

    log_audit_event(
        admin,
        "case_updated",
        f"Case #{case_id} updated to status {status}."
    )

    return redirect_with_notice("Case updated")


@app.post("/case/{case_id}/delete")
async def case_delete(
    case_id: int,
    admin: str = Depends(protected_admin_action)
):
    delete_case(case_id)

    log_audit_event(
        admin,
        "case_deleted",
        f"Deleted case #{case_id}."
    )

    return redirect_with_notice("Case deleted")


@app.post("/clear")
async def clear_data(admin: str = Depends(protected_admin_action)):
    clear_db()
    seed_demo_data_if_needed()

    log_audit_event(
        admin,
        "database_cleared",
        "Cleared logs, alerts, and cases."
    )

    return redirect_with_notice("Database cleared")


@app.get("/export-alerts")
async def export_alerts(admin: str = Depends(protected_admin_action)):
    alerts = get_alerts()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Rule",
        "Severity",
        "Source IP",
        "MITRE",
        "Status",
        "Notes",
        "Occurrences",
        "First Seen",
        "Last Seen",
        "Description"
    ])

    for alert in alerts:
        writer.writerow([
            alert["id"],
            alert["rule"],
            alert["severity"],
            alert["src_ip"],
            alert["mitre"],
            alert["status"],
            alert["notes"],
            alert.get("occurrence_count", ""),
            alert.get("first_seen", ""),
            alert.get("last_seen", ""),
            alert["description"]
        ])

    output.seek(0)

    log_audit_event(
        admin,
        "alerts_exported",
        f"Exported {len(alerts)} alerts to CSV."
    )

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=calebsec_alerts.csv"
        }
    )
