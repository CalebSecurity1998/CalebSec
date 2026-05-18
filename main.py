from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
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
from collections import Counter

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
    delete_case
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

init_db()


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


def seed_demo_data_if_needed():
    if DEMO_MODE and len(get_logs()) == 0:
        with open("sample_logs/auth_logs.json", "r") as f:
            logs = json.load(f)

        alerts = run_all_detections(logs)

        for log in logs:
            insert_log(log)

        for alert in alerts:
            insert_alert(alert)


def paginate(items, page, page_size):
    total_items = len(items)
    total_pages = max(1, math.ceil(total_items / page_size))

    page = max(1, min(page, total_pages))

    start = (page - 1) * page_size
    end = start + page_size

    return items[start:end], page, total_pages


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
    alert_page: int = 1,
    log_page: int = 1
):
    all_logs = get_logs()
    all_alerts = get_alerts()
    cases = get_cases()

    logs = all_logs
    alerts = all_alerts

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

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "alerts": paginated_alerts,
            "logs": paginated_logs,
            "cases": cases,
            "alert_count": len(alerts),
            "log_count": len(logs),
            "case_count": len(cases),
            "q": q,
            "severity": severity,
            "status": status,
            "severity_counts": severity_counts,
            "event_counts": event_counts,
            "macos_ingest_enabled": ENABLE_MACOS_INGEST,
            "demo_mode": DEMO_MODE,
            "alert_page": alert_page,
            "log_page": log_page,
            "total_alert_pages": total_alert_pages,
            "total_log_pages": total_log_pages
        }
    )


@app.post("/ingest")
async def ingest_sample_logs(admin: str = Depends(require_admin)):
    with open("sample_logs/auth_logs.json", "r") as f:
        logs = json.load(f)

    alerts = run_all_detections(logs)

    for log in logs:
        insert_log(log)

    for alert in alerts:
        insert_alert(alert)

    return RedirectResponse(url="/", status_code=303)


@app.post("/ingest-macos")
async def ingest_macos_logs(admin: str = Depends(require_admin)):
    if not ENABLE_MACOS_INGEST:
        return RedirectResponse(url="/", status_code=303)

    logs = collect_macos_logs()
    alerts = run_all_detections(logs)

    for log in logs:
        insert_log(log)

    for alert in alerts:
        insert_alert(alert)

    return RedirectResponse(url="/", status_code=303)


@app.post("/alert/{alert_id}/update")
async def alert_update(
    alert_id: int,
    status: str = Form(...),
    notes: str = Form(""),
    admin: str = Depends(require_admin)
):
    update_alert(alert_id, status, notes)
    return RedirectResponse(url="/", status_code=303)


@app.post("/alert/{alert_id}/delete")
async def alert_delete(
    alert_id: int,
    admin: str = Depends(require_admin)
):
    delete_alert(alert_id)
    return RedirectResponse(url="/", status_code=303)


@app.post("/alert/{alert_id}/case")
async def create_case_route(
    alert_id: int,
    title: str = Form(...),
    notes: str = Form(""),
    admin: str = Depends(require_admin)
):
    create_case(alert_id, title, notes)
    return RedirectResponse(url="/", status_code=303)


@app.post("/case/{case_id}/update")
async def case_update(
    case_id: int,
    status: str = Form(...),
    notes: str = Form(""),
    admin: str = Depends(require_admin)
):
    update_case(case_id, status, notes)
    return RedirectResponse(url="/", status_code=303)


@app.post("/case/{case_id}/delete")
async def case_delete(
    case_id: int,
    admin: str = Depends(require_admin)
):
    delete_case(case_id)
    return RedirectResponse(url="/", status_code=303)


@app.post("/clear")
async def clear_data(admin: str = Depends(require_admin)):
    clear_db()
    seed_demo_data_if_needed()
    return RedirectResponse(url="/", status_code=303)


@app.get("/export-alerts")
async def export_alerts(admin: str = Depends(require_admin)):
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

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=calebsec_alerts.csv"
        }
    )
