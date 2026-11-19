import sys
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(PROJECT_ROOT / ".env", override=True)

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from flows.incident_flow import run_incident_investigation
from schemas.incident_models import RawAlertInput

app = FastAPI(title="DCoders | Autonomous SOC Incident Investigator")
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "templates"))

DEFAULT_ALERT = {
    "alert_id": "ALT-2026-0042",
    "source": "SIEM / Linux Auth & EDR",
    "timestamp": "2026-11-19T02:15:10Z",
    "summary": "Anomalous SSH login followed by remote shell script execution on prod-app-01",
    "source_ip": "185.220.101.45",
    "target_user": "deploy_bot",
    "target_host": "prod-app-01",
}


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"sample_alert": DEFAULT_ALERT, "report": None, "error": None},
    )


@app.post("/investigate", response_class=HTMLResponse)
async def investigate_form(
    request: Request,
    alert_id: str = Form(...),
    source: str = Form(...),
    timestamp: str = Form(...),
    summary: str = Form(...),
    source_ip: str = Form(""),
    target_user: str = Form(""),
    target_host: str = Form(""),
):
    alert = RawAlertInput(
        alert_id=alert_id,
        source=source,
        timestamp=timestamp,
        summary=summary,
        source_ip=source_ip.strip() or None,
        target_user=target_user.strip() or None,
        target_host=target_host.strip() or None,
    )
    try:
        report = run_incident_investigation(alert)
        error = None
    except Exception as exc:
        report = None
        error = str(exc)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"sample_alert": alert.model_dump(), "report": report, "error": error},
    )


@app.post("/api/investigate")
async def investigate_api(alert: RawAlertInput):
    return run_incident_investigation(alert)