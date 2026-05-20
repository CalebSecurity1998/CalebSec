@app.get("/soc-triage", response_class=HTMLResponse)
async def soc_triage_page(request: Request, status: str = "", severity: str = ""):
    alerts = get_triage_alerts(status=status or None, severity=severity or None)
    return templates.TemplateResponse("soc_triage.html", {
        "request": request,
        "alerts": alerts,
        "selected_status": status,
        "selected_severity": severity
    })

@app.post("/soc-triage/generate")
async def soc_triage_generate():
    generate_sample_soc_alerts()
    return RedirectResponse(url="/soc-triage", status_code=303)

@app.post("/soc-triage/update/{alert_id}")
async def soc_triage_update(
    alert_id: int,
    status: str = Form(...),
    analyst_notes: str = Form(""),
    assigned_to: str = Form("")
):
    update_triage_alert(alert_id, status, analyst_notes, assigned_to)
    return RedirectResponse(url="/soc-triage", status_code=303)

@app.get("/threat-intel", response_class=HTMLResponse)
async def threat_intel_page(request: Request):
    history = get_ioc_history()
    return templates.TemplateResponse("threat_intel.html", {
        "request": request,
        "result": None,
        "history": history
    })

@app.post("/threat-intel", response_class=HTMLResponse)
async def threat_intel_lookup(
    request: Request,
    ioc_value: str = Form(...),
    ioc_type: str = Form("auto")
):
    result = lookup_ioc(ioc_value, ioc_type)
    history = get_ioc_history()

    return templates.TemplateResponse("threat_intel.html", {
        "request": request,
        "result": result,
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "history": history
    })
