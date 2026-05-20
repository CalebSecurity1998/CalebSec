@app.get("/detection-rules", response_class=HTMLResponse)
async def detection_rules_page(request: Request):
    rules = get_detection_rules()
    return templates.TemplateResponse("detection_rules.html", {
        "request": request,
        "rules": rules
    })

@app.get("/activity-feed", response_class=HTMLResponse)
async def activity_feed_page(request: Request):
    activity = get_recent_activity()
    return templates.TemplateResponse("activity_feed.html", {
        "request": request,
        "activity": activity
    })

@app.post("/seed-enhanced-demo")
async def seed_enhanced_demo():
    seed_enhanced_demo_data()
    return RedirectResponse(url="/", status_code=303)
