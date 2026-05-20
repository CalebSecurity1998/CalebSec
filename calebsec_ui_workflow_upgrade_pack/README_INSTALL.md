# CalebSec UI + Workflow Upgrade Pack

This package adds polish and workflow improvements to the CalebSec SIEM/SOC platform on your existing `soc-upgrade` branch.

## What this pack adds

- SOC Triage and Threat Intel navigation links
- Detection Rules page
- Analyst Activity Feed
- Improved demo alerts
- Realistic SOC event generator
- Threat severity color styling
- Detection rule documentation
- Architecture diagram for GitHub README
- README sections for "Why This Matters" and screenshots
- Optional route snippets for `main.py`

## Files included

```text
calebsec_ui_workflow_upgrade_pack/
├── README_INSTALL.md
├── enhanced_demo_data.py
├── workflow_extensions.py
├── routes_to_add_to_main.py
├── dashboard_nav_snippet.html
├── static/severity.css
├── templates/detection_rules.html
├── templates/activity_feed.html
├── docs/architecture_diagram.md
├── docs/why_this_matters.md
├── docs/detection_rules.md
└── docs/readme_sections_to_add.md
```

## Safe install process

Make sure you are on your existing upgrade branch:

```bash
cd ~/mini-siem
git checkout soc-upgrade
git status
```

Copy the files into your project:

```bash
cp enhanced_demo_data.py .
cp workflow_extensions.py .
cp routes_to_add_to_main.py .
cp dashboard_nav_snippet.html .
cp static/severity.css static/
cp templates/detection_rules.html templates/
cp templates/activity_feed.html templates/
cp docs/*.md docs/
```

If your repo does not already have `static/` or `docs/`, create them first:

```bash
mkdir -p static docs templates
```

## Update `main.py`

Add this near your imports:

```python
from workflow_extensions import (
    init_workflow_tables,
    get_detection_rules,
    get_recent_activity,
    log_activity,
    seed_enhanced_demo_data
)
```

After your existing database initialization lines, add:

```python
init_workflow_tables()
```

Paste the contents of `routes_to_add_to_main.py` near the bottom of `main.py`.

## Update dashboard navigation

Add the contents of `dashboard_nav_snippet.html` to your top navigation area.

## Test locally

```bash
uvicorn main:app --reload
```

Open:

```text
http://127.0.0.1:8000/detection-rules
http://127.0.0.1:8000/activity-feed
```

## Commit safely

```bash
git add .
git commit -m "Add SOC workflow polish and detection rules"
git push origin soc-upgrade
```
