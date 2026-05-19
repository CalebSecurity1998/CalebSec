# CalebSec SOC Upgrade Pack

This adds two major SOC-style features to your existing CalebSec SIEM:

1. SOC Alert Triage Simulator
2. Threat Intelligence / IOC Enrichment Dashboard

Designed for your existing FastAPI + SQLite project folder:

```bash
~/mini-siem
```

## What this upgrade adds

- IOC lookup for IPs, domains, URLs, hashes, and email indicators
- Local threat intelligence scoring without API keys
- Optional external enrichment fields you can expand later
- Alert triage statuses:
  - New
  - Investigating
  - Escalated
  - Resolved
  - False Positive
- Analyst notes
- Assigned analyst
- Risk score
- MITRE ATT&CK mapping
- Sample SOC alert generator
- New `/threat-intel` page
- New `/soc-triage` page

---

## Install Steps

From your Mac Terminal:

```bash
cd ~/mini-siem
cp /path/to/soc_extensions.py .
cp /path/to/threat_intel.py .
cp /path/to/install_soc_upgrade.py .
cp /path/to/templates/threat_intel.html templates/
cp /path/to/templates/soc_triage.html templates/
python install_soc_upgrade.py
```

Then open `main.py` and add this import near your other imports:

```python
from soc_extensions import (
    init_soc_tables,
    generate_sample_soc_alerts,
    get_triage_alerts,
    update_triage_alert,
    lookup_ioc,
    get_ioc_history
)
```

After your existing `init_db()` line, add:

```python
init_soc_tables()
```

Then paste the routes from `routes_to_add_to_main.py` near the bottom of `main.py`.

Finally run:

```bash
uvicorn main:app --reload
```

Open:

```text
http://127.0.0.1:8000/soc-triage
http://127.0.0.1:8000/threat-intel
```

---

## Recommended Resume Bullet Later

Developed an integrated SOC operations platform featuring SIEM alert monitoring, analyst triage workflows, IOC enrichment, threat intelligence scoring, MITRE ATT&CK mapping, and case-style investigation functionality using FastAPI and SQLite.
