# Suricata, Zeek, and SOAR Network Operations Upgrade

CalebSec offers an **optional network sensor and SOAR integration pack** designed for the existing `calebsec_siem_pro/` FastAPI application. These features become available **only after installing the pack** and configuring external sensors. The integration extends the existing SQLite-backed SIEM without replacing the dashboard, alerts, cases, or authentication.

## Capabilities

| Module | Included functionality |
| --- | --- |
| Suricata | Ingest EVE JSON/JSONL events; map intrusion signatures and severities into CalebSec alerts |
| Zeek | Ingest JSON `conn`, `dns`, `http`, `ssl`, `notice` and other network logs; search network history |
| Correlation | Associate events by Community ID, or by network tuple and timestamp when available |
| SOAR | Local IOC-list enrichment; playbook execution history; audit records; optional case creation for high/critical Suricata alerts |

## Install

1. Back up your local CalebSec checkout and SQLite database. Download and extract `CalebSec_Suricata_Zeek_SOAR_Upgrade.zip`.
2. From the extracted ZIP directory run:

   ```bash
   python install.py --repo /path/to/CalebSec
   ```

3. Review `git diff` and `git status` in your repository checkout. The installer adds `calebsec_siem_pro/network_ops/`, registers a router in `calebsec_siem_pro/main.py`, and adds this documentation to the root `README.md`. Local `.bak` files must **not** be committed.
4. Set a strong private sensor token (keep it out of source control):

   ```bash
   export CALEBSEC_SENSOR_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(36))')"
   ```

5. Start the existing SIEM as usual:

   ```bash
   cd /path/to/CalebSec/calebsec_siem_pro
   pip install -r requirements.txt
   python -m uvicorn main:app --reload
   ```

6. Sign in as an administrator, then open `http://127.0.0.1:8000/network-ops`.

## Ship sample sensor events

With CalebSec running and the **same** `CALEBSEC_SENSOR_TOKEN` configured in the API process and your local shell, run these from the extracted ZIP directory:

```bash
curl -X POST http://127.0.0.1:8000/api/network-ops/ingest/suricata \
  -H "Authorization: Bearer $CALEBSEC_SENSOR_TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @examples/suricata-eve.jsonl

curl -X POST http://127.0.0.1:8000/api/network-ops/ingest/zeek \
  -H "Authorization: Bearer $CALEBSEC_SENSOR_TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @examples/zeek-conn.jsonl
```

The API accepts JSON objects, arrays, and JSONL batches up to 2 MiB and 1,000 records per request. Use `X-Zeek-Log-Type: dns` (or another log type) for Zeek records whose log type cannot be inferred. Configure Zeek to emit **JSON**, not its default TSV output. Production sensors require their own network deployment and a reliable HTTPS collector; installing this pack does **not** install sensors, inspect traffic automatically, or start a shipping daemon. A basic local example is included in `scripts/ship_jsonl.py`.

## SOAR and security controls

- `CALEBSEC_AUTO_SOAR=true` by default: safe triage and case creation for high/critical Suricata alerts; set `false` to disable automatic execution.
- `CALEBSEC_NETWORK_MAX_AGE_MINUTES=10` by default: cross-source correlation window.
- No automatic firewall changes, endpoint isolation, or externally executed response actions are included. Suggested IP blocking is **review-only**.
- IOC enrichment uses a local list, not external IP reputation APIs.
- Sensor ingestion uses a bearer token; network UI and manual actions require the existing CalebSec admin session, and interactive actions use CSRF protection.
- Always configure HTTPS, strong admin/session secrets, retention policies, and least-privilege network access before any externally exposed deployment. Hosted FastAPI on Render/GitHub cannot passively capture your local network.

## Tests and limits

Run `python -m unittest discover -s tests -v` from the extracted upgrade folder. This is a portfolio/lab feature, not a certified production IDS/SOAR product. Existing CalebSec alert deduplication and SQLite limitations still apply. See `README_INSTALL.md` in the pack for additional details.
