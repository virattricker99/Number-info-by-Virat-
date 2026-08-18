# VIRAT KING DEVELOPER ..
— Number Validation Website

This project turns the supplied single-file Flask application into a structured website with a separate **HTML/CSS/JavaScript frontend**, a Python API, a database audit model, and Render deployment configuration. The original terminal-style frontend direction is preserved, while the backend uses a proper international-number parser instead of manual prefix concatenation.

> **Scope:** This tool is for consent-based technical number validation. It returns only number formatting, validity, country/region, carrier, and line type. It deliberately does **not** return a person's identity, address, social accounts, location, call records, or any other private personal information.

## Features

| Area | Implementation |
| --- | --- |
| Frontend | Original green terminal visual language, responsive HTML/CSS/JS, consent gate, safe DOM rendering, live status display. |
| Validation | `phonenumbers` parses local and international input and produces standards-based E.164 formatting. |
| Live provider | Veriphone integration runs strictly server-side; its key is never sent to the browser. A local-metadata mode remains available when no key is configured. |
| Database | SQLAlchemy supports Render PostgreSQL; audit events save only a salted one-way number fingerprint, not raw phone numbers. |
| Reliability | API timeouts, limited retries, in-memory response caching, explicit health endpoint, and sanitized upstream errors. |
| Abuse controls | Per-client rate limiting and a mandatory authorization confirmation in both frontend and backend. |

## Local setup

Create and activate a virtual environment, then install dependencies.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export DEFAULT_COUNTRY=IN
export SECRET_KEY="replace-with-a-long-random-value"
export LOOKUP_AUDIT_PEPPER="replace-with-a-different-long-random-value"
export VERIPHONE_API_KEY="your-veriphone-key"  # optional; enables live carrier/line-type data
python app.py
```

Open `http://127.0.0.1:5000`. With no `VERIPHONE_API_KEY`, the application safely performs local parsing and formatting only. With a valid key, it requests live carrier and line-type metadata from Veriphone. The current Veriphone v2 reference documents its `/v2/verify` endpoint, supported country-default behavior, and technical response fields. [1]

## API contract

The browser calls the versioned endpoint shown below. The legacy `/api/lookup` path is retained for compatibility with the supplied frontend.

```http
POST /api/v1/lookup
Content-Type: application/json

{
  "number": "+91 98765 43210",
  "consent": true
}
```

A successful response contains a `result` object with `msisdn`, `valid`, `country`, `country_code`, `region`, `carrier`, `line_type`, `international`, `local`, `source`, and `live`. The public health check is available at `GET /health` and reports database connectivity without revealing secrets.

## Render deployment

The included [`render.yaml`](./render.yaml) is a Render Blueprint. Push this directory to a Git repository and create a new Blueprint deployment in Render. Render will provision the web service and PostgreSQL database specified in that file. Set `VERIPHONE_API_KEY` as a secret in the Render dashboard before expecting live carrier and line-type results; it is intentionally marked `sync: false` so no key enters source control.

Render's free services can sleep when inactive, and external-platform runtime behavior can differ from local development. Test `/health`, a local-format lookup, and an authorized live lookup after deployment. You can alternatively use Manus's built-in hosting for the frontend workflow, but this Python/Render configuration is included because Render was requested.

The default `RATELIMIT_STORAGE_URI=memory://` is suitable for the single-worker command in `render.yaml`. If you later scale to multiple workers or instances, provision a managed Redis service and set `RATELIMIT_STORAGE_URI` to its private connection URL so rate-limit counters are shared.

## Test command

```bash
python -m unittest discover -s tests -v
```

## References

[1] [Veriphone API Reference (v2)](https://veriphone.io/docs/v2)
