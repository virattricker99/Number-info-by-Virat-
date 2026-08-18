"""
Privacy-safe, consent-based phone-number validation and carrier lookup service.
This service intentionally returns technical phone-number metadata only: formatting,
country/region, carrier and line type. It never attempts to identify an individual,
retrieve addresses, social accounts, call records, or other private personal data.

Combined single-file app: backend + frontend.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from threading import Lock
from typing import Any

import phonenumbers
import requests
from cachetools import TTLCache
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from werkzeug.middleware.proxy_fix import ProxyFix
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""


# Database holds anonymised operational audit records only, never raw phone numbers.
db = SQLAlchemy(model_class=Base)
limiter = Limiter(key_func=get_remote_address, default_limits=[])
cache: TTLCache[str, dict[str, Any]] = TTLCache(maxsize=1_000, ttl=300)
cache_lock = Lock()


class LookupAudit(db.Model):
    """Minimal audit event for abuse monitoring and reliability diagnostics."""

    __tablename__ = "lookup_audits"

    id: Mapped[int] = mapped_column(primary_key=True)
    number_fingerprint: Mapped[str] = mapped_column(db.String(64), index=True, nullable=False)
    country_code: Mapped[str] = mapped_column(db.String(2), nullable=False, default="")
    source: Mapped[str] = mapped_column(db.String(32), nullable=False)
    outcome: Mapped[str] = mapped_column(db.String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc), nullable=False)


class ProviderError(Exception):
    """A sanitized error that can safely be presented to API clients."""

    def __init__(self, code: str, http_status: int = 502):
        super().__init__(code)
        self.code = code
        self.http_status = http_status


def build_http_session() -> requests.Session:
    """Create a conservative retrying HTTP client for the upstream provider."""
    retry = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        raise_on_status=False,
    )
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    session.mount("https://", adapter)
    return session


def normalize_database_url(url: str) -> str:
    """Keep legacy Render PostgreSQL URLs compatible with SQLAlchemy 2."""
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def parse_number(raw: Any, default_country: str) -> tuple[str, dict[str, Any]]:
    """Parse an entered number using libphonenumber rather than manual country-prefix logic."""
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 40:
        raise ValueError("INVALID_NUMBER")

    try:
        parsed = phonenumbers.parse(raw.strip(), default_country)
    except phonenumbers.NumberParseException as exc:
        raise ValueError("INVALID_NUMBER") from exc

    if not phonenumbers.is_possible_number(parsed):
        raise ValueError("INVALID_NUMBER")

    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    region_code = phonenumbers.region_code_for_number(parsed) or ""
    local_valid = phonenumbers.is_valid_number(parsed)
    return e164, {
        "msisdn": e164,
        "valid": local_valid,
        "country": "",
        "country_code": region_code,
        "region": "",
        "carrier": "",
        "line_type": "unknown",
        "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "local": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
    }


def compact_string(value: Any, limit: int = 120) -> str:
    """Limit provider strings before returning them to a browser."""
    return str(value or "").strip()[:limit]


def map_provider_result(payload: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    """Expose only the documented technical fields from the lookup provider."""
    return {
        "msisdn": compact_string(payload.get("e164") or fallback["msisdn"], 32),
        "valid": bool(payload.get("phone_valid")),
        "country": compact_string(payload.get("country")),
        "country_code": compact_string(payload.get("country_code"), 2),
        "region": compact_string(payload.get("phone_region")),
        "carrier": compact_string(payload.get("carrier")),
        "line_type": compact_string(payload.get("phone_type"), 32) or "unknown",
        "international": compact_string(payload.get("international_number") or fallback["international"], 48),
        "local": compact_string(payload.get("local_number") or fallback["local"], 48),
    }


def fetch_live_lookup(app: Flask, e164: str, fallback: dict[str, Any]) -> dict[str, Any]:
    """Use Veriphone server-side; the browser never receives the API key."""
    api_key = app.config["VERIPHONE_API_KEY"]
    if not api_key:
        return {**fallback, "source": "local_metadata", "live": False}

    try:
        response = app.extensions["lookup_http"].get(
            app.config["VERIPHONE_URL"],
            params={"phone": e164, "default_country": app.config["DEFAULT_COUNTRY"]},
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=app.config["UPSTREAM_TIMEOUT_SECONDS"],
        )
    except requests.Timeout as exc:
        raise ProviderError("UPSTREAM_TIMEOUT", 504) from exc
    except requests.RequestException as exc:
        app.logger.warning("Phone provider request failed: %s", exc.__class__.__name__)
        raise ProviderError("UPSTREAM_UNAVAILABLE", 502) from exc

    if response.status_code in (401, 403):
        raise ProviderError("UPSTREAM_CONFIGURATION_ERROR", 503)
    if response.status_code == 402:
        raise ProviderError("UPSTREAM_CREDITS_EXHAUSTED", 503)
    if response.status_code >= 500:
        raise ProviderError("UPSTREAM_UNAVAILABLE", 502)
    if response.status_code != 200:
        raise ProviderError("UPSTREAM_REJECTED_REQUEST", 422)

    try:
        payload = response.json()
    except ValueError as exc:
        raise ProviderError("UPSTREAM_INVALID_RESPONSE", 502) from exc

    if payload.get("status") != "success":
        # The provider uses this response for syntactically invalid and unsupported numbers.
        return {**fallback, "valid": False, "source": "veriphone", "live": True}

    return {**map_provider_result(payload, fallback), "source": "veriphone", "live": True}


def fingerprint_number(e164: str, pepper: str) -> str:
    """Create an irreversible identifier for audit correlation without storing the number."""
    return hashlib.sha256(f"{pepper}:{e164}".encode("utf-8")).hexdigest()


def record_audit(app: Flask, e164: str, result: dict[str, Any], outcome: str) -> None:
    """Record a non-identifying audit row; failure must not block a valid lookup."""
    try:
        db.session.add(
            LookupAudit(
                number_fingerprint=fingerprint_number(e164, app.config["LOOKUP_AUDIT_PEPPER"]),
                country_code=compact_string(result.get("country_code"), 2),
                source=compact_string(result.get("source"), 32),
                outcome=outcome,
            )
        )
        db.session.commit()
    except Exception:  # Audit-only path: retain service availability and avoid exposing internals.
        db.session.rollback()
        app.logger.exception("Could not write lookup audit event")


def lookup_technical_metadata(app: Flask, raw_number: Any) -> tuple[dict[str, Any], bool]:
    """Return one technical lookup result while retaining no raw input in persistent storage."""
    e164, fallback = parse_number(raw_number, app.config["DEFAULT_COUNTRY"])

    with cache_lock:
        cached = cache.get(e164)
    if cached is not None:
        record_audit(app, e164, cached, "cached_success")
        return cached, True

    try:
        result = fetch_live_lookup(app, e164, fallback)
    except ProviderError as exc:
        record_audit(app, e164, {"country_code": fallback["country_code"], "source": "veriphone"}, exc.code)
        raise
    with cache_lock:
        cache[e164] = result
    record_audit(app, e164, result, "success")
    return result, False


# ─── EMBEDDED FRONTEND HTML ────────────────────────────────────────────────
INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0" />
    <meta name="description" content="Consent-based phone number validation with technical carrier and line-type metadata." />
    <title>VIRAT KING DEVELOPER — Number Intelligence</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;900&family=Share+Tech+Mono&family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" />
    <style>
        /* ── ROOT VARIABLES ── */
        :root {
            --grn: #00ff41;
            --drk: #0a0a0f;
            --blk: #000000;
            --sky: #4fc3ff;
            --sky-glow: 0 0 25px rgba(79, 195, 255, 0.3);
            --sky-subtle: rgba(79, 195, 255, 0.08);
            --red: #ff1744;
            --muted: #8899aa;
            --white: #f0f4ff;
            --glow-green: 0 0 20px rgba(0, 255, 65, 0.25);
            --glow-sky: 0 0 30px rgba(79, 195, 255, 0.2);
            --border-glow: 0 0 15px rgba(79, 195, 255, 0.15);
            --card-bg: rgba(10, 14, 23, 0.92);
            --font-mono: 'Share Tech Mono', monospace;
            --font-display: 'Orbitron', monospace;
            --font-body: 'Inter', sans-serif;
        }

        /* ── RESET & BASE ── */
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html {
            scroll-behavior: smooth;
        }

        body {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            background: var(--drk);
            color: var(--white);
            font-family: var(--font-body);
            overflow-x: hidden;
            position: relative;
        }

        /* ── SCANLINE OVERLAY ── */
        body::after {
            position: fixed;
            z-index: 1;
            inset: 0;
            pointer-events: none;
            background:
                linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.20) 50%),
                linear-gradient(90deg, rgba(79, 195, 255, 0.03), rgba(0, 255, 65, 0.02), rgba(79, 195, 255, 0.03));
            background-size: 100% 3px, 4px 100%;
            content: "";
        }

        /* ── ANIMATED GRID BG ── */
        body::before {
            position: fixed;
            z-index: 0;
            inset: 0;
            background-image:
                linear-gradient(rgba(79, 195, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(79, 195, 255, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            content: "";
            animation: gridMove 20s linear infinite;
            pointer-events: none;
        }

        @keyframes gridMove {
            0% {
                transform: translate(0, 0);
            }
            100% {
                transform: translate(50px, 50px);
            }
        }

        /* ── TYPOGRAPHY ── */
        .font-mono {
            font-family: var(--font-mono);
        }
        .font-display {
            font-family: var(--font-display);
        }

        /* ── SCROLLBAR ── */
        ::-webkit-scrollbar {
            width: 6px;
        }
        ::-webkit-scrollbar-track {
            background: var(--blk);
        }
        ::-webkit-scrollbar-thumb {
            background: var(--sky);
            border-radius: 10px;
            box-shadow: var(--sky-glow);
        }

        /* ── UTILITY ── */
        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 0 20px;
            width: 100%;
            position: relative;
            z-index: 2;
        }

        /* ── OVERLAY (Privacy Consent) ── */
        .overlay {
            position: fixed;
            z-index: 1000;
            inset: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            background: rgba(0, 0, 0, 0.94);
            backdrop-filter: blur(8px);
            transition: opacity 0.4s ease, visibility 0.4s ease;
        }
        .overlay.hidden {
            visibility: hidden;
            opacity: 0;
            pointer-events: none;
        }
        .overlay-box {
            width: min(520px, 92%);
            padding: 44px 38px;
            border: 2px solid var(--sky);
            background: var(--card-bg);
            box-shadow: 0 0 60px rgba(79, 195, 255, 0.15), inset 0 0 60px rgba(79, 195, 255, 0.03);
            text-align: center;
            border-radius: 12px;
            position: relative;
            overflow: hidden;
        }
        .overlay-box::before {
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: conic-gradient(from 0deg, transparent, rgba(79, 195, 255, 0.04), transparent, rgba(79, 195, 255, 0.04), transparent);
            animation: spinGlow 12s linear infinite;
            content: "";
            pointer-events: none;
        }
        @keyframes spinGlow {
            0% {
                transform: rotate(0deg);
            }
            100% {
                transform: rotate(360deg);
            }
        }
        .overlay-box>* {
            position: relative;
            z-index: 2;
        }
        .overlay-box h1 {
            color: var(--sky);
            font-family: var(--font-display);
            font-size: 24px;
            letter-spacing: 3px;
            text-shadow: 0 0 30px rgba(79, 195, 255, 0.3);
            margin-bottom: 14px;
        }
        .overlay-box .content {
            color: #b0cce0;
            font-size: 14px;
            line-height: 2;
            font-weight: 300;
            margin-bottom: 28px;
        }
        .overlay-box .content strong {
            color: var(--white);
            font-weight: 600;
        }
        .btn-accept {
            padding: 14px 40px;
            border: 2px solid var(--sky);
            background: transparent;
            color: var(--sky);
            font-family: var(--font-display);
            font-size: 15px;
            letter-spacing: 2px;
            border-radius: 6px;
            transition: 0.25s ease;
            cursor: pointer;
            text-transform: uppercase;
        }
        .btn-accept:hover {
            background: var(--sky);
            color: var(--blk);
            box-shadow: 0 0 35px rgba(79, 195, 255, 0.4);
        }

        /* ── HEADER ── */
        .top-header {
            position: sticky;
            z-index: 100;
            top: 0;
            width: 100%;
            padding: 14px 0 12px;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid rgba(79, 195, 255, 0.2);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.6);
        }
        .top-header .row {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 12px 20px;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .brand .icon {
            font-size: 26px;
            color: var(--sky);
            filter: drop-shadow(0 0 12px rgba(79, 195, 255, 0.3));
        }
        .brand .title {
            font-family: var(--font-display);
            font-size: clamp(16px, 2.6vw, 26px);
            font-weight: 700;
            letter-spacing: 1px;
            background: linear-gradient(135deg, var(--white) 40%, var(--sky) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .brand .title span {
            color: var(--sky);
            -webkit-text-fill-color: var(--sky);
        }
        .brand .badge {
            font-family: var(--font-mono);
            font-size: 10px;
            letter-spacing: 2px;
            color: var(--sky);
            background: rgba(79, 195, 255, 0.12);
            padding: 4px 12px;
            border-radius: 20px;
            border: 1px solid rgba(79, 195, 255, 0.2);
            text-transform: uppercase;
            -webkit-text-fill-color: var(--sky);
        }
        .header-status {
            font-family: var(--font-mono);
            font-size: 11px;
            letter-spacing: 1px;
            color: var(--muted);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .header-status .dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--grn);
            box-shadow: 0 0 15px var(--grn);
            animation: pulse-dot 1.8s ease-in-out infinite;
        }
        @keyframes pulse-dot {
            0%,
            100% {
                opacity: 1;
                transform: scale(1);
            }
            50% {
                opacity: 0.4;
                transform: scale(0.7);
            }
        }
        .header-status .dot.offline {
            background: #ff4444;
            box-shadow: 0 0 15px #ff4444;
        }
        #connection-status {
            color: var(--white);
            font-weight: 400;
        }

        /* ── HERO / INTRO ── */
        .hero {
            padding: 40px 0 16px;
            text-align: center;
            position: relative;
            z-index: 2;
        }
        .hero .glow-title {
            font-family: var(--font-display);
            font-size: clamp(34px, 7vw, 68px);
            font-weight: 900;
            letter-spacing: 4px;
            background: linear-gradient(135deg, #ffffff 30%, var(--sky) 80%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 0 0 60px rgba(79, 195, 255, 0.15);
            line-height: 1.1;
        }
        .hero .glow-title .highlight {
            color: var(--sky);
            -webkit-text-fill-color: var(--sky);
        }
        .hero .sub-tag {
            margin-top: 12px;
            font-family: var(--font-mono);
            font-size: clamp(12px, 1.4vw, 17px);
            letter-spacing: 4px;
            color: var(--muted);
        }
        .hero .sub-tag i {
            color: var(--sky);
            margin: 0 6px;
        }
        .hero .edu-banner {
            margin-top: 18px;
            padding: 14px 28px;
            display: inline-block;
            background: rgba(79, 195, 255, 0.06);
            border: 1px solid rgba(79, 195, 255, 0.15);
            border-radius: 40px;
            font-size: 13px;
            color: #b0d0e8;
            letter-spacing: 0.5px;
            backdrop-filter: blur(4px);
        }
        .hero .edu-banner i {
            color: var(--sky);
            margin-right: 10px;
        }
        .hero .edu-banner strong {
            color: var(--white);
            font-weight: 600;
        }

        /* ── MAIN CARD ── */
        .main-card {
            position: relative;
            z-index: 2;
            margin: 20px auto 30px;
            background: var(--card-bg);
            border: 1px solid rgba(79, 195, 255, 0.20);
            border-radius: 18px;
            box-shadow: 0 0 50px rgba(79, 195, 255, 0.06), var(--border-glow);
            backdrop-filter: blur(4px);
            overflow: hidden;
            transition: box-shadow 0.4s ease;
        }
        .main-card:hover {
            box-shadow: 0 0 70px rgba(79, 195, 255, 0.10), var(--glow-sky);
        }
        .main-card .card-header {
            padding: 16px 28px;
            background: rgba(79, 195, 255, 0.05);
            border-bottom: 1px solid rgba(79, 195, 255, 0.10);
            display: flex;
            align-items: center;
            gap: 14px;
            flex-wrap: wrap;
        }
        .main-card .card-header .term {
            font-family: var(--font-mono);
            font-size: 12px;
            letter-spacing: 1px;
            color: var(--muted);
        }
        .main-card .card-header .term i {
            color: var(--sky);
            margin-right: 6px;
        }
        .main-card .card-header .term strong {
            color: var(--white);
            font-weight: 400;
        }
        .main-card .card-body {
            padding: 32px 30px 34px;
        }

        /* ── FORM ── */
        .form-group {
            margin-bottom: 22px;
        }
        .form-group label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: #c0d8ec;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
            font-family: var(--font-body);
        }
        .form-group label .req {
            color: var(--red);
            margin-left: 2px;
        }
        .input-wrap {
            display: flex;
            align-items: center;
            background: rgba(0, 0, 0, 0.6);
            border: 1.5px solid rgba(79, 195, 255, 0.25);
            border-radius: 10px;
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
            overflow: hidden;
        }
        .input-wrap:focus-within {
            border-color: var(--sky);
            box-shadow: 0 0 25px rgba(79, 195, 255, 0.12), inset 0 0 20px rgba(79, 195, 255, 0.03);
        }
        .input-wrap .prefix {
            padding: 0 0 0 18px;
            font-family: var(--font-mono);
            font-size: 18px;
            color: var(--sky);
            opacity: 0.7;
        }
        .input-wrap input {
            flex: 1;
            padding: 16px 18px;
            border: 0;
            outline: none;
            background: transparent;
            color: var(--white);
            font-size: 17px;
            font-family: var(--font-mono);
            letter-spacing: 1px;
            min-width: 0;
        }
        .input-wrap input::placeholder {
            color: rgba(255, 255, 255, 0.20);
            font-family: var(--font-body);
            font-size: 14px;
            letter-spacing: 0.5px;
        }
        .input-wrap input:focus {
            outline: none;
        }

        /* Consent */
        .consent-wrap {
            display: flex;
            gap: 12px;
            align-items: flex-start;
            margin: 6px 0 14px;
            padding: 12px 16px;
            background: rgba(79, 195, 255, 0.03);
            border-radius: 10px;
            border-left: 3px solid var(--sky);
        }
        .consent-wrap input[type="checkbox"] {
            width: 18px;
            height: 18px;
            margin-top: 1px;
            accent-color: var(--sky);
            cursor: pointer;
            flex-shrink: 0;
        }
        .consent-wrap label {
            font-size: 12px;
            color: #b0cce0;
            line-height: 1.5;
            cursor: pointer;
            font-weight: 300;
        }
        .consent-wrap label strong {
            color: var(--white);
            font-weight: 500;
        }

        /* Status */
        .sys-status {
            display: flex;
            align-items: center;
            gap: 10px;
            margin: 6px 0 16px;
            padding: 10px 16px;
            background: rgba(0, 0, 0, 0.4);
            border-radius: 8px;
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--muted);
            border: 1px solid rgba(79, 195, 255, 0.06);
        }
        .sys-status i {
            color: var(--sky);
            font-size: 14px;
        }
        .sys-status #system-status {
            color: var(--white);
            font-weight: 400;
        }

        /* Error */
        .err-msg {
            display: none;
            margin: 6px 0 16px;
            padding: 12px 18px;
            background: rgba(255, 23, 68, 0.08);
            border: 1px solid rgba(255, 23, 68, 0.25);
            border-radius: 8px;
            color: var(--red);
            font-size: 13px;
            font-weight: 400;
            align-items: center;
            gap: 10px;
        }
        .err-msg.show {
            display: flex;
        }
        .err-msg i {
            font-size: 16px;
        }

        /* Submit Button */
        .btn-submit {
            width: 100%;
            padding: 17px;
            border: 1.5px solid var(--sky);
            background: transparent;
            color: var(--sky);
            font-family: var(--font-display);
            font-size: 16px;
            letter-spacing: 2px;
            border-radius: 10px;
            transition: 0.3s ease;
            cursor: pointer;
            text-transform: uppercase;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
        }
        .btn-submit:hover:not(:disabled) {
            background: var(--sky);
            color: var(--blk);
            box-shadow: 0 0 45px rgba(79, 195, 255, 0.25);
            transform: translateY(-1px);
        }
        .btn-submit:disabled {
            border-color: #445566;
            color: #445566;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        .btn-submit i {
            font-size: 18px;
        }

        /* ── RESULTS ── */
        .results-box {
            display: none;
            margin-top: 30px;
            border: 1px solid rgba(79, 195, 255, 0.20);
            border-radius: 14px;
            background: rgba(0, 0, 0, 0.5);
            overflow: hidden;
            animation: fadeSlide 0.4s ease;
        }
        .results-box.show {
            display: block;
        }
        @keyframes fadeSlide {
            0% {
                opacity: 0;
                transform: translateY(12px);
            }
            100% {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .results-box .res-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px 16px;
            padding: 14px 22px;
            background: rgba(79, 195, 255, 0.05);
            border-bottom: 1px solid rgba(79, 195, 255, 0.08);
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--muted);
        }
        .results-box .res-head .left {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .results-box .res-head .left i {
            color: var(--grn);
        }
        .results-box .res-head .left strong {
            color: var(--white);
            font-weight: 400;
        }
        .results-box .res-head #result-source {
            color: var(--sky);
        }
        .results-box .res-body {
            padding: 6px 0;
        }
        .result-row {
            display: flex;
            gap: 12px;
            padding: 12px 22px;
            border-bottom: 1px solid rgba(79, 195, 255, 0.05);
            font-size: 13px;
            align-items: baseline;
        }
        .result-row:last-child {
            border-bottom: 0;
        }
        .result-row .rl {
            width: 38%;
            color: var(--muted);
            font-weight: 300;
            font-size: 12px;
            letter-spacing: 0.3px;
            font-family: var(--font-body);
        }
        .result-row .rl::before {
            content: "▸ ";
            color: var(--sky);
            opacity: 0.5;
        }
        .result-row .rv {
            width: 62%;
            color: var(--white);
            font-weight: 400;
            overflow-wrap: anywhere;
            font-family: var(--font-mono);
            font-size: 13px;
        }
        .result-row .rv.highlight {
            color: var(--sky);
            font-weight: 600;
        }
        .result-row .rv.green {
            color: var(--grn);
        }

        /* JSON toggle */
        .json-toggle {
            width: 100%;
            margin-top: 18px;
            padding: 11px;
            border: 1px dashed rgba(79, 195, 255, 0.15);
            background: transparent;
            color: #6688aa;
            font-family: var(--font-mono);
            font-size: 12px;
            letter-spacing: 1px;
            border-radius: 8px;
            transition: 0.25s ease;
            cursor: pointer;
        }
        .json-toggle:hover {
            border-color: var(--sky);
            color: var(--sky);
            background: rgba(79, 195, 255, 0.04);
        }
        .json-box {
            display: none;
            max-height: 260px;
            margin-top: 12px;
            overflow: auto;
            padding: 18px 20px;
            border: 1px solid rgba(79, 195, 255, 0.10);
            border-radius: 10px;
            background: rgba(0, 0, 0, 0.6);
            color: var(--grn);
            font-family: var(--font-mono);
            font-size: 11px;
            white-space: pre-wrap;
            word-break: break-word;
            line-height: 1.7;
        }
        .json-box.show {
            display: block;
        }

        /* ── PRIVACY NOTE ── */
        .privacy-note {
            display: flex;
            gap: 14px;
            margin-top: 22px;
            padding: 16px 22px;
            border-left: 3px solid var(--sky);
            background: rgba(79, 195, 255, 0.03);
            border-radius: 10px;
            color: #8899aa;
            font-size: 12px;
            line-height: 1.6;
            align-items: flex-start;
        }
        .privacy-note i {
            color: var(--sky);
            font-size: 18px;
            margin-top: 1px;
            flex-shrink: 0;
        }
        .privacy-note span {
            font-weight: 300;
        }

        /* ── CONTACT SECTION ── */
        .contact-section {
            margin: 30px auto 20px;
            padding: 24px 28px;
            background: var(--card-bg);
            border: 1px solid rgba(79, 195, 255, 0.12);
            border-radius: 16px;
            box-shadow: var(--border-glow);
            position: relative;
            z-index: 2;
        }
        .contact-section .contact-title {
            font-family: var(--font-display);
            font-size: 16px;
            letter-spacing: 2px;
            color: var(--sky);
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .contact-section .contact-title i {
            font-size: 20px;
        }
        .contact-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 18px 30px;
            align-items: center;
        }
        .contact-item {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 14px;
            color: #c0d8ec;
            text-decoration: none;
            transition: 0.25s ease;
            padding: 8px 16px 8px 12px;
            border-radius: 40px;
            background: rgba(79, 195, 255, 0.04);
            border: 1px solid rgba(79, 195, 255, 0.06);
        }
        .contact-item:hover {
            background: rgba(79, 195, 255, 0.10);
            border-color: rgba(79, 195, 255, 0.20);
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(79, 195, 255, 0.06);
        }
        .contact-item .icon-circle {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            color: #fff;
            flex-shrink: 0;
        }
        .contact-item .icon-circle.whatsapp {
            background: #25D366;
        }
        .contact-item .icon-circle.telegram {
            background: #0088cc;
        }
        .contact-item .contact-label {
            font-weight: 300;
            font-size: 12px;
            color: var(--muted);
        }
        .contact-item .contact-value {
            font-weight: 500;
            color: var(--white);
            font-family: var(--font-mono);
            font-size: 13px;
        }

        /* ── FOOTER ── */
        .footer {
            width: 100%;
            margin-top: auto;
            padding: 28px 20px 24px;
            background: rgba(0, 0, 0, 0.85);
            border-top: 1px solid rgba(79, 195, 255, 0.08);
            text-align: center;
            position: relative;
            z-index: 2;
        }
        .footer .footer-inner {
            max-width: 800px;
            margin: 0 auto;
        }
        .footer .footer-brand {
            font-family: var(--font-display);
            font-size: 16px;
            letter-spacing: 2px;
            color: var(--sky);
            margin-bottom: 6px;
        }
        .footer .footer-brand i {
            margin: 0 6px;
        }
        .footer .footer-tagline {
            font-size: 13px;
            color: #8899aa;
            font-weight: 300;
            letter-spacing: 0.5px;
            line-height: 1.7;
        }
        .footer .footer-tagline strong {
            color: var(--white);
            font-weight: 500;
        }
        .footer .footer-tagline .sep {
            color: var(--sky);
            margin: 0 6px;
            opacity: 0.4;
        }
        .footer .footer-divider {
            width: 60px;
            height: 2px;
            margin: 12px auto 14px;
            background: linear-gradient(90deg, transparent, var(--sky), transparent);
            opacity: 0.3;
        }
        .footer .footer-copy {
            font-size: 11px;
            color: #556677;
            letter-spacing: 1px;
            font-family: var(--font-mono);
        }
        .footer .footer-copy i {
            color: var(--sky);
            opacity: 0.5;
        }
        .footer .footer-badges {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 8px 20px;
            margin-top: 12px;
            font-size: 11px;
            color: #445566;
            letter-spacing: 0.3px;
        }
        .footer .footer-badges span {
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .footer .footer-badges i {
            color: var(--sky);
            opacity: 0.5;
            font-size: 12px;
        }

        /* ── RESPONSIVE ── */
        @media (max-width: 640px) {
            .top-header .row {
                flex-direction: column;
                align-items: stretch;
                gap: 8px;
            }
            .brand .badge {
                font-size: 8px;
                padding: 2px 10px;
            }
            .main-card .card-body {
                padding: 22px 18px 26px;
            }
            .main-card .card-header {
                padding: 12px 18px;
            }
            .result-row {
                flex-direction: column;
                gap: 4px;
                padding: 10px 16px;
            }
            .result-row .rl,
            .result-row .rv {
                width: 100%;
            }
            .result-row .rl::before {
                content: "▸ ";
            }
            .contact-grid {
                flex-direction: column;
                align-items: stretch;
            }
            .contact-item {
                justify-content: center;
            }
            .overlay-box {
                padding: 30px 20px;
            }
            .hero .edu-banner {
                font-size: 11px;
                padding: 10px 18px;
            }
            .privacy-note {
                flex-direction: column;
                gap: 6px;
            }
            .results-box .res-head {
                flex-direction: column;
                align-items: flex-start;
                gap: 4px;
            }
        }
        @media (max-width: 420px) {
            .brand .title {
                font-size: 16px;
            }
            .btn-submit {
                font-size: 13px;
                padding: 14px;
            }
            .input-wrap input {
                font-size: 14px;
                padding: 13px 14px;
            }
            .hero .glow-title {
                font-size: 26px;
            }
        }

        /* ── LOADING SPINNER ── */
        .fa-spin {
            animation: fa-spin 1s linear infinite;
        }
        @keyframes fa-spin {
            0% {
                transform: rotate(0deg);
            }
            100% {
                transform: rotate(360deg);
            }
        }
    </style>
</head>
<body>

    <!-- ─── PRIVACY OVERLAY ─── -->
    <div class="overlay" id="privacy-overlay" role="dialog" aria-modal="true" aria-labelledby="overlay-title">
        <div class="overlay-box">
            <h1 id="overlay-title">⚡ VIRAT FYTER</h1>
            <p class="content">
                <strong>CONSENT-BASED NUMBER VALIDATION</strong><br />
                Returns technical carrier &amp; line-type metadata only.<br />
                <span style="color:var(--sky);">No owner identity, address, or private records.</span><br /><br />
                For authorised <strong>business</strong> &amp; <strong>educational</strong> use.
            </p>
            <button class="btn-accept" id="accept-button" type="button">[ INITIATE ]</button>
        </div>
    </div>

    <!-- ─── HEADER ─── -->
    <header class="top-header">
        <div class="container row">
            <div class="brand">
                <span class="icon"><i class="fas fa-shield-halved"></i></span>
                <span class="title">VIRAT<span>_FYTER</span></span>
                <span class="badge"><i class="fas fa-lock" style="margin-right:4px;"></i> v2.0</span>
            </div>
            <div class="header-status">
                <span class="dot" id="status-dot"></span>
                <span>STATUS:</span>
                <span id="connection-status">CHECKING…</span>
            </div>
        </div>
    </header>

    <!-- ─── MAIN ─── -->
    <main>

        <!-- HERO -->
        <section class="hero container">
            <h1 class="glow-title">
                NUMBER <span class="highlight">INTEL</span>
            </h1>
            <p class="sub-tag">
                <i class="fas fa-terminal"></i> VALIDATION SUBSYSTEM <i class="fas fa-chevron-right"></i> CARRIER &amp; LINE-TYPE METADATA
            </p>
            <div class="edu-banner">
                <i class="fas fa-graduation-cap"></i>
                <strong>📘 EDUCATIONAL PURPOSE</strong> — For cybersecurity training &amp; ethical validation awareness.
            </div>
        </section>

        <!-- MAIN CARD -->
        <div class="container">
            <div class="main-card">
                <div class="card-header">
                    <span class="term"><i class="fas fa-code-branch"></i> <strong>ROOT_TERMINAL</strong> — /usr/bin/virat_intel</span>
                    <span class="term" style="margin-left:auto;"><i class="fas fa-clock"></i> <span id="clock-display">--:--:--</span></span>
                </div>
                <div class="card-body">

                    <form id="lookup-form" novalidate>
                        <!-- Number -->
                        <div class="form-group">
                            <label for="number">ENTER AUTHORISED NUMBER <span class="req">*</span></label>
                            <div class="input-wrap">
                                <span class="prefix" aria-hidden="true">&gt;</span>
                                <input
                                id="number"
                                name="number"
                                type="tel"
                                placeholder="+91 98765 43210"
                                inputmode="tel"
                                autocomplete="tel"
                                required
                                />
                            </div>
                        </div>

                        <!-- Consent -->
                        <div class="consent-wrap">
                            <input id="consent" type="checkbox" required />
                            <label for="consent">
                                <strong>I CONFIRM</strong> I am authorised to validate this number for educational &amp; technical purposes.
                            </label>
                        </div>

                        <!-- System Status -->
                        <div class="sys-status">
                            <i class="fas fa-satellite-dish"></i>
                            SYS_MSG: <span id="system-status" role="status">AWAITING INPUT…</span>
                        </div>

                        <!-- Error -->
                        <div class="err-msg" id="error-message" role="alert">
                            <i class="fas fa-triangle-exclamation"></i>
                            <span id="error-text"></span>
                        </div>

                        <!-- Submit -->
                        <button type="submit" class="btn-submit" id="lookup-button">
                            <i class="fas fa-satellite-dish"></i> EXECUTE LOOKUP
                        </button>
                    </form>

                    <!-- ─── RESULTS ─── -->
                    <div class="results-box" id="results" aria-live="polite">
                        <div class="res-head">
                            <span class="left"><i class="fas fa-database"></i> <strong>LOOKUP_SUCCESS</strong></span>
                            <span id="result-source">SOURCE: —</span>
                        </div>
                        <div class="res-body" id="result-content"></div>
                    </div>

                    <!-- JSON Toggle -->
                    <button class="json-toggle" id="json-toggle" type="button" aria-expanded="false">
                        [ VIEW_RESPONSE_JSON ]
                    </button>
                    <pre class="json-box" id="json-box"></pre>

                    <!-- Privacy Note -->
                    <div class="privacy-note">
                        <i class="fas fa-shield-halved"></i>
                        <span>No raw numbers are written to the audit database. Lookup history uses one-way fingerprints.</span>
                    </div>

                </div>
            </div>

            <!-- ─── CONTACT SECTION ─── -->
            <section class="contact-section">
                <div class="contact-title">
                    <i class="fas fa-headset"></i> CONTACT DEVELOPER
                </div>
                <div class="contact-grid">
                    <a href="https://wa.me/917310927827" target="_blank" rel="noopener" class="contact-item">
                        <span class="icon-circle whatsapp"><i class="fab fa-whatsapp"></i></span>
                        <span>
                            <span class="contact-label">WhatsApp</span><br />
                            <span class="contact-value">+91 73109 27827</span>
                        </span>
                    </a>
                    <a href="https://t.me/Viratdeveloper988" target="_blank" rel="noopener" class="contact-item">
                        <span class="icon-circle telegram"><i class="fab fa-telegram-plane"></i></span>
                        <span>
                            <span class="contact-label">Telegram</span><br />
                            <span class="contact-value">@Viratdeveloper988</span>
                        </span>
                    </a>
                    <span class="contact-item" style="border-color:transparent; background:transparent; cursor:default;">
                        <span style="font-size:20px;">👑</span>
                        <span>
                            <span class="contact-label">Developer</span><br />
                            <span class="contact-value" style="color:var(--sky);">Virat King</span>
                        </span>
                    </span>
                </div>
            </section>

        </div>
    </main>

    <!-- ─── FOOTER ─── -->
    <footer class="footer">
        <div class="footer-inner">
            <div class="footer-brand">
                <i class="fas fa-shield-halved"></i> VIRAT FYTER <i class="fas fa-shield-halved"></i>
            </div>
            <div class="footer-tagline">
                <strong>Educational Purpose Only</strong>
                <span class="sep">•</span>
                Cyber Security &amp; Ethical Hacking
                <span class="sep">•</span>
                Web Developer
                <br />
                <span style="color:var(--sky);">Virat king 👑</span>
                <span class="sep">•</span>
                Cyber Security Awareness
            </div>
            <div class="footer-divider"></div>
            <div class="footer-copy">
                <i class="far fa-copyright"></i> 2026 — All Rights Reserved
            </div>
            <div class="footer-badges">
                <span><i class="fas fa-lock"></i> Secure</span>
                <span><i class="fas fa-user-shield"></i> Privacy First</span>
                <span><i class="fas fa-code"></i> Open Source</span>
            </div>
        </div>
    </footer>

    <!-- ─── JAVASCRIPT ─── -->
    <script>
        (function() {
            "use strict";

            // ─── DOM refs ───
            const overlay = document.getElementById("privacy-overlay");
            const acceptBtn = document.getElementById("accept-button");
            const form = document.getElementById("lookup-form");
            const numberInput = document.getElementById("number");
            const consentInput = document.getElementById("consent");
            const submitBtn = document.getElementById("lookup-button");
            const statusEl = document.getElementById("system-status");
            const errorMsg = document.getElementById("error-message");
            const errorText = document.getElementById("error-text");
            const resultsBox = document.getElementById("results");
            const resultContent = document.getElementById("result-content");
            const resultSource = document.getElementById("result-source");
            const jsonToggle = document.getElementById("json-toggle");
            const jsonBox = document.getElementById("json-box");
            const connStatus = document.getElementById("connection-status");
            const statusDot = document.getElementById("status-dot");
            const clockDisplay = document.getElementById("clock-display");

            // ─── Clock ───
            function updateClock() {
                const now = new Date();
                clockDisplay.textContent = now.toTimeString().slice(0, 8);
            }
            updateClock();
            setInterval(updateClock, 1000);

            // ─── Helpers ───
            function setStatus(msg) {
                statusEl.textContent = msg;
            }

            function showError(msg) {
                errorText.textContent = msg;
                errorMsg.classList.add("show");
            }

            function clearError() {
                errorMsg.classList.remove("show");
                errorText.textContent = "";
            }

            function valueOrNA(v) {
                return v ? String(v) : "N/A";
            }

            function showResult(result) {
                const rows = [
                    ["E.164", result.msisdn, "highlight"],
                    ["Format Valid", result.valid ? "✅ YES" : "❌ NO", result.valid ? "green" : ""],
                    ["Country", `${valueOrNA(result.country)}${result.country_code ? ` (${result.country_code})` : ""}`,
                        ""],
                    ["Region", valueOrNA(result.region), ""],
                    ["Carrier", valueOrNA(result.carrier), ""],
                    ["Line Type", valueOrNA(result.line_type), ""],
                    ["International", valueOrNA(result.international), ""],
                    ["Mode", result.live ? "🛰️ LIVE PROVIDER" : "📁 LOCAL METADATA", result.live ? "highlight" : ""],
                ];

                resultContent.replaceChildren(
                    ...rows.map(([label, value, cls]) => {
                        const row = document.createElement("div");
                        row.className = "result-row";
                        const lbl = document.createElement("span");
                        lbl.className = "rl";
                        lbl.textContent = label;
                        const val = document.createElement("span");
                        val.className = "rv" + (cls ? " " + cls : "");
                        val.textContent = value;
                        row.append(lbl, val);
                        return row;
                    })
                );
                resultSource.textContent = `SOURCE: ${String(result.source || "UNKNOWN").toUpperCase()}`;
                resultsBox.classList.add("show");
            }

            // ─── Overlay ───
            acceptBtn.addEventListener("click", () => {
                overlay.classList.add("hidden");
            });

            // ─── JSON toggle ───
            jsonToggle.addEventListener("click", () => {
                const vis = jsonBox.classList.toggle("show");
                jsonToggle.setAttribute("aria-expanded", String(vis));
            });

            // ─── Form submit ───
            form.addEventListener("submit", async (e) => {
                e.preventDefault();
                clearError();
                resultsBox.classList.remove("show");

                const number = numberInput.value.trim();
                if (!number) {
                    showError("ENTER A PHONE NUMBER.");
                    return;
                }
                if (!consentInput.checked) {
                    showError("AUTHORISATION CONFIRMATION REQUIRED.");
                    return;
                }

                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> VALIDATING…';
                setStatus("QUERYING VALIDATION SERVICE…");

                try {
                    const resp = await fetch("/api/v1/lookup", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ number, consent: true }),
                    });
                    const payload = await resp.json();
                    jsonBox.textContent = JSON.stringify(payload, null, 2);

                    if (!resp.ok || payload.status !== "success" || !payload.result) {
                        throw new Error(payload.message || payload.code || "LOOKUP FAILED.");
                    }

                    showResult(payload.result);
                    setStatus(`LOOKUP COMPLETE${payload.cached ? " (CACHED)" : " (LIVE)"}.`);
                } catch (err) {
                    showError(err instanceof Error ? err.message : "NETWORK FAULT.");
                    setStatus("LOOKUP FAILED.");
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="fas fa-satellite-dish"></i> EXECUTE LOOKUP';
                }
            });

            // ─── Status check ───
            fetch("/api/v1/status")
                .then((r) => r.json())
                .then((data) => {
                    const ready = data.live_lookup_configured;
                    connStatus.textContent = ready ? "LIVE READY" : "LOCAL READY";
                    statusDot.className = "dot";
                })
                .catch(() => {
                    connStatus.textContent = "OFFLINE";
                    statusDot.className = "dot offline";
                });

        })();
    </script>

</body>
</html>
"""

# ─── FLASK APPLICATION ──────────────────────────────────────────────────────

def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Application factory used by local development, Gunicorn, and automated tests."""
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "development-only-change-me"),
        SQLALCHEMY_DATABASE_URI=normalize_database_url(
            os.environ.get("DATABASE_URL", "sqlite:///number_info.db")
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        VERIPHONE_API_KEY=os.environ.get("VERIPHONE_API_KEY", "").strip(),
        VERIPHONE_URL=os.environ.get("VERIPHONE_URL", "https://api.veriphone.io/v2/verify"),
        DEFAULT_COUNTRY=os.environ.get("DEFAULT_COUNTRY", "IN").upper(),
        RATE_LIMIT=os.environ.get("RATE_LIMIT", "10 per minute"),
        BATCH_RATE_LIMIT=os.environ.get("BATCH_RATE_LIMIT", "3 per minute"),
        MAX_BATCH_SIZE=int(os.environ.get("MAX_BATCH_SIZE", "15")),
        RATELIMIT_STORAGE_URI=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
        UPSTREAM_TIMEOUT_SECONDS=float(os.environ.get("UPSTREAM_TIMEOUT_SECONDS", "10")),
        CACHE_TTL_SECONDS=int(os.environ.get("CACHE_TTL_SECONDS", "300")),
        LOOKUP_AUDIT_PEPPER=os.environ.get("LOOKUP_AUDIT_PEPPER", os.environ.get("SECRET_KEY", "development-only-change-me")),
    )
    if test_config:
        app.config.update(test_config)

    # A process-local cache avoids repeat provider calls. It is deliberately not persisted,
    # so raw numbers never enter the audit database or any long-lived storage.
    global cache
    with cache_lock:
        cache = TTLCache(maxsize=1_000, ttl=app.config["CACHE_TTL_SECONDS"])

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.extensions["lookup_http"] = build_http_session()
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

    db.init_app(app)
    limiter.init_app(app)
    with app.app_context():
        db.create_all()

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else "public, max-age=300"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; form-action 'self';"
        )
        return response

    @app.get("/")
    def home():
        return INDEX_HTML

    @app.get("/health")
    @app.get("/api/v1/health")
    def health():
        try:
            db.session.execute(text("SELECT 1"))
            database_status = "connected"
        except Exception:
            app.logger.exception("Health check database error")
            database_status = "unavailable"
        status_code = 200 if database_status == "connected" else 503
        return jsonify({"status": "ok" if status_code == 200 else "degraded", "database": database_status}), status_code

    @app.get("/api/v1/status")
    def status():
        return jsonify(
            {
                "status": "ok",
                "provider": "veriphone" if app.config["VERIPHONE_API_KEY"] else "local_metadata",
                "live_lookup_configured": bool(app.config["VERIPHONE_API_KEY"]),
                "privacy": "technical phone metadata only",
            }
        )

    @app.post("/api/v1/lookup")
    @app.post("/api/lookup")  # Backward-compatible path for the supplied frontend.
    @limiter.limit(lambda: app.config["RATE_LIMIT"])
    def lookup():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"status": "error", "code": "INVALID_JSON", "message": "Send a JSON request body."}), 400
        if payload.get("consent") is not True:
            return jsonify({"status": "error", "code": "CONSENT_REQUIRED", "message": "Confirm you are authorised to validate this number."}), 400

        try:
            result, cached = lookup_technical_metadata(app, payload.get("number"))
        except ValueError:
            return jsonify({"status": "error", "code": "INVALID_NUMBER", "message": "Enter a valid local or international phone number."}), 400
        except ProviderError as exc:
            return jsonify({"status": "error", "code": exc.code, "message": "The live validation service is unavailable. Please try again later."}), exc.http_status
        return jsonify({"status": "success", "cached": cached, "result": result})

    @app.post("/api/v1/lookup/batch")
    @limiter.limit(lambda: app.config["BATCH_RATE_LIMIT"])
    def batch_lookup():
        """Validate a small authorised set of numbers without persisting raw input."""
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"status": "error", "code": "INVALID_JSON", "message": "Send a JSON request body."}), 400
        if payload.get("consent") is not True:
            return jsonify({"status": "error", "code": "CONSENT_REQUIRED", "message": "Confirm you are authorised to validate these numbers."}), 400

        numbers = payload.get("numbers")
        if not isinstance(numbers, list) or not numbers:
            return jsonify({"status": "error", "code": "INVALID_BATCH", "message": "Send a non-empty numbers array."}), 400
        if len(numbers) > app.config["MAX_BATCH_SIZE"]:
            return jsonify(
                {
                    "status": "error",
                    "code": "BATCH_LIMIT_EXCEEDED",
                    "message": f"A batch may contain up to {app.config['MAX_BATCH_SIZE']} authorised numbers.",
                }
            ), 400

        items: list[dict[str, Any]] = []
        success_count = 0
        for index, raw_number in enumerate(numbers, start=1):
            try:
                result, cached = lookup_technical_metadata(app, raw_number)
                items.append({"index": index, "status": "success", "cached": cached, "result": result})
                success_count += 1
            except ValueError:
                items.append({"index": index, "status": "error", "code": "INVALID_NUMBER", "message": "Enter a valid local or international phone number."})
            except ProviderError as exc:
                items.append({"index": index, "status": "error", "code": exc.code, "message": "Live validation is temporarily unavailable for this item."})

        return jsonify(
            {
                "status": "success",
                "summary": {
                    "submitted": len(numbers),
                    "successful": success_count,
                    "failed": len(numbers) - success_count,
                    "maximum_batch_size": app.config["MAX_BATCH_SIZE"],
                },
                "items": items,
            }
        )

    @app.errorhandler(429)
    def rate_limited(_error):
        return jsonify({"status": "error", "code": "RATE_LIMITED", "message": "Too many requests. Please wait a minute."}), 429

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"status": "error", "code": "NOT_FOUND", "message": "The requested resource was not found."}), 404

    @app.errorhandler(500)
    def server_error(_error):
        app.logger.exception("Unhandled application error")
        return jsonify({"status": "error", "code": "INTERNAL_ERROR", "message": "An unexpected error occurred."}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)