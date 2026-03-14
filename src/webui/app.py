"""Streamlit frontend for Domain Intelligence.

This dashboard keeps scan controls minimal, uses a light visual theme,
and presents report output in area-specific tabs after each scan.
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dns.flags
import dns.rdatatype
import dns.resolver
import requests
import streamlit as st
import pandas as pd
from datetime import datetime



BACKEND_URL = os.getenv("DOMAIN_INTEL_API", "http://127.0.0.1:8000")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DEFAULT_WORKERS = int(os.getenv("DOMAIN_INTEL_WORKERS", "8"))

REPUTABLE_NS_HINTS = {
    "cloudflare": "Cloudflare",
    "awsdns": "AWS Route53",
    "route53": "AWS Route53",
    "azure-dns": "Azure DNS",
    "google": "Google Cloud DNS",
    "dnsmadeeasy": "DNS Made Easy",
    "akam": "Akamai",
    "gandi": "Gandi",
}

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


st.set_page_config(
    page_title="Domain Intelligence",
    layout="wide",
    initial_sidebar_state="collapsed",
)


def apply_light_theme() -> None:
    """Inject a light-first visual style and hide sidebar scan options."""
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&family=Space+Grotesk:wght@500;600;700&display=swap');

        :root {
            --dl-bg-0: #f7fbff;
            --dl-bg-1: #eef4fb;
            --dl-panel: #ffffff;
            --dl-panel-soft: #f8fbff;
            --dl-panel-tint: #edf5ff;
            --dl-border: #c7d8e8;
            --dl-border-strong: #aac4de;
            --dl-text: #10243a;
            --dl-muted: #4f657c;
            --dl-primary: #0a84f4;
            --dl-primary-ink: #066ac7;
            --dl-accent: #00a38d;
            --dl-shadow-soft: 0 8px 20px rgba(18, 48, 79, 0.08);
            --dl-shadow-lift: 0 14px 30px rgba(18, 48, 79, 0.12);
        }

        [data-testid="stSidebar"] {
            display: none;
        }

        [data-testid="stAppViewContainer"] {
            position: relative;
            background:
                radial-gradient(84rem 52rem at 12% -6%, rgba(10, 132, 244, 0.16), rgba(10, 132, 244, 0) 56%),
                radial-gradient(66rem 48rem at 88% -10%, rgba(0, 163, 141, 0.14), rgba(0, 163, 141, 0) 60%),
                linear-gradient(168deg, var(--dl-bg-0) 0%, var(--dl-bg-1) 58%, #ecf2f9 100%);
            color: var(--dl-text);
        }

        [data-testid="stAppViewContainer"]::before {
            content: "";
            position: fixed;
            inset: 0;
            z-index: 0;
            pointer-events: none;
            background-image:
                linear-gradient(to right, rgba(121, 147, 174, 0.08) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(121, 147, 174, 0.08) 1px, transparent 1px);
            background-size: 28px 28px;
            mask-image: linear-gradient(to bottom, rgba(0, 0, 0, 0.54), rgba(0, 0, 0, 0.12));
        }

        [data-testid="stAppViewContainer"]::after {
            content: "";
            position: fixed;
            inset: 0;
            z-index: 0;
            pointer-events: none;
            background-image: radial-gradient(circle at 18% 24%, rgba(10, 132, 244, 0.10), rgba(10, 132, 244, 0) 28%);
            mix-blend-mode: screen;
        }

        .block-container {
            position: relative;
            z-index: 1;
            max-width: 1280px;
            padding-top: 1.15rem;
            padding-bottom: 2.35rem;
            animation: dl-fade 280ms ease-out;
        }

        .block-container > div {
            animation: dl-rise 340ms ease-out both;
        }

        .block-container > div:nth-child(2) { animation-delay: 45ms; }
        .block-container > div:nth-child(3) { animation-delay: 85ms; }

        @keyframes dl-fade {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes dl-rise {
            from { opacity: 0; transform: translateY(9px); }
            to { opacity: 1; transform: translateY(0); }
        }

        [data-testid="stHeader"] {
            background: transparent;
        }

        html, body,
        p, li, label,
        [data-testid="stMarkdownContainer"],
        [data-testid="stText"],
        [data-testid="stMetricLabel"],
        [data-testid="stMetricValue"],
        [data-testid="stCaptionContainer"] {
            font-family: "IBM Plex Sans", "Segoe UI", sans-serif !important;
            color: var(--dl-text) !important;
        }

        .material-icons,
        .material-symbols-rounded,
        .material-symbols-outlined,
        [class*="material-symbols"],
        [data-testid="stIconMaterial"] {
            font-family: "Material Symbols Rounded", "Material Symbols Outlined" !important;
            font-style: normal !important;
            font-weight: normal !important;
            line-height: 1 !important;
            letter-spacing: normal !important;
            text-transform: none !important;
            white-space: nowrap !important;
            word-wrap: normal !important;
            direction: ltr !important;
            -webkit-font-smoothing: antialiased;
            font-feature-settings: "liga";
        }

        h1, h2, h3 {
            font-family: "Space Grotesk", "Trebuchet MS", sans-serif !important;
            color: var(--dl-text) !important;
            line-height: 1.24;
            letter-spacing: 0.01em;
        }

        h1 {
            font-size: clamp(1.85rem, 2.9vw, 2.45rem);
            font-weight: 700 !important;
        }

        h2, h3 {
            font-weight: 600 !important;
        }

        small,
        .stCaption {
            color: var(--dl-muted) !important;
        }

        a {
            color: var(--dl-primary) !important;
            text-decoration-thickness: 1.5px;
            text-underline-offset: 3px;
        }

        [data-testid="stAlert"],
        [data-testid="stExpander"] > details,
        .stMetric {
            background: linear-gradient(180deg, rgba(255, 255, 255, 0.97), rgba(249, 252, 255, 0.96));
            border: 1px solid var(--dl-border);
            border-radius: 14px;
            box-shadow: var(--dl-shadow-soft);
        }

        .stMetric {
            padding: 12px;
            position: relative;
            overflow: hidden;
        }

        .stMetric::before {
            content: "";
            position: absolute;
            inset: 0 auto auto 0;
            height: 3px;
            width: 100%;
            background: linear-gradient(90deg, var(--dl-primary), var(--dl-accent));
            opacity: 0.9;
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 8px;
            background: rgba(248, 252, 255, 0.84);
            border: 1px solid var(--dl-border);
            border-radius: 14px;
            padding: 6px;
            box-shadow: inset 0 1px 0 #ffffff;
        }

        .stTabs [data-baseweb="tab"] {
            background: transparent;
            border: 1px solid transparent;
            border-radius: 10px;
            color: #1f364e !important;
            font-family: "IBM Plex Sans", "Segoe UI", sans-serif !important;
            font-weight: 600;
            padding: 7px 12px;
            transition: all 140ms ease;
        }

        .stTabs [data-baseweb="tab"]:hover {
            background: rgba(228, 240, 252, 0.8);
            border-color: #c7d9ed;
        }

        .stTabs [aria-selected="true"] {
            background: linear-gradient(130deg, #e9f4ff 0%, #ddf6f1 100%);
            border-color: var(--dl-border-strong);
            box-shadow: 0 2px 10px rgba(10, 132, 244, 0.14);
            transform: translateY(-1px);
        }

        .stButton > button {
            background: linear-gradient(128deg, var(--dl-primary), #2a92f4 55%, var(--dl-accent));
            color: #ffffff;
            border: 1px solid var(--dl-primary-ink);
            border-radius: 11px;
            font-family: "IBM Plex Sans", "Segoe UI", sans-serif !important;
            font-weight: 700;
            letter-spacing: 0.01em;
            box-shadow: 0 10px 22px rgba(10, 132, 244, 0.26);
            transition: transform 140ms ease, box-shadow 140ms ease, filter 140ms ease;
        }

        .stButton > button:hover {
            background: linear-gradient(128deg, var(--dl-primary-ink), #1f7fdf 55%, #00917f);
            border-color: #055bb0;
            transform: translateY(-1px);
            box-shadow: 0 14px 26px rgba(10, 132, 244, 0.31);
            filter: saturate(1.04);
        }

        .stTextArea textarea,
        .stTextInput input,
        .stNumberInput input,
        [data-baseweb="select"] > div,
        [data-baseweb="textarea"] > div {
            color: var(--dl-text) !important;
            background: var(--dl-panel) !important;
            border: 1px solid var(--dl-border) !important;
            border-radius: 10px !important;
            box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.95);
        }

        .stTextArea textarea::placeholder,
        .stTextInput input::placeholder {
            color: #657f97 !important;
        }

        [data-baseweb="textarea"] textarea {
            color: var(--dl-text) !important;
        }

        [data-testid="stTable"] table,
        [data-testid="stDataFrame"] table {
            background: var(--dl-panel) !important;
            border: 1px solid var(--dl-border) !important;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: var(--dl-shadow-soft);
        }

        [data-testid="stDataFrame"] *,
        [data-testid="stTable"] *,
        table,
        th,
        td {
            color: var(--dl-text) !important;
            font-family: "IBM Plex Sans", "Segoe UI", sans-serif !important;
        }

        [data-testid="stCode"],
        [data-testid="stCodeBlock"],
        [data-testid="stJson"] {
            background: #ffffff !important;
            border: 1px solid var(--dl-border) !important;
            border-radius: 12px !important;
            box-shadow: var(--dl-shadow-soft);
        }

        [data-testid="stCode"] pre,
        [data-testid="stCode"] code,
        [data-testid="stCodeBlock"] pre,
        [data-testid="stCodeBlock"] code,
        [data-testid="stJson"] pre,
        [data-testid="stJson"] code {
            background: #ffffff !important;
            color: var(--dl-text) !important;
            border: none !important;
        }

        [data-testid="stJson"] div[style*="background"],
        [data-testid="stJson"] div[style*="background-color"] {
            background: #ffffff !important;
        }

        [data-testid="stJson"] span,
        [data-testid="stJson"] p {
            color: #17324f !important;
        }

        th {
            background: linear-gradient(180deg, var(--dl-panel-tint), #e7f0fb) !important;
            border-bottom: 1px solid var(--dl-border-strong) !important;
            font-weight: 700 !important;
        }

        tr:nth-child(even) td {
            background: #fbfdff !important;
        }

        pre,
        code,
        kbd {
            font-family: "IBM Plex Mono", "Consolas", monospace !important;
            color: #132b45 !important;
            background: #ebf3fc !important;
            border: 1px solid #d1e1f2;
            border-radius: 8px;
        }

        [data-testid="stExpander"] > details > summary {
            color: #17324f !important;
            font-weight: 600;
        }

        [role="progressbar"] {
            background: linear-gradient(90deg, var(--dl-primary), var(--dl-accent)) !important;
        }

        @media (max-width: 992px) {
            .block-container {
                padding-left: 1rem;
                padding-right: 1rem;
            }
        }

        @media (max-width: 768px) {
            html, body {
                font-size: 16px;
            }

            h1 {
                font-size: clamp(1.48rem, 6vw, 1.95rem);
            }

            h2 {
                font-size: clamp(1.18rem, 4.5vw, 1.5rem);
            }

            .stTabs [data-baseweb="tab-list"] {
                gap: 6px;
                border-radius: 12px;
            }

            .stTabs [data-baseweb="tab"] {
                font-size: 0.9rem;
                padding: 6px 8px;
            }

            .stButton > button {
                width: 100%;
                min-height: 2.7rem;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def severity_color(sev: str) -> str:
    return {
        "critical": "#c81e1e",
        "high": "#d97706",
        "medium": "#ca8a04",
        "low": "#0891b2",
        "info": "#64748b",
    }.get(sev, "#64748b")


def parse_domains(text: str) -> List[str]:
    return [d.strip() for d in text.splitlines() if d.strip() and not d.strip().startswith("#")]


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def classify_ns_provider(ns_name: str) -> str:
    lowered = ns_name.lower()
    for hint, provider in REPUTABLE_NS_HINTS.items():
        if hint in lowered:
            return provider
    return "Other/Unknown"


def extract_cert_emails(result: Dict[str, Any]) -> List[str]:
    cert = result.get("tls_certificate") or {}
    candidates: List[str] = []
    for key in ["subject_cn", "issuer", "issuer_org", "organization"]:
        value = cert.get(key)
        if value:
            candidates.append(str(value))

    for san in cert.get("san", []):
        candidates.append(str(san))

    for finding in result.get("findings", []):
        if finding.get("category") == "tls_security" and finding.get("evidence"):
            candidates.append(str(finding.get("evidence")))

    extracted = set()
    for item in candidates:
        for match in EMAIL_RE.findall(item):
            extracted.add(match.lower())

    return sorted(extracted)


@st.cache_data(ttl=900, show_spinner=False)
def query_dns_any(domain: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Query DNS ANY records. Many resolvers refuse; we return reason in that case."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        answer = resolver.resolve(domain, "ANY")
        rows: List[Dict[str, Any]] = []
        for rrset in answer.response.answer:
            record_type = dns.rdatatype.to_text(rrset.rdtype)
            record_name = str(rrset.name).rstrip(".")
            for item in rrset:
                rows.append(
                    {
                        "type": record_type,
                        "name": record_name,
                        "value": item.to_text(),
                        "ttl": rrset.ttl,
                        "source": "live-any",
                    }
                )
        return rows, None
    except Exception as exc:
        return [], str(exc)


@st.cache_data(ttl=900, show_spinner=False)
def check_dnssec_ad_flag(domain: str) -> Tuple[Optional[bool], Optional[str]]:
    """Check AD flag from resolver response as a DNSSEC validation hint."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    resolver.use_edns(edns=True)
    try:
        answer = resolver.resolve(domain, "A", raise_on_no_answer=False)
        if not answer.response:
            return None, "No resolver response payload"
        ad_set = bool(answer.response.flags & dns.flags.AD)
        return ad_set, None
    except Exception as exc:
        return None, str(exc)


def parse_soa_zone_age_days(soa_value: str) -> Optional[int]:
    """Estimate zone age from serial number when serial uses YYYYMMDDnn style."""
    parts = soa_value.split()
    if len(parts) < 3:
        return None

    serial = parts[2]
    if len(serial) < 8 or not serial[:8].isdigit():
        return None

    try:
        serial_date = datetime.strptime(serial[:8], "%Y%m%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    now = datetime.now(timezone.utc)
    if serial_date > now:
        return None
    return (now - serial_date).days


@st.cache_data(ttl=600, show_spinner=False)
def fetch_url(domain: str, path: str, timeout: int = 8) -> Tuple[Optional[requests.Response], Optional[str], Optional[str]]:
    """Fetch a path from https first, then http."""
    headers = {"User-Agent": "DomainIntel-UI/1.0"}
    last_error: Optional[str] = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}{path}"
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers)
            return response, url, None
        except requests.RequestException as exc:
            last_error = str(exc)
    return None, None, last_error


@st.cache_data(ttl=900, show_spinner=False)
def fetch_security_txt(domain: str) -> Dict[str, Any]:
    """Fetch and parse security.txt from /.well-known/security.txt then /security.txt."""
    for path in ("/.well-known/security.txt", "/security.txt"):
        response, url, _ = fetch_url(domain, path, timeout=8)
        if not response:
            continue
        if response.status_code != 200:
            continue

        text = response.text or ""
        fields: Dict[str, List[str]] = {}
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            fields.setdefault(key.strip().lower(), []).append(value.strip())

        expires_raw = (fields.get("expires") or [None])[0]
        expires_at = parse_iso(expires_raw) if expires_raw else None
        expires_future = bool(expires_at and expires_at > datetime.now(timezone.utc))

        return {
            "found": True,
            "location": url,
            "status_code": response.status_code,
            "contact": fields.get("contact", []),
            "expires": expires_raw,
            "expires_future": expires_future,
            "policy": fields.get("policy", []),
            "fields": fields,
        }

    return {
        "found": False,
        "location": None,
        "status_code": None,
        "contact": [],
        "expires": None,
        "expires_future": None,
        "policy": [],
        "fields": {},
    }


def load_evidence_headers(domain: str) -> Dict[str, str]:
    """Load captured headers from evidence if available."""
    evidence_path = Path("evidence") / domain / "homepage_headers.json"
    if not evidence_path.exists():
        return {}
    try:
        with evidence_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return {k.lower(): v for k, v in (payload.get("headers") or {}).items()}
    except Exception:
        return {}


@st.cache_data(ttl=900, show_spinner=False)
def fetch_csaf_metadata(domain: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    response, _, err = fetch_url(domain, "/.well-known/csaf/provider-metadata.json", timeout=8)
    if not response:
        return False, None, err
    if response.status_code != 200:
        return False, None, f"HTTP {response.status_code}"
    try:
        return True, response.json(), None
    except ValueError:
        return True, None, "Invalid JSON payload"


@st.cache_data(ttl=900, show_spinner=False)
def has_robots_txt(domain: str) -> Tuple[bool, Optional[str]]:
    response, _, err = fetch_url(domain, "/robots.txt", timeout=8)
    if not response:
        return False, err
    return response.status_code == 200, None


def find_ti_source(result: Dict[str, Any], names: List[str]) -> Optional[Dict[str, Any]]:
    targets = set(names)
    for item in result.get("threat_intel", []):
        if item.get("source") in targets:
            return item
    return None


def build_local_executive_summary(results: List[Dict[str, Any]]) -> str:
    """Build a concise executive summary from findings and severity."""
    total_domains = len(results)
    total_findings = sum(len(r.get("findings", [])) for r in results)
    critical_or_high = 0
    top_titles: List[str] = []

    for result in results:
        for finding in result.get("findings", []):
            if finding.get("severity") in {"critical", "high"}:
                critical_or_high += 1
                if len(top_titles) < 4:
                    top_titles.append(finding.get("title", "Unnamed finding"))

    lines = [
        f"Analyzed {total_domains} domain(s) with {total_findings} total findings.",
        f"Critical/High findings: {critical_or_high}.",
    ]

    if top_titles:
        lines.append("Priority focus: " + "; ".join(top_titles))
    else:
        lines.append("No high-severity issues were detected in this run.")

    return " ".join(lines)


@st.cache_data(ttl=600, show_spinner=False)
def generate_gemini_summary(results: List[Dict[str, Any]]) -> Tuple[Optional[str], Optional[str]]:
    """Generate an executive summary via Gemini API if key is available."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return None, "GEMINI_API_KEY not configured"

    compact = []
    for result in results:
        compact.append(
            {
                "domain": result.get("domain"),
                "severity_score": result.get("severity_score"),
                "highest_severity": result.get("highest_severity"),
                "top_findings": [f.get("title") for f in result.get("findings", [])[:5]],
            }
        )

    prompt = (
        "You are a cyber risk assistant. Provide a concise executive summary with business language. "
        "Keep it under 120 words and include immediate priorities. Data: "
        + json.dumps(compact)
    )

    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-1.5-flash:generateContent"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 220},
    }

    try:
        response = requests.post(
            endpoint,
            params={"key": api_key},
            json=payload,
            timeout=18,
        )
        response.raise_for_status()
        body = response.json()
        candidates = body.get("candidates") or []
        if not candidates:
            return None, "Gemini returned no candidates"
        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text")
        if not text:
            return None, "Gemini response text missing"
        return text.strip(), None
    except Exception as exc:
        return None, str(exc)


def render_overview(summary: Dict[str, Any], results: List[Dict[str, Any]]) -> None:
    """Render top-level metrics."""
    last_scan_time = results[0].get("scan_timestamp") if results else "-"
    crit = summary.get("severity_counts", {}).get("critical", 0)
    high = summary.get("severity_counts", {}).get("high", 0)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Domains", summary.get("domains", len(results)))
    c2.metric("Critical + High", crit + high)
    c3.metric("Findings", summary.get("total_findings", 0))
    # c4.metric("Last Scan", str(last_scan_time))
    dt = datetime.fromisoformat(last_scan_time)
    c4.metric("Last Scan", dt.strftime("%d %b %H:%M"))

def render_tabs(data: Dict[str, Any]) -> None:
    """Render area-specific report tabs."""
    results = data.get("results", [])
    tabs = st.tabs(
        [
            # "Security.txt",
            "Email Addresses",
            "DNS",
            "SSL/TLS",
            "Reputation",
            "WHOIS",
            "Geolocation",
            "Infrastructure",
            "AI Analysis",
            "Findings",
        ]
    )

    # with tabs[0]:
    #     st.subheader("security.txt")
    #     st.caption("Checks /.well-known/security.txt first, then /security.txt.")
    #     for result in results:
    #         domain = result.get("domain", "")
    #         info = fetch_security_txt(domain)
    #         st.markdown(f"#### {domain}")
    #         if not info["found"]:
    #             st.warning("security.txt not found")
    #             continue

    #         st.success(f"Found at: {info['location']}")
    #         st.write(
    #             {
    #                 "Contact": ", ".join(info["contact"]) if info["contact"] else "-",
    #                 "Expires": info["expires"] or "-",
    #                 "Expires in future": info["expires_future"],
    #                 "Policy": ", ".join(info["policy"]) if info["policy"] else "-",
    #             }
    #         )

    with tabs[0]:
        st.subheader("Certificate Email Addresses")
        for result in results:
            domain = result.get("domain", "")
            emails = extract_cert_emails(result)
            st.markdown(f"#### {domain}")
            if not emails:
                st.info("No certificate email address extracted")
            else:
                st.table({"email": emails, "source": ["TLS certificate"] * len(emails)})

    with tabs[1]:
        st.subheader("DNS Records and DNSSEC")
        requested_types = {"CNAME", "TXT", "AAAA", "A"}

        for result in results:
            domain = result.get("domain", "")
            st.markdown(f"#### {domain}")

            base_records = [
                {
                    "type": r.get("type"),
                    "name": r.get("name"),
                    "value": r.get("value"),
                    "ttl": r.get("ttl"),
                    "source": "scan",
                }
                for r in result.get("dns_records", [])
                if r.get("type") in requested_types
            ]

            any_records, any_error = query_dns_any(domain)
            rows = base_records + any_records
            if rows:
                st.table(rows)
            else:
                st.info("No DNS rows available for A/AAAA/CNAME/TXT/ANY")
            if any_error:
                st.caption(f"ANY query note: {any_error}")

            ns_records = [r for r in result.get("dns_records", []) if r.get("type") == "NS"]
            soa_records = [r for r in result.get("dns_records", []) if r.get("type") == "SOA"]
            if ns_records:
                ns_table = []
                for record in ns_records:
                    value = str(record.get("value", "")).rstrip(".")
                    ns_table.append(
                        {
                            "nameserver": value,
                            "provider_hint": classify_ns_provider(value),
                        }
                    )
                st.write("Reputable NS hints")
                st.table(ns_table)

            ad_flag, ad_error = check_dnssec_ad_flag(domain)
            st.write("DNSSEC (AD flag)")
            if ad_flag is None:
                st.caption(f"Not available: {ad_error}")
            else:
                st.write({"ad_flag": ad_flag})

            if soa_records:
                soa_value = str(soa_records[0].get("value", ""))
                zone_age_days = parse_soa_zone_age_days(soa_value)
                st.write(
                    {
                        "SOA": soa_value,
                        "Estimated zone age (days)": zone_age_days if zone_age_days is not None else "unknown",
                    }
                )

    with tabs[2]:
        st.subheader("SSL/TLS")
        for result in results:
            domain = result.get("domain", "")
            cert = result.get("tls_certificate") or {}
            ssllabs = result.get("ssllabs_result") or {}
            st.markdown(f"#### {domain}")
            st.write(
                {
                    "SSL Labs grade": ssllabs.get("grade") or "not available",
                    "Certificate issued by": cert.get("issuer") or "-",
                    "Cert expiry date": cert.get("not_after") or "-",
                    "Certificate issued to": cert.get("subject_cn") or "-",
                }
            )
            if ssllabs.get("protocols"):
                st.caption("Protocols: " + ", ".join(ssllabs.get("protocols", [])))
            if ssllabs.get("vulnerabilities"):
                st.caption("Vulnerabilities: " + ", ".join(ssllabs.get("vulnerabilities", [])))

    with tabs[3]:
        st.subheader("Reputation Feeds")
        for result in results:
            domain = result.get("domain", "")
            st.markdown(f"#### {domain}")

            vt = find_ti_source(result, ["VirusTotal"])
            vt_url = find_ti_source(result, ["VirusTotal URL"])
            abuse = find_ti_source(result, ["AbuseIPDB"])
            gsb = find_ti_source(result, ["Google Safe Browsing"])
            urlscan = find_ti_source(result, ["URLScan.io"])
            otx = find_ti_source(result, ["AlienVault OTX"])

            rows = [
                {
                    "Area": "VirusTotal domain reputation",
                    "Value": (
                        f"malicious engine count={vt.get('reports_count', 0)}, "
                        f"VT score={round((vt.get('confidence_score') or 0) * 100)}"
                    )
                    if vt
                    else "not collected",
                },
                {
                    "Area": "VirusTotal URL scan",
                    "Value": (
                        f"malicious engine count={vt_url.get('reports_count', 0)}, "
                        f"VT URL score={round((vt_url.get('confidence_score') or 0) * 100)}"
                    )
                    if vt_url
                    else "not collected",
                },
                {
                    "Area": "AbuseIPDB",
                    "Value": f"abuse confidence score={abuse.get('abuse_score')}%"
                    if abuse
                    else "not collected",
                },
                {
                    "Area": "Google Safe Browsing",
                    "Value": (
                        f"phishing/malware matches={gsb.get('reports_count', 0)}, "
                        f"flagged={gsb.get('is_malicious')}"
                    )
                    if gsb
                    else "not collected",
                },
                {
                    "Area": "SecAI",
                    "Value": "not integrated",
                },
                {
                    "Area": "URL Scan (Private mode)",
                    "Value": (
                        f"results={urlscan.get('reports_count', 0)}, malicious={urlscan.get('is_malicious')}"
                        if urlscan
                        else "not collected"
                    ),
                },
                {
                    "Area": "AlienVault",
                    "Value": (
                        f"pulse count={otx.get('reports_count', 0)}, malicious={otx.get('is_malicious')}"
                        if otx
                        else "not collected"
                    ),
                },
            ]
            st.table(rows)

    with tabs[4]:
        st.subheader("WHOIS")
        for result in results:
            domain = result.get("domain", "")
            whois = result.get("whois_info")
            st.markdown(f"#### {domain}")
            if not whois:
                st.info("WHOIS data not available")
                continue
            st.write(
                {
                    "Registrar": whois.get("registrar"),
                    "Creation date": whois.get("creation_date"),
                    "Expiry date": whois.get("expiration_date"),
                    "Updated date": whois.get("updated_date"),
                    "DNSSEC": whois.get("dnssec"),
                    "Domain age (days)": whois.get("domain_age_days"),
                }
            )
            if whois.get("name_servers"):
                st.caption("Name servers: " + ", ".join(whois.get("name_servers", [])))

    with tabs[5]:
        st.subheader("Geolocation and ASN")
        for result in results:
            domain = result.get("domain", "")
            st.markdown(f"#### {domain}")

            passive_dns = find_ti_source(result, ["SecurityTrails PassiveDNS"])

            countries = set()
            providers = set()
            asns = set()
            for item in result.get("threat_intel", []):
                details = item.get("details") or {}
                country = details.get("country")
                provider = details.get("as_owner") or details.get("as_name") or details.get("org") or details.get("isp")
                asn = details.get("asn") or details.get("as_number")
                if country:
                    countries.add(str(country))
                if provider:
                    providers.add(str(provider))
                if asn:
                    asns.add(str(asn))

            passive_dns_value = "not collected"
            if passive_dns:
                pdns_details = passive_dns.get("details") or {}
                historical_ips = pdns_details.get("historical_a_records", []) or []
                if historical_ips:
                    preview = ", ".join(historical_ips[:8])
                    if len(historical_ips) > 8:
                        preview += ", ..."
                    passive_dns_value = f"{len(historical_ips)} historical IP(s): {preview}"
                else:
                    passive_dns_value = "0 historical A records returned"

            st.write(
                {
                    "IP Geolocation (country/provider)": (
                        f"{', '.join(sorted(countries)) or 'not available'} / "
                        f"{', '.join(sorted(providers)) or 'not available'}"
                    ),
                    "ASN reputation": ", ".join(sorted(asns)) or "not available",
                    "Passive DNS / historical records": passive_dns_value,
                }
            )

    with tabs[6]:
        st.subheader("Infrastructure")
        for result in results:
            domain = result.get("domain", "")
            st.markdown(f"#### {domain}")

            robots_present, robots_error = has_robots_txt(domain)
            csaf_present, csaf_payload, csaf_error = fetch_csaf_metadata(domain)

            headers = load_evidence_headers(domain)
            header_rows = []
            for header_name in SECURITY_HEADERS:
                value = headers.get(header_name)
                header_rows.append(
                    {
                        "header": header_name,
                        "present": bool(value),
                        "value": value if value else "missing",
                    }
                )

            st.write(
                {
                    "robots.txt present": robots_present,
                    "CSAF metadata": "present" if csaf_present else f"not present ({csaf_error})",
                }
            )
            if robots_error:
                st.caption(f"robots.txt note: {robots_error}")
            st.write("HTTP security headers")
            st.table(header_rows)

            if csaf_present and csaf_payload:
                st.caption("CSAF provider metadata")
                st.json(csaf_payload)

    with tabs[7]:
        st.subheader("AI Analysis")
        st.caption(
            "Provides a 0-100 risk score and executive summary. "
            "Gemini is used when GEMINI_API_KEY is configured; otherwise local analysis is used."
        )

        total_score = 0
        for result in results:
            total_score += int(result.get("severity_score", 0) or 0)

        average_score = int(total_score / max(len(results), 1))
        if average_score >= 80:
            level = "Critical"
        elif average_score >= 55:
            level = "High"
        elif average_score >= 25:
            level = "Medium"
        else:
            level = "Low"

        st.metric("Risk score (0-100)", average_score)
        st.metric("Risk level", level)

        gemini_text, gemini_error = generate_gemini_summary(results)
        if gemini_text:
            st.success("Gemini executive summary")
            st.write(gemini_text)
        else:
            st.info("Local executive summary")
            st.write(build_local_executive_summary(results))
            if gemini_error:
                st.caption(f"Gemini status: {gemini_error}")

    with tabs[8]:
        st.subheader("Findings")
        for result in results:
            domain = result.get("domain", "")
            st.markdown(f"#### {domain}")
            findings = result.get("findings", [])
            if not findings:
                st.info("No findings")
                continue

            for finding in findings:
                sev = finding.get("severity", "info")
                color = severity_color(sev)
                with st.expander(f"{sev.upper()} - {finding.get('title', 'Untitled finding')}"):
                    st.markdown(
                        f"<div style='border-left:4px solid {color};padding-left:10px;'>"
                        f"{finding.get('description', '')}</div>",
                        unsafe_allow_html=True,
                    )
                    if finding.get("evidence"):
                        st.code(finding.get("evidence"))
                    if finding.get("remediation"):
                        st.write("Remediation:")
                        st.write(finding.get("remediation"))


def run_scan(domains: List[str]) -> Optional[Dict[str, Any]]:
    """Run scan against backend using a fixed profile (scan options hidden)."""
    payload = {
        "domains": domains,
        "output_formats": ["json", "csv", "html"],
        "skip_modules": [],
        "workers": DEFAULT_WORKERS,
        "fast_mode": True,
        "content_scanner_deep_scan": True,
        "content_scanner_link_limit": 10,
        "content_scanner_timeout_ms": 6000,
        "ct_timeout": 5,
        "ct_max_subdomains": 500,
        "dns_timeout": 5,
        "tls_timeout": 5,
        "whois_timeout": 8,
        "redirect_timeout": 5,
        "ssllabs_timeout": 8,
        "ssllabs_poll_interval_seconds": 2,
        "ssllabs_max_attempts": 5,
        "ssllabs_max_age": 48,
    }

    response = requests.post(f"{BACKEND_URL}/scan", json=payload, timeout=600)
    response.raise_for_status()
    return response.json()


def main() -> None:
    apply_light_theme()

    st.title("Domain Intelligence")
    st.caption(
        "Light theme report workspace. Scan options are hidden; "
        "the app runs a fixed internal scan profile."
    )
    st.markdown(
    """
    <style>
    [data-testid="stHeader"] {
        display: none;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

    if "scan_data" not in st.session_state:
        st.session_state["scan_data"] = None

    domains_input = st.text_area(
        "Domains (one per line)",
        placeholder="example.com\nexample.org",
        height=120,
        help="Enter domains like example.com. Do not include http://, https://, or paths."
    )

    c1, c2 = st.columns([1, 3])
    with c1:
        run_button = st.button("Analyze Domains", type="primary")
    with c2:
        st.caption("Profile: full scan, fast mode on, workers auto-tuned.")

    if run_button:
        domains = parse_domains(domains_input)
        if not domains:
            st.error("Please enter at least one domain.")
        else:
            with st.spinner("Running scan and preparing report tabs..."):
                try:
                    st.session_state["scan_data"] = run_scan(domains)
                    st.success("Scan complete")
                except Exception as exc:
                    st.error(f"Scan failed: {exc}")

    data = st.session_state.get("scan_data")
    if not data:
        st.info("Run an analysis to populate report tabs.")
        return

    results = data.get("results", [])
    render_overview(data.get("summary", {}), results)
    st.divider()
    render_tabs(data)

    # st.divider()
    # st.subheader("Generated Reports")
    # for path in data.get("reports", []):
    #     st.write(f"- {path}")
    st.divider()
    st.subheader("Export Report")

    results = data.get("results", [])

    col1, spacer, col2 = st.columns([1,0.3,1])

    # Export JSON
    with col1:
        json_report = json.dumps(data, indent=2)

        st.download_button(
            label="⬇ Download Full JSON Report",
            data=json_report,
            file_name="domain_intelligence_report.json",
            mime="application/json",
            use_container_width=True
        )

        # Export CSV
        with col2:
            rows = []

            for result in results:
                domain = result.get("domain")

                for finding in result.get("findings", []):
                    rows.append({
                    "domain": domain,
                    "severity": finding.get("severity"),
                    "title": finding.get("title"),
                    "description": finding.get("description"),
                    "remediation": finding.get("remediation"),
                })

        if rows:
            df = pd.DataFrame(rows)

            st.download_button(
                label="⬇ Download Findings CSV",
                data=df.to_csv(index=False),
                file_name="domain_findings.csv",
                mime="text/csv",
                use_container_width=True
            )
        else:
            st.caption("No findings available for CSV export.")


if __name__ == "__main__":
    main()
