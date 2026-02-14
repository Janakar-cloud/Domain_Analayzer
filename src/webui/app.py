"""Streamlit frontend for Domain Intelligence.

Allows users to input domains, select options, and trigger scans via the FastAPI backend.
"""

import os
from typing import List

import requests
import streamlit as st


BACKEND_URL = os.getenv("DOMAIN_INTEL_API", "http://127.0.0.1:8000")

st.set_page_config(page_title="Domain Intelligence", layout="wide")
st.title("Domain Intelligence – External Asset Discovery")
st.caption("Scan domains, enumerate CT logs, inspect TLS, and analyze DNS.")


with st.sidebar:
    st.header("Scan Options")
    output_formats = st.multiselect(
        "Output Formats",
        ["json", "csv", "html"],
        default=["json", "csv", "html"],
    )

    st.subheader("Skip Modules")
    skip_ssllabs = st.checkbox("Skip SSL Labs", value=False)
    skip_whois = st.checkbox("Skip WHOIS", value=False)
    skip_threat_intel = st.checkbox("Skip Threat Intel", value=True)
    workers = st.number_input("Workers", min_value=1, max_value=50, value=5, step=1)

    st.subheader("Performance")
    fast_mode = st.checkbox("Fast Mode (no skipping)", value=True, help="Runs all modules with shorter timeouts/polling and tighter content caps.")
    deep_scan = st.checkbox("Deep content scan (crawl shallow links)", value=True)
    shallow_link_limit = st.slider("Shallow link limit", min_value=1, max_value=100, value=20, step=1)
    request_timeout_ms = st.slider("Content request timeout (ms)", min_value=1000, max_value=15000, value=8000, step=500)

    with st.expander("Advanced Tuning"):
        st.caption("Control per-module timeouts and SSL Labs polling without disabling modules.")
        c1, c2 = st.columns(2)
        with c1:
            ct_timeout = st.slider("CT timeout (s)", 3, 15, 5)
            ct_max_subdomains = st.slider("CT max subdomains", 100, 1000, 500, step=50)
            dns_timeout = st.slider("DNS timeout (s)", 3, 15, 5)
            tls_timeout = st.slider("TLS timeout (s)", 3, 15, 5)
        with c2:
            whois_timeout = st.slider("WHOIS timeout (s)", 5, 20, 8)
            redirect_timeout = st.slider("Redirect timeout (s)", 3, 15, 5)
            ssllabs_timeout = st.slider("SSL Labs HTTP timeout (s)", 5, 15, 8)
            ssllabs_poll_interval = st.slider("SSL Labs poll interval (s)", 1, 5, 2)
            ssllabs_max_attempts = st.slider("SSL Labs max attempts", 3, 10, 5)
            ssllabs_max_age = st.slider("SSL Labs max cache age (hours)", 24, 168, 48, step=24)


domains_input = st.text_area(
    "Domains (one per line)",
    "example.com\nexample.org",
    height=120,
)

run_button = st.button("Run Scan", type="primary")


def parse_domains(text: str) -> List[str]:
    return [d.strip() for d in text.splitlines() if d.strip() and not d.strip().startswith("#")]


if run_button:
    domains = parse_domains(domains_input)
    if not domains:
        st.error("Please enter at least one domain.")
    else:
        skip_modules = []
        if skip_ssllabs:
            skip_modules.append("ssllabs")
        if skip_whois:
            skip_modules.append("whois_lookup")
        if skip_threat_intel:
            skip_modules.extend(["abuseipdb", "alienvault_otx", "virustotal", "criminalip", "urlscan"])

        payload = {
            "domains": domains,
            "output_formats": output_formats,
            "skip_modules": skip_modules,
            "workers": int(workers),
            # Runtime tuning for content scanner
            "content_scanner_deep_scan": bool(deep_scan),
            "content_scanner_link_limit": int(shallow_link_limit),
            "content_scanner_timeout_ms": int(request_timeout_ms),
            # Fast mode for all modules (keeps them enabled)
            "fast_mode": bool(fast_mode),
            # Advanced tuning overrides
            "ct_timeout": int(ct_timeout),
            "ct_max_subdomains": int(ct_max_subdomains),
            "dns_timeout": int(dns_timeout),
            "tls_timeout": int(tls_timeout),
            "whois_timeout": int(whois_timeout),
            "redirect_timeout": int(redirect_timeout),
            "ssllabs_timeout": int(ssllabs_timeout),
            "ssllabs_poll_interval_seconds": int(ssllabs_poll_interval),
            "ssllabs_max_attempts": int(ssllabs_max_attempts),
            "ssllabs_max_age": int(ssllabs_max_age),
        }

        # Tighten content caps further when fast mode is enabled
        if fast_mode:
            payload["content_scanner_link_limit"] = min(payload["content_scanner_link_limit"], 10)
            payload["content_scanner_timeout_ms"] = min(payload["content_scanner_timeout_ms"], 6000)

        with st.spinner("Running scan..."):
            try:
                resp = requests.post(f"{BACKEND_URL}/scan", json=payload, timeout=600)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                st.error(f"Scan failed: {e}")
                data = None

        if data:
            st.success("Scan complete")

            # Build tabs UI
            tabs = st.tabs(["Security Posture", "DNS Results", "Certificate", "Reputation", "Findings"])            

            # Helpers
            def severity_color(sev: str) -> str:
                return {
                    "critical": "#dc3545",
                    "high": "#fd7e14",
                    "medium": "#ffc107",
                    "low": "#17a2b8",
                    "info": "#6c757d",
                }.get(sev, "#6c757d")

            results = data.get("results", [])
            last_scan_time = None
            if results:
                last_scan_time = results[0].get("scan_timestamp")

            # Security Posture tab
            with tabs[0]:
                st.subheader("Summary Panel")
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Domains Scanned", data["summary"]["domains"])
                c2.metric("Open Critical/High", data["summary"]["severity_counts"]["critical"] + data["summary"]["severity_counts"]["high"])                
                c3.metric("Total Findings", data["summary"]["total_findings"])                
                c4.metric("Last Scan Time", last_scan_time or "-")

                # Content Scanner summary
                total_hits = 0
                rule_counts = {}
                for r in results:
                    for f in r.get("findings", []):
                        if f.get("category") == "content_scan":
                            hits = (f.get("raw_data") or {}).get("hits", [])
                            total_hits += len(hits)
                            for h in hits:
                                rid = h.get("rule_id") or "unknown"
                                rule_counts[rid] = rule_counts.get(rid, 0) + 1
                if total_hits:
                    top_rule = max(rule_counts.items(), key=lambda x: x[1])[0]
                    st.info(f"Content Scanner: {total_hits} hits (top rule: {top_rule})")

                # Top 3 risky findings
                st.markdown("### Top Risky Findings")
                top_findings = []
                for r in results:
                    for f in r.get("findings", []):
                        top_findings.append((r["domain"], f))
                # sort by severity order
                order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                top_findings.sort(key=lambda x: order.get(x[1]["severity"], 5))
                for domain, f in top_findings[:3]:
                    color = severity_color(f["severity"])
                    st.markdown(f"<div style='border-left:4px solid {color}; padding-left:8px; margin-bottom:8px;'>"
                                f"<strong>{f['title']}</strong> — <em>{domain}</em>"
                                f"</div>", unsafe_allow_html=True)

                st.info("Click the Findings tab for full details.")

            # DNS Results tab
            with tabs[1]:
                st.subheader("DNS Configuration")
                show_email = st.checkbox("Show Email Security (SPF/DMARC/DKIM)", value=False)
                for r in results:
                    st.markdown(f"#### {r['domain']}")
                    # Group records
                    grouped = {}
                    for rec in r.get("dns_records", []):
                        grouped.setdefault(rec["type"], []).append(rec)
                    # Show tables
                    for rt in ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA"]:
                        if rt in grouped:
                            if not show_email and rt in ("MX", "TXT"):
                                continue
                            st.write(f"{rt} records ({len(grouped[rt])})")
                            st.table({
                                "name": [d["name"] for d in grouped[rt]],
                                "value": [d["value"] for d in grouped[rt]],
                                "ttl": [d.get("ttl") for d in grouped[rt]],
                            })

            # Certificate tab
            with tabs[2]:
                for r in results:
                    st.markdown(f"#### {r['domain']}")
                    cert = r.get("tls_certificate")
                    if not cert:
                        st.write("No certificate data")
                        continue
                    st.write({
                        "CN": cert.get("subject_cn"),
                        "Issuer CN": cert.get("issuer"),
                        "Issuer O": cert.get("issuer_org"),
                        "Not Before": cert.get("not_before"),
                        "Not After": cert.get("not_after"),
                        "Expired": cert.get("is_expired"),
                    })
                    if cert.get("san"):
                        st.write("SANs:")
                        st.code("\n".join(cert["san"]))

            # Reputation tab
            with tabs[3]:
                st.subheader("Reputation, Exposure & Attack Surface")
                for r in results:
                    st.markdown(f"#### {r['domain']}")
                    ti = r.get("threat_intel", [])
                    if not ti:
                        st.write("No threat intel data (enable API keys)")
                    else:
                        st.table({
                            "source": [t["source"] for t in ti],
                            "malicious": [t.get("is_malicious") for t in ti],
                            "abuse_score": [t.get("abuse_score") for t in ti],
                            "confidence": [t.get("confidence_score") for t in ti],
                            "categories": [", ".join(t.get("categories", [])) for t in ti],
                        })

            # Findings tab
            with tabs[4]:
                for r in results:
                    st.markdown(f"#### {r['domain']}")
                    for f in r.get("findings", []):
                        color = severity_color(f["severity"])
                        with st.expander(f"{f['severity'].upper()} — {f['title']}"):
                            st.markdown(f"<div style='border-left:4px solid {color}; padding-left:8px;'>"
                                        f"<p>{f['description']}</p>"
                                        f"</div>", unsafe_allow_html=True)
                            if f.get("evidence"):
                                st.code(f["evidence"])
                            # Highlight Content Scanner hits with rule IDs and confidence
                            if f.get("category") == "content_scan":
                                hits = (f.get("raw_data") or {}).get("hits", [])
                                if hits:
                                    st.write("Detected items:")
                                    # Confidence color mapping and compact HTML table
                                    def conf_badge(conf: str) -> str:
                                        color = {"high": "#dc3545", "medium": "#fd7e14", "low": "#6c757d"}.get(conf, "#6c757d")
                                        return f"<span style='background:{color};color:#fff;border-radius:8px;padding:2px 6px;font-size:12px;'>{conf}</span>"

                                    rows = []
                                    for h in hits[:10]:
                                        token = (h.get("token") or "")
                                        token_disp = token[:40] + ("…" if len(token) > 40 else "")
                                        rows.append(
                                            f"<tr><td>{h.get('rule_id')}</td><td>{conf_badge(h.get('confidence','low'))}</td><td>{h.get('weight')}</td><td><code>{token_disp}</code></td></tr>"
                                        )
                                    table_html = (
                                        "<table style='width:100%;border-collapse:collapse;'>"
                                        "<thead><tr>"
                                        "<th style='text-align:left;border-bottom:1px solid #ddd;'>rule</th>"
                                        "<th style='text-align:left;border-bottom:1px solid #ddd;'>confidence</th>"
                                        "<th style='text-align:left;border-bottom:1px solid #ddd;'>weight</th>"
                                        "<th style='text-align:left;border-bottom:1px solid #ddd;'>token</th>"
                                        "</tr></thead><tbody>"
                                        + "".join(rows) + "</tbody></table>"
                                    )
                                    st.markdown(table_html, unsafe_allow_html=True)
                            if f.get("remediation"):
                                st.write("Remediation:")
                                st.markdown(f["remediation"])

            st.divider()
            st.subheader("Generated Reports")
            for p in data.get("reports", []):
                st.write(f"• {p}")
