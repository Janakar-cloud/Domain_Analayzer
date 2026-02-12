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
        }

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
                            if f.get("remediation"):
                                st.write("Remediation:")
                                st.markdown(f["remediation"])

            st.divider()
            st.subheader("Generated Reports")
            for p in data.get("reports", []):
                st.write(f"• {p}")
