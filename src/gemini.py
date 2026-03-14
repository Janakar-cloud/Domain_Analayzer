import os
import time
from google import genai
from google.genai import errors
from google.genai.types import HttpOptions
from dotenv import load_dotenv
import os

load_dotenv()

prompt = """
You are an Enterprise Cybersecurity Domain Intelligence AI.

INPUT DOMAIN:
{domain}

OBJECTIVE:
Identify security risks, DNS misconfigurations, dangling domains, expired certificates,
unauthorized WHOIS ownership, unauthenticated sensitive exposure, reputation threats,
and infrastructure weaknesses.

Perform passive analysis only. Do NOT simulate active exploitation.

=====================================================
PHASE 1 – SINGLE DOMAIN DEEP ANALYSIS
=====================================================

Perform structured analysis for the root domain:

1. DNS Analysis
   - A, AAAA, CNAME, MX, TXT, NS records
   - Dangling CNAME detection
   - Subdomain takeover indicators
   - NXDOMAIN check
   - Suspicious DNS providers
   - DNS misconfiguration risks

2. WHOIS Verification
   - Company name
   - Registrant organization
   - Domain age (days)
   - Country/location
   - Registrar
   - WHOIS privacy masking detection
   - Ownership mismatch risk

3. SSL Certificate Inspection
   - Expired certificate (show ONLY if expired)
   - Expiry date
   - Issuer
   - Subject
   - Self-signed detection
   - Weak cipher support
   - SSL rating (A–F equivalent)
   - TLS misconfiguration risks

4. Domain/IP Reputation
   - AbuseIPDB risk score
   - VirusTotal detection ratio
   - AlienVault OTX pulse presence
   - CriminalIP risk level
   - Hosting ASN reputation
   - Blacklist presence

5. Web Exposure Analysis
   - HTTP to HTTPS enforcement
   - Redirection chain
   - Open sensitive endpoints without authentication
   - Directory listing exposure
   - Admin panels exposed
   - Homepage status:
        organized / parked / broken / suspicious
   - Screenshot risk classification

6. Infrastructure Profiling
   - Hosting provider
   - Cloud/CDN usage
   - Server header
   - Technology fingerprint
   - Reverse IP hosting risk
   - Internal hosting feasibility

7. Risk Scoring
   Assign:
      Critical / High / Medium / Low / Informational
   Provide reasoning.

=====================================================
PHASE 2 – PASSIVE SUBDOMAIN ENUMERATION
=====================================================

Task:
Simulate passive discovery of all subdomains (assume up to 1000).

For each subdomain:
   - DNS status
   - A record IP
   - CNAME target
   - Takeover risk
   - SSL status
   - Expired certificate flag
   - Reputation score
   - HTTP status
   - Sensitive exposure flag

Provide:
   - Total subdomains found
   - High-risk subdomains count
   - CSV-ready structured array
   - Summary risk heatmap

=====================================================
PHASE 3 – ENTERPRISE DEPLOYMENT ARCHITECTURE
=====================================================

Provide architecture guidance for:

A. Internal Hosting
   - Backend: Python microservice
   - Queue processing for 1000+ domains
   - Database recommendation
   - Logging & audit storage
   - API key vault management
   - Rate limiting strategy

B. Web Application Deployment
   - REST API design
   - Frontend dashboard (React / Flutter)
   - Spreadsheet export feature
   - CLI output option
   - Report PDF generation

C. Internal Server Requirements
   - Minimum CPU cores
   - RAM
   - Storage
   - Network bandwidth
   - Horizontal scaling model

D. API Integrations Required
   - AbuseIPDB
   - VirusTotal
   - AlienVault OTX
   - URLScan
   - SSL Labs equivalent
   - dnspython
   - OpenSSL
   - WHOIS providers

=====================================================
PHASE 4 – GEMINI AI + GOOGLE MCP SERVER
=====================================================

Provide:
   - Gemini integration flow
   - Structured JSON enforcement strategy
   - Rate limit handling
   - Retry with exponential backoff
   - Cost optimization strategy
   - MCP server integration model
   - Secure prompt engineering method
   - Audit and traceability design

=====================================================
OUTPUT FORMAT (STRICT)
=====================================================

Respond ONLY in valid JSON.

Structure:

{
  "domain": "",
  "phase1_single_domain_analysis": {},
  "phase2_subdomain_analysis": {
      "total_subdomains_found": 0,
      "high_risk_count": 0,
      "subdomains": []
  },
  "phase3_enterprise_architecture": {},
  "phase4_gemini_mcp_integration": {},
  "overall_risk_level": "",
  "executive_summary": "",
  "recommendations": []
}

Do NOT include markdown.
Do NOT include explanations outside JSON.
Passive security intelligence only.
"""
class GeminiService:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        self.client = genai.Client(
            api_key=api_key,
            http_options=HttpOptions(api_version="v1")
        )
        self.model = "gemini-2.5-flash"   # stable & fast

    def generate(self, prompt, max_retries=3):
        delay = 2  # initial delay (seconds)

        for attempt in range(max_retries):
            try:
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=prompt
                )
                return response.text

            except errors.ClientError as e:
                if "429" in str(e):
                    print(f"Rate limited. Retrying in {delay}s...")
                    time.sleep(delay)
                    delay *= 2  # exponential backoff
                else:
                    raise e

        raise Exception("Max retries exceeded.")


if __name__ == "__main__":
    service = GeminiService()
    prompt = """
      INPUT DOMAIN:
      <<DOMAIN>>
      """
    domain = "cisco.com"
    final_prompt = prompt.replace("<<DOMAIN>>", domain)
    result = service.generate(final_prompt)
    print(result)