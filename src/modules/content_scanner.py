"""Inbuilt content scanner module.

Fetches the homepage (and optional shallow same-origin links) and scans for
potential sensitive content using regex + entropy + context windows.
Stores evidence snippets and adds findings with confidence levels.
"""

import hashlib
import json
import math
import re
from typing import List, Tuple
from urllib.parse import urlparse, urljoin

import requests

from ..core.config import Config
from ..core.domain import DomainResult, Finding, Severity
from ..core.security import IPValidator
from .base import BaseModule


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    # frequency of each character
    freq = {ch: s.count(ch) for ch in set(s)}
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())


class ContentScannerModule(BaseModule):
    name = "content_scanner"
    description = "Fetch homepage and shallow links; scan for sensitive content"

    def __init__(self, config: Config, rate_limiter):
        super().__init__(config, rate_limiter)
        cs_cfg = self.config.get("modules.content_scanner", {}) or {}
        self._module_config = cs_cfg
        self.request_timeout = int(cs_cfg.get("timeout_seconds", 5))
        self.max_redirects = int(cs_cfg.get("max_redirects", 10))
        self.max_body_bytes = int(cs_cfg.get("max_body_bytes", 1048576))
        self.deep_scan = bool(cs_cfg.get("deep_scan", False))
        self.shallow_links_limit = int(cs_cfg.get("shallow_links_limit", 5))
        self.user_agent = self.config.user_agent
        self.rules_path = self.config.get("rules.path", None)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })

        # Load local rules
        self.rules = self._load_rules()

    @property
    def is_enabled(self) -> bool:
        return bool(self._module_config.get("enabled", True))

    def _load_rules(self) -> dict:
        rules = {
            "allowlist": [],
            "denylist": [],
            "sensitive_patterns": [
                {"id": "aws_access_key", "regex": r"AKIA[0-9A-Z]{16}", "weight": 20},
                {"id": "jwt_token", "regex": r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "weight": 20},
                {"id": "api_key_like", "regex": r"(?i)(api[_-]?key|authorization|bearer)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "weight": 15},
                {"id": "secret_like", "regex": r"(?i)(secret|token|password)\s*[:=]\s*['\"][^'\"]{12,}['\"]", "weight": 15},
                {"id": "slack_webhook", "regex": r"https://hooks\.slack\.com/services/T[0-9A-Z]{9}/B[0-9A-Z]{9}/[A-Za-z0-9]{24}", "weight": 20},
                {"id": "google_api_key", "regex": r"AIza[0-9A-Za-z\-_]{35}", "weight": 15},
                {"id": "stripe_live_secret", "regex": r"sk_live_[0-9a-zA-Z]{24}", "weight": 20},
                {"id": "github_pat", "regex": r"ghp_[A-Za-z0-9]{36}", "weight": 20},
            ],
            "risky_paths": ["/login", "/admin", "/api", "/auth"],
        }
        if self.rules_path:
            try:
                import yaml
                with open(self.rules_path, "r", encoding="utf-8") as f:
                    file_rules = yaml.safe_load(f) or {}
                    # Merge shallowly
                    for k, v in file_rules.items():
                        rules[k] = v
            except Exception as e:
                self.logger.warning(f"Failed to load local rules: {e}")
        return rules

    def _safe_to_fetch(self, result: DomainResult) -> Tuple[bool, str]:
        safe_ips = IPValidator.filter_safe_ips(result.resolved_ips)
        if not safe_ips:
            return False, "No safe external IPs resolved; fetch skipped"
        return True, ""

    def _fetch(self, url: str) -> Tuple[requests.Response, List[str]]:
        resp = self.session.get(url, timeout=self.request_timeout, allow_redirects=True, stream=True)
        # track redirect chain
        chain = [h.headers.get("Location", h.url) or h.url for h in resp.history] + [resp.url]
        # enforce redirect cap (informational only; requests already followed)
        return resp, chain

    def _read_body_cap(self, resp: requests.Response) -> bytes:
        total = 0
        chunks = []
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= self.max_body_bytes:
                break
        return b"".join(chunks)

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        links = []
        for m in re.finditer(r"href=\"([^\"]+)\"|href='([^']+)'", html, flags=re.IGNORECASE):
            href = m.group(1) or m.group(2)
            if not href:
                continue
            # make absolute
            abs_url = urljoin(base_url, href)
            # same-origin only
            if urlparse(abs_url).netloc == urlparse(base_url).netloc:
                links.append(abs_url)
        # prioritize risky paths
        prioritized = []
        for rp in self.rules.get("risky_paths", []):
            for l in links:
                if urlparse(l).path.startswith(rp):
                    prioritized.append(l)
        # fill remaining
        for l in links:
            if l not in prioritized:
                prioritized.append(l)
        return prioritized[: self.shallow_links_limit]

    def _scan_text(self, text: str) -> List[dict]:
        hits = []
        for rule in self.rules.get("sensitive_patterns", []):
            for m in re.finditer(rule["regex"], text):
                start = max(0, m.start() - 120)
                end = min(len(text), m.end() + 120)
                snippet = text[start:end]
                token = m.group(0)
                ent = shannon_entropy(token)
                conf = "low"
                if ent >= 3.0 and len(token) >= 16:
                    conf = "medium"
                if ent >= 3.5 and len(token) >= 20:
                    conf = "high"
                hits.append({
                    "rule_id": rule["id"],
                    "weight": rule["weight"],
                    "confidence": conf,
                    "offset": m.start(),
                    "snippet": snippet,
                    "token": token,
                })
        return hits

    def execute(self, domain: str, result: DomainResult) -> None:
        ok, reason = self._safe_to_fetch(result)
        if not ok:
            result.add_finding(Finding(
                title="Content scan skipped",
                description=reason,
                severity=Severity.INFO,
                category="content_scan",
            ))
            return

        base_url = f"https://{domain}"
        try:
            resp, chain = self._fetch(base_url)
        except requests.RequestException:
            # try http
            try:
                resp, chain = self._fetch(f"http://{domain}")
            except requests.RequestException as e:
                result.add_finding(Finding(
                    title="Content fetch failed",
                    description=f"Fetch error: {e}",
                    severity=Severity.INFO,
                    category="content_scan",
                ))
                return

        # If captcha/bot page (heuristic)
        blocked = False
        body = b""
        try:
            body = self._read_body_cap(resp)
        except Exception:
            pass
        text = ""
        try:
            text = body.decode(resp.encoding or "utf-8", errors="replace")
        except Exception:
            text = body.decode("utf-8", errors="replace")

        if re.search(r"(?i)captcha|robot|bot\s*detection", text):
            blocked = True

        # Evidence files
        ev_dir = self.config.evidence_dir
        domain_dir = ev_dir / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        headers_path = domain_dir / "homepage_headers.json"
        snippets_path = domain_dir / "homepage_snippets.json"
        hash_path = domain_dir / "homepage_hash.txt"

        try:
            headers = {
                "status_code": resp.status_code,
                "url": resp.url,
                "history": chain,
                "headers": dict(resp.headers),
            }
            with open(headers_path, "w", encoding="utf-8") as f:
                json.dump(headers, f, indent=2)
            with open(hash_path, "w", encoding="utf-8") as f:
                f.write(hashlib.sha256(body).hexdigest())
        except Exception:
            pass

        hits = self._scan_text(text)
        if self.deep_scan and not blocked:
            links = self._extract_links(text, resp.url)
            for l in links:
                try:
                    r2, _ = self._fetch(l)
                    b2 = self._read_body_cap(r2)
                    t2 = b2.decode(r2.encoding or "utf-8", errors="replace")
                    hits.extend(self._scan_text(t2))
                except Exception:
                    continue

        # Persist snippets
        try:
            with open(snippets_path, "w", encoding="utf-8") as f:
                json.dump({"hits": hits}, f, indent=2)
        except Exception:
            pass

        # Findings
        if blocked:
            result.add_finding(Finding(
                title="Automated access blocked",
                description="Encountered bot detection/CAPTCHA; recorded headers, no deep content scan",
                severity=Severity.INFO,
                category="content_scan",
            ))

        if hits:
            # escalate based on top confidence
            conf_order = {"low": 0, "medium": 1, "high": 2}
            top = max(hits, key=lambda h: conf_order.get(h["confidence"], 0))
            sev = Severity.LOW
            if top["confidence"] == "medium":
                sev = Severity.MEDIUM
            elif top["confidence"] == "high":
                sev = Severity.HIGH

            evidence_lines = []
            for h in hits[:5]:
                evidence_lines.append(f"[{h['confidence']}] {h['rule_id']}: {h['token']}\n---\n{h['snippet']}")
            result.add_finding(Finding(
                title="Sensitive content indicators",
                description=f"Detected {len(hits)} potential secrets/tokens across homepage/shallow links",
                severity=sev,
                category="content_scan",
                evidence="\n\n".join(evidence_lines),
                raw_data={"hits": hits},
                remediation="Review exposed content; remove secrets from client-side, rotate tokens, add security headers.",
            ))
        else:
            result.add_finding(Finding(
                title="No sensitive content indicators",
                description="Homepage scan did not reveal likely secrets/tokens",
                severity=Severity.INFO,
                category="content_scan",
            ))
