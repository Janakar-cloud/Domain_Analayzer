"""WHOIS lookup module."""

from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests
import whois
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

from ..core.domain import DomainResult, Finding, Severity, WHOISInfo
from .base import BaseModule


class WHOISModule(BaseModule):
    """
    WHOIS lookup for domain registration information.
    
    Extracts registrar, registrant, dates, and performs age analysis.
    """

    name = "whois_lookup"
    description = "Retrieve WHOIS registration information"

    def execute(self, domain: str, result: DomainResult) -> None:
        """
        Perform RDAP-first registration lookup for the domain.

        Falls back to classic WHOIS when RDAP is unavailable.

        Args:
            domain: Domain to lookup
            result: DomainResult to populate
        """
        self.rate_limit("whois")

        whois_info = self._lookup_rdap(domain)
        if not whois_info:
            whois_info = self._lookup_whois(domain)

        if whois_info:
            result.whois_info = whois_info
            self._analyze_whois(whois_info, domain, result)
        else:
            result.add_error(f"Could not retrieve WHOIS/RDAP information for {domain}")

    def _lookup_rdap(self, domain: str) -> Optional[WHOISInfo]:
        """
        Perform RDAP lookup.

        Args:
            domain: Domain to look up

        Returns:
            WHOISInfo object or None
        """
        endpoints = self.get_setting("rdap_endpoints", ["https://rdap.org/domain/{domain}"])
        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": self.config.user_agent,
        }

        for template in endpoints:
            url = str(template).format(domain=domain)
            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    headers=headers,
                    proxies=self.config.proxy_settings,
                )
            except requests.RequestException as exc:
                self.logger.debug(f"RDAP request failed for {domain} via {url}: {exc}")
                continue

            if response.status_code == 200:
                try:
                    data = response.json() or {}
                except ValueError:
                    self.logger.debug(f"RDAP returned non-JSON response for {domain} via {url}")
                    continue

                parsed = self._parse_rdap_response(data)
                if parsed:
                    parsed.lookup_source = "RDAP"
                    return parsed
                continue

            if response.status_code in (404, 501):
                continue

            self.logger.debug(
                f"RDAP returned status {response.status_code} for {domain} via {url}"
            )

        return None

    def _parse_rdap_response(self, data: Dict) -> Optional[WHOISInfo]:
        """Parse RDAP response into WHOISInfo."""
        if not isinstance(data, dict) or not data:
            return None

        entities = data.get("entities") or []

        registrar = None
        registrant_org = None
        registrant_country = None

        for entity in entities:
            roles = [str(r).lower() for r in entity.get("roles", [])]
            vcard = self._vcard_map(entity)
            name = self._pick_vcard(vcard, "fn") or self._pick_vcard(vcard, "org")
            country = self._pick_vcard_country(vcard)

            if "registrar" in roles and not registrar:
                registrar = name

            if "registrant" in roles:
                if not registrant_org:
                    registrant_org = name
                if not registrant_country:
                    registrant_country = country

        if not registrar:
            registrar = data.get("registrar")

        creation_date = self._extract_rdap_event_date(
            data, {"registration", "registered"}
        )
        expiration_date = self._extract_rdap_event_date(
            data, {"expiration", "expiry", "expire", "expiration date"}
        )
        updated_date = self._extract_rdap_event_date(
            data,
            {
                "last changed",
                "last update of rdap database",
                "last update",
                "updated",
                "changed",
            },
        )

        domain_age_days = None
        if creation_date:
            now = datetime.now(timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            domain_age_days = (now - creation_date).days

        nameservers = []
        for item in data.get("nameservers", []) or []:
            if isinstance(item, dict):
                value = item.get("ldhName") or item.get("unicodeName")
            else:
                value = None
            if value:
                nameservers.append(str(value).lower())

        secure_dns = data.get("secureDNS") or {}
        dnssec = None
        if isinstance(secure_dns, dict) and "delegationSigned" in secure_dns:
            dnssec = "signed" if secure_dns.get("delegationSigned") else "unsigned"

        status_raw = data.get("status") or []
        if isinstance(status_raw, list):
            status = [str(s) for s in status_raw]
        elif status_raw:
            status = [str(status_raw)]
        else:
            status = []

        has_useful_data = any(
            [registrar, registrant_org, creation_date, expiration_date, nameservers, status]
        )
        if not has_useful_data:
            return None

        return WHOISInfo(
            registrar=registrar,
            registrant_org=registrant_org,
            registrant_country=registrant_country,
            creation_date=creation_date,
            expiration_date=expiration_date,
            updated_date=updated_date,
            name_servers=nameservers,
            dnssec=dnssec,
            status=status,
            domain_age_days=domain_age_days,
            lookup_source="RDAP",
        )

    def _vcard_map(self, entity: Dict) -> Dict[str, List]:
        """Convert entity vcardArray structure to a key->list mapping."""
        result: Dict[str, List] = {}
        vcard_array = entity.get("vcardArray")

        if not isinstance(vcard_array, list) or len(vcard_array) < 2:
            return result

        rows = vcard_array[1]
        if not isinstance(rows, list):
            return result

        for row in rows:
            if not isinstance(row, list) or len(row) < 4:
                continue
            key = str(row[0]).lower()
            value = row[3]
            result.setdefault(key, []).append(value)

        return result

    def _pick_vcard(self, vcard_map: Dict[str, List], key: str) -> Optional[str]:
        values = vcard_map.get(key) or []
        for value in values:
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return None

    def _pick_vcard_country(self, vcard_map: Dict[str, List]) -> Optional[str]:
        country = self._pick_vcard(vcard_map, "country")
        if country:
            return country

        for value in vcard_map.get("adr", []):
            if isinstance(value, list) and len(value) >= 7 and value[6]:
                return str(value[6]).strip()
        return None

    def _extract_rdap_event_date(self, data: Dict, actions: set[str]) -> Optional[datetime]:
        events = data.get("events") or []
        for event in events:
            action = str(event.get("eventAction", "")).strip().lower()
            if action in actions:
                return self._parse_whois_date(event.get("eventDate"))
        return None

    def _lookup_whois(self, domain: str) -> Optional[WHOISInfo]:
        """
        Perform WHOIS lookup.

        Args:
            domain: Domain to lookup

        Returns:
            WHOISInfo object or None
        """
        try:
            # Run WHOIS in a thread to enforce a timeout on slow registries
            def _do_lookup():
                return whois.whois(domain)

            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_do_lookup)
                try:
                    w = future.result(timeout=self.timeout)
                except FuturesTimeout:
                    self.logger.warning(f"WHOIS lookup timed out for {domain} after {self.timeout}s")
                    return None
            
            if not w or not w.domain_name:
                return None
            
            # Parse dates
            creation_date = self._parse_whois_date(w.creation_date)
            expiration_date = self._parse_whois_date(w.expiration_date)
            updated_date = self._parse_whois_date(w.updated_date)
            
            # Calculate domain age
            domain_age_days = None
            if creation_date:
                now = datetime.now(timezone.utc)
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                domain_age_days = (now - creation_date).days
            
            # Parse name servers
            name_servers = []
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    name_servers = [ns.lower() for ns in w.name_servers if ns]
                else:
                    name_servers = [w.name_servers.lower()]
            
            # Parse status
            status = []
            if w.status:
                if isinstance(w.status, list):
                    status = list(w.status)
                else:
                    status = [w.status]
            
            return WHOISInfo(
                registrar=w.registrar,
                registrant_org=getattr(w, 'org', None) or getattr(w, 'registrant_org', None),
                registrant_country=getattr(w, 'country', None) or getattr(w, 'registrant_country', None),
                creation_date=creation_date,
                expiration_date=expiration_date,
                updated_date=updated_date,
                name_servers=name_servers,
                dnssec=getattr(w, 'dnssec', None),
                status=status,
                domain_age_days=domain_age_days,
                lookup_source="WHOIS",
            )
            
        except whois.parser.PywhoisError as e:
            self.logger.warning(f"WHOIS error for {domain}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error looking up WHOIS for {domain}: {e}")
            return None

    def _parse_whois_date(self, date_value) -> Optional[datetime]:
        """Parse WHOIS date field which may be a list or single value."""
        if not date_value:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0]
        
        if isinstance(date_value, datetime):
            return date_value
        
        if isinstance(date_value, str):
            try:
                return datetime.fromisoformat(date_value.replace('Z', '+00:00'))
            except ValueError:
                pass
        
        return None

    def _analyze_whois(self, info: WHOISInfo, domain: str, result: DomainResult) -> None:
        """
        Analyze WHOIS information for security insights.

        Args:
            info: WHOISInfo to analyze
            domain: Domain being analyzed
            result: DomainResult to add findings to
        """
        # Check domain age (newly registered domains are often suspicious)
        if info.domain_age_days is not None:
            if info.domain_age_days < 30:
                result.add_finding(Finding(
                    title="Newly Registered Domain",
                    description=f"Domain was registered {info.domain_age_days} days ago",
                    severity=Severity.MEDIUM,
                    category="domain_reputation",
                    evidence=f"Creation date: {info.creation_date}",
                    remediation="Newly registered domains may indicate phishing or fraud. Verify domain ownership.",
                ))
            elif info.domain_age_days < 90:
                result.add_finding(Finding(
                    title="Recently Registered Domain",
                    description=f"Domain was registered {info.domain_age_days} days ago",
                    severity=Severity.LOW,
                    category="domain_reputation",
                    evidence=f"Creation date: {info.creation_date}",
                ))
        
        # Check for expiring domain
        if info.expiration_date:
            now = datetime.now(timezone.utc)
            exp_date = info.expiration_date
            if exp_date.tzinfo is None:
                exp_date = exp_date.replace(tzinfo=timezone.utc)
            
            days_until_expiry = (exp_date - now).days
            
            if days_until_expiry < 0:
                result.add_finding(Finding(
                    title="Domain Registration Expired",
                    description=f"Domain registration expired {abs(days_until_expiry)} days ago",
                    severity=Severity.HIGH,
                    category="domain_management",
                    evidence=f"Expiration date: {info.expiration_date}",
                    remediation="Renew the domain registration immediately to prevent takeover.",
                ))
            elif days_until_expiry <= 30:
                result.add_finding(Finding(
                    title="Domain Registration Expiring Soon",
                    description=f"Domain registration expires in {days_until_expiry} days",
                    severity=Severity.MEDIUM,
                    category="domain_management",
                    evidence=f"Expiration date: {info.expiration_date}",
                    remediation="Renew the domain registration to prevent service disruption.",
                ))
        
        # Check DNSSEC
        if info.dnssec and info.dnssec.lower() in ['unsigned', 'no', 'inactive']:
            result.add_finding(Finding(
                title="DNSSEC Not Enabled",
                description="Domain does not have DNSSEC enabled",
                severity=Severity.LOW,
                category="dns_security",
                remediation="Consider enabling DNSSEC to protect against DNS spoofing attacks.",
            ))
        
        # Check for privacy protection (may indicate legitimate business or suspicious activity)
        privacy_indicators = ['privacy', 'proxy', 'redacted', 'whoisguard', 'domains by proxy']
        registrar_lower = (info.registrar or '').lower()
        org_lower = (info.registrant_org or '').lower()
        
        is_privacy_protected = any(
            ind in registrar_lower or ind in org_lower 
            for ind in privacy_indicators
        )
        
        if is_privacy_protected:
            result.add_finding(Finding(
                title="WHOIS Privacy Protection Enabled",
                description="Domain uses WHOIS privacy protection service",
                severity=Severity.INFO,
                category="domain_reputation",
                evidence=f"Registrant: {info.registrant_org or 'N/A'}",
            ))
        
        # Add informational finding with registration details.
        result.add_finding(Finding(
            title="WHOIS Information",
            description=f"Registration details for {domain}",
            severity=Severity.INFO,
            category="domain_information",
            evidence=(
                f"Source: {info.lookup_source or 'WHOIS'}\n"
                f"Registrar: {info.registrar or 'N/A'}\n"
                f"Organization: {info.registrant_org or 'N/A'}\n"
                f"Country: {info.registrant_country or 'N/A'}\n"
                f"Created: {info.creation_date or 'N/A'}\n"
                f"Expires: {info.expiration_date or 'N/A'}\n"
                f"Age: {info.domain_age_days or 'N/A'} days"
            ),
        ))
