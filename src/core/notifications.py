"""Webhook and Notification System for Domain Intelligence."""

import json
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass
from enum import Enum


class WebhookType(Enum):
    """Supported webhook types."""
    GENERIC = "generic"
    SLACK = "slack"
    DISCORD = "discord"
    TEAMS = "teams"
    CUSTOM = "custom"


@dataclass
class NotificationPayload:
    """Notification payload structure."""
    event_type: str
    title: str
    message: str
    severity: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "data": self.data,
            "timestamp": self.timestamp.isoformat()
        }


class WebhookNotifier:
    """Send notifications to webhooks."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def send(self, url: str, payload: NotificationPayload, 
             webhook_type: str = "generic") -> tuple[bool, Optional[str]]:
        """
        Send notification to a webhook.
        
        Returns:
            Tuple of (success, error_message)
        """
        try:
            if webhook_type == WebhookType.SLACK.value:
                formatted_payload = self._format_slack(payload)
            elif webhook_type == WebhookType.DISCORD.value:
                formatted_payload = self._format_discord(payload)
            elif webhook_type == WebhookType.TEAMS.value:
                formatted_payload = self._format_teams(payload)
            else:
                formatted_payload = payload.to_dict()
            
            response = requests.post(
                url,
                json=formatted_payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code in (200, 201, 202, 204):
                return True, None
            else:
                return False, f"HTTP {response.status_code}: {response.text[:200]}"
                
        except requests.exceptions.Timeout:
            return False, "Request timed out"
        except requests.exceptions.ConnectionError:
            return False, "Connection failed"
        except Exception as e:
            return False, str(e)
    
    def _format_slack(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Format payload for Slack webhook."""
        color = self._get_severity_color(payload.severity)
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": payload.title,
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": payload.message
                }
            }
        ]
        
        # Add data fields if present
        if payload.data:
            fields = []
            for key, value in list(payload.data.items())[:10]:
                fields.append({
                    "type": "mrkdwn",
                    "text": f"*{key}:*\n{value}"
                })
            
            if fields:
                blocks.append({
                    "type": "section",
                    "fields": fields[:10]
                })
        
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Domain Intelligence | {payload.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                }
            ]
        })
        
        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks
                }
            ]
        }
    
    def _format_discord(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Format payload for Discord webhook."""
        color = self._get_severity_color_int(payload.severity)
        
        embed = {
            "title": payload.title,
            "description": payload.message,
            "color": color,
            "timestamp": payload.timestamp.isoformat(),
            "footer": {
                "text": "Domain Intelligence"
            }
        }
        
        if payload.data:
            fields = []
            for key, value in list(payload.data.items())[:25]:
                fields.append({
                    "name": key,
                    "value": str(value)[:1024],
                    "inline": True
                })
            embed["fields"] = fields
        
        return {
            "embeds": [embed]
        }
    
    def _format_teams(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Format payload for Microsoft Teams webhook."""
        color = self._get_severity_color(payload.severity)
        
        facts = []
        if payload.data:
            for key, value in list(payload.data.items())[:10]:
                facts.append({
                    "name": key,
                    "value": str(value)
                })
        
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color.replace("#", ""),
            "summary": payload.title,
            "sections": [
                {
                    "activityTitle": payload.title,
                    "activitySubtitle": payload.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "facts": facts,
                    "text": payload.message
                }
            ]
        }
    
    @staticmethod
    def _get_severity_color(severity: Optional[str]) -> str:
        """Get color code for severity level."""
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d"
        }
        return colors.get(severity.lower() if severity else "", "#00d4aa")
    
    @staticmethod
    def _get_severity_color_int(severity: Optional[str]) -> int:
        """Get color as integer for Discord."""
        colors = {
            "critical": 0xdc3545,
            "high": 0xfd7e14,
            "medium": 0xffc107,
            "low": 0x17a2b8,
            "info": 0x6c757d
        }
        return colors.get(severity.lower() if severity else "", 0x00d4aa)


class NotificationService:
    """Service for managing and sending notifications."""
    
    def __init__(self):
        self.notifier = WebhookNotifier()
    
    def notify_scan_complete(self, webhooks: List[Dict], scan_data: Dict[str, Any]) -> List[Dict]:
        """Send scan completion notification to all webhooks."""
        results = []
        
        # Build summary
        domains = scan_data.get("domains", [])
        total_findings = scan_data.get("total_findings", 0)
        severity_breakdown = scan_data.get("severity_breakdown", {})
        duration = scan_data.get("duration_seconds", 0)
        
        highest_severity = "info"
        for sev in ["critical", "high", "medium", "low"]:
            if severity_breakdown.get(sev, 0) > 0:
                highest_severity = sev
                break
        
        payload = NotificationPayload(
            event_type="scan_complete",
            title="Domain Scan Complete",
            message=f"Scan of {len(domains)} domain(s) completed in {duration:.1f}s",
            severity=highest_severity,
            data={
                "Domains Scanned": len(domains),
                "Total Findings": total_findings,
                "Critical": severity_breakdown.get("critical", 0),
                "High": severity_breakdown.get("high", 0),
                "Medium": severity_breakdown.get("medium", 0),
                "Low": severity_breakdown.get("low", 0),
                "Duration": f"{duration:.1f}s"
            }
        )
        
        for webhook in webhooks:
            success, error = self.notifier.send(
                webhook["url"],
                payload,
                webhook.get("webhook_type", "generic")
            )
            results.append({
                "webhook_id": webhook.get("id"),
                "webhook_name": webhook.get("name"),
                "success": success,
                "error": error
            })
        
        return results
    
    def notify_critical_finding(self, webhooks: List[Dict], finding_data: Dict[str, Any]) -> List[Dict]:
        """Send critical finding notification."""
        results = []
        
        payload = NotificationPayload(
            event_type="critical_finding",
            title="Critical Security Finding Detected",
            message=finding_data.get("description", "A critical security issue was detected"),
            severity="critical",
            data={
                "Domain": finding_data.get("domain", "Unknown"),
                "Finding": finding_data.get("title", "Unknown"),
                "Category": finding_data.get("category", "Unknown")
            }
        )
        
        for webhook in webhooks:
            success, error = self.notifier.send(
                webhook["url"],
                payload,
                webhook.get("webhook_type", "generic")
            )
            results.append({
                "webhook_id": webhook.get("id"),
                "success": success,
                "error": error
            })
        
        return results
    
    def send_test_notification(self, url: str, webhook_type: str = "generic") -> tuple[bool, Optional[str]]:
        """Send a test notification."""
        payload = NotificationPayload(
            event_type="test",
            title="Test Notification",
            message="This is a test notification from Domain Intelligence",
            severity="info",
            data={
                "Status": "Connected",
                "Source": "Domain Intelligence"
            }
        )
        
        return self.notifier.send(url, payload, webhook_type)


# Global notification service instance
notification_service = NotificationService()
