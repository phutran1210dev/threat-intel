"""
Alert management system for threat intelligence dashboard.
Handles alert generation, notification, and lifecycle management.
"""

import asyncio
import logging
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Optional
import aiohttp
import json

from src.models.ioc import IOCModel, ThreatLevel
from src.models.alert import (
    AlertModel, AlertRule, AlertSeverity, AlertStatus, AlertCategory,
    IOCMatch, ThreatContext, Evidence
)
from src.database.elasticsearch_client import ElasticsearchClient

logger = logging.getLogger(__name__)


class AlertManager:
    """Manages security alerts and notifications."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize alert manager with configuration."""
        self.config = config
        self.alert_config = config.get('alerting', {})
        self.es_client = ElasticsearchClient(config['elasticsearch'])
        
        # Alert rules
        self.rules = self._initialize_rules()
        
        # Rate limiting
        self.alert_history = {}
        self.max_alerts_per_hour = self.alert_config.get('max_alerts_per_hour', 100)
        
    def _initialize_rules(self) -> List[AlertRule]:
        """Initialize default alert rules."""
        rules = [
            # High confidence IOC rule
            AlertRule(
                id="high_confidence_ioc",
                name="High Confidence IOC Detected",
                description="IOC with confidence >= 80%",
                severity=AlertSeverity.HIGH
            ),
            
            # Critical threat level rule
            AlertRule(
                id="critical_threat_ioc",
                name="Critical Threat Level IOC",
                description="IOC with critical threat level",
                severity=AlertSeverity.CRITICAL
            ),
            
            # APT related IOC rule
            AlertRule(
                id="apt_related_ioc",
                name="APT-Related IOC Detected",
                description="IOC tagged with APT campaigns",
                severity=AlertSeverity.HIGH
            ),
            
            # Mass IOC correlation rule
            AlertRule(
                id="mass_ioc_correlation",
                name="Mass IOC Correlation",
                description="Multiple related IOCs detected",
                severity=AlertSeverity.MEDIUM
            ),
            
            # Malware family rule
            AlertRule(
                id="known_malware_family",
                name="Known Malware Family IOC",
                description="IOC associated with known malware family",
                severity=AlertSeverity.HIGH
            )
        ]
        
        return rules
        
    async def evaluate_ioc(self, ioc: IOCModel) -> List[AlertModel]:
        """Evaluate IOC against alert rules and generate alerts."""
        alerts = []
        
        try:
            # Check if alerting is enabled
            if not self.alert_config.get('enabled', True):
                return alerts
                
            # Check rate limiting
            if not self._check_rate_limit():
                logger.warning("Alert rate limit exceeded, skipping alert generation")
                return alerts
                
            # Evaluate each rule
            for rule in self.rules:
                if await self._evaluate_rule(rule, ioc):
                    alert = await self._create_alert(rule, ioc)
                    if alert:
                        alerts.append(alert)
                        
        except Exception as e:
            logger.error(f"Error evaluating IOC for alerts: {e}")
            
        return alerts
        
    async def _evaluate_rule(self, rule: AlertRule, ioc: IOCModel) -> bool:
        """Evaluate a specific rule against an IOC."""
        try:
            # High confidence IOC rule
            if rule.id == "high_confidence_ioc":
                return ioc.get_max_confidence() >= 80
                
            # Critical threat level rule
            elif rule.id == "critical_threat_ioc":
                return ioc.threat_level == ThreatLevel.CRITICAL
                
            # APT related IOC rule
            elif rule.id == "apt_related_ioc":
                apt_tags = ['apt', 'advanced persistent threat', 'targeted attack']
                return any(tag.lower() in apt_tags for tag in ioc.tags)
                
            # Known malware family rule
            elif rule.id == "known_malware_family":
                if ioc.enrichment and ioc.enrichment.malware_families:
                    return len(ioc.enrichment.malware_families) > 0
                return False
                
            # Mass IOC correlation rule
            elif rule.id == "mass_ioc_correlation":
                # This would check for correlated IOCs
                correlations = await self.es_client.correlate_iocs(ioc.value)
                return len(correlations.get('related_iocs', [])) >= 5
                
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating rule {rule.id}: {e}")
            return False
            
    async def _create_alert(self, rule: AlertRule, ioc: IOCModel) -> Optional[AlertModel]:
        """Create alert from rule and IOC."""
        try:
            # Create IOC match
            ioc_match = IOCMatch(
                ioc_id=ioc.value,  # Using value as ID for now
                ioc_value=ioc.value,
                ioc_type=ioc.type.value,
                confidence=ioc.get_max_confidence(),
                source="threat_intelligence_collector",
                context={"rule_triggered": rule.id}
            )
            
            # Create threat context if available
            threat_context = None
            if ioc.enrichment:
                threat_context = ThreatContext(
                    threat_actors=ioc.enrichment.threat_actors or [],
                    campaigns=ioc.enrichment.campaigns or [],
                    malware_families=ioc.enrichment.malware_families or []
                )
                
            # Create evidence
            evidence = [
                Evidence(
                    type="ioc_detection",
                    value=ioc.value,
                    description=f"IOC detected: {ioc.description or 'No description'}",
                    confidence=ioc.get_max_confidence(),
                    source=ioc.sources[0].name if ioc.sources else "unknown"
                )
            ]
            
            # Add enrichment data as evidence
            if ioc.enrichment:
                if ioc.enrichment.geo_location:
                    geo = ioc.enrichment.geo_location
                    evidence.append(Evidence(
                        type="geolocation",
                        value=f"{geo.country or 'Unknown'} ({geo.city or 'Unknown'})",
                        description="Geographic location information",
                        confidence=70,
                        source="geolocation_enrichment"
                    ))
                    
            # Determine alert category
            category = AlertCategory.IOC_MATCH
            if threat_context and threat_context.threat_actors:
                category = AlertCategory.THREAT_ACTOR
            elif threat_context and threat_context.malware_families:
                category = AlertCategory.MALWARE\n                \n            # Create alert\n            alert = AlertModel(\n                title=f"{rule.name}: {ioc.value}",\n                description=f"{rule.description}. IOC Type: {ioc.type.value}, Confidence: {ioc.get_max_confidence()}%",\n                severity=rule.severity,\n                category=category,\n                rule=rule,\n                ioc_matches=[ioc_match],\n                threat_context=threat_context,\n                evidence=evidence,\n                confidence=ioc.get_max_confidence(),\n                source_system="threat_intelligence_dashboard",\n                tags=ioc.tags\n            )\n            \n            # Calculate risk score\n            alert.update_risk_score()\n            \n            return alert\n            \n        except Exception as e:\n            logger.error(f"Error creating alert: {e}")\n            return None\n            \n    async def send_alert(self, alert: AlertModel):\n        """Send alert through configured notification channels."""\n        try:\n            # Check if alert meets minimum severity\n            min_severity_order = {\n                AlertSeverity.LOW: 0,\n                AlertSeverity.MEDIUM: 1,\n                AlertSeverity.HIGH: 2,\n                AlertSeverity.CRITICAL: 3\n            }\n            \n            min_severity = self.alert_config.get('min_severity', 'medium')\n            if min_severity_order.get(alert.severity, 1) < min_severity_order.get(min_severity, 1):\n                return\n                \n            # Store alert in Elasticsearch\n            await self._store_alert(alert)\n            \n            # Send notifications\n            notification_tasks = []\n            \n            # Email notifications\n            if self.alert_config.get('email', {}).get('enabled', False):\n                notification_tasks.append(self._send_email_alert(alert))\n                \n            # Slack notifications\n            if self.alert_config.get('slack', {}).get('enabled', False):\n                notification_tasks.append(self._send_slack_alert(alert))\n                \n            # Discord notifications\n            if self.alert_config.get('discord', {}).get('enabled', False):\n                notification_tasks.append(self._send_discord_alert(alert))\n                \n            # Webhook notifications\n            if self.alert_config.get('webhook', {}).get('enabled', False):\n                notification_tasks.append(self._send_webhook_alert(alert))\n                \n            # Execute all notifications concurrently\n            if notification_tasks:\n                await asyncio.gather(*notification_tasks, return_exceptions=True)\n                \n            logger.info(f"Alert sent: {alert.title}")\n            \n        except Exception as e:\n            logger.error(f"Error sending alert: {e}")\n            \n    async def _store_alert(self, alert: AlertModel):\n        """Store alert in Elasticsearch."""\n        try:\n            from src.models.alert import AlertDocument\n            \n            doc = AlertDocument.from_model(alert)\n            await self.es_client.index_document(doc)\n            \n        except Exception as e:\n            logger.error(f"Error storing alert: {e}")\n            \n    async def _send_email_alert(self, alert: AlertModel):\n        """Send alert via email."""\n        try:\n            email_config = self.alert_config['email']\n            \n            # Create email content\n            subject = f"[{alert.severity.value.upper()}] {alert.title}"\n            \n            body = f\"\"\"\n            Threat Intelligence Alert\n            \n            Title: {alert.title}\n            Severity: {alert.severity.value.upper()}\n            Category: {alert.category.value}\n            Risk Score: {alert.risk_score:.1f}\n            \n            Description:\n            {alert.description}\n            \n            IOC Details:\n            """\n            \n            for ioc_match in alert.ioc_matches:\n                body += f\"\n            - Type: {ioc_match.ioc_type}\n            - Value: {ioc_match.ioc_value}\n            - Confidence: {ioc_match.confidence}%\"\n            \n            if alert.threat_context:\n                if alert.threat_context.threat_actors:\n                    body += f\"\n            \n            Associated Threat Actors:\n            {', '.join(alert.threat_context.threat_actors)}\"\n                    \n                if alert.threat_context.malware_families:\n                    body += f\"\n            \n            Malware Families:\n            {', '.join(alert.threat_context.malware_families)}\"\n                    \n            body += f\"\n            \n            Created: {alert.created_at.isoformat()}\n            Source: {alert.source_system}\n            \n            Please review and take appropriate action.\n            \"\"\"\n            \n            # Send email\n            msg = MIMEMultipart()\n            msg['From'] = email_config['username']\n            msg['To'] = ', '.join(email_config['recipients'])\n            msg['Subject'] = subject\n            \n            msg.attach(MIMEText(body, 'plain'))\n            \n            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])\n            server.starttls()\n            server.login(email_config['username'], email_config['password'])\n            \n            text = msg.as_string()\n            server.sendmail(email_config['username'], email_config['recipients'], text)\n            server.quit()\n            \n            logger.info(f"Email alert sent: {alert.title}")\n            \n        except Exception as e:\n            logger.error(f"Error sending email alert: {e}")\n            \n    async def _send_slack_alert(self, alert: AlertModel):\n        """Send alert via Slack webhook."""\n        try:\n            slack_config = self.alert_config['slack']\n            \n            # Create Slack message\n            color_map = {\n                AlertSeverity.LOW: "good",\n                AlertSeverity.MEDIUM: "warning",\n                AlertSeverity.HIGH: "danger",\n                AlertSeverity.CRITICAL: "danger"\n            }\n            \n            message = {\n                "channel": slack_config['channel'],\n                "username": "Threat Intelligence Bot",\n                "icon_emoji": ":warning:",\n                "attachments": [\n                    {\n                        "color": color_map.get(alert.severity, "warning"),\n                        "title": alert.title,\n                        "text": alert.description,\n                        "fields": [\n                            {\n                                "title": "Severity",\n                                "value": alert.severity.value.upper(),\n                                "short": True\n                            },\n                            {\n                                "title": "Risk Score",\n                                "value": f"{alert.risk_score:.1f}",\n                                "short": True\n                            },\n                            {\n                                "title": "Category",\n                                "value": alert.category.value,\n                                "short": True\n                            },\n                            {\n                                "title": "IOCs",\n                                "value": f"{len(alert.ioc_matches)} IOC(s)",\n                                "short": True\n                            }\n                        ],\n                        "ts": int(alert.created_at.timestamp())\n                    }\n                ]\n            }\n            \n            # Send to Slack\n            async with aiohttp.ClientSession() as session:\n                async with session.post(\n                    slack_config['webhook_url'],\n                    json=message\n                ) as response:\n                    if response.status == 200:\n                        logger.info(f"Slack alert sent: {alert.title}")\n                    else:\n                        logger.error(f"Slack alert failed: {response.status}")\n                        \n        except Exception as e:\n            logger.error(f"Error sending Slack alert: {e}")\n            \n    async def _send_discord_alert(self, alert: AlertModel):\n        """Send alert via Discord webhook."""\n        try:\n            discord_config = self.alert_config['discord']\n            \n            # Create Discord embed\n            color_map = {\n                AlertSeverity.LOW: 3447003,      # Blue\n                AlertSeverity.MEDIUM: 16776960,  # Yellow\n                AlertSeverity.HIGH: 16744448,    # Orange\n                AlertSeverity.CRITICAL: 15158332 # Red\n            }\n            \n            embed = {\n                "title": alert.title,\n                "description": alert.description[:2048],  # Discord limit\n                "color": color_map.get(alert.severity, 16776960),\n                "timestamp": alert.created_at.isoformat(),\n                "fields": [\n                    {\n                        "name": "Severity",\n                        "value": alert.severity.value.upper(),\n                        "inline": True\n                    },\n                    {\n                        "name": "Risk Score",\n                        "value": f"{alert.risk_score:.1f}",\n                        "inline": True\n                    },\n                    {\n                        "name": "Category",\n                        "value": alert.category.value,\n                        "inline": True\n                    }\n                ],\n                "footer": {\n                    "text": f"Source: {alert.source_system}"\n                }\n            }\n            \n            # Add IOC information\n            if alert.ioc_matches:\n                ioc_text = "\\n".join([\n                    f"{match.ioc_type}: {match.ioc_value} ({match.confidence}%)"\n                    for match in alert.ioc_matches[:5]  # Limit to 5\n                ])\n                embed["fields"].append({\n                    "name": "IOCs",\n                    "value": ioc_text[:1024],  # Discord field limit\n                    "inline": False\n                })\n                \n            message = {\n                "embeds": [embed]\n            }\n            \n            # Send to Discord\n            async with aiohttp.ClientSession() as session:\n                async with session.post(\n                    discord_config['webhook_url'],\n                    json=message\n                ) as response:\n                    if response.status in [200, 204]:\n                        logger.info(f"Discord alert sent: {alert.title}")\n                    else:\n                        logger.error(f"Discord alert failed: {response.status}")\n                        \n        except Exception as e:\n            logger.error(f"Error sending Discord alert: {e}")\n            \n    async def _send_webhook_alert(self, alert: AlertModel):\n        """Send alert via custom webhook."""\n        try:\n            webhook_config = self.alert_config['webhook']\n            \n            # Create webhook payload\n            payload = {\n                "alert": alert.dict(),\n                "timestamp": datetime.utcnow().isoformat()\n            }\n            \n            # Prepare headers\n            headers = {\n                "Content-Type": "application/json"\n            }\n            headers.update(webhook_config.get('headers', {}))\n            \n            # Send webhook\n            async with aiohttp.ClientSession() as session:\n                async with session.post(\n                    webhook_config['url'],\n                    json=payload,\n                    headers=headers\n                ) as response:\n                    if 200 <= response.status < 300:\n                        logger.info(f"Webhook alert sent: {alert.title}")\n                    else:\n                        logger.error(f"Webhook alert failed: {response.status}")\n                        \n        except Exception as e:\n            logger.error(f"Error sending webhook alert: {e}")\n            \n    def _check_rate_limit(self) -> bool:\n        """Check if alert rate limit is exceeded."""\n        try:\n            current_time = datetime.utcnow()\n            hour_key = current_time.strftime("%Y-%m-%d-%H")\n            \n            # Clean old entries\n            cutoff_time = current_time - timedelta(hours=2)\n            self.alert_history = {\n                key: count for key, count in self.alert_history.items()\n                if datetime.strptime(key, "%Y-%m-%d-%H") > cutoff_time\n            }\n            \n            # Check current hour count\n            current_count = self.alert_history.get(hour_key, 0)\n            \n            if current_count >= self.max_alerts_per_hour:\n                return False\n                \n            # Increment count\n            self.alert_history[hour_key] = current_count + 1\n            return True\n            \n        except Exception as e:\n            logger.error(f"Error checking rate limit: {e}")\n            return True  # Allow on error\n            \n    async def get_alert_metrics(self) -> Dict[str, Any]:\n        """Get alert system metrics."""\n        try:\n            # Get current hour stats\n            current_hour = datetime.utcnow().strftime("%Y-%m-%d-%H")\n            alerts_this_hour = self.alert_history.get(current_hour, 0)\n            \n            # Get recent alert statistics from Elasticsearch\n            recent_query = {\n                'date_range': {\n                    'from': (datetime.utcnow() - timedelta(hours=24)).isoformat()\n                }\n            }\n            \n            recent_alerts = await self.es_client.search_alerts(recent_query, size=0)\n            \n            return {\n                "alerts_this_hour": alerts_this_hour,\n                "max_alerts_per_hour": self.max_alerts_per_hour,\n                "rate_limit_remaining": self.max_alerts_per_hour - alerts_this_hour,\n                "alerts_last_24h": recent_alerts['total'],\n                "enabled_channels": {\n                    "email": self.alert_config.get('email', {}).get('enabled', False),\n                    "slack": self.alert_config.get('slack', {}).get('enabled', False),
                    "discord": self.alert_config.get('discord', {}).get('enabled', False),
                    "webhook": self.alert_config.get('webhook', {}).get('enabled', False)
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting alert metrics: {e}")
            return {}