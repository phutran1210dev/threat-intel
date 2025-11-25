"""
Alert management system for threat intelligence dashboard.
"""

import asyncio
import smtplib
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from ..models.alert import AlertModel, AlertSeverity, AlertStatus
from ..models.ioc import IOCModel


class AlertManager:
    """Manages security alerts and notifications."""
    
    def __init__(self, es_client, alert_config: Dict[str, Any]):
        """Initialize alert manager."""
        self.es_client = es_client
        self.alert_config = alert_config
        self.max_alerts_per_hour = alert_config.get('max_alerts_per_hour', 100)
        self.alert_history = {}
        
    async def create_alert_from_ioc(self, ioc: IOCModel, rule: Dict[str, Any], 
                                   threat_context: Optional[Dict[str, Any]] = None) -> Optional[AlertModel]:
        """Create alert from IOC match."""
        try:
            # Check rate limit
            if not self._check_rate_limit():
                return None
                
            # Create IOC match object
            ioc_match = {
                'ioc_value': ioc.value,
                'ioc_type': ioc.type.value,
                'confidence': ioc.confidence,
                'matched_rule': rule['name']
            }
            
            # Determine alert category
            category = "ioc_match"
            if threat_context and threat_context.get('threat_actors'):
                category = "threat_actor"
            elif threat_context and threat_context.get('malware_families'):
                category = "malware"
                
            # Create alert
            alert = AlertModel(
                title=f"{rule['name']}: {ioc.value}",
                description=f"{rule['description']}. IOC Type: {ioc.type.value}, Confidence: {ioc.confidence}%",
                severity=AlertSeverity(rule['severity']),
                category=category,
                ioc_matches=[ioc_match],
                threat_context=threat_context,
                confidence=ioc.confidence,
                source_system="threat_intelligence_dashboard",
                tags=ioc.tags or []
            )
            
            # Calculate risk score
            alert.update_risk_score()
            
            return alert
            
        except Exception as e:
            print(f"Error creating alert: {e}")
            return None
            
    async def send_alert(self, alert: AlertModel):
        """Send alert through configured notification channels."""
        try:
            # Store alert in Elasticsearch
            await self._store_alert(alert)
            
            # Send notifications
            notification_tasks = []
            
            if self.alert_config.get('email', {}).get('enabled', False):
                notification_tasks.append(self._send_email_alert(alert))
                
            if self.alert_config.get('slack', {}).get('enabled', False):
                notification_tasks.append(self._send_slack_alert(alert))
                
            # Execute notifications
            if notification_tasks:
                await asyncio.gather(*notification_tasks, return_exceptions=True)
                
        except Exception as e:
            print(f"Error sending alert: {e}")
            
    async def _store_alert(self, alert: AlertModel):
        """Store alert in Elasticsearch."""
        try:
            from ..models.alert import AlertDocument
            doc = AlertDocument.from_model(alert)
            await self.es_client.index_document(doc)
        except Exception as e:
            print(f"Error storing alert: {e}")
            
    async def _send_email_alert(self, alert: AlertModel):
        """Send alert via email."""
        try:
            email_config = self.alert_config['email']
            subject = f"[{alert.severity.value.upper()}] {alert.title}"
            
            body = f"""
            Threat Intelligence Alert
            
            Title: {alert.title}
            Severity: {alert.severity.value.upper()}
            Risk Score: {alert.risk_score:.1f}
            
            Description: {alert.description}
            
            Created: {alert.created_at.isoformat()}
            """
            
            msg = MIMEMultipart()
            msg['From'] = email_config['username']
            msg['To'] = ', '.join(email_config['recipients'])
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['username'], email_config['password'])
            server.sendmail(email_config['username'], email_config['recipients'], msg.as_string())
            server.quit()
            
        except Exception as e:
            print(f"Error sending email alert: {e}")
            
    async def _send_slack_alert(self, alert: AlertModel):
        """Send alert via Slack webhook."""
        try:
            slack_config = self.alert_config['slack']
            
            message = {
                "channel": slack_config['channel'],
                "username": "Threat Intelligence Bot",
                "text": f"*{alert.title}*\n{alert.description}\nSeverity: {alert.severity.value.upper()}"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(slack_config['webhook_url'], json=message) as response:
                    if response.status == 200:
                        print(f"Slack alert sent: {alert.title}")
                        
        except Exception as e:
            print(f"Error sending Slack alert: {e}")
            
    def _check_rate_limit(self) -> bool:
        """Check if alert rate limit is exceeded."""
        try:
            current_time = datetime.utcnow()
            hour_key = current_time.strftime("%Y-%m-%d-%H")
            
            current_count = self.alert_history.get(hour_key, 0)
            
            if current_count >= self.max_alerts_per_hour:
                return False
                
            self.alert_history[hour_key] = current_count + 1
            return True
            
        except Exception:
            return True
            
    async def get_alert_metrics(self) -> Dict[str, Any]:
        """Get alert system metrics."""
        try:
            current_hour = datetime.utcnow().strftime("%Y-%m-%d-%H")
            alerts_this_hour = self.alert_history.get(current_hour, 0)
            
            return {
                "alerts_this_hour": alerts_this_hour,
                "max_alerts_per_hour": self.max_alerts_per_hour,
                "rate_limit_remaining": self.max_alerts_per_hour - alerts_this_hour,
                "enabled_channels": {
                    "email": self.alert_config.get('email', {}).get('enabled', False),
                    "slack": self.alert_config.get('slack', {}).get('enabled', False)
                }
            }
            
        except Exception as e:
            print(f"Error getting alert metrics: {e}")
            return {}