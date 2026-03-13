"""
Proofpoint TAP (Threat & Anomaly Protection) Connector
Cobre: DLP / CASB / Email Security
"""
from connectors.base import BaseConnector
from typing import Dict, List, Optional
import uuid
from datetime import datetime, timedelta, timezone


class ProofpointConnector(BaseConnector):
    source_name = "proofpoint"
    display_name = "Proofpoint DLP/CASB"

    def __init__(self):
        super().__init__()
        self.base_url = self._get_credential("base_url", "PROOFPOINT_BASE_URL") or "https://tap-api-v2.proofpoint.com"
        self.principal = self._get_credential("service_principal", "PROOFPOINT_SERVICE_PRINCIPAL")
        self.secret = self._get_credential("secret", "PROOFPOINT_SECRET")

    def _auth(self):
        return (self.principal, self.secret)

    def test_connection(self) -> bool:
        if not self.principal or not self.secret:
            return False
        try:
            with self.get_http_client(self.base_url) as client:
                since = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                r = client.get("/v2/siem/all", auth=self._auth(), params={"sinceTime": since, "format": "JSON"})
                return r.status_code in (200, 204)
        except Exception as e:
            self.logger.error(f"Proofpoint test failed: {e}")
            return False

    def fetch_siem_events(self, hours_back: int = 24) -> Dict:
        try:
            since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
            with self.get_http_client(self.base_url) as client:
                r = client.get("/v2/siem/all", auth=self._auth(), params={"sinceTime": since, "format": "JSON"})
                r.raise_for_status()
                return r.json()
        except Exception as e:
            self.logger.error(f"Proofpoint SIEM fetch error: {e}")
            return {}

    def fetch_all(self) -> Dict:
        return self.fetch_siem_events(hours_back=24)

    def normalize_and_store(self, records: Dict, db) -> int:
        from models import ThreatEvent
        count = 0
        all_events = (
            records.get("messagesDelivered", []) +
            records.get("messagesBlocked", []) +
            records.get("clicksPermitted", []) +
            records.get("clicksBlocked", [])
        )
        for ev in all_events:
            try:
                src_id = ev.get("GUID") or ev.get("id", "")
                exists = db.query(ThreatEvent).filter(
                    ThreatEvent.source == "proofpoint",
                    ThreatEvent.source_event_id == str(src_id)
                ).first()
                if exists:
                    continue

                threat_score = float(ev.get("threatsInfoMap", [{}])[0].get("threatScore", 0) or 0) if ev.get("threatsInfoMap") else 0
                severity = "critical" if threat_score > 90 else "high" if threat_score > 70 else "medium" if threat_score > 40 else "low"

                event = ThreatEvent(
                    id=str(uuid.uuid4()),
                    source="proofpoint",
                    source_event_id=str(src_id),
                    event_type=ev.get("classification", "email_threat"),
                    severity=severity,
                    title=f"Proofpoint: {ev.get('subject', 'Email Threat')}",
                    description=f"Sender: {ev.get('sender')} | Recipients: {', '.join(ev.get('recipient', []))}",
                    status="open",
                    event_timestamp=_parse_dt(ev.get("messageTime")),
                    raw_data=ev,
                )
                db.add(event)
                count += 1
            except Exception as e:
                self.logger.error(f"Proofpoint normalize error: {e}")

        db.commit()
        return count


class MantisConnector(BaseConnector):
    """Mantis Threat Intelligence Platform Connector."""
    source_name = "mantis"
    display_name = "Mantis Threat Intelligence"

    def __init__(self):
        super().__init__()
        self.base_url = self._get_credential("base_url", "MANTIS_BASE_URL") or "https://api.mantis.internal"
        self.api_key = self._get_credential("api_key", "MANTIS_API_KEY")

    def _headers(self) -> Dict:
        return {"X-API-Key": self.api_key, "Accept": "application/json"}

    def test_connection(self) -> bool:
        if not self.api_key:
            return False
        try:
            with self.get_http_client(self.base_url) as client:
                r = client.get("/api/v1/health", headers=self._headers())
                return r.status_code == 200
        except Exception as e:
            self.logger.error(f"Mantis test failed: {e}")
            return False

    def fetch_iocs(self, page: int = 1, page_size: int = 500) -> List[Dict]:
        try:
            with self.get_http_client(self.base_url) as client:
                r = client.get("/api/v1/iocs", headers=self._headers(),
                                params={"page": page, "per_page": page_size, "status": "active"})
                r.raise_for_status()
                return r.json().get("data", [])
        except Exception as e:
            self.logger.error(f"Mantis IOC fetch error: {e}")
            return []

    def fetch_all(self) -> List[Dict]:
        return self._paginate(self.fetch_iocs, 500)

    def normalize_and_store(self, records: List[Dict], db) -> int:
        from models import ThreatEvent
        count = 0
        for ioc in records:
            try:
                src_id = str(ioc.get("id", ""))
                exists = db.query(ThreatEvent).filter(
                    ThreatEvent.source == "mantis",
                    ThreatEvent.source_event_id == src_id
                ).first()
                if exists:
                    continue

                event = ThreatEvent(
                    id=str(uuid.uuid4()),
                    source="mantis",
                    source_event_id=src_id,
                    event_type="threat_intel_ioc",
                    severity=self._map_severity(ioc.get("severity", "medium")),
                    title=f"Threat Intel IOC: {ioc.get('value', 'Unknown')}",
                    description=ioc.get("description"),
                    ioc_type=ioc.get("type"),
                    ioc_value=ioc.get("value"),
                    mitre_tactic=ioc.get("mitre_tactic"),
                    mitre_technique=ioc.get("mitre_technique"),
                    status="open",
                    event_timestamp=_parse_dt(ioc.get("created_at")),
                    raw_data=ioc,
                )
                db.add(event)
                count += 1
            except Exception as e:
                self.logger.error(f"Mantis normalize error: {e}")

        db.commit()
        return count


class CISOAssistanceConnector(BaseConnector):
    """CISO Assistance GRC — API Interna."""
    source_name = "ciso_assistance"
    display_name = "CISO Assistance GRC"

    def __init__(self):
        super().__init__()
        self.base_url = self._get_credential("base_url", "CISO_BASE_URL") or "http://ciso-assistance.internal:8080"
        self.api_key = self._get_credential("api_key", "CISO_API_KEY")
        import os
        self.verify_ssl = os.getenv("CISO_VERIFY_SSL", "false").lower() == "true"

    def _headers(self) -> Dict:
        return {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"}

    def test_connection(self) -> bool:
        if not self.api_key:
            return False
        try:
            with self.get_http_client(self.base_url, verify_ssl=self.verify_ssl) as client:
                r = client.get("/api/health", headers=self._headers())
                return r.status_code == 200
        except Exception as e:
            self.logger.error(f"CISO Assistance test failed: {e}")
            return False

    def fetch_controls(self, page: int = 1, page_size: int = 200) -> List[Dict]:
        try:
            with self.get_http_client(self.base_url, verify_ssl=self.verify_ssl) as client:
                r = client.get("/api/v1/controls", headers=self._headers(),
                                params={"page": page, "per_page": page_size})
                r.raise_for_status()
                return r.json().get("controls", [])
        except Exception as e:
            self.logger.error(f"CISO controls fetch error: {e}")
            return []

    def fetch_all(self) -> List[Dict]:
        return self._paginate(self.fetch_controls, 200)

    def normalize_and_store(self, records: List[Dict], db) -> int:
        from models import ComplianceRecord
        count = 0
        for ctrl in records:
            try:
                src_id = str(ctrl.get("id", ""))
                existing = db.query(ComplianceRecord).filter(
                    ComplianceRecord.source == "ciso_assistance",
                    ComplianceRecord.control_id == src_id
                ).first()

                data = {
                    "source": "ciso_assistance",
                    "framework": ctrl.get("framework", "custom"),
                    "control_id": src_id,
                    "control_name": ctrl.get("name"),
                    "status": ctrl.get("status"),
                    "score": float(ctrl.get("score") or 0),
                    "evidence": ctrl.get("evidence"),
                    "owner": ctrl.get("owner"),
                    "due_date": _parse_dt(ctrl.get("due_date")),
                    "raw_data": ctrl,
                }

                if existing:
                    for k, v in data.items():
                        setattr(existing, k, v)
                else:
                    existing = ComplianceRecord(id=str(uuid.uuid4()), **data)
                    db.add(existing)

                count += 1
            except Exception as e:
                self.logger.error(f"CISO normalize error: {e}")

        db.commit()
        return count


class MSSecurityConnector(BaseConnector):
    """Microsoft Security — Defender for Cloud + Sentinel."""
    source_name = "ms_security"
    display_name = "Microsoft Security"

    def __init__(self):
        super().__init__()
        self.tenant_id = self._get_credential("tenant_id", "MS_TENANT_ID")
        self.client_id = self._get_credential("client_id", "MS_CLIENT_ID")
        self.client_secret = self._get_credential("client_secret", "MS_CLIENT_SECRET")
        self._access_token = None

    def _get_token(self) -> Optional[str]:
        if self._access_token:
            return self._access_token
        try:
            import msal
            app = msal.ConfidentialClientApplication(
                self.client_id, authority=f"https://login.microsoftonline.com/{self.tenant_id}",
                client_credential=self.client_secret,
            )
            result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
            self._access_token = result.get("access_token")
            return self._access_token
        except Exception as e:
            self.logger.error(f"MS token error: {e}")
            return None

    def test_connection(self) -> bool:
        return bool(self._get_token())

    def fetch_secure_score(self) -> Dict:
        token = self._get_token()
        if not token:
            return {}
        try:
            with self.get_http_client("https://graph.microsoft.com") as client:
                r = client.get("/v1.0/security/secureScores",
                               headers={"Authorization": f"Bearer {token}"})
                r.raise_for_status()
                scores = r.json().get("value", [])
                return scores[0] if scores else {}
        except Exception as e:
            self.logger.error(f"MS secure score error: {e}")
            return {}

    def fetch_alerts(self, page: int = 1, page_size: int = 100) -> List[Dict]:
        token = self._get_token()
        if not token:
            return []
        try:
            with self.get_http_client("https://graph.microsoft.com") as client:
                r = client.get("/v1.0/security/alerts_v2",
                               headers={"Authorization": f"Bearer {token}"},
                               params={"$top": page_size, "$filter": "status ne 'resolved'"})
                r.raise_for_status()
                return r.json().get("value", [])
        except Exception as e:
            self.logger.error(f"MS alerts error: {e}")
            return []

    def fetch_all(self) -> Dict:
        alerts = self._paginate(self.fetch_alerts)
        score = self.fetch_secure_score()
        return {"alerts": alerts, "secure_score": score}

    def normalize_and_store(self, records: Dict, db) -> int:
        from models import ThreatEvent, ComplianceRecord
        count = 0

        for alert in records.get("alerts", []):
            try:
                src_id = alert.get("id", "")
                exists = db.query(ThreatEvent).filter(
                    ThreatEvent.source == "ms_security",
                    ThreatEvent.source_event_id == src_id
                ).first()
                if exists:
                    continue

                event = ThreatEvent(
                    id=str(uuid.uuid4()),
                    source="ms_security",
                    source_event_id=src_id,
                    event_type=alert.get("category", "ms_alert"),
                    severity=self._map_severity(alert.get("severity", "medium")),
                    title=alert.get("title", "Microsoft Security Alert"),
                    description=alert.get("description"),
                    mitre_tactic=alert.get("mitreTechniques", [None])[0],
                    status=alert.get("status", "new"),
                    event_timestamp=_parse_dt(alert.get("createdDateTime")),
                    raw_data=alert,
                )
                db.add(event)
                count += 1
            except Exception as e:
                self.logger.error(f"MS alert normalize error: {e}")

        # Secure Score → Compliance
        score_data = records.get("secure_score", {})
        if score_data:
            try:
                existing = db.query(ComplianceRecord).filter(
                    ComplianceRecord.source == "ms_security",
                    ComplianceRecord.control_id == "secure_score"
                ).first()
                data = {
                    "source": "ms_security",
                    "framework": "Microsoft Secure Score",
                    "control_id": "secure_score",
                    "control_name": "Microsoft Secure Score",
                    "score": score_data.get("currentScore"),
                    "status": "active",
                    "raw_data": score_data,
                }
                if existing:
                    for k, v in data.items():
                        setattr(existing, k, v)
                else:
                    db.add(ComplianceRecord(id=str(uuid.uuid4()), **data))
                count += 1
            except Exception as e:
                self.logger.error(f"MS score normalize error: {e}")

        db.commit()
        return count


class AWSSecurityConnector(BaseConnector):
    """AWS Security Hub Connector."""
    source_name = "aws_security"
    display_name = "AWS Security Hub"

    def __init__(self):
        super().__init__()
        import os
        self.aws_access_key = self._get_credential("access_key_id", "AWS_ACCESS_KEY_ID")
        self.aws_secret_key = self._get_credential("secret_access_key", "AWS_SECRET_ACCESS_KEY")
        self.region = self._get_credential("region", "AWS_REGION") or "us-east-1"

    def _get_client(self):
        import boto3
        return boto3.client(
            "securityhub",
            region_name=self.region,
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key,
        )

    def test_connection(self) -> bool:
        try:
            client = self._get_client()
            client.describe_hub()
            return True
        except Exception as e:
            self.logger.error(f"AWS Security Hub test failed: {e}")
            return False

    def fetch_findings(self, page: int = 1, page_size: int = 100) -> List[Dict]:
        try:
            client = self._get_client()
            paginator = client.get_paginator("get_findings")
            findings = []
            pages = paginator.paginate(
                Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]},
                PaginationConfig={"MaxItems": 1000, "PageSize": page_size}
            )
            for pg in pages:
                findings.extend(pg.get("Findings", []))
            return findings
        except Exception as e:
            self.logger.error(f"AWS findings error: {e}")
            return []

    def fetch_all(self) -> List[Dict]:
        return self.fetch_findings()

    def normalize_and_store(self, records: List[Dict], db) -> int:
        from models import ThreatEvent, Vulnerability, Asset
        count = 0
        for finding in records:
            try:
                src_id = finding.get("Id", "")
                severity_label = finding.get("Severity", {}).get("Label", "MEDIUM")
                finding_type = finding.get("Types", ["Software and Configuration Checks"])[0]
                is_vuln = "Vulnerabilities" in finding_type or finding.get("Vulnerabilities")

                if is_vuln:
                    exists = db.query(Vulnerability).filter(
                        Vulnerability.source == "aws_security",
                        Vulnerability.source_vuln_id == src_id
                    ).first()
                    if not exists:
                        # Resolve asset
                        resources = finding.get("Resources", [{}])
                        instance_id = resources[0].get("Id", "").split("/")[-1] if resources else None
                        asset = db.query(Asset).filter(Asset.cloud_instance_id == instance_id).first() if instance_id else None

                        vuln = Vulnerability(
                            id=str(uuid.uuid4()),
                            asset_id=asset.id if asset else None,
                            source="aws_security",
                            source_vuln_id=src_id,
                            cve_id=(finding.get("Vulnerabilities") or [{}])[0].get("Id"),
                            title=finding.get("Title", "AWS Security Finding"),
                            severity=self._map_severity(severity_label),
                            cvss_score=finding.get("Severity", {}).get("Normalized", 0) / 10.0,
                            status="open",
                            first_detected=_parse_dt(finding.get("FirstObservedAt")),
                            last_detected=_parse_dt(finding.get("LastObservedAt")),
                            raw_data=finding,
                        )
                        db.add(vuln)
                        count += 1
                else:
                    exists = db.query(ThreatEvent).filter(
                        ThreatEvent.source == "aws_security",
                        ThreatEvent.source_event_id == src_id
                    ).first()
                    if not exists:
                        event = ThreatEvent(
                            id=str(uuid.uuid4()),
                            source="aws_security",
                            source_event_id=src_id,
                            event_type=finding_type.split("/")[-1] if "/" in finding_type else finding_type,
                            severity=self._map_severity(severity_label),
                            title=finding.get("Title", "AWS Security Alert"),
                            description=finding.get("Description"),
                            status="open",
                            event_timestamp=_parse_dt(finding.get("FirstObservedAt")),
                            raw_data=finding,
                        )
                        db.add(event)
                        count += 1
            except Exception as e:
                self.logger.error(f"AWS finding normalize error: {e}")

        db.commit()
        return count


class GoogleSecurityConnector(BaseConnector):
    """Google Security Command Center Connector."""
    source_name = "google_security"
    display_name = "Google Security Command Center"

    def __init__(self):
        super().__init__()
        self.project_id = self._get_credential("project_id", "GOOGLE_PROJECT_ID")
        self.sa_json = self._get_credential("service_account_json", "GOOGLE_SERVICE_ACCOUNT_JSON")

    def _get_client(self):
        from google.cloud import securitycenter
        import json
        if self.sa_json:
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                f.write(self.sa_json)
                tmp = f.name
            client = securitycenter.SecurityCenterClient.from_service_account_file(tmp)
            os.unlink(tmp)
            return client
        return securitycenter.SecurityCenterClient()

    def test_connection(self) -> bool:
        try:
            client = self._get_client()
            parent = f"projects/{self.project_id}/sources/-"
            list(client.list_findings(request={"parent": parent, "page_size": 1}))
            return True
        except Exception as e:
            self.logger.error(f"Google SCC test failed: {e}")
            return False

    def fetch_all(self) -> List[Dict]:
        try:
            from google.cloud import securitycenter
            client = self._get_client()
            parent = f"projects/{self.project_id}/sources/-"
            findings = []
            for r in client.list_findings(request={"parent": parent,
                                                    "filter": 'state="ACTIVE"'}):
                findings.append({
                    "id": r.finding.name,
                    "category": r.finding.category,
                    "severity": r.finding.severity.name,
                    "state": r.finding.state.name,
                    "event_time": str(r.finding.event_time),
                    "resource_name": r.finding.resource_name,
                    "description": r.finding.description,
                })
            return findings
        except Exception as e:
            self.logger.error(f"Google SCC findings error: {e}")
            return []

    def normalize_and_store(self, records: List[Dict], db) -> int:
        from models import ThreatEvent
        count = 0
        for finding in records:
            try:
                src_id = finding.get("id", "")
                exists = db.query(ThreatEvent).filter(
                    ThreatEvent.source == "google_security",
                    ThreatEvent.source_event_id == src_id
                ).first()
                if exists:
                    continue
                event = ThreatEvent(
                    id=str(uuid.uuid4()),
                    source="google_security",
                    source_event_id=src_id,
                    event_type=finding.get("category", "gcp_finding"),
                    severity=self._map_severity(finding.get("severity", "MEDIUM")),
                    title=f"GCP Security: {finding.get('category', 'Alert')}",
                    description=finding.get("description"),
                    status="open",
                    event_timestamp=_parse_dt(finding.get("event_time")),
                    raw_data=finding,
                )
                db.add(event)
                count += 1
            except Exception as e:
                self.logger.error(f"GCP normalize error: {e}")
        db.commit()
        return count


class FortigateConnector(BaseConnector):
    """Fortigate Security Rating — API Interna."""
    source_name = "fortigate"
    display_name = "Fortigate Security Rating"

    def __init__(self):
        super().__init__()
        import os
        self.base_url = self._get_credential("base_url", "FORTIGATE_BASE_URL") or "http://fortigate.internal/api/v2"
        self.api_key = self._get_credential("api_key", "FORTIGATE_API_KEY")
        self.verify_ssl = os.getenv("FORTIGATE_VERIFY_SSL", "false").lower() == "true"

    def _headers(self) -> Dict:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def test_connection(self) -> bool:
        if not self.api_key:
            return False
        try:
            with self.get_http_client(self.base_url, verify_ssl=self.verify_ssl) as client:
                r = client.get("/monitor/system/status", headers=self._headers())
                return r.status_code == 200
        except Exception as e:
            self.logger.error(f"Fortigate test failed: {e}")
            return False

    def fetch_security_rating(self) -> Dict:
        try:
            with self.get_http_client(self.base_url, verify_ssl=self.verify_ssl) as client:
                r = client.get("/monitor/system/security-rating", headers=self._headers())
                r.raise_for_status()
                return r.json()
        except Exception as e:
            self.logger.error(f"Fortigate security rating error: {e}")
            return {}

    def fetch_all(self) -> Dict:
        return self.fetch_security_rating()

    def normalize_and_store(self, records: Dict, db) -> int:
        from models import ComplianceRecord
        count = 0
        results = records.get("results", [])
        for item in results if isinstance(results, list) else [records]:
            try:
                ctrl_id = str(item.get("id") or item.get("name", "fortigate_rating"))
                existing = db.query(ComplianceRecord).filter(
                    ComplianceRecord.source == "fortigate",
                    ComplianceRecord.control_id == ctrl_id
                ).first()
                data = {
                    "source": "fortigate",
                    "framework": "Fortigate Security Rating",
                    "control_id": ctrl_id,
                    "control_name": item.get("name") or "Fortigate Security Rating",
                    "score": float(item.get("score") or item.get("rating") or 0),
                    "status": item.get("status", "active"),
                    "raw_data": item,
                }
                if existing:
                    for k, v in data.items():
                        setattr(existing, k, v)
                else:
                    db.add(ComplianceRecord(id=str(uuid.uuid4()), **data))
                count += 1
            except Exception as e:
                self.logger.error(f"Fortigate normalize error: {e}")
        db.commit()
        return count


# ─── Helpers ──────────────────────────────────────────────────────────────────
def _parse_dt(val) -> Optional[datetime]:
    if not val:
        return None
    try:
        if isinstance(val, datetime):
            return val
        return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
    except Exception:
        return None
