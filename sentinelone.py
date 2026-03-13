from connectors.base import BaseConnector
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import uuid


class SentinelOneConnector(BaseConnector):
    """Conector para SentinelOne EDR API v2.1"""

    source_name = "sentinelone"
    display_name = "SentinelOne EDR"

    def __init__(self):
        super().__init__()
        self.base_url = self._get_credential("base_url", "SENTINELONE_BASE_URL")
        self.api_token = self._get_credential("api_token", "SENTINELONE_API_TOKEN")

    def _headers(self) -> Dict:
        return {
            "Authorization": f"ApiToken {self.api_token}",
            "Content-Type": "application/json",
        }

    def test_connection(self) -> bool:
        if not self.base_url or not self.api_token:
            return False
        try:
            with self.get_http_client(self.base_url) as client:
                r = client.get("/web/api/v2.1/system/status", headers=self._headers())
                return r.status_code == 200
        except Exception as e:
            self.logger.error(f"SentinelOne connection test failed: {e}")
            return False

    def fetch_agents(self, page: int = 1, page_size: int = 100) -> List[Dict]:
        """Busca agentes (endpoints) registrados."""
        try:
            with self.get_http_client(self.base_url) as client:
                r = client.get(
                    "/web/api/v2.1/agents",
                    headers=self._headers(),
                    params={"limit": page_size, "skip": (page - 1) * page_size}
                )
                r.raise_for_status()
                return r.json().get("data", [])
        except Exception as e:
            self.logger.error(f"Failed to fetch S1 agents: {e}")
            return []

    def fetch_threats(self, page: int = 1, page_size: int = 100) -> List[Dict]:
        """Busca ameaças/alertas detectados."""
        try:
            with self.get_http_client(self.base_url) as client:
                r = client.get(
                    "/web/api/v2.1/threats",
                    headers=self._headers(),
                    params={"limit": page_size, "skip": (page - 1) * page_size, "resolved": "false"}
                )
                r.raise_for_status()
                return r.json().get("data", [])
        except Exception as e:
            self.logger.error(f"Failed to fetch S1 threats: {e}")
            return []

    def fetch_all(self) -> List[Dict]:
        agents = self._paginate(self.fetch_agents)
        threats = self._paginate(self.fetch_threats)
        return {"agents": agents, "threats": threats}

    def normalize_and_store(self, records: Dict, db) -> int:
        from models import Asset, ThreatEvent
        count = 0

        # Normalizar agentes → Assets
        for agent in records.get("agents", []):
            try:
                existing = db.query(Asset).filter(
                    Asset.sentinelone_id == str(agent.get("id", ""))
                ).first()

                if not existing:
                    existing = db.query(Asset).filter(
                        Asset.hostname == agent.get("computerName", "").lower()
                    ).first()

                asset_data = {
                    "hostname": agent.get("computerName", "").lower(),
                    "ip_address": (agent.get("networkInterfaces") or [{}])[0].get("inet", [None])[0],
                    "os_name": agent.get("osName"),
                    "os_version": agent.get("osRevision"),
                    "os_platform": agent.get("osFamilyName"),
                    "sentinelone_id": str(agent.get("id", "")),
                    "asset_type": "workstation" if agent.get("machineType") == "desktop" else "server",
                    "is_active": agent.get("isActive", True),
                    "last_seen": _parse_date(agent.get("lastActiveDate")),
                    "tags": {"sentinelone_tags": agent.get("tags", [])},
                }

                if existing:
                    for k, v in asset_data.items():
                        if v is not None:
                            setattr(existing, k, v)
                else:
                    existing = Asset(id=str(uuid.uuid4()), **asset_data)
                    db.add(existing)

                count += 1
            except Exception as e:
                self.logger.error(f"Failed to normalize S1 agent: {e}")

        # Normalizar threats → ThreatEvents
        for threat in records.get("threats", []):
            try:
                existing_event = db.query(ThreatEvent).filter(
                    ThreatEvent.source == "sentinelone",
                    ThreatEvent.source_event_id == str(threat.get("id", ""))
                ).first()

                if existing_event:
                    continue

                # Resolver asset
                asset = db.query(Asset).filter(
                    Asset.hostname == threat.get("agentComputerName", "").lower()
                ).first()

                event = ThreatEvent(
                    id=str(uuid.uuid4()),
                    asset_id=asset.id if asset else None,
                    source="sentinelone",
                    source_event_id=str(threat.get("id", "")),
                    event_type=threat.get("classification", "malware"),
                    severity=self._map_severity(threat.get("confidenceLevel", "medium")),
                    title=threat.get("displayName") or threat.get("threatName", "Unknown Threat"),
                    description=threat.get("description"),
                    mitre_tactic=_extract_mitre_tactic(threat),
                    mitre_technique=_extract_mitre_technique(threat),
                    status="open" if not threat.get("resolved") else "closed",
                    event_timestamp=_parse_date(threat.get("createdDate")),
                    raw_data=threat,
                )
                db.add(event)
                count += 1
            except Exception as e:
                self.logger.error(f"Failed to normalize S1 threat: {e}")

        db.commit()
        return count


def _parse_date(val) -> Optional[datetime]:
    if not val:
        return None
    try:
        if isinstance(val, str):
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        return val
    except Exception:
        return None


def _extract_mitre_tactic(threat: Dict) -> Optional[str]:
    indicators = threat.get("indicators", [])
    for ind in indicators:
        if ind.get("category") == "tactic":
            return ind.get("description")
    return None


def _extract_mitre_technique(threat: Dict) -> Optional[str]:
    indicators = threat.get("indicators", [])
    for ind in indicators:
        if ind.get("category") == "technique":
            return ind.get("description")
    return None
