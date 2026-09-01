import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from app.schemas.report import DFIRReportDTO


def _get_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class STIX21Exporter:
    """
    Standards-compliant STIX 2.1 Cyber Threat Intelligence (CTI) Bundle Generator.
    Serializes indicators, MITRE ATT&CK attack patterns, courses of action, and relational graphs.
    """

    def __init__(self, report: DFIRReportDTO):
        self.report = report
        self.identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'aegis.soc.platform')}"

    def export_stix_bundle(self) -> Dict[str, Any]:
        """Generates a complete STIX 2.1 bundle dictionary."""
        timestamp = _get_utc_iso()
        objects: List[Dict[str, Any]] = []

        # 1. Identity (AEGIS Cyber Defense Platform)
        identity_obj = {
            "type": "identity",
            "spec_version": "2.1",
            "id": self.identity_id,
            "created": timestamp,
            "modified": timestamp,
            "name": "AEGIS Automated Forensic & Threat Intelligence Platform",
            "description": "Autonomous static forensic analysis and cyber threat intelligence ingestion engine.",
            "identity_class": "system",
            "sectors": ["technology", "cybersecurity"],
            "contact_information": "aegis-soc-engine@cyberdefense.internal",
        }
        objects.append(identity_obj)

        # 2. Observed Data (Forensic Email Transmission)
        meta = self.report.email_metadata
        observed_data_id = f"observed-data--{uuid.uuid4()}"
        observed_data_obj = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_data_id,
            "created_by_ref": self.identity_id,
            "created": timestamp,
            "modified": timestamp,
            "first_observed": timestamp,
            "last_observed": timestamp,
            "number_observed": 1,
            "objects": {
                "0": {
                    "type": "email-message",
                    "from_ref": "1",
                    "subject": meta.get("subject", "No Subject"),
                    "date": meta.get("date") or timestamp,
                    "body": meta.get("subject", "Email Payload"),
                },
                "1": {
                    "type": "email-addr",
                    "value": meta.get("from_email", "unknown@sender.external"),
                    "display_name": meta.get("from_name") or "External Sender",
                },
            },
        }
        objects.append(observed_data_obj)

        # 3. Attack Patterns (MITRE ATT&CK Techniques)
        attack_pattern_map: Dict[str, str] = {}
        for tech in self.report.mitre_matrix:
            ap_id = f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_DNS, tech.technique_id)}"
            attack_pattern_map[tech.technique_id] = ap_id

            tactic_slug = tech.tactic.lower().replace(" ", "-").replace("&", "and")
            ap_obj = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created_by_ref": self.identity_id,
                "created": timestamp,
                "modified": timestamp,
                "name": tech.name,
                "description": tech.description,
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": tactic_slug,
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech.technique_id,
                        "url": tech.url,
                    }
                ],
            }
            objects.append(ap_obj)

        # 4. Indicators (IoCs)
        indicator_ids: List[str] = []
        for ioc in self.report.iocs:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)

            # Build STIX 2.1 SCO Comparison Pattern
            pattern_str = self._format_stix_pattern(ioc.ioc_type, ioc.value)
            stage_slug = ioc.killchain_stage.lower().replace(" ", "-").replace("&", "and")

            ind_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created_by_ref": self.identity_id,
                "created": timestamp,
                "modified": timestamp,
                "name": f"Malicious {ioc.ioc_type}: {ioc.value[:64]}",
                "description": ioc.threat_context,
                "indicator_types": ["malicious-activity", "anomalous-activity"],
                "pattern": pattern_str,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": timestamp,
                "confidence": 95 if ioc.severity == "critical" else 80 if ioc.severity == "high" else 65,
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                        "phase_name": stage_slug,
                    }
                ],
            }
            objects.append(ind_obj)

            # Relationship: Indicator -> indicates -> Attack Pattern
            if attack_pattern_map:
                target_ap = list(attack_pattern_map.values())[0]
                rel_obj = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created_by_ref": self.identity_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": target_ap,
                }
                objects.append(rel_obj)

        # 5. Course of Action (Remediation Playbook Actions)
        for act in self.report.remediation_plan:
            coa_id = f"course-of-action--{uuid.uuid4()}"
            coa_obj = {
                "type": "course-of-action",
                "spec_version": "2.1",
                "id": coa_id,
                "created_by_ref": self.identity_id,
                "created": timestamp,
                "modified": timestamp,
                "name": f"[{act.priority}] {act.title}",
                "description": f"Target: {act.target_system} — {act.description}",
                "action_type": act.category.lower(),
                "x_aegis_priority": act.priority,
                "x_aegis_target_system": act.target_system,
            }
            objects.append(coa_obj)

            # Relationship: Course of Action -> mitigates -> Attack Pattern
            if attack_pattern_map:
                target_ap = list(attack_pattern_map.values())[0]
                rel_coa = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created_by_ref": self.identity_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type": "mitigates",
                    "source_ref": coa_id,
                    "target_ref": target_ap,
                }
                objects.append(rel_coa)

        # Master STIX 2.1 Bundle Container
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }
        return bundle

    def export_stix_json(self, indent: int = 2) -> str:
        """Serializes the STIX 2.1 bundle to formatted JSON string."""
        bundle_dict = self.export_stix_bundle()
        return json.dumps(bundle_dict, indent=indent)

    def _format_stix_pattern(self, ioc_type: str, value: str) -> str:
        """Generates valid STIX 2.1 comparison expression."""
        val_escaped = value.replace("'", "\\'")
        ioc_lower = ioc_type.lower()
        if "url" in ioc_lower:
            return f"[url:value = '{val_escaped}']"
        elif "domain" in ioc_lower:
            return f"[domain-name:value = '{val_escaped}']"
        elif "ip" in ioc_lower:
            return f"[ipv4-addr:value = '{val_escaped}']"
        elif "sha256" in ioc_lower or len(value) == 64:
            return f"[file:hashes.'SHA-256' = '{val_escaped}']"
        elif "email" in ioc_lower:
            return f"[email-addr:value = '{val_escaped}']"
        else:
            return f"[file:name = '{val_escaped}']"
