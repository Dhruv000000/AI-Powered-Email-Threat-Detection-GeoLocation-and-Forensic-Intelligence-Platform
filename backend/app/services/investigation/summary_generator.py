from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from app.db.models.email_analysis import EmailAnalysisModel
from app.schemas.email_analysis import EmailAnalysisResponse


def generate_investigation_summary(
    threat_type: Optional[str],
    risk_score: Optional[int],
    severity: Optional[str],
    entity_count: int,
    threat_path_count: int,
    finding_count: int,
) -> str:
    """
    Generate a clean DFIR analyst executive summary string based on graph structure,
    threat paths, and risk metrics.
    """
    threat_type_label = (threat_type or "suspicious").replace("_", " ").title()
    score = risk_score or 0
    sev_label = (severity or "medium").upper()

    return (
        f"Forensic investigation completed for {threat_type_label} threat (Risk Score: {score}/100, Severity: {sev_label}). "
        f"Correlated {entity_count} distinct entities across {threat_path_count} threat infrastructure paths, "
        f"identifying {finding_count} evidentiary findings."
    )


class SummaryEngine:
    """
    Forensic Summary Engine.
    Aggregates Task 01 authoritative threat metrics, computes evidence completeness confidence,
    summarizes entity and finding distributions, and builds an evidentiary chronological timeline.
    """

    def __init__(
        self,
        analysis: Union[EmailAnalysisModel, EmailAnalysisResponse, Dict[str, Any]],
        investigation_id: str,
        entities: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        threat_paths: List[Dict[str, Any]],
        investigation_created_at: Optional[datetime] = None,
    ):
        self.analysis = analysis
        if isinstance(analysis, dict):
            self.analysis_id = analysis.get("analysis_id", "ANL-UNKNOWN")
            self.risk_score = analysis.get("risk_score")
            self.threat_type = analysis.get("threat_type")
            self.severity = analysis.get("severity")
            self.ai_confidence = analysis.get("ai_confidence")
            self.metadata_obj = analysis.get("metadata") or analysis.get("metadata_record")
            self.relay_hops = analysis.get("relay_hops") or []
            self.authentication = analysis.get("authentication")
            self.sha256 = analysis.get("sha256")
            self.completed_at = analysis.get("completed_at")
        else:
            self.analysis_id = getattr(analysis, "analysis_id", "ANL-UNKNOWN")
            self.risk_score = getattr(analysis, "risk_score", None)
            self.threat_type = getattr(analysis, "threat_type", None)
            self.severity = getattr(analysis, "severity", None)
            self.ai_confidence = getattr(analysis, "ai_confidence", None)
            self.metadata_obj = getattr(analysis, "metadata_record", None) or getattr(analysis, "metadata", None)
            self.relay_hops = getattr(analysis, "relay_hops", []) or []
            self.authentication = getattr(analysis, "authentication", None)
            self.sha256 = getattr(analysis, "sha256", None)
            self.completed_at = getattr(analysis, "completed_at", None)

        self.investigation_id = investigation_id
        self.entities = entities
        self.findings = findings
        self.threat_paths = threat_paths
        self.investigation_created_at = investigation_created_at or datetime.now(timezone.utc)

    def compute_investigation_confidence(self) -> float:
        """
        Computes evidence completeness confidence based on presence of headers, authentication,
        relay hops, and cryptographic evidence seals.
        """
        score = 0.50  # Baseline
        if self.metadata_obj:
            score += 0.15
        
        spf_status = None
        if self.authentication:
            spf_status = getattr(self.authentication, "spf_status", None) if not isinstance(self.authentication, dict) else self.authentication.get("spf_status")
        if spf_status and spf_status != "unknown":
            score += 0.15
        
        if len(self.relay_hops) > 0:
            score += 0.10
        if self.sha256:
            score += 0.10
        return min(round(score, 2), 1.0)

    def generate_timeline(self) -> List[Dict[str, Any]]:
        """
        Builds chronological timeline derived strictly from evidence timestamps that actually exist.
        """
        timeline = []
        meta = self.metadata_obj

        date_header = None
        if meta:
            date_header = getattr(meta, "date_header", None) if not isinstance(meta, dict) else (meta.get("date_header") or meta.get("date"))

        # 1. Email Date Header
        if date_header:
            timeline.append({
                "id": "tl-evt-1",
                "timestamp": str(date_header),
                "title": "Email Message Date Header",
                "event_type": "email_received",
                "description": f"RFC 822 Date header observed in message headers: '{date_header}'.",
                "source": "email_headers:Date",
                "evidence_reference": "email_metadata:date_header",
            })

        # 2. Relay Hops Timestamps
        for hop in self.relay_hops:
            ts = getattr(hop, "timestamp", None) if not isinstance(hop, dict) else hop.get("timestamp")
            hop_num = getattr(hop, "hop_number", 1) if not isinstance(hop, dict) else hop.get("hop_number", 1)
            server = getattr(hop, "by_server", None) or getattr(hop, "from_server", "relay") if not isinstance(hop, dict) else (hop.get("by_server") or hop.get("from_server", "relay"))
            if ts:
                timeline.append({
                    "id": f"tl-evt-hop-{hop_num}",
                    "timestamp": str(ts),
                    "title": f"SMTP Relay Hop #{hop_num} Observed",
                    "event_type": "header_observed",
                    "description": f"Received header transit logged via server '{server}'.",
                    "source": f"email_relay_hops:hop_{hop_num}",
                    "evidence_reference": f"email_relay_hops:hop_{hop_num}",
                })

        # 3. Task 01 Analysis Completed
        if self.completed_at:
            ts_str = self.completed_at.isoformat().replace("T", " ")[:19] + " UTC" if hasattr(self.completed_at, "isoformat") else str(self.completed_at)
            timeline.append({
                "id": "tl-evt-analysis-completed",
                "timestamp": ts_str,
                "title": "Task 01 Forensic Analysis Completed",
                "event_type": "analysis_completed",
                "description": f"Classification determined: {self.threat_type or 'suspicious'} (Score: {self.risk_score}/100).",
                "source": "aegis-email-analysis-engine",
                "evidence_reference": f"email_analyses:{self.analysis_id}",
            })

        # 4. Investigation Created
        inv_ts_str = self.investigation_created_at.isoformat().replace("T", " ")[:19] + " UTC"
        timeline.append({
            "id": "tl-evt-investigation-started",
            "timestamp": inv_ts_str,
            "title": "Threat Investigation Engine Initialized",
            "event_type": "investigation_started",
            "description": f"Evidence correlation graph and findings generated for investigation '{self.investigation_id}'.",
            "source": "aegis-investigation-engine",
            "evidence_reference": f"investigations:{self.investigation_id}",
        })

        return timeline

    def generate_summary(self) -> Dict[str, Any]:
        # Entity counts by type
        entity_counts = dict(Counter(e.get("type", "Unknown") for e in self.entities))

        # Finding counts by severity
        finding_counts = dict(Counter(f.get("severity", "medium") for f in self.findings))

        # Top findings (sorted by severity rank)
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "moderate": 1, "low": 0}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_rank.get(f.get("severity", "medium").lower(), 1),
            reverse=True,
        )
        top_findings = sorted_findings[:5]

        # Key threat paths
        key_threat_paths = self.threat_paths[:3]

        # Executive summary narrative based strictly on evidence
        executive_summary = generate_investigation_summary(
            threat_type=self.threat_type,
            risk_score=self.risk_score,
            severity=self.severity,
            entity_count=len(self.entities),
            threat_path_count=len(self.threat_paths),
            finding_count=len(self.findings),
        )

        return {
            "investigation_id": self.investigation_id,
            "analysis_id": self.analysis_id,
            "threat_type": self.threat_type,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "ai_confidence": self.ai_confidence,
            "investigation_confidence": self.compute_investigation_confidence(),
            "entity_counts": entity_counts,
            "finding_counts": finding_counts,
            "top_findings": top_findings,
            "key_threat_paths": key_threat_paths,
            "timeline": self.generate_timeline(),
            "executive_summary": executive_summary,
        }
