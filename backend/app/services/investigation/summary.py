from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.db.models.email_analysis import EmailAnalysisModel


class SummaryEngine:
    """
    Forensic Summary Engine.
    Aggregates Task 01 authoritative threat metrics, computes evidence completeness confidence,
    summarizes entity and finding distributions, and builds an evidentiary chronological timeline.
    """

    def __init__(
        self,
        analysis: EmailAnalysisModel,
        investigation_id: str,
        entities: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        threat_paths: List[Dict[str, Any]],
        investigation_created_at: Optional[datetime] = None,
    ):
        self.analysis = analysis
        self.analysis_id = analysis.analysis_id
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
        if self.analysis.metadata_record:
            score += 0.15
        if self.analysis.authentication and self.analysis.authentication.spf_status != "unknown":
            score += 0.15
        if len(self.analysis.relay_hops) > 0:
            score += 0.10
        if self.analysis.sha256:
            score += 0.10
        return min(round(score, 2), 1.0)

    def generate_timeline(self) -> List[Dict[str, Any]]:
        """
        Builds chronological timeline derived strictly from evidence timestamps that actually exist.
        """
        timeline = []
        meta = self.analysis.metadata_record

        # 1. Email Date Header
        if meta and meta.date_header:
            timeline.append({
                "id": "tl-evt-1",
                "timestamp": meta.date_header,
                "title": "Email Message Date Header",
                "event_type": "email_received",
                "description": f"RFC 822 Date header observed in message headers: '{meta.date_header}'.",
                "source": "email_headers:Date",
                "evidence_reference": "email_metadata:date_header",
            })

        # 2. Relay Hops Timestamps
        for hop in self.analysis.relay_hops:
            if hop.timestamp:
                timeline.append({
                    "id": f"tl-evt-hop-{hop.hop_number}",
                    "timestamp": hop.timestamp,
                    "title": f"SMTP Relay Hop #{hop.hop_number} Observed",
                    "event_type": "header_observed",
                    "description": f"Received header transit logged via server '{hop.by_server or hop.from_server or 'relay'}'.",
                    "source": f"email_relay_hops:hop_{hop.hop_number}",
                    "evidence_reference": f"email_relay_hops:hop_{hop.hop_number}",
                })

        # 3. Task 01 Analysis Completed
        if self.analysis.completed_at:
            ts_str = self.analysis.completed_at.isoformat().replace("T", " ")[:19] + " UTC"
            timeline.append({
                "id": "tl-evt-analysis-completed",
                "timestamp": ts_str,
                "title": "Task 01 Forensic Analysis Completed",
                "event_type": "analysis_completed",
                "description": f"Classification determined: {self.analysis.threat_type or 'suspicious'} (Score: {self.analysis.risk_score}/100).",
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
        threat_type_label = (self.analysis.threat_type or "suspicious").replace("_", " ").title()
        risk_score = self.analysis.risk_score or 0
        sev_label = (self.analysis.severity or "medium").upper()
        entity_total = len(self.entities)
        finding_total = len(self.findings)

        executive_summary = (
            f"Forensic investigation completed for {threat_type_label} threat (Risk Score: {risk_score}/100, Severity: {sev_label}). "
            f"Correlated {entity_total} distinct entities across {len(self.threat_paths)} threat infrastructure paths, "
            f"identifying {finding_total} evidentiary findings."
        )

        return {
            "investigation_id": self.investigation_id,
            "analysis_id": self.analysis_id,
            "threat_type": self.analysis.threat_type,
            "risk_score": self.analysis.risk_score,
            "severity": self.analysis.severity,
            "ai_confidence": self.analysis.ai_confidence,
            "investigation_confidence": self.compute_investigation_confidence(),
            "entity_counts": entity_counts,
            "finding_counts": finding_counts,
            "top_findings": top_findings,
            "key_threat_paths": key_threat_paths,
            "timeline": self.generate_timeline(),
            "executive_summary": executive_summary,
        }
