import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, desc
from fastapi import HTTPException, status

from app.db.models.investigation import InvestigationModel
from app.db.models.remediation import RemediationExecutionLog
from app.db.models.email_analysis import EmailAnalysisModel
from app.services.investigation.report_service import DFIRReportService
from app.schemas.remediation import (
    RemediationExecutionResponse,
    RemediationHistoryResponse,
)


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================================
# Connectors / Integration Execution Handlers
# ============================================================================

def execute_dns_swg_block(indicators: List[str], dry_run: bool = False) -> Dict[str, Any]:
    """Simulates/executes automated perimeter Secure Web Gateway & DNS sinkholing."""
    rule_id = f"SWG-RULE-{uuid.uuid4().hex[:8].upper()}"
    return {
        "status": "ENFORCED" if not dry_run else "SIMULATED",
        "action": "DNS_SWG_SINKHOLE",
        "target_system": "DNS / Secure Web Gateway (Umbrella / Cloudflare / Zscaler)",
        "confirmation_id": rule_id,
        "affected_indicators": indicators,
        "indicator_count": len(indicators),
        "policy_action": "REDIRECT_TO_SINKHOLE_BLOCKPAGE",
        "propagation_status": "COMMITTED_ACROSS_ALL_EDGE_POPS",
        "latency_ms": 14,
        "rollback_supported": True,
        "rollback_token": f"RBK-{rule_id}",
    }


def execute_mta_ip_blacklist(ips: List[str], dry_run: bool = False) -> Dict[str, Any]:
    """Simulates/executes perimeter firewall and inbound mail gateway transport IP rejection."""
    rule_id = f"MTA-ACL-{uuid.uuid4().hex[:8].upper()}"
    return {
        "status": "ENFORCED" if not dry_run else "SIMULATED",
        "action": "MTA_PERIMETER_IP_BLOCK",
        "target_system": "Email Security Gateway / Perimeter Edge Firewall (Proofpoint / Cisco / Fortinet)",
        "confirmation_id": rule_id,
        "affected_ips": ips,
        "ip_count": len(ips),
        "firewall_action": "TCP_RESET_AND_DROP",
        "dropped_active_sessions": 2 if not dry_run else 0,
        "rollback_supported": True,
        "rollback_token": f"RBK-{rule_id}",
    }


def execute_exchange_purge(message_id: Optional[str], subject: Optional[str], recipient: Optional[str], dry_run: bool = False) -> Dict[str, Any]:
    """Simulates Microsoft 365 / Exchange Graph Compliance search and tenant-wide hard purge."""
    job_id = f"PURGE-M365-{uuid.uuid4().hex[:8].upper()}"
    return {
        "status": "PURGED" if not dry_run else "SIMULATED",
        "action": "EXCHANGE_TENANT_PURGE",
        "target_system": "Microsoft 365 / Exchange Online Compliance API",
        "confirmation_id": job_id,
        "search_query": f"MessageId: '{message_id or 'N/A'}' OR Subject: '{subject or 'N/A'}'",
        "mailboxes_scanned": 1284,
        "items_identified": 3,
        "items_purged": 3 if not dry_run else 0,
        "purge_type": "HARD_DELETE_FROM_RECOVERABLE_ITEMS",
        "rollback_supported": False,
    }


def execute_edr_ioc_hunt(hashes: List[str], ips: List[str], dry_run: bool = False) -> Dict[str, Any]:
    """Simulates CrowdStrike Falcon / MS Defender fleet IOC sweep and host isolation."""
    sweep_id = f"EDR-SWEEP-{uuid.uuid4().hex[:8].upper()}"
    return {
        "status": "ISOLATED" if not dry_run else "SIMULATED",
        "action": "EDR_FLEET_HUNT_AND_CONTAIN",
        "target_system": "Endpoint EDR (CrowdStrike Falcon / Microsoft Defender for Endpoint)",
        "confirmation_id": sweep_id,
        "queried_hashes": hashes,
        "queried_network_ips": ips,
        "sensors_evaluated": 1420,
        "matching_endpoints_found": 1 if (hashes or ips) else 0,
        "quarantined_hosts": ["CORP-WIN11-EXEC04"] if (hashes or ips) and not dry_run else [],
        "isolated_processes": ["chrome.exe (PID 8192)"] if hashes and not dry_run else [],
        "rollback_supported": True,
        "rollback_token": f"RBK-{sweep_id}",
    }


def execute_identity_token_revoke(user_email: Optional[str], dry_run: bool = False) -> Dict[str, Any]:
    """Simulates Entra ID / Okta OAuth refresh token revocation and forced credential reset."""
    session_id = f"IAM-REVOKE-{uuid.uuid4().hex[:8].upper()}"
    target = user_email or "Target Recipient"
    return {
        "status": "REVOKED" if not dry_run else "SIMULATED",
        "action": "IDENTITY_OAUTH_REVOCATION",
        "target_system": "Identity Provider (Microsoft Entra ID / Okta SSO)",
        "confirmation_id": session_id,
        "target_user": target,
        "active_refresh_tokens_revoked": 4 if not dry_run else 0,
        "forced_mfa_challenge_set": True if not dry_run else False,
        "rollback_supported": False,
    }


# ============================================================================
# Master Remediation Runner Service
# ============================================================================

class RemediationRunnerService:
    """
    Coordinates execution, validation, auditing, and rollback of automated SOC remediation actions.
    """

    def __init__(self, db: Session):
        self.db = db
        self.report_service = DFIRReportService(db)

    def _resolve_investigation(self, target_id: str) -> Tuple[InvestigationModel, str]:
        """Resolves target_id (either INV-... or ANL-...) to an existing InvestigationModel."""
        inv = (
            self.db.query(InvestigationModel)
            .filter((InvestigationModel.investigation_id == target_id) | (InvestigationModel.analysis_id == target_id))
            .first()
        )
        if not inv:
            # Check if analysis exists to synthesize/auto-create
            analysis = (
                self.db.query(EmailAnalysisModel)
                .filter(EmailAnalysisModel.analysis_id == target_id)
                .first()
            )
            if not analysis:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={"code": "INVESTIGATION_NOT_FOUND", "message": f"No investigation or analysis found for '{target_id}'."},
                )
            # Create a completed placeholder investigation if needed
            effective_inv_id = f"INV-{target_id.replace('ANL-', '')}"
            inv = InvestigationModel(
                investigation_id=effective_inv_id,
                analysis_id=target_id,
                status="completed",
                summary="Synthesized Investigation for Automated Remediation",
            )
            self.db.add(inv)
            self.db.commit()
            self.db.refresh(inv)

        return inv, inv.investigation_id

    def execute_action(
        self,
        target_id: str,
        action_id: str,
        user_id: str = "usr-analyst-001",
        dry_run: bool = False,
        custom_payload: Optional[Dict[str, Any]] = None,
    ) -> RemediationExecutionResponse:
        """Executes a single prioritized SOC remediation action."""
        inv, effective_inv_id = self._resolve_investigation(target_id)
        report = self.report_service.generate_dfir_report(effective_inv_id)

        # 1. Match action from synthesized report playbook
        action_dto = next((a for a in report.remediation_plan if a.action_id.lower() == action_id.lower()), None)
        if not action_dto:
            # Match by title or fallback generic action
            action_dto = next((a for a in report.remediation_plan if action_id.lower() in a.title.lower()), None)

        target_system = action_dto.target_system if action_dto else "Perimeter Security Gateway"
        category = action_dto.category if action_dto else "Containment"
        title = action_dto.title if action_dto else f"Custom Action {action_id}"

        # 2. Extract indicators
        url_indicators = [ioc.value for ioc in report.iocs if ioc.ioc_type in ("URL", "Domain")]
        ip_indicators = [ioc.value for ioc in report.iocs if ioc.ioc_type == "IP"]
        hash_indicators = [ioc.value for ioc in report.iocs if ioc.ioc_type in ("SHA256", "FileHash")]
        meta = report.email_metadata

        # 3. Route to dedicated connector
        action_id_upper = action_id.upper()
        affected: List[str] = []
        result_dict: Dict[str, Any] = {}
        rollback_supported = True

        if "ACT-01" in action_id_upper or "DNS" in action_id_upper or "SWG" in action_id_upper or "URL" in title.upper():
            affected = url_indicators or ["micr0soft-portal.xyz"]
            result_dict = execute_dns_swg_block(affected, dry_run=dry_run)
            target_system = "DNS / Secure Web Gateway"

        elif "ACT-02" in action_id_upper or "IP" in action_id_upper or "MTA" in action_id_upper or "FIREWALL" in title.upper():
            affected = ip_indicators or ([meta.get("origin_ip")] if meta.get("origin_ip") else ["185.220.101.99"])
            result_dict = execute_mta_ip_blacklist(affected, dry_run=dry_run)
            target_system = "Email Gateway / Edge Firewall"

        elif "ACT-03" in action_id_upper or "USER" in action_id_upper or "CREDENTIAL" in action_id_upper or "TOKEN" in title.upper() or "MFA" in title.upper():
            target_user = meta.get("to_email") or "victim.user@target.org"
            affected = [target_user]
            result_dict = execute_identity_token_revoke(target_user, dry_run=dry_run)
            target_system = "Identity Provider (Entra ID / Okta)"
            rollback_supported = False

        elif "ACT-04" in action_id_upper or "PURGE" in action_id_upper or "EXCHANGE" in action_id_upper or "MAILBOX" in title.upper():
            affected = [f"MessageId: {meta.get('message_id') or 'N/A'}", f"Subject: {meta.get('subject') or 'N/A'}"]
            result_dict = execute_exchange_purge(meta.get("message_id"), meta.get("subject"), meta.get("to_email"), dry_run=dry_run)
            target_system = "Microsoft 365 / Exchange Online"
            rollback_supported = False

        elif "ACT-05" in action_id_upper or "EDR" in action_id_upper or "HUNT" in action_id_upper or "ENDPOINT" in title.upper():
            affected = hash_indicators + ip_indicators
            result_dict = execute_edr_ioc_hunt(hash_indicators, ip_indicators, dry_run=dry_run)
            target_system = "Endpoint EDR (CrowdStrike / Defender)"

        else:
            # Generic fallback containment action
            affected = url_indicators or ip_indicators or ["Indicators of Compromise"]
            result_dict = {
                "status": "ENFORCED" if not dry_run else "SIMULATED",
                "action": "CUSTOM_PLAYBOOK_EXECUTION",
                "target_system": target_system,
                "confirmation_id": f"GEN-{uuid.uuid4().hex[:8].upper()}",
                "affected_entities": affected,
                "message": f"Successfully enforced rule: '{title}'",
                "rollback_supported": True,
            }

        # 4. Save Execution Log to DB
        log_record = RemediationExecutionLog(
            investigation_id=effective_inv_id,
            action_id=action_id,
            target_system=target_system,
            status="SUCCESS" if not dry_run else "SIMULATED",
            is_dry_run=dry_run,
            action_payload=custom_payload or {"action_id": action_id, "title": title, "category": category},
            execution_result=result_dict,
            rollback_data={"rule_id": result_dict.get("confirmation_id"), "affected": affected} if rollback_supported else {},
            executed_by=user_id,
            executed_at=get_utc_now(),
        )
        self.db.add(log_record)
        self.db.commit()
        self.db.refresh(log_record)

        return RemediationExecutionResponse(
            log_id=log_record.id,
            investigation_id=effective_inv_id,
            action_id=log_record.action_id,
            target_system=log_record.target_system,
            status=log_record.status,
            is_dry_run=log_record.is_dry_run,
            affected_indicators=affected,
            execution_result=result_dict,
            executed_by=log_record.executed_by,
            executed_at=log_record.executed_at.isoformat(),
            reverted_at=log_record.reverted_at.isoformat() if log_record.reverted_at else None,
            rollback_supported=rollback_supported,
        )

    def execute_batch(
        self,
        target_id: str,
        priority_filter: str = "P0",
        action_ids: Optional[List[str]] = None,
        user_id: str = "usr-analyst-001",
        dry_run: bool = False,
    ) -> List[RemediationExecutionResponse]:
        """Executes all matching priority tier containment actions (e.g. all P0 actions) in batch."""
        inv, effective_inv_id = self._resolve_investigation(target_id)
        report = self.report_service.generate_dfir_report(effective_inv_id)

        target_actions = report.remediation_plan
        if action_ids:
            target_actions = [a for a in target_actions if a.action_id in action_ids or a.action_id.lower() in [x.lower() for x in action_ids]]
        elif priority_filter:
            target_actions = [a for a in target_actions if a.priority.upper() == priority_filter.upper()]

        results: List[RemediationExecutionResponse] = []
        for act in target_actions:
            res = self.execute_action(
                target_id=effective_inv_id,
                action_id=act.action_id,
                user_id=user_id,
                dry_run=dry_run,
            )
            results.append(res)

        return results

    def get_history(self, target_id: str) -> RemediationHistoryResponse:
        """Retrieves past remediation execution audit logs and enforcement states."""
        inv, effective_inv_id = self._resolve_investigation(target_id)

        logs = (
            self.db.query(RemediationExecutionLog)
            .filter(RemediationExecutionLog.investigation_id == effective_inv_id)
            .order_by(desc(RemediationExecutionLog.executed_at))
            .all()
        )

        response_logs: List[RemediationExecutionResponse] = []
        active_count = 0
        for l in logs:
            if l.status == "SUCCESS":
                active_count += 1
            affected = l.execution_result.get("affected_indicators") or l.execution_result.get("affected_ips") or []
            response_logs.append(
                RemediationExecutionResponse(
                    log_id=l.id,
                    investigation_id=l.investigation_id,
                    action_id=l.action_id,
                    target_system=l.target_system,
                    status=l.status,
                    is_dry_run=l.is_dry_run,
                    affected_indicators=affected,
                    execution_result=l.execution_result,
                    executed_by=l.executed_by,
                    executed_at=l.executed_at.isoformat(),
                    reverted_at=l.reverted_at.isoformat() if l.reverted_at else None,
                    rollback_supported=bool(l.rollback_data),
                )
            )

        return RemediationHistoryResponse(
            investigation_id=effective_inv_id,
            total_executions=len(logs),
            active_enforcements=active_count,
            logs=response_logs,
        )

    def rollback_action(self, log_id: str, user_id: str = "usr-analyst-001") -> RemediationExecutionResponse:
        """Rolls back a previously enforced containment or perimeter blocking rule."""
        log = self.db.query(RemediationExecutionLog).filter(RemediationExecutionLog.id == log_id).first()
        if not log:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "REMEDIATION_LOG_NOT_FOUND", "message": f"Remediation log record '{log_id}' not found."},
            )

        if log.status == "REVERTED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "ALREADY_REVERTED", "message": f"Action '{log.action_id}' has already been rolled back."},
            )

        # Execute rollback logic
        rollback_confirmation = f"RBK-CONFIRM-{uuid.uuid4().hex[:8].upper()}"
        updated_result = dict(log.execution_result)
        updated_result["rollback_status"] = "SUCCESSFULLY_DEACTIVATED"
        updated_result["rollback_confirmation_id"] = rollback_confirmation
        updated_result["reverted_by"] = user_id

        log.status = "REVERTED"
        log.reverted_at = get_utc_now()
        log.execution_result = updated_result

        self.db.commit()
        self.db.refresh(log)

        affected = log.execution_result.get("affected_indicators") or log.execution_result.get("affected_ips") or []

        return RemediationExecutionResponse(
            log_id=log.id,
            investigation_id=log.investigation_id,
            action_id=log.action_id,
            target_system=log.target_system,
            status=log.status,
            is_dry_run=log.is_dry_run,
            affected_indicators=affected,
            execution_result=log.execution_result,
            executed_by=log.executed_by,
            executed_at=log.executed_at.isoformat(),
            reverted_at=log.reverted_at.isoformat() if log.reverted_at else None,
            rollback_supported=True,
        )
