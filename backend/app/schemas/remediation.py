from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class RemediationExecuteRequest(BaseModel):
    action_id: str = Field(..., description="Action ID from DFIR report (e.g. ACT-01, ACT-02)")
    target_system: Optional[str] = Field(None, description="Target enforcement system (DNS, SWG, MTA, Exchange, EDR)")
    action_payload: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Custom payload parameters or indicator overrides")
    dry_run: bool = Field(default=False, description="If True, simulates execution without making external API changes")


class RemediationBatchRequest(BaseModel):
    action_ids: Optional[List[str]] = Field(default=None, description="List of specific action IDs to execute. If omitted, executes all matching priority_filter.")
    priority_filter: Optional[str] = Field(default="P0", description="Priority tier to execute (e.g. P0, P1, P2)")
    dry_run: bool = Field(default=False, description="If True, simulates execution without making external API changes")


class RemediationExecutionResponse(BaseModel):
    log_id: str
    investigation_id: str
    action_id: str
    target_system: str
    status: str = Field(..., description="SUCCESS, FAILED, REVERTED, RUNNING, PENDING")
    is_dry_run: bool = False
    affected_indicators: List[str] = Field(default_factory=list)
    execution_result: Dict[str, Any] = Field(default_factory=dict)
    executed_by: str = "usr-analyst-001"
    executed_at: str
    reverted_at: Optional[str] = None
    rollback_supported: bool = True


class RemediationHistoryResponse(BaseModel):
    investigation_id: str
    total_executions: int
    active_enforcements: int
    logs: List[RemediationExecutionResponse] = Field(default_factory=list)


class STIXBundleDTO(BaseModel):
    type: str = "bundle"
    id: str
    objects: List[Dict[str, Any]] = Field(default_factory=list)
