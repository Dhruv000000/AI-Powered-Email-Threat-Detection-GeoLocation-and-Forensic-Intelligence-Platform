export interface RemediationExecutionLog {
  log_id: string;
  investigation_id: string;
  action_id: string;
  target_system: string;
  status: 'SUCCESS' | 'FAILED' | 'REVERTED' | 'RUNNING' | 'PENDING' | 'SIMULATED';
  is_dry_run: boolean;
  affected_indicators: string[];
  execution_result: {
    status?: string;
    action?: string;
    target_system?: string;
    confirmation_id?: string;
    message?: string;
    rollback_supported?: boolean;
    rollback_token?: string;
    rollback_status?: string;
    [key: string]: any;
  };
  executed_by: string;
  executed_at: string;
  reverted_at?: string | null;
  rollback_supported: boolean;
}

export interface RemediationHistoryResponse {
  investigation_id: string;
  total_executions: number;
  active_enforcements: number;
  logs: RemediationExecutionLog[];
}

export interface RemediationExecuteRequest {
  action_id: string;
  target_system?: string;
  action_payload?: Record<string, any>;
  dry_run?: boolean;
}

export interface RemediationBatchRequest {
  action_ids?: string[];
  priority_filter?: string;
  dry_run?: boolean;
}

export interface STIXObject {
  type: string;
  spec_version?: string;
  id: string;
  name?: string;
  description?: string;
  created?: string;
  modified?: string;
  [key: string]: any;
}

export interface STIXBundle {
  type: 'bundle';
  id: string;
  objects: STIXObject[];
}
