import {
  RemediationExecutionLog,
  RemediationHistoryResponse,
  RemediationExecuteRequest,
  RemediationBatchRequest,
  STIXBundle,
} from '../types/remediation';

const API_BASE = '/api/v1';

export const remediationService = {
  /**
   * Execute a specific SOC remediation action (containment, SWG block, firewall drop, mailbox purge, EDR sweep).
   */
  async executeAction(
    targetId: string,
    actionId: string,
    dryRun: boolean = false,
    customPayload?: Record<string, any>
  ): Promise<RemediationExecutionLog> {
    const payload: RemediationExecuteRequest = {
      action_id: actionId,
      dry_run: dryRun,
      action_payload: customPayload,
    };
    const res = await fetch(`${API_BASE}/investigations/${targetId}/remediation/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to execute action '${actionId}' for investigation '${targetId}'`);
    }
    return res.json();
  },

  /**
   * Batch-execute all containment actions for a given priority tier (e.g. all P0 actions).
   */
  async executeBatch(
    targetId: string,
    priorityFilter: string = 'P0',
    actionIds?: string[],
    dryRun: boolean = false
  ): Promise<RemediationExecutionLog[]> {
    const payload: RemediationBatchRequest = {
      priority_filter: priorityFilter,
      action_ids: actionIds,
      dry_run: dryRun,
    };
    const res = await fetch(`${API_BASE}/investigations/${targetId}/remediation/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to execute batch ${priorityFilter} remediation for '${targetId}'`);
    }
    return res.json();
  },

  /**
   * Get past remediation execution audit logs and enforcement states.
   */
  async getExecutionHistory(targetId: string): Promise<RemediationHistoryResponse> {
    const res = await fetch(`${API_BASE}/investigations/${targetId}/remediation/history`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to fetch remediation history for '${targetId}'`);
    }
    return res.json();
  },

  /**
   * Rollback a previously active perimeter firewall, SWG, or mail filter rule.
   */
  async rollbackAction(targetId: string, logId: string): Promise<RemediationExecutionLog> {
    const res = await fetch(`${API_BASE}/investigations/${targetId}/remediation/${logId}/rollback`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to rollback action '${logId}'`);
    }
    return res.json();
  },

  /**
   * Export and trigger download of the standards-compliant STIX 2.1 CTI JSON bundle.
   */
  async downloadStixBundle(targetId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/investigations/${targetId}/export/stix`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail?.message || `Failed to export STIX 2.1 bundle for '${targetId}'`);
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AEGIS_STIX_${targetId.replace(/ /g, '_')}.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },
};
