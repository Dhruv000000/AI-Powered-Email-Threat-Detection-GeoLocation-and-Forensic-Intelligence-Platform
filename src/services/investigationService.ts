import {
  InvestigationDetail,
  InvestigationListItem,
  CytoscapeGraphData,
  InvestigationFinding,
  EntityDetail,
  ThreatPath,
} from '../types/investigation';

const API_BASE = '/api/v1/investigations';

class InvestigationService {
  private getHeaders(): HeadersInit {
    return {
      'Content-Type': 'application/json',
      Authorization: 'Bearer mock-jwt-token-analyst-001',
    };
  }

  /**
   * Trigger or create threat investigation for a specific Task 01 analysis ID.
   * Sends POST /api/v1/investigations
   */
  async createInvestigation(
    analysisId: string,
    forceReinvestigation = false,
    mode: 'direct' | 'queued' = 'direct'
  ): Promise<InvestigationDetail> {
    const response = await fetch(API_BASE, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        analysis_id: analysisId,
        force_reinvestigation: forceReinvestigation,
        mode,
      }),
    });

    if (!response.ok) {
      const errorJson = await response.json().catch(() => ({}));
      const errorMsg =
        errorJson.detail?.message ||
        errorJson.error?.message ||
        errorJson.detail ||
        `Failed to create investigation: ${response.statusText} (${response.status})`;
      console.error('[InvestigationService] createInvestigation error:', errorMsg);
      throw new Error(errorMsg);
    }

    return await response.json();
  }

  /**
   * Retrieve full investigation details by ID.
   * Sends GET /api/v1/investigations/{investigationId}
   */
  async getInvestigation(investigationId: string): Promise<InvestigationDetail> {
    const response = await fetch(`${API_BASE}/${encodeURIComponent(investigationId)}`, {
      headers: this.getHeaders(),
    });

    if (!response.ok) {
      const errorJson = await response.json().catch(() => ({}));
      const errorMsg =
        errorJson.detail?.message ||
        errorJson.error?.message ||
        `Failed to load investigation: ${response.statusText} (${response.status})`;
      console.error('[InvestigationService] getInvestigation error:', errorMsg);
      throw new Error(errorMsg);
    }

    return await response.json();
  }

  /**
   * Poll investigation execution stage and progress.
   * Sends GET /api/v1/investigations/{investigationId}/status
   */
  async getInvestigationStatus(investigationId: string): Promise<{
    investigation_id: string;
    analysis_id: string;
    status: string;
    stage: string;
    progress: number;
    error_code?: string;
    error_message_safe?: string;
  }> {
    const response = await fetch(`${API_BASE}/${encodeURIComponent(investigationId)}/status`, {
      headers: this.getHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Failed to retrieve investigation status (${response.status})`);
    }

    return await response.json();
  }

  /**
   * Get Cytoscape formatted graph data for an investigation.
   * Sends GET /api/v1/investigations/{investigationId}/graph
   */
  async getInvestigationGraph(
    investigationId: string,
    maxNodes = 250,
    maxEdges = 500
  ): Promise<CytoscapeGraphData> {
    const response = await fetch(
      `${API_BASE}/${encodeURIComponent(investigationId)}/graph?max_nodes=${maxNodes}&max_edges=${maxEdges}`,
      { headers: this.getHeaders() }
    );

    if (!response.ok) {
      const errorJson = await response.json().catch(() => ({}));
      const errorMsg =
        errorJson.detail?.message ||
        errorJson.error?.message ||
        `Graph retrieval failed: ${response.statusText} (${response.status})`;
      console.error('[InvestigationService] getInvestigationGraph error:', errorMsg);
      throw new Error(errorMsg);
    }

    return await response.json();
  }

  /**
   * Get all evidentiary findings for an investigation.
   * Sends GET /api/v1/investigations/{investigationId}/findings
   */
  async getInvestigationFindings(investigationId: string): Promise<InvestigationFinding[]> {
    const response = await fetch(`${API_BASE}/${encodeURIComponent(investigationId)}/findings`, {
      headers: this.getHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Findings retrieval failed (${response.status})`);
    }

    return await response.json();
  }

  /**
   * Get entity details including connected relationships and evidence references.
   * Sends GET /api/v1/investigations/{investigationId}/entities/{entityId}
   */
  async getEntityDetail(investigationId: string, entityId: string): Promise<EntityDetail> {
    const response = await fetch(
      `${API_BASE}/${encodeURIComponent(investigationId)}/entities/${encodeURIComponent(entityId)}`,
      { headers: this.getHeaders() }
    );

    if (!response.ok) {
      throw new Error(`Entity details retrieval failed (${response.status})`);
    }

    return await response.json();
  }

  /**
   * Get discovered threat paths.
   * Sends GET /api/v1/investigations/{investigationId}/paths
   */
  async getThreatPaths(investigationId: string): Promise<ThreatPath[]> {
    const response = await fetch(`${API_BASE}/${encodeURIComponent(investigationId)}/paths`, {
      headers: this.getHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Threat paths retrieval failed (${response.status})`);
    }

    const data = await response.json();
    return data.paths || [];
  }

  /**
   * List all investigations.
   * Sends GET /api/v1/investigations
   */
  async listInvestigations(): Promise<InvestigationListItem[]> {
    const response = await fetch(API_BASE, { headers: this.getHeaders() });
    if (!response.ok) {
      throw new Error(`List investigations failed (${response.status})`);
    }

    const data = await response.json();
    return data.items || [];
  }
}

export const investigationService = new InvestigationService();
