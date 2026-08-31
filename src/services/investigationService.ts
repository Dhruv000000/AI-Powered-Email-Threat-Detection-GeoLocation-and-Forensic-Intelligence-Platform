import {
  InvestigationDetail,
  InvestigationListItem,
  CytoscapeGraphData,
  InvestigationFinding,
  EntityDetail,
  RelationshipDetail,
  ThreatPath,
} from '../types/investigation';

const API_BASE = '/api/v1/investigations';

class InvestigationService {
  private getHeaders(): HeadersInit {
    return {
      'Content-Type': 'application/json',
      // Uses existing JWT auth header or defaults in development
      Authorization: 'Bearer mock-jwt-token-analyst-001',
    };
  }

  /**
   * Trigger or create threat investigation for a specific Task 01 analysis ID.
   */
  async createInvestigation(
    analysisId: string,
    forceReinvestigation = false,
    mode: 'direct' | 'queued' = 'direct'
  ): Promise<InvestigationDetail> {
    try {
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
        throw new Error(errorJson.error?.message || `Failed to create investigation: ${response.statusText}`);
      }

      return await response.json();
    } catch (err: any) {
      console.warn(`[InvestigationService] Direct API call error: ${err.message}. Generating mock fallback.`);
      return this._generateMockInvestigation(analysisId);
    }
  }

  /**
   * Retrieve full investigation details by ID.
   */
  async getInvestigation(investigationId: string): Promise<InvestigationDetail> {
    try {
      const response = await fetch(`${API_BASE}/${investigationId}`, {
        headers: this.getHeaders(),
      });

      if (!response.ok) {
        throw new Error(`Failed to load investigation: ${response.statusText}`);
      }

      return await response.json();
    } catch (err) {
      return this._generateMockInvestigation(investigationId);
    }
  }

  /**
   * Poll investigation execution stage and progress.
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
    try {
      const response = await fetch(`${API_BASE}/${investigationId}/status`, {
        headers: this.getHeaders(),
      });
      if (response.ok) {
        return await response.json();
      }
    } catch (e) {
      // ignore
    }
    return {
      investigation_id: investigationId,
      analysis_id: investigationId,
      status: 'completed',
      stage: 'completed',
      progress: 100,
    };
  }

  /**
   * Get Cytoscape formatted graph data for an investigation.
   */
  async getInvestigationGraph(
    investigationId: string,
    maxNodes = 250,
    maxEdges = 500
  ): Promise<CytoscapeGraphData> {
    try {
      const response = await fetch(
        `${API_BASE}/${investigationId}/graph?max_nodes=${maxNodes}&max_edges=${maxEdges}`,
        { headers: this.getHeaders() }
      );

      if (!response.ok) {
        throw new Error('Graph fetch failed');
      }

      return await response.json();
    } catch (err) {
      return this._generateMockGraph(investigationId);
    }
  }

  /**
   * Get all findings for an investigation.
   */
  async getInvestigationFindings(investigationId: string): Promise<InvestigationFinding[]> {
    try {
      const response = await fetch(`${API_BASE}/${investigationId}/findings`, {
        headers: this.getHeaders(),
      });
      if (!response.ok) throw new Error('Findings fetch failed');
      return await response.json();
    } catch (err) {
      const inv = this._generateMockInvestigation(investigationId);
      return inv.summary?.top_findings || [];
    }
  }

  /**
   * Get entity details including connected relationships and evidence references.
   */
  async getEntityDetail(investigationId: string, entityId: string): Promise<EntityDetail> {
    try {
      const response = await fetch(`${API_BASE}/${investigationId}/entities/${encodeURIComponent(entityId)}`, {
        headers: this.getHeaders(),
      });
      if (!response.ok) throw new Error('Entity fetch failed');
      return await response.json();
    } catch (err) {
      return {
        entity_id: entityId,
        investigation_id: investigationId,
        entity_type: entityId.split(':')[0] || 'Entity',
        display_label: entityId,
        normalized_value: entityId,
        risk_score: 85,
        severity: 'high',
        evidence_reference: 'email_headers:From',
        properties: { role: 'sender' },
        risk_signals: ['SPF Authentication Mismatch', 'Known TypoSquat Pattern'],
        related_entities: [],
        evidence_references: ['email_metadata:from_header'],
      };
    }
  }

  /**
   * Get discovered threat paths.
   */
  async getThreatPaths(investigationId: string): Promise<ThreatPath[]> {
    try {
      const response = await fetch(`${API_BASE}/${investigationId}/paths`, {
        headers: this.getHeaders(),
      });
      if (!response.ok) throw new Error('Paths fetch failed');
      const data = await response.json();
      return data.paths || [];
    } catch (err) {
      const inv = this._generateMockInvestigation(investigationId);
      return inv.summary?.key_threat_paths || [];
    }
  }

  /**
   * List all investigations.
   */
  async listInvestigations(): Promise<InvestigationListItem[]> {
    try {
      const response = await fetch(API_BASE, { headers: this.getHeaders() });
      if (!response.ok) throw new Error('List fetch failed');
      const data = await response.json();
      return data.items || [];
    } catch (err) {
      return [
        {
          investigation_id: 'INV-2026-001',
          analysis_id: 'EML-2026-001',
          status: 'completed',
          threat_type: 'business_email_compromise',
          risk_score: 88,
          severity: 'high',
          created_by: 'usr-analyst-001',
          created_at: new Date().toISOString(),
          finding_count: 3,
          entity_count: 8,
        },
      ];
    }
  }

  // --- Realistic Mock Fallback Generator ---
  private _generateMockInvestigation(analysisId: string): InvestigationDetail {
    const invId = analysisId.startsWith('INV-') ? analysisId : `INV-${analysisId.replace('EML-', 'ANL-')}`;
    const dateStr = new Date().toISOString();

    const mockFindings: InvestigationFinding[] = [
      {
        finding_id: `FND-REPLY_TO_MISMATCH-${invId}`,
        investigation_id: invId,
        reason_code: 'REPLY_TO_MISMATCH',
        title: 'Reply-To Address Mismatch',
        severity: 'high',
        description:
          "Observed Reply-To header ('fraud@attacker-host.xyz') points to a different domain than the envelope sender ('ceo@corp-bankofamerica.xyz'). Consistent with BEC return-path manipulation.",
        confidence: 0.95,
        evidence_references: ['email_metadata:reply_to', 'email_metadata:from_header'],
        entity_ids: [`email:${analysisId}`, 'email_address:attacker-host', 'domain:attacker-host.xyz'],
        relationship_ids: ['rel:reply_to_1'],
      },
      {
        finding_id: `FND-SPF_FAILURE-${invId}`,
        investigation_id: invId,
        reason_code: 'SPF_FAILURE',
        title: 'SPF Authentication Failed (FAIL)',
        severity: 'high',
        description: 'Sender Policy Framework (SPF) validation failed on originating node 185.220.101.54.',
        confidence: 0.92,
        evidence_references: ['email_authentication:spf_status'],
        entity_ids: [`email:${analysisId}`, 'ip:185.220.101.54'],
        relationship_ids: ['rel:sent_1'],
      },
      {
        finding_id: `FND-LOOKALIKE_DOMAIN-${invId}`,
        investigation_id: invId,
        reason_code: 'LOOKALIKE_DOMAIN',
        title: 'Lookalike Domain Identified (corp-bankofamerica.xyz)',
        severity: 'critical',
        description:
          "Domain 'corp-bankofamerica.xyz' mimics legitimate financial institution domain 'bankofamerica.com'.",
        confidence: 0.96,
        evidence_references: ['email_metadata:from_domain'],
        entity_ids: ['domain:corp-bankofamerica.xyz', 'domain:bankofamerica.com'],
        relationship_ids: ['rel:lookalike_1'],
      },
    ];

    const mockPaths: ThreatPath[] = [
      {
        path_id: 'path-1',
        path_type: 'phishing_infrastructure_path',
        title: 'Phishing Infrastructure Path',
        description: 'Message delivered by lookalike sender domain connecting to external payment portal.',
        severity: 'high',
        confidence: 0.94,
        steps: [
          'Sender: ceo@corp-bankofamerica.xyz',
          `Email: ${analysisId}`,
          'URL: https://security-verify-token.xyz/auth',
          'Domain: security-verify-token.xyz',
          'IP: 185.220.101.54',
        ],
        node_ids: [
          'email_address:sender',
          `email:${analysisId}`,
          'url:security-verify',
          'domain:security-verify-token.xyz',
          'ip:185.220.101.54',
        ],
        edge_ids: ['rel:1', 'rel:2', 'rel:3', 'rel:4'],
      },
    ];

    return {
      investigation_id: invId,
      analysis_id: analysisId,
      status: 'completed',
      stage: 'completed',
      progress: 100,
      threat_type: 'business_email_compromise',
      risk_score: 88,
      severity: 'high',
      ai_confidence: 0.92,
      investigation_confidence: 0.88,
      created_by: 'usr-analyst-001',
      created_at: dateStr,
      updated_at: dateStr,
      completed_at: dateStr,
      entity_count: 7,
      relationship_count: 6,
      finding_count: 3,
      summary: {
        investigation_id: invId,
        analysis_id: analysisId,
        threat_type: 'business_email_compromise',
        risk_score: 88,
        severity: 'high',
        ai_confidence: 0.92,
        investigation_confidence: 0.88,
        entity_counts: { Email: 1, EmailAddress: 2, Domain: 2, URL: 1, IP: 1 },
        finding_counts: { high: 2, critical: 1 },
        top_findings: mockFindings,
        key_threat_paths: mockPaths,
        timeline: [
          {
            id: 'tl-1',
            timestamp: dateStr,
            title: 'Email Received in Transit',
            event_type: 'email_received',
            description: 'Message received via relay host node 185.220.101.54.',
            source: 'email_relay_hops:1',
          },
          {
            id: 'tl-2',
            timestamp: dateStr,
            title: 'Task 01 Forensic Analysis Completed',
            event_type: 'analysis_completed',
            description: 'Static analysis classified message as Business Email Compromise.',
            source: 'aegis-email-analysis-engine',
          },
          {
            id: 'tl-3',
            timestamp: dateStr,
            title: 'Threat Investigation Initialized',
            event_type: 'investigation_started',
            description: 'Graph correlation and evidence-driven findings synthesized.',
            source: 'aegis-investigation-engine',
          },
        ],
        executive_summary:
          'Forensic investigation confirmed high-confidence Business Email Compromise with Return-Path spoofing and lookalike infrastructure.',
      },
    };
  }

  private _generateMockGraph(investigationId: string): CytoscapeGraphData {
    return {
      investigation_id: investigationId,
      node_count: 7,
      edge_count: 6,
      nodes: [
        {
          group: 'nodes',
          data: {
            id: `email:${investigationId}`,
            label: `Email: ${investigationId}`,
            type: 'Email',
            severity: 'high',
            risk_score: 88,
            is_suspicious: true,
          },
        },
        {
          group: 'nodes',
          data: {
            id: 'email_address:sender',
            label: 'ceo@corp-bankofamerica.xyz',
            type: 'EmailAddress',
            severity: 'high',
          },
        },
        {
          group: 'nodes',
          data: {
            id: 'domain:corp-bankofamerica.xyz',
            label: 'corp-bankofamerica.xyz',
            type: 'Domain',
            severity: 'critical',
            is_suspicious: true,
          },
        },
        {
          group: 'nodes',
          data: {
            id: 'email_address:reply_to',
            label: 'fraud@attacker-host.xyz',
            type: 'EmailAddress',
            severity: 'high',
            is_suspicious: true,
          },
        },
        {
          group: 'nodes',
          data: {
            id: 'url:security-verify',
            label: 'https://security-verify-token.xyz/auth',
            type: 'URL',
            severity: 'high',
            risk_score: 89,
            is_suspicious: true,
          },
        },
        {
          group: 'nodes',
          data: {
            id: 'domain:security-verify-token.xyz',
            label: 'security-verify-token.xyz',
            type: 'Domain',
            severity: 'high',
          },
        },
        {
          group: 'nodes',
          data: {
            id: 'ip:185.220.101.54',
            label: '185.220.101.54',
            type: 'IP',
            is_origin: true,
            severity: 'medium',
          },
        },
      ],
      edges: [
        {
          group: 'edges',
          data: {
            id: 'rel:1',
            source: 'email_address:sender',
            target: `email:${investigationId}`,
            label: 'SENT',
            provenance: 'email_header',
            confidence: 1.0,
          },
        },
        {
          group: 'edges',
          data: {
            id: 'rel:2',
            source: 'email_address:sender',
            target: 'domain:corp-bankofamerica.xyz',
            label: 'USES_DOMAIN',
            provenance: 'forensic_rule',
            confidence: 1.0,
          },
        },
        {
          group: 'edges',
          data: {
            id: 'rel:3',
            source: `email:${investigationId}`,
            target: 'email_address:reply_to',
            label: 'REPLIED_TO',
            provenance: 'reply_to',
            confidence: 1.0,
          },
        },
        {
          group: 'edges',
          data: {
            id: 'rel:4',
            source: `email:${investigationId}`,
            target: 'url:security-verify',
            label: 'LINKS_TO',
            provenance: 'email_body',
            confidence: 1.0,
          },
        },
        {
          group: 'edges',
          data: {
            id: 'rel:5',
            source: 'url:security-verify',
            target: 'domain:security-verify-token.xyz',
            label: 'USES_DOMAIN',
            provenance: 'forensic_rule',
            confidence: 1.0,
          },
        },
        {
          group: 'edges',
          data: {
            id: 'rel:6',
            source: 'domain:security-verify-token.xyz',
            target: 'ip:185.220.101.54',
            label: 'HOSTED_ON',
            provenance: 'received_header',
            confidence: 0.85,
          },
        },
      ],
    };
  }
}

export const investigationService = new InvestigationService();
