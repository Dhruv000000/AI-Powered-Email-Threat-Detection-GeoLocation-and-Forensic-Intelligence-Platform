"""
Parameterized, server-side Cypher query templates.
Strictly disallows arbitrary user-supplied Cypher to prevent Cypher injection vulnerabilities.
"""

# ---------------------------------------------------------------------------
# Schema & Constraints
# ---------------------------------------------------------------------------

CREATE_ENTITY_ID_CONSTRAINT = """
CREATE CONSTRAINT entity_id_unique IF NOT EXISTS
FOR (n:Entity) REQUIRE n.id IS UNIQUE
"""

CREATE_EMAIL_ANALYSIS_ID_CONSTRAINT = """
CREATE CONSTRAINT email_analysis_id_unique IF NOT EXISTS
FOR (e:Email) REQUIRE e.analysis_id IS UNIQUE
"""

CREATE_EMAIL_ADDRESS_CONSTRAINT = """
CREATE CONSTRAINT email_address_unique IF NOT EXISTS
FOR (a:EmailAddress) REQUIRE a.address IS UNIQUE
"""

CREATE_DOMAIN_NAME_CONSTRAINT = """
CREATE CONSTRAINT domain_name_unique IF NOT EXISTS
FOR (d:Domain) REQUIRE d.domain_name IS UNIQUE
"""

CREATE_URL_NORMALIZED_CONSTRAINT = """
CREATE CONSTRAINT url_normalized_unique IF NOT EXISTS
FOR (u:URL) REQUIRE u.normalized_url IS UNIQUE
"""

CREATE_IP_ADDRESS_CONSTRAINT = """
CREATE CONSTRAINT ip_address_unique IF NOT EXISTS
FOR (i:IPAddress) REQUIRE i.ip IS UNIQUE
"""

CREATE_ATTACHMENT_SHA256_CONSTRAINT = """
CREATE CONSTRAINT attachment_sha256_unique IF NOT EXISTS
FOR (att:Attachment) REQUIRE att.sha256 IS UNIQUE
"""

CREATE_INVESTIGATION_INDEX = """
CREATE INDEX entity_investigation_idx IF NOT EXISTS
FOR (n:Entity) ON (n.investigation_id)
"""

CREATE_ENTITY_TYPE_INDEX = """
CREATE INDEX entity_type_idx IF NOT EXISTS
FOR (n:Entity) ON (n.type)
"""


# ---------------------------------------------------------------------------
# Node Mutations (Idempotent MERGE)
# ---------------------------------------------------------------------------

MERGE_NODES_BATCH = """
UNWIND $batch AS row
MERGE (n:Entity {id: row.id})
ON CREATE SET
    n.type = row.type,
    n.label = row.label,
    n.investigation_id = row.investigation_id,
    n.display_label = row.display_label,
    n.normalized_value = row.normalized_value,
    n.risk_score = row.risk_score,
    n.severity = row.severity,
    n.evidence_reference = row.evidence_reference,
    n.properties = row.properties_json,
    n.created_at = timestamp()
ON MATCH SET
    n.type = row.type,
    n.label = row.label,
    n.investigation_id = row.investigation_id,
    n.display_label = row.display_label,
    n.normalized_value = row.normalized_value,
    n.risk_score = row.risk_score,
    n.severity = row.severity,
    n.evidence_reference = row.evidence_reference,
    n.properties = row.properties_json,
    n.updated_at = timestamp()
"""

# ---------------------------------------------------------------------------
# Relationship Mutations (Idempotent MERGE)
# ---------------------------------------------------------------------------

MERGE_RELATIONSHIPS_BATCH = """
UNWIND $batch AS row
MATCH (s:Entity {id: row.source_id})
MATCH (t:Entity {id: row.target_id})
MERGE (s)-[r:RELATION {id: row.id, investigation_id: row.investigation_id}]->(t)
ON CREATE SET
    r.type = row.type,
    r.label = row.type,
    r.provenance = row.provenance,
    r.source_reference = row.source_reference,
    r.confidence = row.confidence,
    r.properties = row.properties_json,
    r.created_at = timestamp()
ON MATCH SET
    r.type = row.type,
    r.label = row.type,
    r.provenance = row.provenance,
    r.source_reference = row.source_reference,
    r.confidence = row.confidence,
    r.properties = row.properties_json,
    r.updated_at = timestamp()
"""

# ---------------------------------------------------------------------------
# Graph Retrieval & Isolation
# ---------------------------------------------------------------------------

GET_INVESTIGATION_GRAPH = """
MATCH (n:Entity {investigation_id: $investigation_id})
WITH n LIMIT $max_nodes
OPTIONAL MATCH (n)-[r:RELATION {investigation_id: $investigation_id}]-(m:Entity {investigation_id: $investigation_id})
RETURN collect(DISTINCT n) AS nodes, collect(DISTINCT r) AS edges
"""

GET_ENTITY_DETAIL = """
MATCH (n:Entity {id: $entity_id, investigation_id: $investigation_id})
OPTIONAL MATCH (n)-[r:RELATION {investigation_id: $investigation_id}]-(m:Entity {investigation_id: $investigation_id})
RETURN n, collect(DISTINCT {rel: r, target: m, is_outgoing: (startNode(r) = n)}) AS related
"""

GET_ENTITY_NEIGHBORS = """
MATCH (n:Entity {id: $entity_id, investigation_id: $investigation_id})
OPTIONAL MATCH (n)-[r:RELATION {investigation_id: $investigation_id}]-(m:Entity {investigation_id: $investigation_id})
RETURN n, collect(DISTINCT m) AS neighbors, collect(DISTINCT r) AS edges
"""

GET_BOUNDED_PATHS = """
MATCH (s:Entity {id: $start_id, investigation_id: $investigation_id})
MATCH (t:Entity {id: $end_id, investigation_id: $investigation_id})
MATCH p = shortestPath((s)-[:RELATION*..5]-(t))
WHERE all(x IN nodes(p) WHERE x.investigation_id = $investigation_id)
RETURN p
LIMIT $max_results
"""

FIND_CROSS_INVESTIGATION_MATCHES = """
MATCH (n:Entity)
WHERE n.id IN $entity_ids AND n.investigation_id <> $current_investigation_id
RETURN DISTINCT n.id AS entity_id, n.investigation_id AS other_investigation_id, n.type AS entity_type
LIMIT 50
"""

DELETE_INVESTIGATION_GRAPH = """
MATCH (n:Entity {investigation_id: $investigation_id})
DETACH DELETE n
"""
