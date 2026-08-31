import json
from typing import Dict, Any, List, Optional
from neo4j import GraphDatabase, Driver
from app.core.config import settings
from app.core.logging import logger
from app.graph.constraints import apply_neo4j_constraints
from app.graph.queries import (
    MERGE_NODES_BATCH,
    MERGE_RELATIONSHIPS_BATCH,
    GET_INVESTIGATION_GRAPH,
    GET_ENTITY_DETAIL,
    GET_ENTITY_NEIGHBORS,
    GET_BOUNDED_PATHS,
    FIND_CROSS_INVESTIGATION_MATCHES,
    DELETE_INVESTIGATION_GRAPH,
)


class Neo4jGraphStore:
    """
    Production graph store backed by official Neo4j driver and parameterized Cypher queries.
    Enforces strict investigation scoping, server-side parameterization, and bounded traversals.
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
    ):
        self.uri = uri or settings.NEO4J_URI
        self.username = username or settings.NEO4J_USERNAME
        self.password = password or settings.NEO4J_PASSWORD
        self.database = database or settings.NEO4J_DATABASE
        self._driver: Optional[Driver] = None
        self._connect()

    def _connect(self) -> None:
        try:
            self._driver = GraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password),
                max_connection_lifetime=settings.NEO4J_MAX_CONNECTION_LIFETIME,
            )
            # Verify connectivity immediately
            self._driver.verify_connectivity()
            logger.info(f"Connected to Neo4j database at {self.uri} (DB: {self.database})")
            self.initialize_schema()
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j instance at {self.uri}: {e}")
            self._driver = None
            raise ConnectionError(f"Neo4j instance is unreachable at {self.uri}: {e}")

    def ping(self) -> bool:
        if not self._driver:
            return False
        try:
            self._driver.verify_connectivity()
            return True
        except Exception as e:
            logger.warning(f"Neo4j ping failed: {e}")
            return False

    def initialize_schema(self) -> None:
        if not self._driver:
            return
        with self._driver.session(database=self.database) as session:
            apply_neo4j_constraints(session)

    def create_or_merge_nodes(self, nodes: List[Dict[str, Any]]) -> None:
        if not self._driver:
            raise ConnectionError("Neo4j driver not connected")
        if not nodes:
            return

        batch_params = []
        for n in nodes:
            props = n.get("properties", {})
            props_json = json.dumps(props) if isinstance(props, dict) else str(props)
            batch_params.append({
                "id": n["id"],
                "type": n.get("type", "Entity"),
                "label": n.get("label", n.get("display_label", n["id"])),
                "investigation_id": n["investigation_id"],
                "display_label": n.get("display_label", n.get("label", n["id"])),
                "normalized_value": n.get("normalized_value", ""),
                "risk_score": n.get("risk_score"),
                "severity": n.get("severity"),
                "evidence_reference": n.get("evidence_reference"),
                "properties_json": props_json,
            })

        with self._driver.session(database=self.database) as session:
            session.run(MERGE_NODES_BATCH, batch=batch_params)

    def create_or_merge_relationships(self, relationships: List[Dict[str, Any]]) -> None:
        if not self._driver:
            raise ConnectionError("Neo4j driver not connected")
        if not relationships:
            return

        batch_params = []
        for r in relationships:
            props = r.get("properties", {})
            props_json = json.dumps(props) if isinstance(props, dict) else str(props)
            batch_params.append({
                "id": r["id"],
                "source_id": r["source_id"],
                "target_id": r["target_id"],
                "type": r.get("type", "RELATION"),
                "investigation_id": r["investigation_id"],
                "provenance": r.get("provenance", "forensic_rule"),
                "source_reference": r.get("source_reference"),
                "confidence": float(r.get("confidence", 1.0)),
                "properties_json": props_json,
            })

        with self._driver.session(database=self.database) as session:
            session.run(MERGE_RELATIONSHIPS_BATCH, batch=batch_params)

    def get_investigation_graph(
        self, investigation_id: str, max_nodes: int = 250, max_edges: int = 500
    ) -> Dict[str, List[Dict[str, Any]]]:
        if not self._driver:
            raise ConnectionError("Neo4j driver not connected")

        with self._driver.session(database=self.database) as session:
            result = session.run(
                GET_INVESTIGATION_GRAPH,
                investigation_id=investigation_id,
                max_nodes=max_nodes,
            )
            record = result.single()
            if not record:
                return {"nodes": [], "edges": []}

            raw_nodes = record.get("nodes", [])
            raw_edges = record.get("edges", [])

            nodes_out = []
            for n in raw_nodes:
                props_raw = n.get("properties", "{}")
                try:
                    props = json.loads(props_raw) if isinstance(props_raw, str) else props_raw
                except Exception:
                    props = {}

                nodes_out.append({
                    "id": n.get("id"),
                    "label": n.get("display_label") or n.get("label") or n.get("id"),
                    "type": n.get("type", "Entity"),
                    "severity": n.get("severity"),
                    "risk_score": n.get("risk_score"),
                    "is_origin": n.get("is_origin", False),
                    "is_suspicious": n.get("is_suspicious", False),
                    "evidence_reference": n.get("evidence_reference"),
                    "properties": props,
                })

            edges_out = []
            for e in raw_edges:
                props_raw = e.get("properties", "{}")
                try:
                    props = json.loads(props_raw) if isinstance(props_raw, str) else props_raw
                except Exception:
                    props = {}

                # Retrieve start and end node IDs from relationship
                source_id = e.start_node.get("id") if hasattr(e, "start_node") else e.get("source_id")
                target_id = e.end_node.get("id") if hasattr(e, "end_node") else e.get("target_id")

                edges_out.append({
                    "id": e.get("id"),
                    "source": source_id,
                    "target": target_id,
                    "label": e.get("type") or e.get("label", "RELATION"),
                    "provenance": e.get("provenance"),
                    "source_reference": e.get("source_reference"),
                    "confidence": float(e.get("confidence", 1.0)),
                    "properties": props,
                })

            return {"nodes": nodes_out, "edges": edges_out}

    def get_entity(self, entity_id: str, investigation_id: str) -> Optional[Dict[str, Any]]:
        if not self._driver:
            raise ConnectionError("Neo4j driver not connected")

        with self._driver.session(database=self.database) as session:
            result = session.run(
                GET_ENTITY_DETAIL,
                entity_id=entity_id,
                investigation_id=investigation_id,
            )
            record = result.single()
            if not record or not record.get("n"):
                return None

            n = record["n"]
            props_raw = n.get("properties", "{}")
            try:
                props = json.loads(props_raw) if isinstance(props_raw, str) else props_raw
            except Exception:
                props = {}

            return {
                "id": n.get("id"),
                "label": n.get("display_label") or n.get("label"),
                "type": n.get("type"),
                "normalized_value": n.get("normalized_value"),
                "risk_score": n.get("risk_score"),
                "severity": n.get("severity"),
                "evidence_reference": n.get("evidence_reference"),
                "properties": props,
            }

    def get_neighbors(
        self, entity_id: str, investigation_id: str, max_depth: int = 1
    ) -> Dict[str, List[Dict[str, Any]]]:
        if not self._driver:
            raise ConnectionError("Neo4j driver not connected")

        with self._driver.session(database=self.database) as session:
            result = session.run(
                GET_ENTITY_NEIGHBORS,
                entity_id=entity_id,
                investigation_id=investigation_id,
            )
            record = result.single()
            if not record or not record.get("n"):
                return {"nodes": [], "edges": []}

            nodes = [dict(record["n"])] + [dict(m) for m in record.get("neighbors", [])]
            edges = [dict(r) for r in record.get("edges", [])]
            return {"nodes": nodes, "edges": edges}

    def get_paths(
        self, investigation_id: str, start_entity_id: str, end_entity_id: str, max_depth: int = 5
    ) -> List[List[Dict[str, Any]]]:
        if not self._driver:
            raise ConnectionError("Neo4j driver not connected")

        with self._driver.session(database=self.database) as session:
            result = session.run(
                GET_BOUNDED_PATHS,
                investigation_id=investigation_id,
                start_id=start_entity_id,
                end_id=end_entity_id,
                max_results=5,
            )
            paths_out = []
            for record in result:
                path = record["p"]
                steps = []
                for node in path.nodes:
                    steps.append({"node": dict(node)})
                paths_out.append(steps)
            return paths_out

    def find_threat_paths(
        self, investigation_id: str, max_depth: int = 5, max_paths: int = 10
    ) -> List[Dict[str, Any]]:
        # Fetch the investigation graph and compute threat paths deterministically
        graph = self.get_investigation_graph(investigation_id)
        nodes_by_id = {n["id"]: n for n in graph["nodes"]}
        edges = graph["edges"]

        adj: Dict[str, List[Dict[str, Any]]] = {}
        for e in edges:
            adj.setdefault(e["source"], []).append(e)

        paths = []
        email_nodes = [n for n in graph["nodes"] if n["type"] == "Email"]
        if not email_nodes:
            return []

        email_node = email_nodes[0]
        email_id = email_node["id"]

        for e in adj.get(email_id, []):
            target_node = nodes_by_id.get(e["target"])
            if not target_node:
                continue

            # Phishing path: Email -> URL -> Domain -> IP
            if target_node["type"] == "URL":
                url_node = target_node
                for u_edge in adj.get(url_node["id"], []):
                    dom_node = nodes_by_id.get(u_edge["target"])
                    if dom_node and dom_node["type"] == "Domain":
                        ip_node = None
                        ip_edge = None
                        for d_edge in adj.get(dom_node["id"], []):
                            cand_ip = nodes_by_id.get(d_edge["target"])
                            if cand_ip and cand_ip["type"] == "IP":
                                ip_node = cand_ip
                                ip_edge = d_edge
                                break

                        steps = [
                            f"Email: {email_node['label']}",
                            f"Extracted URL: {url_node['label']}",
                            f"Host Domain: {dom_node['label']}",
                        ]
                        node_ids = [email_id, url_node["id"], dom_node["id"]]
                        edge_ids = [e["id"], u_edge["id"]]

                        if ip_node:
                            steps.append(f"Hosted IP: {ip_node['label']}")
                            node_ids.append(ip_node["id"])
                            if ip_edge:
                                edge_ids.append(ip_edge["id"])

                        paths.append({
                            "path_id": f"path-url-{len(paths) + 1}",
                            "path_type": "phishing_infrastructure_path",
                            "title": "Phishing URL & Domain Infrastructure Path",
                            "description": f"Email links to URL '{url_node['label']}' hosted on domain '{dom_node['label']}'.",
                            "severity": url_node.get("severity", "high"),
                            "confidence": 0.95,
                            "steps": steps,
                            "node_ids": node_ids,
                            "edge_ids": edge_ids,
                        })

            # Attachment path: Email -> Attachment -> FileHash
            elif target_node["type"] == "Attachment":
                att_node = target_node
                hash_node = None
                hash_edge = None
                for a_edge in adj.get(att_node["id"], []):
                    cand_h = nodes_by_id.get(a_edge["target"])
                    if cand_h and cand_h["type"] == "FileHash":
                        hash_node = cand_h
                        hash_edge = a_edge
                        break

                steps = [
                    f"Email: {email_node['label']}",
                    f"Attachment: {att_node['label']}",
                ]
                node_ids = [email_id, att_node["id"]]
                edge_ids = [e["id"]]

                if hash_node:
                    steps.append(f"SHA-256 Hash: {hash_node['label'][:16]}...")
                    node_ids.append(hash_node["id"])
                    if hash_edge:
                        edge_ids.append(hash_edge["id"])

                paths.append({
                    "path_id": f"path-att-{len(paths) + 1}",
                    "path_type": "malware_delivery_path",
                    "title": "Malicious Attachment Delivery Path",
                    "description": f"Email delivered attachment '{att_node['label']}' with cryptographic hash.",
                    "severity": att_node.get("severity", "high"),
                    "confidence": 0.92,
                    "steps": steps,
                    "node_ids": node_ids,
                    "edge_ids": edge_ids,
                })

        return paths[:max_paths]

    def find_cross_investigation_matches(
        self, entity_ids: List[str], current_investigation_id: str
    ) -> List[Dict[str, Any]]:
        if not self._driver:
            raise ConnectionError("Neo4j driver not connected")

        with self._driver.session(database=self.database) as session:
            result = session.run(
                FIND_CROSS_INVESTIGATION_MATCHES,
                entity_ids=entity_ids,
                current_investigation_id=current_investigation_id,
            )
            return [dict(r) for r in result]

    def delete_investigation_graph(self, investigation_id: str) -> None:
        if not self._driver:
            raise ConnectionError("Neo4j driver not connected")

        with self._driver.session(database=self.database) as session:
            session.run(DELETE_INVESTIGATION_GRAPH, investigation_id=investigation_id)

    def close(self) -> None:
        if self._driver:
            try:
                self._driver.close()
            except Exception:
                pass
            self._driver = None
