import json
from collections import deque
from typing import Dict, Any, List, Optional, Set
from app.core.logging import logger


class InMemoryGraphStore:
    """
    In-memory graph store implementation strictly for unit testing, offline development,
    and automatic resilient fallback when Neo4j is offline.
    Maintains graph isolation by investigation_id, deterministic node indexing, and BFS path discovery.
    """

    def __init__(self):
        # Key: node_id -> node_dict
        self._nodes: Dict[str, Dict[str, Any]] = {}
        # Key: relationship_id -> rel_dict
        self._edges: Dict[str, Dict[str, Any]] = {}
        # Adjacency index: node_id -> set of edge_ids
        self._adjacency: Dict[str, Set[str]] = {}

    def ping(self) -> bool:
        return True

    def initialize_schema(self) -> None:
        logger.info("InMemoryGraphStore initialized schema (in-memory mode).")

    def merge_node(self, label: str, canonical_id: str, properties: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Merge or create a single node with canonical ID and label.
        """
        props = dict(properties or {})
        node_entry = {
            "id": canonical_id,
            "label": props.get("display_label") or props.get("label") or canonical_id,
            "type": label or props.get("type", "Entity"),
            "name": props.get("name") or props.get("display_label") or canonical_id,
            "investigation_id": props.get("investigation_id", "default"),
            "display_label": props.get("display_label") or canonical_id,
            "normalized_value": props.get("normalized_value", canonical_id),
            "risk_score": props.get("risk_score"),
            "severity": props.get("severity"),
            "evidence_reference": props.get("evidence_reference"),
            "properties": props,
        }
        if canonical_id in self._nodes:
            self._nodes[canonical_id].update(node_entry)
            if "properties" in self._nodes[canonical_id] and isinstance(self._nodes[canonical_id]["properties"], dict):
                self._nodes[canonical_id]["properties"].update(props)
        else:
            self._nodes[canonical_id] = node_entry
            self._adjacency.setdefault(canonical_id, set())
        return self._nodes[canonical_id]

    def create_edge(
        self,
        source_id: str,
        target_id: str,
        label: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create or update a directed edge connecting source_id to target_id.
        """
        props = dict(properties or {})
        edge_id = props.get("id") or f"edge:{source_id}->{target_id}:{label}"
        edge_entry = {
            "id": edge_id,
            "source_id": source_id,
            "target_id": target_id,
            "source": source_id,
            "target": target_id,
            "type": label,
            "label": label,
            "investigation_id": props.get("investigation_id", "default"),
            "provenance": props.get("provenance", "forensic_rule"),
            "source_reference": props.get("source_reference"),
            "confidence": float(props.get("confidence", 1.0)),
            "properties": props,
        }
        self._adjacency.setdefault(source_id, set()).add(edge_id)
        self._adjacency.setdefault(target_id, set()).add(edge_id)
        if edge_id in self._edges:
            self._edges[edge_id].update(edge_entry)
        else:
            self._edges[edge_id] = edge_entry
        return self._edges[edge_id]

    def get_graph(self, investigation_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Return the graph dictionary containing all nodes and edges (or filtered by investigation_id).
        """
        if investigation_id:
            return self.get_investigation_graph(investigation_id)

        nodes = list(self._nodes.values())
        edges = list(self._edges.values())
        return {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }

    def find_paths(self, pattern: Optional[str] = None, max_paths: int = 10) -> List[Dict[str, Any]]:
        """
        Search for paths matching a type sequence pattern (e.g. 'Email->URL->Domain->IP') or return threat paths.
        """
        if pattern:
            type_sequence = [t.strip() for t in pattern.replace("->", " ").replace(",", " ").split() if t.strip()]
            if len(type_sequence) >= 2:
                matched_paths: List[Dict[str, Any]] = []
                start_nodes = [
                    n for n in self._nodes.values()
                    if n.get("type") == type_sequence[0] or n.get("label") == type_sequence[0]
                ]
                for sn in start_nodes:
                    def dfs(curr_id: str, seq_idx: int, path_nodes: List[str], path_edges: List[str]):
                        if seq_idx == len(type_sequence) - 1:
                            matched_paths.append({
                                "pattern": pattern,
                                "node_ids": list(path_nodes),
                                "edge_ids": list(path_edges),
                            })
                            return
                        for eid in self._adjacency.get(curr_id, set()):
                            edge = self._edges.get(eid)
                            if not edge:
                                continue
                            next_id = edge["target_id"] if edge["source_id"] == curr_id else edge["source_id"]
                            if next_id in path_nodes:
                                continue
                            next_node = self._nodes.get(next_id)
                            if next_node and (
                                next_node.get("type") == type_sequence[seq_idx + 1]
                                or next_node.get("label") == type_sequence[seq_idx + 1]
                            ):
                                dfs(next_id, seq_idx + 1, path_nodes + [next_id], path_edges + [eid])

                    dfs(sn["id"], 0, [sn["id"]], [])
                return matched_paths[:max_paths]

        investigation_ids = {n.get("investigation_id") for n in self._nodes.values() if n.get("investigation_id")}
        all_paths: List[Dict[str, Any]] = []
        for inv_id in sorted(list(investigation_ids)):
            all_paths.extend(self.find_threat_paths(inv_id, max_paths=max_paths))
        return all_paths[:max_paths]

    def clear(self) -> None:
        """
        Wipe all nodes, edges, and adjacency indices from the in-memory graph.
        """
        self._nodes.clear()
        self._edges.clear()
        self._adjacency.clear()

    def create_or_merge_nodes(self, nodes: List[Dict[str, Any]]) -> None:
        for n in nodes:
            node_id = n["id"]
            if node_id in self._nodes:
                existing = self._nodes[node_id]
                existing.update(n)
                if "properties" in n and isinstance(n["properties"], dict):
                    existing.setdefault("properties", {}).update(n["properties"])
            else:
                self._nodes[node_id] = dict(n)
                self._adjacency.setdefault(node_id, set())

    def create_or_merge_relationships(self, relationships: List[Dict[str, Any]]) -> None:
        for r in relationships:
            rel_id = r["id"]
            source_id = r["source_id"]
            target_id = r["target_id"]

            self._adjacency.setdefault(source_id, set()).add(rel_id)
            self._adjacency.setdefault(target_id, set()).add(rel_id)

            if rel_id in self._edges:
                self._edges[rel_id].update(r)
            else:
                self._edges[rel_id] = dict(r)

    def get_investigation_graph(
        self, investigation_id: str, max_nodes: int = 250, max_edges: int = 500
    ) -> Dict[str, Any]:
        scoped_nodes = [
            n for n in self._nodes.values()
            if n.get("investigation_id") == investigation_id
        ][:max_nodes]

        scoped_node_ids = {n["id"] for n in scoped_nodes}

        scoped_edges = [
            e for e in self._edges.values()
            if e.get("investigation_id") == investigation_id
            and e["source_id"] in scoped_node_ids
            and e["target_id"] in scoped_node_ids
        ][:max_edges]

        nodes_out = []
        for n in scoped_nodes:
            props = n.get("properties", {})
            if isinstance(props, str):
                try:
                    props = json.loads(props)
                except Exception:
                    props = {}
            nodes_out.append({
                "id": n["id"],
                "label": n.get("display_label", n.get("label", n["id"])),
                "name": n.get("name", n.get("display_label", n.get("label", n["id"]))),
                "type": n.get("type", "Entity"),
                "severity": n.get("severity"),
                "risk_score": n.get("risk_score"),
                "is_origin": n.get("is_origin", False),
                "is_suspicious": n.get("is_suspicious", False),
                "evidence_reference": n.get("evidence_reference"),
                "properties": props,
            })

        edges_out = []
        for e in scoped_edges:
            props = e.get("properties", {})
            if isinstance(props, str):
                try:
                    props = json.loads(props)
                except Exception:
                    props = {}
            edges_out.append({
                "id": e["id"],
                "source": e.get("source_id") or e.get("source"),
                "target": e.get("target_id") or e.get("target"),
                "label": e.get("type") or e.get("label", "RELATION"),
                "provenance": e.get("provenance"),
                "source_reference": e.get("source_reference"),
                "confidence": float(e.get("confidence", 1.0)),
                "properties": props,
            })

        return {
            "investigation_id": investigation_id,
            "node_count": len(nodes_out),
            "edge_count": len(edges_out),
            "nodes": nodes_out,
            "edges": edges_out,
        }

    def get_entity(self, entity_id: str, investigation_id: str) -> Optional[Dict[str, Any]]:
        node = self._nodes.get(entity_id)
        if not node or node.get("investigation_id") != investigation_id:
            return None
        return dict(node)

    def get_neighbors(
        self, entity_id: str, investigation_id: str, max_depth: int = 1
    ) -> Dict[str, List[Dict[str, Any]]]:
        if entity_id not in self._nodes:
            return {"nodes": [], "edges": []}

        visited_nodes: Set[str] = {entity_id}
        visited_edges: Set[str] = set()

        queue = deque([(entity_id, 0)])

        while queue:
            curr_node, depth = queue.popleft()
            if depth >= max_depth:
                continue

            for edge_id in self._adjacency.get(curr_node, set()):
                edge = self._edges.get(edge_id)
                if not edge or edge.get("investigation_id") != investigation_id:
                    continue

                visited_edges.add(edge_id)
                neighbor_id = edge["target_id"] if edge["source_id"] == curr_node else edge["source_id"]
                if neighbor_id not in visited_nodes:
                    visited_nodes.add(neighbor_id)
                    queue.append((neighbor_id, depth + 1))

        nodes_out = [
            self._nodes[nid] for nid in visited_nodes
            if nid in self._nodes and self._nodes[nid].get("investigation_id") == investigation_id
        ]
        edges_out = [
            self._edges[eid] for eid in visited_edges
            if eid in self._edges and self._edges[eid].get("investigation_id") == investigation_id
        ]

        return {"nodes": nodes_out, "edges": edges_out}

    def get_paths(
        self, investigation_id: str, start_entity_id: str, end_entity_id: str, max_depth: int = 5
    ) -> List[List[Dict[str, Any]]]:
        if start_entity_id not in self._nodes or end_entity_id not in self._nodes:
            return []

        queue = deque([[ (start_entity_id, None) ]])
        visited: Set[str] = {start_entity_id}
        found_paths = []

        while queue:
            path = queue.popleft()
            curr_node, _ = path[-1]

            if curr_node == end_entity_id:
                path_steps = []
                for nid, eid in path:
                    node_obj = dict(self._nodes.get(nid, {"id": nid}))
                    edge_obj = dict(self._edges.get(eid, {})) if eid else None
                    path_steps.append({"node": node_obj, "edge": edge_obj})
                found_paths.append(path_steps)
                break

            if len(path) > max_depth:
                continue

            for edge_id in self._adjacency.get(curr_node, set()):
                edge = self._edges.get(edge_id)
                if not edge or edge.get("investigation_id") != investigation_id:
                    continue

                next_node = edge["target_id"] if edge["source_id"] == curr_node else edge["source_id"]
                if next_node not in visited:
                    visited.add(next_node)
                    new_path = list(path)
                    new_path.append((next_node, edge_id))
                    queue.append(new_path)

        return found_paths

    def find_threat_paths(
        self, investigation_id: str, max_depth: int = 5, max_paths: int = 10
    ) -> List[Dict[str, Any]]:
        paths = []
        email_nodes = [
            n for n in self._nodes.values()
            if n.get("investigation_id") == investigation_id and n.get("type") == "Email"
        ]
        if not email_nodes:
            return []

        email_id = email_nodes[0]["id"]

        for edge_id in self._adjacency.get(email_id, set()):
            edge = self._edges.get(edge_id)
            if not edge or edge.get("investigation_id") != investigation_id:
                continue

            target_node = self._nodes.get(edge.get("target_id") or edge.get("target"))
            if target_node and target_node.get("type") == "URL":
                url_id = target_node["id"]
                for u_edge_id in self._adjacency.get(url_id, set()):
                    u_edge = self._edges.get(u_edge_id)
                    if not u_edge or u_edge.get("investigation_id") != investigation_id:
                        continue
                    dom_node = self._nodes.get(u_edge.get("target_id") or u_edge.get("target"))
                    if dom_node and dom_node.get("type") == "Domain":
                        dom_id = dom_node["id"]
                        ip_nodes = []
                        for d_edge_id in self._adjacency.get(dom_id, set()):
                            d_edge = self._edges.get(d_edge_id)
                            if not d_edge or d_edge.get("investigation_id") != investigation_id:
                                continue
                            ip_node = self._nodes.get(d_edge.get("target_id") or d_edge.get("target"))
                            if ip_node and ip_node.get("type") == "IP":
                                ip_nodes.append(ip_node)

                        path_steps = [
                            f"Email: {email_nodes[0].get('display_label', 'Email')}",
                            f"Extracted URL: {target_node.get('display_label', target_node['id'])}",
                            f"Host Domain: {dom_node.get('display_label', dom_node['id'])}",
                        ]
                        node_ids = [email_id, url_id, dom_id]
                        edge_ids = [edge_id, u_edge_id]

                        if ip_nodes:
                            path_steps.append(f"Hosted IP: {ip_nodes[0].get('display_label', ip_nodes[0]['id'])}")
                            node_ids.append(ip_nodes[0]["id"])
                            for d_edge_id in self._adjacency.get(dom_id, set()):
                                if (self._edges[d_edge_id].get("target_id") or self._edges[d_edge_id].get("target")) == ip_nodes[0]["id"]:
                                    edge_ids.append(d_edge_id)
                                    break

                        paths.append({
                            "path_id": f"path-url-{len(paths) + 1}",
                            "path_type": "phishing_infrastructure_path",
                            "title": "Phishing URL & Domain Infrastructure Path",
                            "description": f"Email links to URL '{target_node.get('display_label')}' hosted under domain '{dom_node.get('display_label')}'.",
                            "severity": target_node.get("severity", "high"),
                            "confidence": 0.95,
                            "steps": path_steps,
                            "node_ids": node_ids,
                            "edge_ids": edge_ids,
                        })

            elif target_node and target_node.get("type") == "Attachment":
                att_id = target_node["id"]
                hash_nodes = []
                hash_edge_id = None
                for a_edge_id in self._adjacency.get(att_id, set()):
                    a_edge = self._edges.get(a_edge_id)
                    if not a_edge or a_edge.get("investigation_id") != investigation_id:
                        continue
                    h_node = self._nodes.get(a_edge.get("target_id") or a_edge.get("target"))
                    if h_node and h_node.get("type") == "FileHash":
                        hash_nodes.append(h_node)
                        hash_edge_id = a_edge_id
                        break

                path_steps = [
                    f"Email: {email_nodes[0].get('display_label', 'Email')}",
                    f"Attachment: {target_node.get('display_label', target_node['id'])}",
                ]
                node_ids = [email_id, att_id]
                edge_ids = [edge_id]

                if hash_nodes:
                    path_steps.append(f"SHA-256 Hash: {hash_nodes[0].get('display_label', hash_nodes[0]['id'])[:16]}...")
                    node_ids.append(hash_nodes[0]["id"])
                    if hash_edge_id:
                        edge_ids.append(hash_edge_id)

                paths.append({
                    "path_id": f"path-att-{len(paths) + 1}",
                    "path_type": "malware_delivery_path",
                    "title": "Malicious Attachment Delivery Path",
                    "description": f"Email delivered attachment '{target_node.get('display_label')}' with SHA-256 hash.",
                    "severity": target_node.get("severity", "high"),
                    "confidence": 0.92,
                    "steps": path_steps,
                    "node_ids": node_ids,
                    "edge_ids": edge_ids,
                })

        return paths[:max_paths]

    def find_cross_investigation_matches(
        self, entity_ids: List[str], current_investigation_id: str
    ) -> List[Dict[str, Any]]:
        matches = []
        target_ids = set(entity_ids)
        for node in self._nodes.values():
            if node["id"] in target_ids and node.get("investigation_id") != current_investigation_id:
                matches.append({
                    "entity_id": node["id"],
                    "other_investigation_id": node.get("investigation_id"),
                    "entity_type": node.get("type"),
                })
        return matches

    def delete_investigation_graph(self, investigation_id: str) -> None:
        nodes_to_del = [
            nid for nid, n in self._nodes.items()
            if n.get("investigation_id") == investigation_id
        ]
        for nid in nodes_to_del:
            self._nodes.pop(nid, None)
            self._adjacency.pop(nid, None)

        edges_to_del = [
            eid for eid, e in self._edges.items()
            if e.get("investigation_id") == investigation_id
        ]
        for eid in edges_to_del:
            self._edges.pop(eid, None)

    def close(self) -> None:
        self.clear()
