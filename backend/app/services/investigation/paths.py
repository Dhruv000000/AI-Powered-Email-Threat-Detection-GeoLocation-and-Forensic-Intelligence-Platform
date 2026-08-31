from typing import Dict, Any, List, Optional
from app.db.models.email_analysis import EmailAnalysisModel


class ThreatPathEngine:
    """
    Threat Path Engine.
    Computes bounded, security-relevant forensic threat paths connecting threat actors,
    email messages, external infrastructure, URLs, and malicious payloads.
    """

    def __init__(
        self,
        analysis: EmailAnalysisModel,
        investigation_id: str,
        entities: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
    ):
        self.analysis = analysis
        self.analysis_id = analysis.analysis_id
        self.investigation_id = investigation_id
        self.entities_by_id = {e["id"]: e for e in entities}
        self.relationships = relationships
        self._paths: List[Dict[str, Any]] = []

    def compute_threat_paths(self, max_paths: int = 10) -> List[Dict[str, Any]]:
        self._paths.clear()
        email_id = f"email:{self.analysis_id}"
        email_node = self.entities_by_id.get(email_id)
        if not email_node:
            return []

        # Find sender node
        sender_node = None
        sender_edge = None
        for r in self.relationships:
            if r.get("target_id") == email_id and r.get("type") == "SENT":
                sender_node = self.entities_by_id.get(r["source_id"])
                sender_edge = r
                break

        # 1. Phishing URL & Domain Infrastructure Paths
        url_edges = [r for r in self.relationships if r.get("source_id") == email_id and r.get("type") == "LINKS_TO"]
        for u_edge in url_edges:
            url_node = self.entities_by_id.get(u_edge["target_id"])
            if not url_node:
                continue

            dom_node = None
            dom_edge = None
            for d_edge in self.relationships:
                if d_edge.get("source_id") == url_node["id"] and d_edge.get("type") == "USES_DOMAIN":
                    dom_node = self.entities_by_id.get(d_edge["target_id"])
                    dom_edge = d_edge
                    break

            ip_node = None
            ip_edge = None
            if dom_node:
                for i_edge in self.relationships:
                    if i_edge.get("source_id") in (dom_node["id"], url_node["id"]) and i_edge.get("type") == "HOSTED_ON":
                        ip_node = self.entities_by_id.get(i_edge["target_id"])
                        ip_edge = i_edge
                        break

            steps = []
            node_ids = []
            edge_ids = []

            if sender_node and sender_edge:
                steps.append(f"Sender: {sender_node.get('display_label')}")
                node_ids.append(sender_node["id"])
                edge_ids.append(sender_edge["id"])

            steps.append(f"Email: {email_node.get('display_label')}")
            node_ids.append(email_id)

            steps.append(f"Extracted URL: {url_node.get('display_label')}")
            node_ids.append(url_node["id"])
            edge_ids.append(u_edge["id"])

            if dom_node and dom_edge:
                steps.append(f"Host Domain: {dom_node.get('display_label')}")
                node_ids.append(dom_node["id"])
                edge_ids.append(dom_edge["id"])

            if ip_node and ip_edge:
                steps.append(f"Hosted IP: {ip_node.get('display_label')}")
                node_ids.append(ip_node["id"])
                edge_ids.append(ip_edge["id"])

            self._paths.append({
                "path_id": f"path-phishing-{len(self._paths) + 1}",
                "path_type": "phishing_infrastructure_path",
                "title": f"Phishing Infrastructure Path ({url_node.get('display_label')[:30]}...)",
                "description": (
                    f"Message links to external URL '{url_node.get('display_label')}' hosted under "
                    f"domain '{dom_node.get('display_label') if dom_node else 'unknown'}'."
                ),
                "severity": url_node.get("severity", "high"),
                "confidence": 0.94,
                "steps": steps,
                "node_ids": node_ids,
                "edge_ids": edge_ids,
            })

        # 2. Malicious Attachment Delivery Paths
        att_edges = [r for r in self.relationships if r.get("source_id") == email_id and r.get("type") == "HAS_ATTACHMENT"]
        for a_edge in att_edges:
            att_node = self.entities_by_id.get(a_edge["target_id"])
            if not att_node:
                continue

            hash_node = None
            hash_edge = None
            for h_edge in self.relationships:
                if h_edge.get("source_id") == att_node["id"] and h_edge.get("type") == "HAS_HASH":
                    hash_node = self.entities_by_id.get(h_edge["target_id"])
                    hash_edge = h_edge
                    break

            steps = []
            node_ids = []
            edge_ids = []

            if sender_node and sender_edge:
                steps.append(f"Sender: {sender_node.get('display_label')}")
                node_ids.append(sender_node["id"])
                edge_ids.append(sender_edge["id"])

            steps.append(f"Email: {email_node.get('display_label')}")
            node_ids.append(email_id)

            steps.append(f"Delivered Attachment: {att_node.get('display_label')}")
            node_ids.append(att_node["id"])
            edge_ids.append(a_edge["id"])

            if hash_node and hash_edge:
                steps.append(f"SHA-256 Hash: {hash_node.get('display_label')}")
                node_ids.append(hash_node["id"])
                edge_ids.append(hash_edge["id"])

            self._paths.append({
                "path_id": f"path-malware-{len(self._paths) + 1}",
                "path_type": "malware_delivery_path",
                "title": f"Malware Delivery Path ({att_node.get('display_label')})",
                "description": f"Email delivered attachment '{att_node.get('display_label')}' with cryptographic SHA-256 seal.",
                "severity": att_node.get("severity", "critical"),
                "confidence": 0.95,
                "steps": steps,
                "node_ids": node_ids,
                "edge_ids": edge_ids,
            })

        # 3. Origin Relay Trace Path (if relay hops exist)
        origin_ips = [e for e in self.entities_by_id.values() if e.get("type") == "IP" and e.get("is_origin")]
        if origin_ips:
            orig_ip_node = origin_ips[0]
            steps = [f"Email: {email_node.get('display_label')}"]
            node_ids = [email_id]
            edge_ids = []

            # Check if there is an intermediate mail server
            hop_servers = [e for e in self.entities_by_id.values() if e.get("type") == "MailServer" and e.get("is_origin")]
            if hop_servers:
                server_node = hop_servers[0]
                obs_edge = next((r for r in self.relationships if r.get("source_id") == email_id and r.get("target_id") == server_node["id"]), None)
                if obs_edge:
                    steps.append(f"Origin Mail Server: {server_node.get('display_label')}")
                    node_ids.append(server_node["id"])
                    edge_ids.append(obs_edge["id"])

                has_ip_edge = next((r for r in self.relationships if r.get("source_id") == server_node["id"] and r.get("target_id") == orig_ip_node["id"]), None)
                if has_ip_edge:
                    steps.append(f"Probable Origin IP: {orig_ip_node.get('display_label')}")
                    node_ids.append(orig_ip_node["id"])
                    edge_ids.append(has_ip_edge["id"])
            else:
                direct_edge = next((r for r in self.relationships if r.get("source_id") == email_id and r.get("target_id") == orig_ip_node["id"]), None)
                steps.append(f"Probable Origin IP: {orig_ip_node.get('display_label')}")
                node_ids.append(orig_ip_node["id"])
                if direct_edge:
                    edge_ids.append(direct_edge["id"])

            self._paths.append({
                "path_id": f"path-relay-{len(self._paths) + 1}",
                "path_type": "origin_relay_path",
                "title": f"SMTP Relay Origin Trace ({orig_ip_node.get('display_label')})",
                "description": f"Hop-by-hop SMTP reconstruction traced probable email origin to IP '{orig_ip_node.get('display_label')}'.",
                "severity": "medium",
                "confidence": 0.88,
                "steps": steps,
                "node_ids": node_ids,
                "edge_ids": edge_ids,
            })

        return self._paths[:max_paths]
