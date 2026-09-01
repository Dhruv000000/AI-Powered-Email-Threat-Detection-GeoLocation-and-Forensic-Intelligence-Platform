from typing import Dict, Any, List, Optional, Union
from app.db.models.email_analysis import EmailAnalysisModel
from app.schemas.email_analysis import EmailAnalysisResponse
from app.schemas.investigation import ThreatPath


class ThreatPathEngine:
    """
    Threat Path Engine.
    Computes bounded, security-relevant forensic threat paths connecting threat actors,
    email messages, external infrastructure, URLs, and malicious payloads.
    Discovers:
    1. Credential Phishing Path
    2. Infrastructure Relay Path
    3. Sender Deception Path
    4. Malicious Attachment Delivery Path
    """

    def __init__(
        self,
        analysis: Union[EmailAnalysisModel, EmailAnalysisResponse, Dict[str, Any]],
        investigation_id: str,
        entities: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
    ):
        self.analysis = analysis
        if isinstance(analysis, dict):
            self.analysis_id = analysis.get("analysis_id", "ANL-UNKNOWN")
        else:
            self.analysis_id = getattr(analysis, "analysis_id", "ANL-UNKNOWN")

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

        # Find sender node and edge
        sender_node = None
        sender_edge = None
        for r in self.relationships:
            if r.get("target_id") == email_id and r.get("type") == "SENT":
                sender_node = self.entities_by_id.get(r["source_id"])
                sender_edge = r
                break

        # 1. Credential Phishing Path: EmailAddress -> Email -> URL -> Domain (is_lookalike=True or suspicious)
        url_edges = [
            r for r in self.relationships
            if r.get("source_id") == email_id and r.get("type") in ("CONTAINS_URL", "LINKS_TO")
        ]
        # Deduplicate url edges by target_id
        seen_targets = set()
        unique_url_edges = []
        for ue in url_edges:
            if ue["target_id"] not in seen_targets:
                seen_targets.add(ue["target_id"])
                unique_url_edges.append(ue)

        for u_edge in unique_url_edges:
            url_node = self.entities_by_id.get(u_edge["target_id"])
            if not url_node:
                continue

            dom_node = None
            dom_edge = None
            for d_edge in self.relationships:
                if d_edge.get("source_id") == url_node["id"] and d_edge.get("type") in ("HOSTED_ON_DOMAIN", "USES_DOMAIN"):
                    dom_node = self.entities_by_id.get(d_edge["target_id"])
                    dom_edge = d_edge
                    break

            ip_node = None
            ip_edge = None
            if dom_node:
                for i_edge in self.relationships:
                    if i_edge.get("source_id") in (dom_node["id"], url_node["id"]) and i_edge.get("type") in ("POINTS_TO_IP", "HOSTED_ON"):
                        ip_node = self.entities_by_id.get(i_edge["target_id"])
                        ip_edge = i_edge
                        break
            else:
                for i_edge in self.relationships:
                    if i_edge.get("source_id") == url_node["id"] and i_edge.get("type") in ("POINTS_TO_IP", "HOSTED_ON"):
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

            is_lookalike = dom_node.get("properties", {}).get("is_lookalike", False) if dom_node else False
            is_susp = url_node.get("is_suspicious", False) or is_lookalike
            sev = "critical" if is_lookalike else ("high" if is_susp else "medium")

            self._paths.append({
                "path_id": f"path-phishing-{len(self._paths) + 1}",
                "path_type": "phishing_infrastructure_path",
                "title": f"Credential Phishing Infrastructure Path ({url_node.get('display_label')[:30]}...)",
                "description": (
                    f"Message links to external URL '{url_node.get('display_label')}' hosted under "
                    f"domain '{dom_node.get('display_label') if dom_node else 'unknown'}'."
                ),
                "severity": sev,
                "confidence": 0.95,
                "steps": steps,
                "node_ids": node_ids,
                "edge_ids": edge_ids,
            })

        # 2. Sender Deception Path: EmailAddress (From) -> Email <- EmailAddress (Reply-To Mismatch)
        reply_to_edges = [
            r for r in self.relationships
            if (r.get("target_id") == email_id and r.get("type") == "SPECIFIED_AS_REPLY_TO")
            or (r.get("source_id") == email_id and r.get("type") == "REPLIED_TO")
        ]
        if sender_node and reply_to_edges:
            r_edge = reply_to_edges[0]
            reply_to_id = r_edge["source_id"] if r_edge["target_id"] == email_id else r_edge["target_id"]
            reply_to_node = self.entities_by_id.get(reply_to_id)
            if reply_to_node and reply_to_node["id"] != sender_node["id"]:
                from_addr = sender_node.get("display_label", "")
                rt_addr = reply_to_node.get("display_label", "")
                from_dom = sender_node.get("properties", {}).get("domain", "")
                rt_dom = reply_to_node.get("properties", {}).get("domain", "")

                if from_dom != rt_dom or from_addr != rt_addr:
                    self._paths.append({
                        "path_id": f"path-deception-{len(self._paths) + 1}",
                        "path_type": "sender_deception_path",
                        "title": f"Sender Deception & Reply-To Hijack Path ({from_addr} -> {rt_addr})",
                        "description": (
                            f"Email specifies sender '{from_addr}' but redirects reply traffic to distinct "
                            f"address '{rt_addr}' under domain '{rt_dom}', indicating potential impersonation or BEC."
                        ),
                        "severity": "high",
                        "confidence": 0.92,
                        "steps": [
                            f"Sender (From): {from_addr}",
                            f"Email: {email_node.get('display_label')}",
                            f"Reply-To Target: {rt_addr}",
                        ],
                        "node_ids": [sender_node["id"], email_id, reply_to_node["id"]],
                        "edge_ids": [sender_edge["id"] if sender_edge else "rel:from", r_edge["id"]],
                    })

        # 3. Infrastructure Relay Path: Email -> IPAddress <- URL (or Relay MTA IP matching a hosted URL IP or origin trace)
        relay_ips = [
            e for e in self.entities_by_id.values()
            if e.get("type") in ("IP", "IPAddress") and (e.get("is_origin") or e.get("properties", {}).get("source") == "received_header")
        ]
        url_ips = [
            e for e in self.entities_by_id.values()
            if e.get("type") in ("IP", "IPAddress") and e.get("properties", {}).get("source") == "url_host"
        ]

        shared_ips = [ip for ip in relay_ips if any(u_ip["id"] == ip["id"] for u_ip in url_ips)]
        if shared_ips:
            for s_ip in shared_ips:
                rel_edge = next((r for r in self.relationships if r.get("target_id") == s_ip["id"] and r.get("source_id") == email_id), None)
                url_ip_edge = next((r for r in self.relationships if r.get("target_id") == s_ip["id"] and r.get("source_id").startswith("url:")), None)
                
                self._paths.append({
                    "path_id": f"path-shared-relay-{len(self._paths) + 1}",
                    "path_type": "infrastructure_relay_path",
                    "title": f"Infrastructure Relay & URL Shared IP Path ({s_ip.get('display_label')})",
                    "description": f"Relayed email MTA IP '{s_ip.get('display_label')}' directly matches the hosting IP address of extracted payload URLs.",
                    "severity": "critical",
                    "confidence": 0.96,
                    "steps": [
                        f"Email: {email_node.get('display_label')}",
                        f"Relay IP: {s_ip.get('display_label')}",
                        f"Hosted URL IP Match: {s_ip.get('display_label')}",
                    ],
                    "node_ids": [email_id, s_ip["id"]],
                    "edge_ids": [e["id"] for e in [rel_edge, url_ip_edge] if e],
                })
        elif relay_ips:
            orig_ip_node = relay_ips[0]
            steps = [f"Email: {email_node.get('display_label')}"]
            node_ids = [email_id]
            edge_ids = []

            hop_servers = [
                e for e in self.entities_by_id.values()
                if e.get("type") == "MailServer" and e.get("is_origin")
            ]
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
                direct_edge = next(
                    (r for r in self.relationships if r.get("source_id") == email_id and r.get("target_id") == orig_ip_node["id"]),
                    None
                )
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

        # 4. Malicious Attachment Delivery Path: EmailAddress -> Email -> Attachment (is_suspicious=True) -> FileHash
        att_edges = [
            r for r in self.relationships
            if r.get("source_id") == email_id and r.get("type") in ("ATTACHED", "HAS_ATTACHMENT")
        ]
        seen_att_targets = set()
        unique_att_edges = []
        for ae in att_edges:
            if ae["target_id"] not in seen_att_targets:
                seen_att_targets.add(ae["target_id"])
                unique_att_edges.append(ae)

        for a_edge in unique_att_edges:
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

            is_susp = att_node.get("is_suspicious", False) or att_node.get("properties", {}).get("is_executable", False)
            sev = "critical" if is_susp else "medium"

            self._paths.append({
                "path_id": f"path-malware-{len(self._paths) + 1}",
                "path_type": "malware_delivery_path",
                "title": f"Malicious Attachment Delivery Path ({att_node.get('display_label')})",
                "description": f"Email delivered attachment '{att_node.get('display_label')}' with cryptographic SHA-256 seal.",
                "severity": sev,
                "confidence": 0.95,
                "steps": steps,
                "node_ids": node_ids,
                "edge_ids": edge_ids,
            })

        return self._paths[:max_paths]
