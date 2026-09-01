import urllib.request
import json

raw_eml = """From: "Microsoft Security Team" <alert-service@micr0soft-cloud-verify.com>
To: target@victim.org
Subject: Urgent Security Action Required: Your Office365 Account is Compromised
Reply-To: security-ops@micr0soft-cloud-verify.com
Date: Tue, 01 Sep 2026 12:00:00 +0000
Received: from mail.micr0soft-cloud-verify.com (185.220.101.99) by mx.victim.org with ESMTP; Tue, 01 Sep 2026 12:00:00 +0000

Dear User,
Please verify your Microsoft Account immediately at http://micr0soft-cloud-verify.com/login to prevent suspension.
"""

def test_live_investigation():
    # 1. Analyze raw email
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/email-analysis/analyze-raw",
        data=json.dumps({"raw_content": raw_eml, "filename": "microsoft_phish.eml", "force_reanalysis": True}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res = urllib.request.urlopen(req)
    analysis_data = json.loads(res.read().decode("utf-8"))
    analysis_id = analysis_data["analysis_id"]
    print("ANALYSIS ID:", analysis_id)

    # 2. Trigger Investigation
    req_inv = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/investigations",
        data=json.dumps({"analysis_id": analysis_id, "mode": "direct"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res_inv = urllib.request.urlopen(req_inv)
        inv_data = json.loads(res_inv.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        print("INVESTIGATION TRIGGER FAILED:", e.code)
        print("ERROR BODY:\n", body)
        return
    inv_id = inv_data["investigation_id"]
    print("INVESTIGATION ID:", inv_id)
    print("INVESTIGATION ENTITIES COUNT:", inv_data.get("entity_count"))
    print("INVESTIGATION FINDINGS COUNT:", inv_data.get("finding_count"))

    # 3. Get Graph
    req_graph = urllib.request.Request(f"http://127.0.0.1:8000/api/v1/investigations/{inv_id}/graph")
    res_graph = urllib.request.urlopen(req_graph)
    graph_data = json.loads(res_graph.read().decode("utf-8"))
    print("GRAPH NODE COUNT:", graph_data.get("node_count"))
    print("GRAPH EDGE COUNT:", graph_data.get("edge_count"))
    labels = [n["data"]["label"] for n in graph_data.get("nodes", [])]
    print("NODE LABELS:", labels)

    # 4. Check for any trace of bankofamerica
    has_boa = any("bankofamerica" in l.lower() for l in labels)
    print("CONTAINS BANK OF AMERICA?:", has_boa)
    assert not has_boa, "Found bankofamerica in graph nodes!"

    # 5. Check for genuine microsoft indicators
    has_ms = any("micr0soft" in l.lower() for l in labels)
    print("CONTAINS MICR0SOFT INDICATORS?:", has_ms)
    assert has_ms, "Did not find micr0soft in graph nodes!"

    # 6. Check Threat Paths
    req_paths = urllib.request.Request(f"http://127.0.0.1:8000/api/v1/investigations/{inv_id}/paths")
    res_paths = urllib.request.urlopen(req_paths)
    paths_data = json.loads(res_paths.read().decode("utf-8"))
    print("PATHS COUNT:", paths_data.get("total_paths"))
    for p in paths_data.get("paths", []):
        print(" - PATH:", p.get("title"), "| Steps:", p.get("steps"))

    print("\nSUCCESS: All live investigation endpoints verified with genuine dynamic data!")

if __name__ == "__main__":
    test_live_investigation()
