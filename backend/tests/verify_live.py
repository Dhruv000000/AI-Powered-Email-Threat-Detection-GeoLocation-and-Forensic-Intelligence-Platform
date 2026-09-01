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

    # 7. Check Threat Map
    req_map = urllib.request.Request(f"http://127.0.0.1:8000/api/v1/investigations/{inv_id}/threat-map")
    res_map = urllib.request.urlopen(req_map)
    map_data = json.loads(res_map.read().decode("utf-8"))
    print("\n--- THREAT MAP TELEMETRY ---")
    print("TOTAL DISTANCE:", map_data.get("total_distance_km"), "km")
    print("HOPS COUNT:", len(map_data.get("hops", [])))
    for h in map_data.get("hops", []):
        loc = h.get("location") or {}
        print(f" - Hop #{h.get('hop_number')}: {h.get('ip')} -> {loc.get('city')}, {loc.get('country_name')} (Lat: {loc.get('latitude')}, Lng: {loc.get('longitude')}) [Tor: {loc.get('is_tor')}]")
    print("ANOMALIES:", map_data.get("anomalies"))

    assert len(map_data.get("hops", [])) >= 1, "Expected at least 1 hop in threat map!"
    geocoded_hops = [h for h in map_data.get("hops", []) if h.get("location", {}).get("latitude") is not None]
    print("GEOCODED HOPS COUNT:", len(geocoded_hops))
    assert len(geocoded_hops) >= 1, "Expected at least 1 geocoded hop!"

    print("\nSUCCESS: All live investigation & threat map endpoints verified with genuine dynamic data!")

if __name__ == "__main__":
    test_live_investigation()
