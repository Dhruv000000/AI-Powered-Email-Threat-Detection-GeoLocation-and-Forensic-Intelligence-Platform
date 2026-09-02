import pytest
from app.services.geo.geo_resolver import GeoResolver, geo_resolver
from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailRelayHopModel,
)


def test_geo_resolver_private_and_bogon_ips():
    bogon_ips = ["127.0.0.1", "10.0.0.5", "192.168.1.100", "172.16.5.4", "::1", "169.254.1.1"]
    for ip in bogon_ips:
        res = geo_resolver.resolve_ip(ip)
        assert res.is_bogon is True
        assert res.is_private is True
        assert res.latitude is None
        assert res.longitude is None
        assert res.country_code == "LOCAL"


def test_geo_resolver_public_catalog_and_fallback():
    # 1. Known Tor Exit Node in Catalog (Amsterdam)
    res_tor = geo_resolver.resolve_ip("185.220.101.99")
    assert res_tor.is_bogon is False
    assert res_tor.is_private is False
    assert res_tor.country_code == "NL"
    assert res_tor.country_name == "Netherlands"
    assert res_tor.city == "Amsterdam"
    assert res_tor.region == "North Holland"
    assert "Amsterdam" in res_tor.formatted_address
    assert "Netherlands" in res_tor.formatted_address
    assert res_tor.is_tor is True
    assert res_tor.asn == 60729
    assert res_tor.latitude == 52.3676

    # 2. Known Google DNS in Catalog (Mountain View, CA)
    res_google = geo_resolver.resolve_ip("8.8.8.8")
    assert res_google.country_code == "US"
    assert res_google.city == "Mountain View"
    assert res_google.region == "California"
    assert "Mountain View" in res_google.formatted_address
    assert res_google.is_tor is False
    assert res_google.asn == 15169

    # 5. Known Fin-Proxy / Frankfurt in Catalog (Frankfurt, Hesse)
    res_frankfurt = geo_resolver.resolve_ip("185.220.101.5")
    assert res_frankfurt.city == "Frankfurt"
    assert res_frankfurt.country_code == "DE"
    assert res_frankfurt.region == "Hesse"
    assert res_frankfurt.latitude == 50.1109
    assert res_frankfurt.longitude == 8.6821

    # 6. Known Sydney Gateway in Catalog (Sydney, NSW)
    res_syd_gw = geo_resolver.resolve_ip("198.51.100.10")
    assert res_syd_gw.city == "Sydney"
    assert res_syd_gw.country_code == "AU"
    assert res_syd_gw.latitude == -33.8688

    # 7. Unlisted Public IP (Fallback with formatted address)
    res_unlisted = geo_resolver.resolve_ip("45.33.32.156")
    assert res_unlisted.is_bogon is False
    assert res_unlisted.latitude is not None
    assert res_unlisted.longitude is not None
    assert res_unlisted.country_name is not None
    assert res_unlisted.formatted_address is not None
    assert len(res_unlisted.formatted_address) > 0
    assert -90.0 <= res_unlisted.latitude <= 90.0
    assert -180.0 <= res_unlisted.longitude <= 180.0


def test_haversine_distance_calculation():
    # Amsterdam (52.3702, 4.8952) to London (51.5074, -0.1278) ~357 km
    dist = GeoResolver.calculate_haversine_distance(52.3702, 4.8952, 51.5074, -0.1278)
    assert 340.0 < dist < 380.0

    # Same location -> 0.0
    dist_zero = GeoResolver.calculate_haversine_distance(52.3702, 4.8952, 52.3702, 4.8952)
    assert dist_zero == 0.0

    # None coordinates -> 0.0
    dist_none = GeoResolver.calculate_haversine_distance(None, None, 51.5074, -0.1278)
    assert dist_none == 0.0


def test_get_investigation_threat_map_endpoint(client, db_session):
    analysis_id = "ANL-GEO-MAP-001"
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="geo_sample.eml",
        sha256="geo1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        status="completed",
        threat_type="phishing",
        risk_score=90,
        severity="critical",
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="alert@tor-phish.nl",
        reply_to="attacker@darkhost.xyz",
        subject="Urgent Security Action",
    )
    # Hop 1: Tor Node in Amsterdam -> Hop 2: Cloudflare in Ashburn, US (Hop delay: 1.5s -> impossible speed)
    analysis.relay_hops = [
        EmailRelayHopModel(
            analysis_id=analysis_id,
            hop_number=1,
            from_server="tor-node-01.nl",
            by_server="mail.tor-phish.nl",
            ip="185.220.101.99",
            protocol="ESMTP",
            delay_seconds=0,
            is_origin_node=True,
            raw_header="Received: from tor-node-01.nl (185.220.101.99) by mail.tor-phish.nl",
        ),
        EmailRelayHopModel(
            analysis_id=analysis_id,
            hop_number=2,
            from_server="mail.tor-phish.nl",
            by_server="mx.victim.com",
            ip="198.51.100.25",
            protocol="ESMTP",
            delay_seconds=1,
            is_origin_node=False,
            raw_header="Received: from mail.tor-phish.nl (198.51.100.25) by mx.victim.com",
        ),
    ]
    db_session.add(analysis)
    db_session.commit()

    # Trigger investigation
    res_inv = client.post(
        "/api/v1/investigations",
        json={"analysis_id": analysis_id, "mode": "direct"},
    )
    assert res_inv.status_code == 200
    inv_id = res_inv.json()["investigation_id"]

    # Call GET /api/v1/investigations/{inv_id}/threat-map
    res_map = client.get(f"/api/v1/investigations/{inv_id}/threat-map")
    assert res_map.status_code == 200
    map_data = res_map.json()

    assert map_data["investigation_id"] == inv_id
    assert map_data["analysis_id"] == analysis_id
    assert len(map_data["hops"]) == 2

    # Verify Hop 1 details
    hop1 = map_data["hops"][0]
    assert hop1["hop_number"] == 1
    assert hop1["ip"] == "185.220.101.99"
    assert hop1["is_origin"] is True
    assert hop1["location"]["city"] == "Amsterdam"
    assert hop1["location"]["is_tor"] is True

    # Verify Hop 2 details
    hop2 = map_data["hops"][1]
    assert hop2["hop_number"] == 2
    assert hop2["ip"] == "198.51.100.25"
    assert hop2["is_destination"] is True
    assert hop2["location"]["city"] == "Ashburn"

    # Verify distance and anomalies
    assert map_data["total_distance_km"] > 5000.0
    assert len(map_data["anomalies"]) >= 1
    assert any("Tor Exit Node" in a for a in map_data["anomalies"])


def test_geo_lookup_batch_endpoint(client):
    payload = {"ips": ["8.8.8.8", "127.0.0.1", "185.220.101.99"]}
    res = client.post("/api/v1/geo/lookup", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["total_resolved"] == 3
    assert len(data["results"]) == 3

    results_by_ip = {r["ip"]: r for r in data["results"]}
    assert results_by_ip["127.0.0.1"]["is_private"] is True
    assert results_by_ip["8.8.8.8"]["country_code"] == "US"
    assert results_by_ip["185.220.101.99"]["is_tor"] is True


def test_get_threat_map_with_analysis_id_directly(client, db_session):
    analysis_id = "ANL-DIRECT-MAP-002"
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="direct_map.eml",
        sha256="direct1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        status="completed",
        probable_origin_ip="185.220.101.99",
        threat_type="phishing",
        risk_score=88,
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="alert@micr0soft-cloud-verify.com",
        subject="Action Required",
    )
    db_session.add(analysis)
    db_session.commit()

    # Query threat map directly using analysis_id (without creating investigation first)
    res = client.get(f"/api/v1/investigations/{analysis_id}/threat-map")
    assert res.status_code == 200
    data = res.json()
    assert data["analysis_id"] == analysis_id
    assert len(data["hops"]) >= 1
    assert data["hops"][0]["ip"] == "185.220.101.99"
    assert data["hops"][0]["location"]["city"] == "Amsterdam"


def test_3_hop_multi_continent_threat_map(client, db_session):
    analysis_id = "ANL-3HOP-MAP-003"
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="multi_hop.eml",
        sha256="multi1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        status="completed",
        probable_origin_ip="185.220.101.99",
        threat_type="bec",
        risk_score=94,
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="ceo@executive-update.org",
        subject="Wire Transfer",
    )
    # Hop 1: Amsterdam (Tor) -> Hop 2: Tokyo (Sakura) -> Hop 3: Frankfurt (Fin-Proxy)
    analysis.relay_hops = [
        EmailRelayHopModel(
            analysis_id=analysis_id,
            hop_number=1,
            from_server="tor-nl.exit.net",
            by_server="mail.origin.org",
            ip="185.220.101.99",
            protocol="ESMTP",
            delay_seconds=0,
            is_origin_node=True,
            raw_header="Received: from tor-nl.exit.net (185.220.101.99) by mail.origin.org",
        ),
        EmailRelayHopModel(
            analysis_id=analysis_id,
            hop_number=2,
            from_server="sakura-node.jp",
            by_server="relay.jp.net",
            ip="133.242.18.1",
            protocol="ESMTP",
            delay_seconds=2,
            is_origin_node=False,
            raw_header="Received: from sakura-node.jp (133.242.18.1) by relay.jp.net",
        ),
        EmailRelayHopModel(
            analysis_id=analysis_id,
            hop_number=3,
            from_server="relay-eu-central.fin-proxy.de",
            by_server="mx.victim.de",
            ip="185.220.101.5",
            protocol="ESMTP",
            delay_seconds=1,
            is_origin_node=False,
            raw_header="Received: from relay-eu-central.fin-proxy.de (185.220.101.5) by mx.victim.de",
        ),
    ]
    db_session.add(analysis)
    db_session.commit()

    res = client.get(f"/api/v1/investigations/{analysis_id}/threat-map")
    assert res.status_code == 200
    data = res.json()
    assert len(data["hops"]) == 3

    # Check distinct cities and countries
    cities = [h["location"]["city"] for h in data["hops"]]
    assert cities == ["Amsterdam", "Tokyo", "Frankfurt"]

    countries = [h["location"]["country_name"] for h in data["hops"]]
    assert countries == ["Netherlands", "Japan", "Germany"]

    # Verify total transit distance
    assert data["total_distance_km"] > 18000.0  # Europe to Asia to Europe > 18,000 km
    assert any("Multi-national routing" in a for a in data["anomalies"])


def test_nigeria_mtn_as29465_lookup_and_subnet():
    # Exact IP
    dto_exact = geo_resolver.resolve_ip("105.112.44.180")
    assert dto_exact.country_code == "NG"
    assert dto_exact.country_name == "Nigeria"
    assert dto_exact.city == "Lagos"
    assert dto_exact.asn == 29465
    assert "MTN NIGERIA" in (dto_exact.as_org or "")

    # Subnet IP in 105.112.0.0/16
    dto_subnet = geo_resolver.resolve_ip("105.112.99.200")
    assert dto_subnet.country_code == "NG"
    assert dto_subnet.country_name == "Nigeria"
    assert dto_subnet.asn == 29465


def test_threat_map_3hop_loop_and_severity_binding(client, db_session):
    analysis_id = "ANL-3HOP-LOOP-001"
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="bec_phish.eml",
        sha256="bec3hop1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        status="completed",
        threat_type="phishing",
        risk_score=92,
        severity="critical",
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="billing@secure-portal.com",
        subject="Action Required: Verify Account",
    )
    # Hop 1: Nigeria MTN -> Hop 2: Tor / Fin-Proxy Germany
    analysis.relay_hops = [
        EmailRelayHopModel(
            analysis_id=analysis_id,
            hop_number=1,
            from_server="mtn-lagos-node.net",
            by_server="mail.secure-portal.com",
            ip="105.112.44.180",
            protocol="ESMTP",
            delay_seconds=0,
            is_origin_node=True,
            raw_header="Received: from mtn-lagos-node.net (105.112.44.180) by mail.secure-portal.com",
        ),
        EmailRelayHopModel(
            analysis_id=analysis_id,
            hop_number=2,
            from_server="mail.secure-portal.com",
            by_server="relay-eu-central.fin-proxy.de",
            ip="185.220.101.5",
            protocol="ESMTP",
            delay_seconds=1,
            is_origin_node=False,
            raw_header="Received: from mail.secure-portal.com (185.220.101.5) by relay-eu-central.fin-proxy.de",
        ),
    ]
    # URL pointing to portal-verification-service-auth.com
    from app.db.models.email_analysis import EmailUrlModel
    analysis.urls = [
        EmailUrlModel(
            analysis_id=analysis_id,
            original_url="https://portal-verification-service-auth.com/login",
            normalized_url="https://portal-verification-service-auth.com/login",
            domain="portal-verification-service-auth.com",
            risk_score=95,
            threat_level="critical",
            is_lookalike=True,
        )
    ]
    db_session.add(analysis)
    db_session.commit()

    res = client.get(f"/api/v1/investigations/{analysis_id}/threat-map")
    assert res.status_code == 200
    data = res.json()

    # Verify 3-Hop Geospatial Loop: Origin -> Relay -> Target Host
    assert len(data["hops"]) == 3
    assert data["severity"] == "critical"
    assert data["risk_score"] == 92

    # Hop 1: Nigeria
    assert data["hops"][0]["ip"] == "105.112.44.180"
    assert data["hops"][0]["location"]["country_name"] == "Nigeria"
    assert data["hops"][0]["is_origin"] is True

    # Hop 2: Transit Relay
    assert data["hops"][1]["ip"] == "185.220.101.5"
    assert data["hops"][1]["location"]["country_name"] == "Germany"

    # Hop 3: Terminal Target Host
    assert data["hops"][2]["hostname"] == "portal-verification-service-auth.com"
    assert data["hops"][2]["is_destination"] is True
    assert data["hops"][2]["is_target"] is True

