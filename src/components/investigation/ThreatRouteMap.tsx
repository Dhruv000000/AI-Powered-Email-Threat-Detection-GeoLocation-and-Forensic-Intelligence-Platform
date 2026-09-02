import React, { useEffect, useRef, useState, useCallback } from 'react';
import L from 'leaflet';
import { ThreatMapData, ThreatMapHop } from '../../types/threatMap';
import {
  Globe,
  Navigation,
  Clock,
  AlertTriangle,
  Layers,
  Crosshair,
} from 'lucide-react';

interface ThreatRouteMapProps {
  threatMap: ThreatMapData;
  className?: string;
  onSelectHop?: (hop: ThreatMapHop | null) => void;
}

function calculateHaversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371; // Earth radius in km
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

export const ThreatRouteMap: React.FC<ThreatRouteMapProps> = ({
  threatMap,
  className = 'h-full',
  onSelectHop,
}) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const layersGroupRef = useRef<L.LayerGroup | null>(null);
  const markersRef = useRef<Record<number, L.Marker>>({});

  const [selectedHop, setSelectedHop] = useState<ThreatMapHop | null>(
    threatMap.hops[0] || null
  );

  // Filter for valid geocoded coordinates FIRST, then map the display indices
  const geocodedHops = threatMap.hops.filter(
    (h) =>
      h.location &&
      h.location.latitude != null &&
      h.location.longitude != null &&
      !(h as any).is_private &&
      !h.location.is_private
  );

  const displayHops = geocodedHops.map((hop, index) => {
    const isTarget = (hop as any).is_target || (hop as any).role === 'TARGET_HOST';
    const isOrigin = hop.is_origin || index === 0;
    const markerLabel = isOrigin
      ? `#${index + 1} Origin`
      : isTarget
      ? `#${index + 1} Target Host`
      : `#${index + 1} Relay`;
    return {
      ...hop,
      displayIndex: index + 1,
      markerLabel,
    };
  });

  // 1. Initialize Map with ResizeObserver and Invalidation Guards
  useEffect(() => {
    if (!mapContainerRef.current) return;

    if (!mapInstanceRef.current) {
      const map = L.map(mapContainerRef.current, {
        center: [30.0, 10.0],
        zoom: 2,
        minZoom: 2,
        maxZoom: 14,
        zoomControl: false,
        attributionControl: false,
        worldCopyJump: true,
        maxBoundsViscosity: 0.0,
      });

      L.control.zoom({ position: 'bottomright' }).addTo(map);

      // Base dark canvas
      L.tileLayer(
        'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
        {
          attribution: '&copy; Esri, HERE, Garmin, &copy; OpenStreetMap contributors',
          maxZoom: 16,
        }
      ).addTo(map);

      // Reference text overlay for City, State, and Country labels
      L.tileLayer(
        'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}',
        {
          maxZoom: 16,
          pane: 'overlayPane',
        }
      ).addTo(map);

      const layersGroup = L.layerGroup().addTo(map);
      layersGroupRef.current = layersGroup;
      mapInstanceRef.current = map;
    }

    const map = mapInstanceRef.current;

    // Trigger invalidateSize after container rendering & transitions
    const timer = setTimeout(() => {
      if (map) map.invalidateSize();
    }, 200);

    const handleResize = () => {
      if (map) map.invalidateSize();
    };

    window.addEventListener('resize', handleResize);

    let resizeObserver: ResizeObserver | null = null;
    if (mapContainerRef.current && typeof window.ResizeObserver !== 'undefined') {
      resizeObserver = new ResizeObserver(() => {
        if (map) map.invalidateSize();
      });
      resizeObserver.observe(mapContainerRef.current);
    }

    return () => {
      clearTimeout(timer);
      window.removeEventListener('resize', handleResize);
      if (resizeObserver) resizeObserver.disconnect();
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  // 2. Render Markers, Impossible Travel Arcs, and Fit Bounds
  useEffect(() => {
    const map = mapInstanceRef.current;
    const layersGroup = layersGroupRef.current;
    if (!map || !layersGroup) return;

    layersGroup.clearLayers();
    markersRef.current = {};

    if (displayHops.length === 0) return;

    const latLngs: L.LatLngTuple[] = [];
    const coordOccurrences = new Map<string, number>();

    // 1. Plot Sequential Numbered Markers with Spiderfy Offset for Co-located Hops
    displayHops.forEach((hop) => {
      const rawLat = hop.location!.latitude!;
      const rawLng = hop.location!.longitude!;

      // Group nearby/identical coordinates
      const key = `${rawLat.toFixed(2)},${rawLng.toFixed(2)}`;
      const occurrence = coordOccurrences.get(key) || 0;
      coordOccurrences.set(key, occurrence + 1);

      let adjustedLat = rawLat;
      let adjustedLng = rawLng;

      // Apply radial offset if co-located
      if (occurrence > 0) {
        const angle = occurrence * (Math.PI / 3);
        const radius = 0.3 * Math.ceil(occurrence / 6);
        adjustedLat = rawLat + radius * Math.sin(angle);
        adjustedLng = rawLng + radius * Math.cos(angle);
      }

      const latLng: L.LatLngTuple = [adjustedLat, adjustedLng];
      latLngs.push(latLng);

      const isOrigin = hop.is_origin;
      const isTarget = (hop as any).is_target || (hop as any).role === 'TARGET_HOST';
      const isDest = hop.is_destination && !isTarget;
      const isTor = hop.location?.is_tor || hop.location?.asn === 60729 || (hop.location?.as_org && /tor/i.test(hop.location.as_org));
      const isBulletproof = hop.location?.asn === 208323 || (hop.location?.as_org && /bulletproof|fin-proxy|proxy layer/i.test(hop.location.as_org));
      const isSuspicious = hop.is_suspicious || isTor || isBulletproof || isTarget;

      const markerColor = isTarget
        ? '#A855F7' // Purple for terminal target
        : isOrigin
        ? '#EF4444' // Red
        : isDest
        ? '#10B981' // Emerald
        : isSuspicious
        ? '#F59E0B' // Amber
        : '#3B82F6'; // Blue

      const glowColor = isTarget
        ? 'rgba(168, 85, 247, 0.6)'
        : isOrigin
        ? 'rgba(239, 68, 68, 0.4)'
        : isDest
        ? 'rgba(16, 185, 129, 0.4)'
        : isSuspicious
        ? 'rgba(245, 158, 11, 0.4)'
        : 'rgba(59, 130, 246, 0.4)';

      const markerHtml = `
        <div style="
          position: relative;
          display: flex;
          align-items: center;
          justify-content: center;
          width: ${isTarget ? '38px' : '34px'};
          height: ${isTarget ? '38px' : '34px'};
          border-radius: 50%;
          background: #0F172A;
          border: 2px solid ${markerColor};
          box-shadow: 0 0 ${isTarget ? '20px' : '16px'} ${glowColor};
          cursor: pointer;
          transition: transform 0.2s ease;
        ">
          <span style="
            color: ${markerColor};
            font-weight: 700;
            font-size: ${isTarget ? '11px' : '13px'};
            font-family: monospace;
          ">${isTarget ? '🎯' : hop.displayIndex}</span>
          ${
            isTor
              ? `<div style="
                  position: absolute;
                  top: -4px;
                  right: -4px;
                  width: 10px;
                  height: 10px;
                  border-radius: 50%;
                  background: #EF4444;
                  border: 1px solid #0F172A;
                "></div>`
              : isBulletproof
              ? `<div style="
                  position: absolute;
                  top: -4px;
                  right: -4px;
                  width: 10px;
                  height: 10px;
                  border-radius: 50%;
                  background: #A855F7;
                  border: 1px solid #0F172A;
                "></div>`
              : ''
          }
        </div>
      `;

      const customIcon = L.divIcon({
        className: 'threat-map-hop-marker',
        html: markerHtml,
        iconSize: [isTarget ? 38 : 34, isTarget ? 38 : 34],
        iconAnchor: [isTarget ? 19 : 17, isTarget ? 19 : 17],
      });

      const marker = L.marker(latLng, { icon: customIcon }).addTo(layersGroup);
      markersRef.current[hop.hop_number] = marker;
      markersRef.current[hop.displayIndex] = marker;

      // Popup details
      const formattedAddress =
        hop.location?.formatted_address ||
        [hop.location?.city, hop.location?.region, hop.location?.country_name]
          .filter(Boolean)
          .join(', ') ||
        'Unknown Location';

      const hopRoleLabel = isTarget
        ? 'CREDENTIAL HARVESTING HOST'
        : isOrigin
        ? 'ORIGINATING SENDER NODE'
        : isDest
        ? 'DESTINATION MX GATEWAY'
        : 'INTERMEDIATE TRANSIT RELAY';

      const popupContent = `
        <div style="font-family: monospace; font-size: 11px; color: #E2E8F0; padding: 6px; min-width: 230px;">
          <div style="font-weight: bold; color: ${markerColor}; margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #334155; padding-bottom: 4px;">
            <span>${hop.markerLabel}: ${hopRoleLabel}</span>
            ${isTor ? '<span style="color: #EF4444; font-size: 9px; background: rgba(239,68,68,0.2); padding: 1px 4px; border-radius: 2px;">TOR EXIT</span>' : isBulletproof ? '<span style="color: #A855F7; font-size: 9px; background: rgba(168,85,247,0.2); padding: 1px 4px; border-radius: 2px;">BULLETPROOF</span>' : ''}
          </div>
          <div style="margin-bottom: 3px;"><strong>IP:</strong> <span style="color: #93C5FD;">${hop.ip}</span></div>
          <div style="margin-bottom: 3px;"><strong>Hostname:</strong> <span style="color: #CBD5E1;">${hop.hostname || hop.ip}</span></div>
          <div style="margin-bottom: 3px;"><strong>Location:</strong> <span style="color: #F8FAFC;">📍 ${formattedAddress}</span></div>
          <div style="margin-bottom: 3px; font-size: 10px; color: #94A3B8;">
            <strong>City:</strong> ${hop.location?.city || 'Unknown'} | <strong>Region:</strong> ${hop.location?.region || 'N/A'}
          </div>
          <div style="margin-bottom: 3px;"><strong>Autonomous System:</strong> AS${hop.location?.asn || 'N/A'} (${hop.location?.as_org || 'Unknown'})</div>
          <div><strong>Transit Delay:</strong> ${hop.delay_seconds != null ? `${hop.delay_seconds.toFixed(1)}s` : '0.0s'}</div>
          ${hop.anomaly_reason ? `<div style="color: #F59E0B; margin-top: 4px; background: rgba(245,158,11,0.1); padding: 2px 4px; border-radius: 2px;">⚠️ ${hop.anomaly_reason}</div>` : ''}
        </div>
      `;

      marker.bindPopup(popupContent, {
        className: 'custom-dark-leaflet-popup',
      });

      // Permanent on-canvas City / Region / Country label
      const tooltipCityRegion = hop.location?.city
        ? `${hop.location.city}${hop.location.region ? `, ${hop.location.region}` : ''}`
        : hop.location?.country_name || 'Unknown Location';

      marker.bindTooltip(
        `<div style="font-family: monospace; font-size: 10px; font-weight: 700; color: #F1F5F9; background: rgba(15, 23, 42, 0.9); padding: 2px 6px; border-radius: 4px; border: 1px solid ${markerColor}99; box-shadow: 0 2px 8px rgba(0,0,0,0.6); white-space: nowrap;">
          <span style="color: ${markerColor};">${hop.markerLabel}</span> ${tooltipCityRegion}
        </div>`,
        {
          permanent: true,
          direction: 'bottom',
          offset: [0, 10],
          className: 'threat-map-permanent-label',
        }
      );

      marker.on('click', () => {
        setSelectedHop(hop);
        if (onSelectHop) onSelectHop(hop);
      });
    });

    // 2. Draw Geodesic Directional Polylines & Velocity Arc Check between consecutive hops
    if (latLngs.length > 1) {
      for (let i = 0; i < displayHops.length - 1; i++) {
        const h1 = displayHops[i];
        const h2 = displayHops[i + 1];
        const p1 = latLngs[i];
        const p2 = latLngs[i + 1];

        const distKm = calculateHaversineKm(
          h1.location!.latitude!,
          h1.location!.longitude!,
          h2.location!.latitude!,
          h2.location!.longitude!
        );
        const delaySec = h2.delay_seconds ?? 0;
        const isImpossibleVelocity = distKm > 4000 && delaySec < 2.0;

        if (isImpossibleVelocity) {
          // Bright pulsing crimson polyline for impossible velocity
          const polyline = L.polyline([p1, p2], {
            color: '#EF4444',
            weight: 3.5,
            opacity: 0.95,
            dashArray: '8, 8',
            lineCap: 'round',
            lineJoin: 'round',
          }).addTo(layersGroup);

          polyline.bindTooltip(
            `<div style="font-family: monospace; font-size: 10px; color: #FCA5A5; background: rgba(69, 10, 10, 0.95); padding: 4px 8px; border-radius: 4px; border: 1px solid #EF4444; box-shadow: 0 2px 8px rgba(0,0,0,0.8);">
              ⚠️ <strong>Impossible Velocity / Proxy Jump</strong> (${distKm.toFixed(0)} km in ${delaySec.toFixed(1)}s across continents)
            </div>`,
            { sticky: true }
          );
        } else {
          // Standard flight route
          L.polyline([p1, p2], {
            color: '#3B82F6',
            weight: 6,
            opacity: 0.25,
            lineCap: 'round',
            lineJoin: 'round',
          }).addTo(layersGroup);

          L.polyline([p1, p2], {
            color: '#60A5FA',
            weight: 2.5,
            opacity: 0.85,
            dashArray: '6, 8',
            lineCap: 'round',
            lineJoin: 'round',
          }).addTo(layersGroup);
        }
      }

      // Fit map bounds
      const bounds = L.latLngBounds(latLngs);
      map.fitBounds(bounds, { padding: [60, 60], maxZoom: 6 });
    } else if (latLngs.length === 1) {
      map.setView(latLngs[0], 5);
    }
  }, [threatMap, displayHops, onSelectHop]);

  // Recenter Path Action
  const handleRecenterPath = useCallback(() => {
    const map = mapInstanceRef.current;
    if (!map || displayHops.length === 0) return;
    map.invalidateSize();
    if (displayHops.length > 1) {
      const latLngs = displayHops.map((h) =>
        L.latLng(h.location!.latitude!, h.location!.longitude!)
      );
      const bounds = L.latLngBounds(latLngs);
      map.fitBounds(bounds, { padding: [60, 60], maxZoom: 6 });
    } else if (displayHops.length === 1) {
      map.setView(
        [displayHops[0].location!.latitude!, displayHops[0].location!.longitude!],
        5,
        { animate: true }
      );
    }
  }, [displayHops]);

  // Interactive Hop Sequence Fly-To
  const handleHopClick = (hop: ThreatMapHop) => {
    setSelectedHop(hop);
    if (onSelectHop) onSelectHop(hop);
    if (
      mapInstanceRef.current &&
      hop.location?.latitude != null &&
      hop.location?.longitude != null
    ) {
      mapInstanceRef.current.flyTo(
        [hop.location.latitude, hop.location.longitude],
        7,
        { duration: 1.2, easeLinearity: 0.25 }
      );
      const marker = markersRef.current[hop.hop_number];
      if (marker) {
        setTimeout(() => {
          marker.openPopup();
        }, 350);
      }
    }
  };

  // Dynamic Severity Badge Calculation
  const hasTor = threatMap.hops.some((h) => h.location?.is_tor || h.location?.asn === 60729 || (h.location?.as_org && /tor/i.test(h.location.as_org)));
  const hasBulletproof = threatMap.hops.some((h) => h.location?.asn === 208323 || (h.location?.as_org && /bulletproof|fin-proxy/i.test(h.location.as_org)));
  const anomalyCount = threatMap.anomalies.length;
  const riskScore = threatMap.risk_score ?? 0;
  const severityProp = (threatMap as any).severity?.toLowerCase();

  let severityLabel = 'BENIGN';
  let severityClass =
    'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 font-mono text-xs font-bold px-2.5 py-0.5 rounded';

  if (riskScore >= 80 || severityProp === 'critical' || anomalyCount >= 3 || hasTor) {
    severityLabel = 'CRITICAL';
    severityClass =
      'bg-rose-500/20 text-rose-400 border border-rose-500/40 font-mono text-xs font-bold px-2.5 py-0.5 rounded shadow-sm shadow-rose-950/50';
  } else if (riskScore >= 50 || severityProp === 'high' || anomalyCount > 0 || hasBulletproof) {
    severityLabel = 'HIGH THREAT';
    severityClass =
      'bg-amber-500/20 text-amber-400 border border-amber-500/40 font-mono text-xs font-bold px-2.5 py-0.5 rounded shadow-sm shadow-amber-950/50';
  } else if (riskScore >= 25 || severityProp === 'medium') {
    severityLabel = 'MODERATE';
    severityClass =
      'bg-blue-500/20 text-blue-400 border border-blue-500/40 font-mono text-xs font-bold px-2.5 py-0.5 rounded';
  }

  return (
    <div className={`grid grid-cols-1 lg:grid-cols-12 gap-4 h-full max-h-[82vh] ${className}`}>
      {/* Map Canvas Area */}
      <div className="lg:col-span-8 bg-[#0D1525] border border-[#263244] rounded-lg overflow-hidden flex flex-col relative h-full min-h-[420px]">
        {/* Top Control Overlay */}
        <div className="absolute top-3 left-3 z-[1000] flex items-center gap-2 bg-[#0B1120]/90 backdrop-blur-md px-3 py-1.5 rounded-md border border-[#263244] shadow-lg">
          <Navigation className="w-4 h-4 text-blue-400" />
          <span className="text-xs font-mono font-medium text-gray-200">
            Relay Transit Route
          </span>
          <span className="text-2xs font-mono text-gray-400">
            • {displayHops.length} Mapped Hops • {threatMap.total_distance_km.toLocaleString()} km
          </span>
        </div>

        {/* Floating Recenter Path Button */}
        <div className="absolute top-3 right-3 z-[1000] flex items-center gap-2">
          <button
            onClick={handleRecenterPath}
            className="flex items-center gap-1.5 bg-[#0B1120]/90 hover:bg-[#151E2E] backdrop-blur-md px-2.5 py-1.5 rounded-md border border-[#263244] hover:border-blue-500/50 shadow-lg text-xs font-mono text-gray-200 transition-all cursor-pointer group"
            title="Recenter flight path bounding box"
          >
            <Crosshair className="w-3.5 h-3.5 text-blue-400 group-hover:text-blue-300 transition-colors" />
            <span className="font-semibold">Recenter Path</span>
          </button>
        </div>

        {/* Legend Overlay */}
        <div className="absolute bottom-3 left-3 z-[1000] flex items-center gap-3 bg-[#0B1120]/90 backdrop-blur-md px-3 py-1.5 rounded-md border border-[#263244] text-2xs font-mono">
          <span className="flex items-center gap-1.5 text-red-400">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-sm" /> Origin
          </span>
          <span className="flex items-center gap-1.5 text-blue-400">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500 shadow-sm" /> Transit Hop
          </span>
          <span className="flex items-center gap-1.5 text-purple-400">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-500 shadow-sm" /> Target Host
          </span>
          <span className="flex items-center gap-1.5 text-emerald-400">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-sm" /> Destination
          </span>
          <span className="flex items-center gap-1.5 text-amber-400">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500 shadow-sm" /> Tor/VPN
          </span>
        </div>

        {/* Leaflet DOM Element */}
        <div ref={mapContainerRef} className="w-full flex-1" />
      </div>

      {/* Sidebar Details & Sequential Timeline */}
      <div className="lg:col-span-4 flex flex-col gap-3 h-full max-h-[82vh] min-h-0 overflow-hidden">
        {/* Transit Overview Card */}
        <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-3.5 space-y-3 flex-shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-blue-400" />
              <h3 className="text-xs font-mono font-bold text-gray-200 uppercase tracking-wider">
                Geospatial Telemetry
              </h3>
            </div>
            <span className={severityClass}>
              {severityLabel}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="bg-[#111C30] p-2 rounded border border-[#202C3F]">
              <span className="text-2xs text-gray-400 block">Total Distance</span>
              <span className="text-sm font-bold text-gray-100">
                {threatMap.total_distance_km.toLocaleString()} km
              </span>
              <span className="text-3xs text-gray-500 block">
                (~{(threatMap.total_distance_km * 0.621371).toFixed(0)} miles)
              </span>
            </div>
            <div className="bg-[#111C30] p-2 rounded border border-[#202C3F]">
              <span className="text-2xs text-gray-400 block">Relay Hops</span>
              <span className="text-sm font-bold text-gray-100">
                {threatMap.hops.length} nodes
              </span>
              <span className="text-3xs text-gray-500 block">
                {displayHops.length} geocoded
              </span>
            </div>
          </div>

          {/* Anomalies Box */}
          {threatMap.anomalies.length > 0 && (
            <div className="p-2.5 bg-red-950/20 border border-red-800/40 rounded space-y-1.5 max-h-32 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
              <div className="flex items-center gap-1.5 text-2xs font-mono font-bold text-red-400 uppercase">
                <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                Routing Anomalies ({threatMap.anomalies.length})
              </div>
              <ul className="space-y-1">
                {threatMap.anomalies.map((anom, i) => (
                  <li key={i} className="text-2xs font-mono text-gray-300 leading-snug flex items-start gap-1">
                    <span className="text-red-500">•</span>
                    <span>{anom}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Sequential Hop Timeline */}
        <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-3 flex-1 flex flex-col min-h-0 overflow-hidden">
          <div className="flex items-center justify-between pb-2 border-b border-[#263244] mb-2 flex-shrink-0">
            <span className="text-xs font-mono font-bold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-blue-400" />
              Transit Hop Sequence
            </span>
            <span className="text-2xs font-mono text-gray-400">
              Click node to fly
            </span>
          </div>

          <div className="flex-1 overflow-y-auto pr-2 space-y-3 scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
            {threatMap.hops.map((hop) => {
              const dHop = displayHops.find((dh) => dh.hop_number === hop.hop_number);
              const isSelected = selectedHop?.hop_number === hop.hop_number;
              const isTarget = (hop as any).is_target || (hop as any).role === 'TARGET_HOST';
              const isTor = hop.location?.is_tor || hop.location?.asn === 60729 || (hop.location?.as_org && /tor/i.test(hop.location.as_org));
              const isBulletproof = hop.location?.asn === 208323 || (hop.location?.as_org && /bulletproof|fin-proxy|proxy layer/i.test(hop.location.as_org));

              return (
                <div
                  key={hop.hop_number}
                  onClick={() => handleHopClick(hop)}
                  className={`p-2.5 rounded border transition-all cursor-pointer font-mono text-xs ${
                    isSelected
                      ? 'bg-[#15233D] border-blue-500 shadow-md ring-1 ring-blue-500/50'
                      : 'bg-[#101A2E] border-[#202C3F] hover:border-gray-600 hover:bg-[#132038]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`w-5 h-5 rounded-full flex items-center justify-center text-3xs font-bold ${
                          isTarget
                            ? 'bg-purple-500/20 text-purple-400 border border-purple-500/50'
                            : hop.is_origin
                            ? 'bg-red-500/20 text-red-400 border border-red-500/50'
                            : hop.is_destination
                            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/50'
                            : dHop
                            ? 'bg-blue-500/20 text-blue-400 border border-blue-500/50'
                            : 'bg-gray-800 text-gray-400 border border-gray-700'
                        }`}
                      >
                        {isTarget ? '🎯' : dHop ? dHop.displayIndex : '—'}
                      </span>
                      <span className="font-bold text-gray-200">
                        {hop.ip}
                      </span>
                    </div>

                    <div className="flex items-center gap-1">
                      {isTarget && (
                        <span className="text-3xs px-2 py-0.5 rounded bg-purple-900/60 text-purple-300 border border-purple-500/60 font-bold shadow-sm">
                          Target Host
                        </span>
                      )}
                      {!dHop && (
                        <span className="text-3xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700" title="Private LAN (non-geocoded)">
                          Internal LAN
                        </span>
                      )}
                      {hop.is_origin && !isTarget && (
                        <span className="text-3xs px-1.5 py-0.5 rounded bg-red-900/40 text-red-300 border border-red-700/50">
                          Origin
                        </span>
                      )}
                      {hop.is_destination && !isTarget && (
                        <span className="text-3xs px-1.5 py-0.5 rounded bg-emerald-900/40 text-emerald-300 border border-emerald-700/50">
                          Destination
                        </span>
                      )}
                      {isTor && (
                        <span className="text-3xs px-2 py-0.5 rounded bg-rose-900/60 text-rose-300 border border-rose-500/60 font-bold shadow-sm shadow-rose-950/40">
                          TOR EXIT NODE
                        </span>
                      )}
                      {isBulletproof && !isTor && (
                        <span className="text-3xs px-2 py-0.5 rounded bg-purple-900/60 text-purple-300 border border-purple-500/60 font-bold shadow-sm shadow-purple-950/40">
                          BULLETPROOF RELAY
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="text-2xs text-gray-400 space-y-1">
                    <div className="flex items-start justify-between gap-1">
                      <span className="text-gray-200 font-medium leading-snug">
                        📍 {hop.location?.formatted_address || [hop.location?.city, hop.location?.region, hop.location?.country_name].filter(Boolean).join(', ') || 'Unknown Location'}
                      </span>
                      {hop.delay_seconds != null && (
                        <span className="text-3xs text-gray-400 flex items-center gap-0.5 flex-shrink-0">
                          <Clock className="w-3 h-3 text-gray-500" />
                          +{hop.delay_seconds.toFixed(1)}s
                        </span>
                      )}
                    </div>

                    <div className="text-3xs text-gray-400 flex items-center gap-2">
                      <span>City: <strong className="text-gray-300">{hop.location?.city || 'N/A'}</strong></span>
                      <span>•</span>
                      <span>Region: <strong className="text-gray-300">{hop.location?.region || 'N/A'}</strong></span>
                    </div>

                    {hop.location?.as_org && (
                      <div className="text-3xs text-gray-400 truncate">
                        AS{hop.location.asn} • {hop.location.as_org}
                      </div>
                    )}

                    {hop.anomaly_reason && (
                      <div className="text-3xs text-amber-400 pt-0.5">
                        ⚠️ {hop.anomaly_reason}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
