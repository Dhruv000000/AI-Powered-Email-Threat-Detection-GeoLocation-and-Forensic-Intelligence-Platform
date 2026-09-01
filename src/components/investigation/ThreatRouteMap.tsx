import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import { ThreatMapData, ThreatMapHop } from '../../types/threatMap';
import {
  MapPin,
  Globe,
  Navigation,
  Clock,
  ShieldAlert,
  AlertTriangle,
  Server,
  Layers,
  ChevronRight,
  Crosshair,
  Maximize2,
} from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';

interface ThreatRouteMapProps {
  threatMap: ThreatMapData;
  className?: string;
  onSelectHop?: (hop: ThreatMapHop | null) => void;
}

export const ThreatRouteMap: React.FC<ThreatRouteMapProps> = ({
  threatMap,
  className = 'h-full',
  onSelectHop,
}) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const layersGroupRef = useRef<L.LayerGroup | null>(null);

  const [selectedHop, setSelectedHop] = useState<ThreatMapHop | null>(
    threatMap.hops[0] || null
  );

  // Filter hops that have valid coordinates
  const geoHops = threatMap.hops.filter(
    (h) => h.location && h.location.latitude != null && h.location.longitude != null
  );

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
      });

      L.control.zoom({ position: 'bottomright' }).addTo(map);

      // 1. Base dark canvas
      L.tileLayer(
        'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
        {
          attribution: '&copy; Esri, HERE, Garmin, &copy; OpenStreetMap contributors',
          maxZoom: 16,
        }
      ).addTo(map);

      // 2. Reference text overlay for City, State, and Country labels
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

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  // Render Markers, Curved Polylines, and Fit Bounds
  useEffect(() => {
    const map = mapInstanceRef.current;
    const layersGroup = layersGroupRef.current;
    if (!map || !layersGroup) return;

    layersGroup.clearLayers();

    if (geoHops.length === 0) return;

    const latLngs: L.LatLngTuple[] = [];
    const coordOccurrences = new Map<string, number>();

    // 1. Plot Sequential Numbered Markers with Spiderfy Offset for Co-located Hops
    geoHops.forEach((hop, idx) => {
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
      const isDest = hop.is_destination;
      const isTor = hop.location?.is_tor;
      const isSuspicious = hop.is_suspicious || isTor;

      const markerColor = isOrigin
        ? '#EF4444' // Red
        : isDest
        ? '#10B981' // Emerald
        : isSuspicious
        ? '#F59E0B' // Amber
        : '#3B82F6'; // Blue

      const glowColor = isOrigin
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
          width: 34px;
          height: 34px;
          border-radius: 50%;
          background: #0F172A;
          border: 2px solid ${markerColor};
          box-shadow: 0 0 16px ${glowColor};
          cursor: pointer;
          transition: transform 0.2s ease;
        ">
          <span style="
            color: ${markerColor};
            font-weight: 700;
            font-size: 13px;
            font-family: monospace;
          ">${hop.hop_number}</span>
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
              : ''
          }
        </div>
      `;

      const customIcon = L.divIcon({
        className: 'threat-map-hop-marker',
        html: markerHtml,
        iconSize: [34, 34],
        iconAnchor: [17, 17],
      });

      const marker = L.marker(latLng, { icon: customIcon }).addTo(layersGroup);

      // Popup details
      const formattedAddress =
        hop.location?.formatted_address ||
        [hop.location?.city, hop.location?.region, hop.location?.country_name]
          .filter(Boolean)
          .join(', ') ||
        'Unknown Location';

      const popupContent = `
        <div style="font-family: monospace; font-size: 11px; color: #E2E8F0; padding: 6px; min-width: 220px;">
          <div style="font-weight: bold; color: ${markerColor}; margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #334155; padding-bottom: 4px;">
            <span>HOP #${hop.hop_number} ${isOrigin ? '(ORIGIN)' : isDest ? '(DESTINATION)' : ''}</span>
            ${isTor ? '<span style="color: #EF4444; font-size: 9px; background: rgba(239,68,68,0.2); padding: 1px 4px; border-radius: 2px;">TOR EXIT</span>' : ''}
          </div>
          <div style="margin-bottom: 3px;"><strong>IP:</strong> <span style="color: #93C5FD;">${hop.ip}</span></div>
          <div style="margin-bottom: 3px;"><strong>Address:</strong> <span style="color: #F8FAFC;">📍 ${formattedAddress}</span></div>
          <div style="margin-bottom: 3px; font-size: 10px; color: #94A3B8;">
            <strong>City:</strong> ${hop.location?.city || 'Unknown'} | <strong>Region/State:</strong> ${hop.location?.region || 'N/A'}
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
          <span style="color: ${markerColor};">#${hop.hop_number}</span> ${tooltipCityRegion}
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

    // 2. Draw Geodesic Directional Polylines between consecutive hops
    if (latLngs.length > 1) {
      // Glow polyline
      L.polyline(latLngs, {
        color: '#3B82F6',
        weight: 6,
        opacity: 0.25,
        lineCap: 'round',
        lineJoin: 'round',
      }).addTo(layersGroup);

      // Main dashed animated polyline
      L.polyline(latLngs, {
        color: '#60A5FA',
        weight: 2.5,
        opacity: 0.85,
        dashArray: '6, 8',
        lineCap: 'round',
        lineJoin: 'round',
      }).addTo(layersGroup);

      // Fit map bounds
      const bounds = L.latLngBounds(latLngs);
      map.fitBounds(bounds, { padding: [50, 50], maxZoom: 8 });
    } else if (latLngs.length === 1) {
      map.setView(latLngs[0], 5);
    }
  }, [threatMap, geoHops.length]);

  const handleHopClick = (hop: ThreatMapHop) => {
    setSelectedHop(hop);
    if (onSelectHop) onSelectHop(hop);
    if (
      mapInstanceRef.current &&
      hop.location?.latitude != null &&
      hop.location?.longitude != null
    ) {
      mapInstanceRef.current.setView(
        [hop.location.latitude, hop.location.longitude],
        6,
        { animate: true }
      );
    }
  };

  // Dynamic Severity Badge Calculation
  const hasTor = threatMap.hops.some((h) => h.location?.is_tor);
  const anomalyCount = threatMap.anomalies.length;

  let severityLabel = 'BENIGN';
  let severityClass =
    'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 font-mono text-xs font-bold px-2.5 py-0.5 rounded';

  if (anomalyCount >= 3 || hasTor) {
    severityLabel = 'CRITICAL';
    severityClass =
      'bg-rose-500/20 text-rose-400 border border-rose-500/40 font-mono text-xs font-bold px-2.5 py-0.5 rounded';
  } else if (anomalyCount > 0) {
    severityLabel = 'HIGH THREAT';
    severityClass =
      'bg-amber-500/20 text-amber-400 border border-amber-500/40 font-mono text-xs font-bold px-2.5 py-0.5 rounded';
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
            • {geoHops.length} Mapped Hops • {threatMap.total_distance_km.toLocaleString()} km
          </span>
        </div>

        {/* Legend Overlay */}
        <div className="absolute bottom-3 left-3 z-[1000] flex items-center gap-3 bg-[#0B1120]/90 backdrop-blur-md px-3 py-1.5 rounded-md border border-[#263244] text-2xs font-mono">
          <span className="flex items-center gap-1.5 text-red-400">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-sm" /> Origin
          </span>
          <span className="flex items-center gap-1.5 text-blue-400">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500 shadow-sm" /> Transit Hop
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
                {geoHops.length} geocoded
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
              Ordered by Relay Chain
            </span>
          </div>

          <div className="flex-1 overflow-y-auto pr-2 space-y-3 scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
            {threatMap.hops.map((hop) => {
              const isSelected = selectedHop?.hop_number === hop.hop_number;
              const isTor = hop.location?.is_tor;
              const isSuspicious = hop.is_suspicious || isTor;

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
                          hop.is_origin
                            ? 'bg-red-500/20 text-red-400 border border-red-500/50'
                            : hop.is_destination
                            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/50'
                            : 'bg-blue-500/20 text-blue-400 border border-blue-500/50'
                        }`}
                      >
                        {hop.hop_number}
                      </span>
                      <span className="font-bold text-gray-200">
                        {hop.ip}
                      </span>
                    </div>

                    <div className="flex items-center gap-1">
                      {hop.is_origin && (
                        <span className="text-3xs px-1.5 py-0.5 rounded bg-red-900/40 text-red-300 border border-red-700/50">
                          Origin
                        </span>
                      )}
                      {hop.is_destination && (
                        <span className="text-3xs px-1.5 py-0.5 rounded bg-emerald-900/40 text-emerald-300 border border-emerald-700/50">
                          Destination
                        </span>
                      )}
                      {isTor && (
                        <span className="text-3xs px-1.5 py-0.5 rounded bg-red-900/40 text-red-300 border border-red-700/50">
                          Tor Exit
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
