import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import { GeoLocationCluster } from '../../types/infrastructure';
import { SeverityBadge } from '../common/SeverityBadge';
import { MapPin, Server, Filter, ArrowRight, ShieldAlert, X, Eye } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

interface ThreatMapComponentProps {
  clusters: GeoLocationCluster[];
  selectedClusterId?: string;
  onSelectCluster?: (cluster: GeoLocationCluster | null) => void;
  className?: string;
}

export const ThreatMapComponent: React.FC<ThreatMapComponentProps> = ({
  clusters,
  selectedClusterId,
  onSelectCluster,
  className,
}) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const markersLayerRef = useRef<L.LayerGroup | null>(null);
  const navigate = useNavigate();

  const [activeCluster, setActiveCluster] = useState<GeoLocationCluster | null>(
    clusters.find((c) => c.id === selectedClusterId) || clusters[0] || null
  );

  // Filters State
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedCountry, setSelectedCountry] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<string>('7d');

  // Filter clusters
  const filteredClusters = clusters.filter((c) => {
    if (selectedSeverity !== 'all' && c.highestSeverity !== selectedSeverity) return false;
    if (selectedCountry !== 'all' && c.country !== selectedCountry) return false;
    return true;
  });

  // Unique countries list
  const countries = Array.from(new Set(clusters.map((c) => c.country)));

  // Initialize Map
  useEffect(() => {
    if (!mapContainerRef.current) return;

    if (!mapInstanceRef.current) {
      const map = L.map(mapContainerRef.current, {
        center: [30.0, 15.0],
        zoom: 2.5,
        minZoom: 2,
        maxZoom: 12,
        zoomControl: false,
        attributionControl: false,
      });

      L.control.zoom({ position: 'bottomright' }).addTo(map);

      // 1. Keyless Esri World Dark Gray Canvas Basemap
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

      const markersGroup = L.layerGroup().addTo(map);
      markersLayerRef.current = markersGroup;
      mapInstanceRef.current = map;
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  // Update Markers when clusters or filters change
  useEffect(() => {
    const map = mapInstanceRef.current;
    const markersGroup = markersLayerRef.current;
    if (!map || !markersGroup) return;

    markersGroup.clearLayers();

    filteredClusters.forEach((cluster) => {
      const isCritical = cluster.highestSeverity === 'critical';
      const isHigh = cluster.highestSeverity === 'high';
      const isMedium = cluster.highestSeverity === 'medium';

      const color = isCritical ? '#EF4444' : isHigh ? '#F97316' : isMedium ? '#F59E0B' : '#10B981';
      const markerSize = Math.max(18, Math.min(32, 16 + cluster.threatCount));

      const customIcon = L.divIcon({
        className: 'custom-leaflet-marker',
        html: `
          <div style="
            width: ${markerSize}px;
            height: ${markerSize}px;
            background-color: ${color}33;
            border: 2px solid ${color};
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #FFFFFF;
            font-family: 'JetBrains Mono', monospace;
            font-size: 10px;
            font-weight: bold;
            cursor: pointer;
            box-shadow: 0 0 12px ${color}66;
          ">
            ${cluster.threatCount}
          </div>
        `,
        iconSize: [markerSize, markerSize],
        iconAnchor: [markerSize / 2, markerSize / 2],
      });

      const marker = L.marker([cluster.lat, cluster.lng], { icon: customIcon });

      marker.on('click', () => {
        setActiveCluster(cluster);
        if (onSelectCluster) onSelectCluster(cluster);
        map.setView([cluster.lat, cluster.lng], Math.max(map.getZoom(), 4), { animate: true });
      });

      marker.addTo(markersGroup);
    });
  }, [filteredClusters, onSelectCluster]);

  return (
    <div className={`relative flex flex-col h-full w-full rounded-lg border border-[#263244] overflow-hidden ${className}`}>
      {/* Top Filter Bar */}
      <div className="bg-[#111827] border-b border-[#263244] p-3 flex flex-wrap items-center justify-between gap-3 z-10">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-gray-300 font-mono font-semibold">
            <Filter className="w-3.5 h-3.5 text-blue-400" />
            <span>Map Filters:</span>
          </div>

          {/* Time Range Filter */}
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="bg-[#151E2E] border border-[#263244] text-gray-200 text-xs rounded px-2.5 py-1 font-mono focus:outline-none focus:border-blue-500"
          >
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
            <option value="all">All Telemetry</option>
          </select>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-[#151E2E] border border-[#263244] text-gray-200 text-xs rounded px-2.5 py-1 font-mono focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High & Above</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Country Filter */}
          <select
            value={selectedCountry}
            onChange={(e) => setSelectedCountry(e.target.value)}
            className="bg-[#151E2E] border border-[#263244] text-gray-200 text-xs rounded px-2.5 py-1 font-mono focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Geographies ({countries.length})</option>
            {countries.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-3 text-2xs font-mono text-gray-400">
          <span>Active Origin Nodes: <strong className="text-gray-200">{filteredClusters.length}</strong></span>
          <span className="hidden sm:inline">|</span>
          <span className="hidden sm:inline">Aggregate Threats: <strong className="text-red-400">{filteredClusters.reduce((acc, c) => acc + c.threatCount, 0)}</strong></span>
        </div>
      </div>

      {/* Map + Side Drawer Container */}
      <div className="relative flex-1 min-h-[500px] w-full bg-[#0B1120]">
        <div ref={mapContainerRef} className="absolute inset-0 w-full h-full z-0" />

        {/* Floating Side Inspector Panel */}
        {activeCluster && (
          <div className="absolute top-4 right-4 w-80 bg-[#151E2E]/95 backdrop-blur-md border border-[#263244] rounded-lg shadow-2xl p-4 z-10 animate-in fade-in slide-in-from-right-4 space-y-3">
            <div className="flex items-start justify-between border-b border-[#263244] pb-2.5">
              <div className="space-y-0.5">
                <span className="text-[10px] uppercase tracking-wider text-gray-400 font-mono font-bold block">
                  Probable Origin / Infrastructure
                </span>
                <h4 className="text-sm font-bold text-gray-100 font-mono">
                  {activeCluster.city}, {activeCluster.country}
                </h4>
              </div>
              <button
                onClick={() => setActiveCluster(null)}
                className="text-gray-400 hover:text-gray-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-400 font-mono">Highest Threat Level:</span>
              <SeverityBadge severity={activeCluster.highestSeverity} size="sm" />
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs font-mono bg-[#0B1120] p-2.5 rounded border border-[#263244]">
              <div>
                <span className="text-[10px] uppercase text-gray-400 block">Related Threats</span>
                <span className="text-sm font-bold text-red-400">{activeCluster.threatCount} incidents</span>
              </div>
              <div>
                <span className="text-[10px] uppercase text-gray-400 block">Associated IPs</span>
                <span className="text-sm font-bold text-blue-400">{activeCluster.ipCount} addresses</span>
              </div>
            </div>

            <div className="text-xs font-mono space-y-1">
              <span className="text-[10px] uppercase text-gray-400 font-semibold block">Primary Infrastructure ISP:</span>
              <p className="text-gray-200 truncate">{activeCluster.sampleIsp}</p>
            </div>

            <div className="text-xs font-mono space-y-1">
              <span className="text-[10px] uppercase text-gray-400 font-semibold block">Identified Threat Vectors:</span>
              <div className="flex flex-wrap gap-1">
                {activeCluster.threatTypes.map((tt) => (
                  <span
                    key={tt}
                    className="px-1.5 py-0.5 bg-[#1E293B] border border-[#263244] rounded text-[10px] text-gray-300"
                  >
                    {tt}
                  </span>
                ))}
              </div>
            </div>

            <div className="pt-2 border-t border-[#263244] flex flex-col gap-2">
              <button
                onClick={() => navigate('/threats')}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-mono font-semibold transition"
              >
                <span>View Related Threats ({activeCluster.threatCount})</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => navigate('/graph')}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 bg-[#1E293B] hover:bg-[#263244] text-gray-200 border border-[#263244] rounded text-xs font-mono transition"
              >
                <span>Pivot to Correlation Graph</span>
                <Eye className="w-3.5 h-3.5 text-blue-400" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
