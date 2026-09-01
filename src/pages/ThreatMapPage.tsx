import React, { useState, useEffect } from 'react';
import { ThreatMapComponent } from '../components/map/ThreatMapComponent';
import { ThreatRouteMap } from '../components/investigation/ThreatRouteMap';
import { intelService } from '../services/intelService';
import { threatMapService } from '../services/threatMapService';
import { investigationService } from '../services/investigationService';
import { GeoLocationCluster } from '../types/infrastructure';
import { ThreatMapData } from '../types/threatMap';
import { InvestigationListItemResponse } from '../types/investigation';
import { LoadingState } from '../components/common/LoadingState';
import { MapPin, Globe, Navigation, Layers, AlertTriangle } from 'lucide-react';

export const ThreatMapPage: React.FC = () => {
  const [viewMode, setViewMode] = useState<'clusters' | 'route'>('clusters');
  const [clusters, setClusters] = useState<GeoLocationCluster[]>([]);
  const [investigations, setInvestigations] = useState<InvestigationListItemResponse[]>([]);
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<string>('');
  const [threatMapData, setThreatMapData] = useState<ThreatMapData | null>(null);
  const [loading, setLoading] = useState(true);
  const [routeLoading, setRouteLoading] = useState(false);
  const [routeError, setRouteError] = useState<string | null>(null);

  // Initial Load: Geo Clusters and Investigations list
  useEffect(() => {
    async function loadInitialData() {
      setLoading(true);
      try {
        const [clusterData, invList] = await Promise.all([
          intelService.getGeoClusters(),
          investigationService.listInvestigations().catch(() => []),
        ]);
        setClusters(clusterData);
        setInvestigations(invList);
        if (invList.length > 0) {
          setSelectedInvestigationId(invList[0].investigation_id);
        }
      } catch (e) {
        console.error('Failed to load map data:', e);
      } finally {
        setLoading(false);
      }
    }
    loadInitialData();
  }, []);

  // Fetch Threat Map for selected investigation
  useEffect(() => {
    if (viewMode !== 'route' || !selectedInvestigationId) return;

    let isMounted = true;
    async function fetchRoute() {
      setRouteLoading(true);
      setRouteError(null);
      try {
        const data = await threatMapService.getInvestigationThreatMap(selectedInvestigationId);
        if (isMounted) {
          setThreatMapData(data);
        }
      } catch (err: any) {
        if (isMounted) {
          setRouteError(err.message || 'Unable to load relay transit map for this investigation.');
        }
      } finally {
        if (isMounted) {
          setRouteLoading(false);
        }
      }
    }
    fetchRoute();

    return () => {
      isMounted = false;
    };
  }, [viewMode, selectedInvestigationId]);

  if (loading) {
    return <LoadingState message="Aggregating geographic infrastructure telemetry..." />;
  }

  return (
    <div className="space-y-4 flex flex-col h-[calc(100vh-8.5rem)]">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#263244] pb-3 flex-shrink-0">
        <div>
          <h1 className="text-xl font-bold text-gray-100 font-mono tracking-tight flex items-center gap-2">
            <MapPin className="w-5 h-5 text-blue-400" />
            Geographic Infrastructure & Threat Transit
          </h1>
          <p className="text-xs text-gray-400 font-mono mt-0.5">
            Real-time geospatial mapping of probable originating mail nodes, anonymizing relays, and transit route topology.
          </p>
        </div>

        {/* View Mode Switcher */}
        <div className="flex items-center gap-3">
          <div className="flex items-center bg-[#0D1525] border border-[#263244] rounded-lg p-1 font-mono text-xs">
            <button
              onClick={() => setViewMode('clusters')}
              className={`flex items-center gap-1.5 px-3 py-1 rounded transition ${
                viewMode === 'clusters'
                  ? 'bg-blue-600 text-white font-bold shadow'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Global Clusters</span>
            </button>
            <button
              onClick={() => setViewMode('route')}
              className={`flex items-center gap-1.5 px-3 py-1 rounded transition ${
                viewMode === 'route'
                  ? 'bg-blue-600 text-white font-bold shadow'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              <Navigation className="w-3.5 h-3.5" />
              <span>Investigation Route</span>
            </button>
          </div>
        </div>
      </div>

      {/* Mode 1: Global Clusters */}
      {viewMode === 'clusters' && (
        <div className="flex-1 w-full min-h-0">
          <ThreatMapComponent clusters={clusters} className="h-full" />
        </div>
      )}

      {/* Mode 2: Investigation Route Transit */}
      {viewMode === 'route' && (
        <div className="flex-1 w-full min-h-0 flex flex-col gap-3">
          {/* Investigation Selector Bar */}
          <div className="bg-[#0D1525] border border-[#263244] rounded-lg p-2.5 flex items-center justify-between gap-4 font-mono text-xs flex-shrink-0">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-400" />
              <span className="font-bold text-gray-300">Select Investigation Target:</span>
              <select
                value={selectedInvestigationId}
                onChange={(e) => setSelectedInvestigationId(e.target.value)}
                className="bg-[#152033] border border-[#2B3B52] rounded px-3 py-1 text-gray-200 focus:outline-none focus:border-blue-500 font-mono text-xs"
              >
                {investigations.map((inv) => (
                  <option key={inv.investigation_id} value={inv.investigation_id}>
                    {inv.investigation_id} — {inv.threat_type || 'Unknown'} (Risk: {inv.risk_score ?? 'N/A'})
                  </option>
                ))}
              </select>
            </div>

            {threatMapData && (
              <div className="text-2xs text-gray-400 hidden sm:flex items-center gap-3">
                <span>Total Distance: <strong className="text-gray-200">{threatMapData.total_distance_km.toLocaleString()} km</strong></span>
                <span>•</span>
                <span>Relay Hops: <strong className="text-gray-200">{threatMapData.hops.length}</strong></span>
              </div>
            )}
          </div>

          {/* Main Map / Route Container */}
          <div className="flex-1 min-h-0">
            {routeLoading ? (
              <div className="h-full flex items-center justify-center bg-[#0D1525] border border-[#263244] rounded-lg">
                <LoadingState message="Reconstructing transit hops and calculating geospatial route..." />
              </div>
            ) : routeError ? (
              <div className="h-full flex flex-col items-center justify-center bg-[#0D1525] border border-[#263244] rounded-lg p-6 text-center">
                <AlertTriangle className="w-10 h-10 text-amber-400 mb-2" />
                <h3 className="text-sm font-mono font-bold text-gray-200 mb-1">
                  Investigation Route Not Available
                </h3>
                <p className="text-xs font-mono text-gray-400 max-w-md">{routeError}</p>
              </div>
            ) : threatMapData ? (
              <ThreatRouteMap threatMap={threatMapData} className="h-full" />
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
};
