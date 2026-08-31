import React, { useState, useEffect } from 'react';
import { ThreatMapComponent } from '../components/map/ThreatMapComponent';
import { intelService } from '../services/intelService';
import { GeoLocationCluster } from '../types/infrastructure';
import { LoadingState } from '../components/common/LoadingState';
import { MapPin, Globe, Server, AlertOctagon, HelpCircle } from 'lucide-react';

export const ThreatMapPage: React.FC = () => {
  const [clusters, setClusters] = useState<GeoLocationCluster[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadMapData() {
      setLoading(true);
      const data = await intelService.getGeoClusters();
      setClusters(data);
      setLoading(false);
    }
    loadMapData();
  }, []);

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
            Geographic Infrastructure & Origin Distribution
          </h1>
          <p className="text-xs text-gray-400 font-mono mt-0.5">
            Real-time geospatial mapping of probable originating mail nodes, anonymizing relays, and bulletproof hosting autonomous systems.
          </p>
        </div>

        <div className="flex items-center gap-3 text-2xs font-mono text-gray-400">
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-red-500" /> Critical Cluster
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-orange-500" /> High
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-amber-500" /> Medium
          </span>
        </div>
      </div>

      {/* Main Map Container */}
      <div className="flex-1 w-full min-h-0">
        <ThreatMapComponent clusters={clusters} className="h-full" />
      </div>
    </div>
  );
};
