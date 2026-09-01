import React, { useEffect, useState } from 'react';
import { ThreatRouteMap } from './ThreatRouteMap';
import { threatMapService } from '../../services/threatMapService';
import { ThreatMapData } from '../../types/threatMap';
import { LoadingState } from '../common/LoadingState';
import { X, MapPin, AlertOctagon, ExternalLink } from 'lucide-react';

interface ThreatMapModalProps {
  investigationId: string;
  isOpen: boolean;
  onClose: () => void;
}

export const ThreatMapModal: React.FC<ThreatMapModalProps> = ({
  investigationId,
  isOpen,
  onClose,
}) => {
  const [threatMap, setThreatMap] = useState<ThreatMapData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen || !investigationId) return;

    let isMounted = true;
    async function fetchMap() {
      setLoading(true);
      setError(null);
      try {
        const data = await threatMapService.getInvestigationThreatMap(investigationId);
        if (isMounted) {
          setThreatMap(data);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err.message || 'Failed to load threat map');
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    }

    fetchMap();

    return () => {
      isMounted = false;
    };
  }, [isOpen, investigationId]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-fade-in">
      <div className="bg-[#0B1120] border border-[#263244] rounded-xl w-full max-w-6xl h-[88vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#263244] bg-[#0D1525]">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20 text-blue-400">
              <MapPin className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-gray-100 font-mono flex items-center gap-2">
                Trace Origin & Geographic Relay Route
              </h2>
              <p className="text-2xs text-gray-400 font-mono">
                Investigation ID: <span className="text-blue-400">{investigationId}</span>
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-gray-200 hover:bg-[#1E293B] rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 p-4 min-h-0 bg-[#0B1120] overflow-hidden">
          {loading ? (
            <div className="h-full flex items-center justify-center">
              <LoadingState message="Reconstructing relay hop coordinates and calculating geodesic routing..." />
            </div>
          ) : error ? (
            <div className="h-full flex flex-col items-center justify-center p-8 text-center">
              <AlertOctagon className="w-12 h-12 text-red-400 mb-3" />
              <h3 className="text-sm font-bold font-mono text-gray-200 mb-1">
                Unable to Load Threat Map
              </h3>
              <p className="text-xs font-mono text-gray-400 max-w-md mb-4">{error}</p>
              <button
                onClick={onClose}
                className="px-4 py-1.5 bg-[#1E293B] hover:bg-[#2A3B52] text-xs font-mono text-gray-200 rounded border border-[#263244]"
              >
                Close Window
              </button>
            </div>
          ) : threatMap ? (
            <ThreatRouteMap threatMap={threatMap} className="h-full" />
          ) : null}
        </div>
      </div>
    </div>
  );
};
