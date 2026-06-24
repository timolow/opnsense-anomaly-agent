// ═══════════════════════════════════════════════════
// Tab Query Wrapper - Unified loading/error handling per tab
// Wraps tab children with skeleton loaders during loading
// and error UI with retry button on failed queries.
// Usage:
//   const { data, isLoading, isError, error, refetch } = useQuery(...);
//   return (
//     <TabQueryWrapper tab="alerts" isLoading={isLoading} isError={isError} error={error} onRetry={refetch}>
//       {/* actual tab content using data */}
//     </TabQueryWrapper>
//   );
// ═══════════════════════════════════════════════════

import React from 'react';
import { AlertTriangle, RotateCcw, WifiOff } from 'lucide-react';
import { TabSkeleton } from './SkeletonLoaders';

interface Props {
  children: React.ReactNode;
  tab: string;
  isLoading: boolean;
  isError: boolean;
  error?: Error | null;
  onRetry?: () => void;
}

export function TabQueryWrapper({ children, tab, isLoading, isError, error, onRetry }: Props) {
  // Loading state: show skeleton that mimics actual tab layout
  if (isLoading) {
    return <TabSkeleton tab={tab} />;
  }

  // Error state: show user-friendly error with retry
  if (isError) {
    const errorMessage = error?.message || 'Failed to load data';
    const isNetworkError = errorMessage.toLowerCase().includes('fetch') ||
                           errorMessage.toLowerCase().includes('network') ||
                           errorMessage.toLowerCase().includes('failed') ||
                           errorMessage.toLowerCase().includes('unavailable');

    return (
      <div className="flex items-center justify-center min-h-[300px] p-6">
        <div className="cyber-card p-8 max-w-lg w-full text-center">
          <div className="flex justify-center mb-4">
            <div className="w-16 h-16 rounded-full bg-cyber-red/10 border border-cyber-red/30 flex items-center justify-center">
              {isNetworkError ? (
                <WifiOff size={32} className="text-cyber-red" />
              ) : (
                <AlertTriangle size={32} className="text-cyber-red" />
              )}
            </div>
          </div>
          <h2 className="text-xl font-bold text-cyber-text mb-2">
            {isNetworkError ? 'Connection Error' : 'Data Error'}
          </h2>
          <p className="text-sm text-cyber-textMuted mb-6">
            {isNetworkError
              ? 'Unable to reach the backend API. Check your connection and try again.'
              : `Something went wrong while loading data: ${errorMessage}`
            }
          </p>
          <div className="cyber-card p-4 mb-6 text-left bg-cyber-darker/50">
            <pre className="text-xs text-cyber-red font-mono break-all whitespace-pre-wrap">
              {errorMessage}
            </pre>
          </div>
          {onRetry && (
            <button
              onClick={onRetry}
              className="inline-flex items-center gap-2 px-6 py-2.5 rounded-md bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent font-semibold text-sm hover:bg-cyber-accent/20 transition-all cursor-pointer"
            >
              <RotateCcw size={14} />
              Retry
            </button>
          )}
        </div>
      </div>
    );
  }

  return <>{children}</>;
}