// ═══════════════════════════════════════════════════
// Tab Error Boundary - Catches per-tab render errors + React Query errors
// ═══════════════════════════════════════════════════

import { Component, ReactNode, createContext, useContext, useState, useCallback, useEffect } from 'react';
import { AlertTriangle, RotateCcw, WifiOff } from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';

interface Props {
  children: ReactNode;
  tabName: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

// Context for children to report query-level errors that ErrorBoundary can't catch
const TabErrorContext = createContext<{
  reportError: (error: Error) => void;
  clearError: () => void;
} | null>(null);

export class TabErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo): void {
    console.error(`[TabErrorBoundary] "${this.props.tabName}" crashed:`, error, errorInfo);
  }

  handleRetry = (): void => {
    this.setState({ hasError: false, error: null });
  };

  // Exposed for query-level error reporting
  reportQueryError = (error: Error): void => {
    console.error(`[TabErrorBoundary] "${this.props.tabName}" query failed:`, error);
    this.setState({ hasError: true, error });
  };

  clearQueryError = (): void => {
    this.setState({ hasError: false, error: null });
  };

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <ErrorFallback tabName={this.props.tabName} error={this.state.error} onRetry={this.handleRetry} />
      );
    }

    return (
      <TabErrorContext.Provider value={{ reportError: this.reportQueryError, clearError: this.clearQueryError }}>
        {this.props.children}
      </TabErrorContext.Provider>
    );
  }
}

// ── Error fallback UI ──
function ErrorFallback({ tabName, error, onRetry }: { tabName: string; error: Error | null; onRetry: () => void }) {
  return (
    <div className="flex items-center justify-center min-h-[300px] p-6">
      <div className="cyber-card p-8 max-w-lg w-full text-center">
        <div className="flex justify-center mb-4">
          <div className="w-16 h-16 rounded-full bg-cyber-red/10 border border-cyber-red/30 flex items-center justify-center">
            <AlertTriangle size={32} className="text-cyber-red" />
          </div>
        </div>
        <h2 className="text-xl font-bold text-cyber-text mb-2">
          Tab Error
        </h2>
        <p className="text-sm text-cyber-textMuted mb-1 font-mono">
          {tabName}
        </p>
        <p className="text-sm text-cyber-textMuted mb-6">
          Something went wrong while loading this tab. The rest of the dashboard is unaffected.
        </p>
        <div className="cyber-card p-4 mb-6 text-left bg-cyber-darker/50">
          <pre className="text-xs text-cyber-red font-mono break-all whitespace-pre-wrap">
            {error?.message || 'Unknown error'}
          </pre>
        </div>
        <button
          onClick={onRetry}
          className="inline-flex items-center gap-2 px-6 py-2.5 rounded-md bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent font-semibold text-sm hover:bg-cyber-accent/20 transition-all cursor-pointer"
        >
          <RotateCcw size={14} />
          Retry
        </button>
      </div>
    </div>
  );
}

// ── Hook for tab components to surface query errors to the ErrorBoundary ──
export function useTabQueryError() {
  const context = useContext(TabErrorContext);
  const queryClient = useQueryClient();
  const [retryCount, setRetryCount] = useState(0);

  const reportError = useCallback((error: Error) => {
    context?.reportError(error);
  }, [context]);

  const clearError = useCallback(() => {
    context?.clearError();
  }, [context]);

  // Invalidate queries on retry to trigger re-fetch
  const retry = useCallback(() => {
    setRetryCount(c => c + 1);
    queryClient.invalidateQueries();
    clearError();
  }, [queryClient, clearError]);

  return { reportError, clearError, retry, retryCount };
}

// ── Inline error state component for useQuery results ──
// Usage: <QueryErrorState error={query.error} isError={query.isError} onRetry={query.refetch} tabName="TabName" />
export function QueryErrorState({ error, isError, onRetry, tabName }: {
  error: Error | null;
  isError: boolean;
  onRetry: () => void;
  tabName: string;
}) {
  if (!isError || !error) return null;

  return (
    <div className="flex items-center justify-center min-h-[300px] p-6">
      <div className="cyber-card p-8 max-w-lg w-full text-center">
        <div className="flex justify-center mb-4">
          <div className="w-16 h-16 rounded-full bg-cyber-red/10 border border-cyber-red/30 flex items-center justify-center">
            <WifiOff size={32} className="text-cyber-red" />
          </div>
        </div>
        <h2 className="text-xl font-bold text-cyber-text mb-2">
          Failed to Load Data
        </h2>
        <p className="text-sm text-cyber-textMuted mb-1 font-mono">
          {tabName}
        </p>
        <p className="text-sm text-cyber-textMuted mb-4">
          Could not reach the server. Check your connection and try again.
        </p>
        <div className="cyber-card p-4 mb-6 text-left bg-cyber-darker/50">
          <pre className="text-xs text-cyber-red font-mono break-all whitespace-pre-wrap">
            {error.message}
          </pre>
        </div>
        <button
          onClick={onRetry}
          className="inline-flex items-center gap-2 px-6 py-2.5 rounded-md bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent font-semibold text-sm hover:bg-cyber-accent/20 transition-all cursor-pointer"
        >
          <RotateCcw size={14} />
          Retry
        </button>
      </div>
    </div>
  );
}