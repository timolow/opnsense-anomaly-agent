// ═══════════════════════════════════════════════════
// TabShell - ErrorBoundary wrapper per tab
//
// Catches render-time crashes and shows a user-friendly
// error with retry button. The rest of the dashboard
// remains unaffected.
//
// Usage in App.tsx TabContent:
//   case 'alerts':
//     return (
//       <TabShell tab="alerts" tabName="Threat Alerts">
//         <AlertsTab />
//       </TabShell>
//     );
// ═══════════════════════════════════════════════════

import { Component, ReactNode } from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
  tab: string;
  tabName: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class TabShell extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error): void {
    console.error(`[TabShell] "${this.props.tab}" crashed:`, error);
  }

  handleRetry = (): void => {
    this.setState({ hasError: false, error: null });
  };

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="flex items-center justify-center min-h-[300px] p-6">
          <div className="cyber-card p-8 max-w-lg w-full text-center">
            <div className="flex justify-center mb-4">
              <div className="w-16 h-16 rounded-full bg-cyber-red/10 border border-cyber-red/30 flex items-center justify-center">
                <AlertTriangle size={32} className="text-cyber-red" />
              </div>
            </div>
            <h2 className="text-xl font-bold text-cyber-text mb-2">
              Tab Crashed
            </h2>
            <p className="text-sm text-cyber-textMuted mb-1 font-mono">
              {this.props.tabName}
            </p>
            <p className="text-sm text-cyber-textMuted mb-6">
              This tab encountered a critical error. The rest of the dashboard is unaffected.
            </p>
            <div className="cyber-card p-4 mb-6 text-left bg-cyber-darker/50">
              <pre className="text-xs text-cyber-red font-mono break-all whitespace-pre-wrap">
                {this.state.error?.message || 'Unknown error'}
              </pre>
            </div>
            <button
              onClick={this.handleRetry}
              className="inline-flex items-center gap-2 px-6 py-2.5 rounded-md bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent font-semibold text-sm hover:bg-cyber-accent/20 transition-all cursor-pointer"
            >
              <RotateCcw size={14} />
              Retry
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

// ── Inline error state for useQuery results ──
// Usage: <TabQueryError error={query.error} isError={query.isError} onRetry={query.refetch} tabName="TabName" />
export function TabQueryError({ error, isError, onRetry, tabName }: {
  error: Error | null;
  isError: boolean;
  onRetry: () => void;
  tabName: string;
}) {
  if (!isError || !error) return null;

  const isNetworkError = error.message.toLowerCase().includes('fetch') ||
                         error.message.toLowerCase().includes('network') ||
                         error.message.toLowerCase().includes('failed') ||
                         error.message.toLowerCase().includes('unavailable');

  return (
    <div className="flex items-center justify-center min-h-[300px] p-6">
      <div className="cyber-card p-8 max-w-lg w-full text-center">
        <div className="flex justify-center mb-4">
          <div className="w-16 h-16 rounded-full bg-cyber-red/10 border border-cyber-red/30 flex items-center justify-center">
            <AlertTriangle size={32} className="text-cyber-red" />
          </div>
        </div>
        <h2 className="text-xl font-bold text-cyber-text mb-2">
          {isNetworkError ? 'Connection Error' : 'Data Error'}
        </h2>
        <p className="text-sm text-cyber-textMuted mb-1 font-mono">
          {tabName}
        </p>
        <p className="text-sm text-cyber-textMuted mb-6">
          {isNetworkError
            ? 'Unable to reach the backend API. Check your connection and try again.'
            : 'Something went wrong while loading data.'}
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