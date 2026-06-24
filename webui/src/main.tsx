import React from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';
import './index.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchInterval: 30000,
      staleTime: 10000,
      retry: 2,
      networkMode: 'online',
    },
  },
});

// Global query error handler — logs failures for debugging
queryClient.getQueryCache().config.onError = (error, query) => {
  console.error(`[QueryError] "${query.queryKey.join('.')}":`, error.message);
};

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>
);
