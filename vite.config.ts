import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const backendTarget = env.VITE_BACKEND_TARGET || env.BACKEND_URL || 'http://127.0.0.1:8000';

  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        '/api': {
          target: backendTarget,
          changeOrigin: true,
          secure: false,
          timeout: 120000,
          proxyTimeout: 120000,
          configure: (proxy) => {
            proxy.on('error', (err, _req, res) => {
              console.warn('[Vite Proxy Warning]:', err.message);
              if (res && !('headersSent' in res && res.headersSent) && 'writeHead' in res) {
                res.writeHead(502, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                  error: {
                    code: 'GATEWAY_TIMEOUT',
                    message: 'Backend connection dropped or timed out. Please ensure the backend is running and retry.'
                  }
                }));
              }
            });
          },
        },
      },
    },
  };
});
