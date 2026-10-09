import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Le proxy redirige les appels /api vers le backend FastAPI (port 8080).
// Ainsi, le frontend appelle /api/... sans se soucier de l'URL complète,
// et il n'y a pas de problème de CORS en développement.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
