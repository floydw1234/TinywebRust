import { defineConfig, loadEnv } from 'vite'
import type { Plugin } from 'vite'
import react from '@vitejs/plugin-react'

// Dev server for the TinyWebC test UI.
// - Binds 0.0.0.0:5173 so it is reachable over Tailscale at http://100.122.205.122:5173
// - Proxies /api/* to the node on localhost:8000 (path prefix stripped),
//   so browser calls are same-origin and avoid CORS entirely.
// - API-key gate (added Nov 14, 2026 at William's request): the page is also
//   exposed publicly as https://dev.tinyweb.win through a Cloudflare tunnel,
//   so EVERY request (page, assets, and the /api proxy) requires a private key:
//     * an X-Api-Key header equal to the key, or
//     * a tw_dev_key cookie equal to the key, or
//     * a first visit to /?key=<key>, which sets the cookie and redirects to /
//   The key is read from TW_DEV_KEY in webui/.env.local (gitignored) and is
//   never committed. If no key is configured, the gate fails closed (401).

function apiKeyGate(key: string): Plugin {
  return {
    name: 'tw-dev-api-key-gate',
    configureServer(server) {
      // A plain configureServer hook registers before Vite's internal
      // middlewares, including the /api proxy, so the gate covers both.
      server.middlewares.use((req, res, next) => {
        const deny = () => {
          res.statusCode = 401
          res.setHeader('Content-Type', 'text/plain; charset=utf-8')
          res.end('Unauthorized: a valid API key is required.')
        }
        if (!key) return deny()
        if (req.headers['x-api-key'] === key) return next()
        const cookieHeader = req.headers.cookie || ''
        const match = cookieHeader.match(/(?:^|;\s*)tw_dev_key=([^;]*)/)
        if (match && decodeURIComponent(match[1]) === key) return next()
        const url = new URL(req.url || '/', 'http://localhost')
        if (url.pathname === '/' && url.searchParams.get('key') === key) {
          res.setHeader(
            'Set-Cookie',
            `tw_dev_key=${encodeURIComponent(key)}; Path=/; HttpOnly; Secure; SameSite=Lax`,
          )
          res.statusCode = 302
          res.setHeader('Location', '/')
          res.end()
          return
        }
        return deny()
      })
    },
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const devKey = env.TW_DEV_KEY || process.env.TW_DEV_KEY || ''
  if (!devKey) {
    console.warn(
      '[tw-dev-gate] TW_DEV_KEY is not set (see webui/.env.local) - the gate will reject all requests.',
    )
  }
  return {
    plugins: [react(), apiKeyGate(devKey)],
    server: {
      host: '0.0.0.0',
      port: 5173,
      allowedHosts: ['dev.tinyweb.win'],
      proxy: {
        '/api': {
          target: 'http://localhost:8000',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
      },
    },
  }
})
