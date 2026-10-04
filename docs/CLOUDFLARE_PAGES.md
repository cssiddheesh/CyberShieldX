# Cloudflare Pages deployment

Cloudflare Pages serves the React frontend as static files; it does not run Flask
or SQLite. The Pages Function in `functions/api/[[proxy]].js` forwards `/api/*`
requests to the Flask server. The frontend continues to use same-origin `/api`
URLs, so no frontend CORS changes are needed. `frontend/build.mjs` writes the
Pages `_routes.json` into the build output, routing only API requests through the
Function and leaving the remaining requests static.

## 1. Push the project to GitHub

Initialize and commit the project if it is not already a Git repository. Confirm
`.env`, `.venv`, `frontend/node_modules`, and the local SQLite database are
excluded by `.gitignore`. Add the GitHub remote URL for your repository and push
the `main` branch.

## 2. Run Flask behind a Cloudflare Tunnel

Keep Flask bound to `127.0.0.1` (the default in `.env.example`) and port `8000`.
On the laptop that runs the app:

1. Install `cloudflared` and authenticate with `cloudflared tunnel login`.
2. Create a named tunnel: `cloudflared tunnel create cybershield`.
3. Route a hostname in a Cloudflare-managed domain to it:
   `cloudflared tunnel route dns cybershield cybershield-api.yourdomain.com`.
4. Create `%USERPROFILE%\.cloudflared\config.yml`, replacing the placeholders:

   ```yaml
   tunnel: <TUNNEL-UUID>
   credentials-file: 'C:\Users\<USERNAME>\.cloudflared\<TUNNEL-UUID>.json'
   ingress:
     - hostname: cybershield-api.yourdomain.com
       service: http://127.0.0.1:8000
     - service: http_status:404
   ```

5. Start `run.bat`, then start the named tunnel in another terminal:
   `cloudflared tunnel run cybershield`.

Both processes must remain running while the site uses the local backend. The
tunnel does not require an inbound port to be opened on the laptop.

## 3. Configure the Cloudflare Pages project

Connect the GitHub repository in **Workers & Pages → Create → Pages → Connect
to Git**. Use:

- Framework preset: **None**
- Build command: `npm --prefix frontend ci && npm --prefix frontend run build`
- Build output directory: `frontend/dist`
- Root directory: repository root
- Environment variable `BACKEND_URL`: `https://cybershield-api.yourdomain.com`

Set `BACKEND_URL` in both Preview and Production environments if both are used.
Do not add a trailing slash. Build with Node.js 18 or newer. After deployment,
`https://<your-pages-hostname>/api/health` should return the backend health JSON.

## Protect the public endpoints

The backend currently has no user authentication. A public Pages URL therefore
allows visitors to use its scan, upload, and settings APIs; a public Tunnel
hostname also allows bypassing Pages entirely. Do not expose this deployment
without access controls.

For a personal deployment, protect the Pages hostname with a Cloudflare Access
user policy and protect the Tunnel hostname with a Cloudflare Access service
auth policy. Create an Access service token and add both values as Pages
environment secrets:

- `BACKEND_ACCESS_CLIENT_ID`
- `BACKEND_ACCESS_CLIENT_SECRET`

The Pages Function sends these credentials only to the configured backend
origin. Requests with only one of the two values configured fail with HTTP 503.
Keep the service-token secret out of source control and do not put it in a
`NEXT_PUBLIC_*`/frontend build variable. The local backend must still be running
for the Pages site to work.
