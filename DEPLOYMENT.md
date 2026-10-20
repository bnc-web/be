# Hosted BNC deployment

Production API: https://be-chi-one.vercel.app
Production app: https://bnc-ui.vercel.app
Vercel workspace: `buildkart1` (display name BUILDKART), Hobby plan.

The API runs on Vercel Python functions in Mumbai. The app uses Supabase
PostgreSQL, Supabase authentication and private Supabase Storage. No production
service connects to localhost or requires the laptop to stay running. Production
secrets are stored as Vercel environment variables and excluded from deployments.
The existing `.env` and `.env.local` remain local development configurations.

The UI proxies `/api/*` to the API so its HTTP-only refresh cookie works on the
app origin. Production cookies use Secure and SameSite=Lax. Supabase's site URL
and redirect allowlist include the production app URL.

## Operations

Backend project: https://vercel.com/buildkart1/be
Frontend project: https://vercel.com/buildkart1/bnc-ui
Database: https://supabase.com/dashboard/project/avbdslhviowhxgsbiwlt

From each repository directory, publish with:

```powershell
npx vercel deploy --prod --scope buildkart1
```

The backend repository is connected to Vercel. The frontend was published with
the CLI: Vercel Hobby rejects automatic Git integration for private organization
repositories. Its repository remains private. Future frontend releases can use
the CLI without changing repository visibility or upgrading the plan.

Database migrations are applied explicitly with `python -m alembic upgrade head`;
they do not run during builds or function startup. Migration 0023 enables RLS on
backend-only tables; public Supabase API roles have no policies granting access.
For Android-to-web admin handoff, apply migration 0024 before enabling the client
flow. It uses the configured Supabase Admin API key to issue a separate browser
session, so the native refresh token is not rotated. Keep Supabase's **Single
session per user** setting disabled to allow the native app and browser to remain
signed in concurrently; Supabase permits multiple active sessions by default.

## First free release limitations

- `PAYMENT_AUTO_VERIFY_ENABLED=false`, `PAYMENT_AUTO_VERIFY_SHADOW_MODE=true`.
- `PAYMENT_OCR_ENABLED=false`: this function bundle has no Tesseract executable.
  Submitted proofs can still be reviewed and approved manually.
- There is no minute-level worker. Gmail Sync now remains available to admins.
  Scheduled reminders, retries and backup processing require a hosted scheduler
  and bounded worker jobs before they can be called automatic.
- SMTP is not configured in the current environment. Outbound application email
  has not been enabled or tested by this deployment.
- Register the following existing OAuth-client redirect URIs before reconnecting
  Google Drive or Gmail on these Vercel domains:
  `https://be-chi-one.vercel.app/api/v1/admin/backups/google/callback` and
  `https://be-chi-one.vercel.app/api/v1/admin/payment-verification/google/callback`.
- The former custom domains still need DNS cutover. The Vercel URLs work directly.
- Free services have quotas. A low-activity Supabase project may pause and need
  resuming from its dashboard. No paid plan or paid service was enabled.

## Verification on 2026-10-20

Supabase was resumed from its paused state. The cloud database contained 52 users
and 211 payments. The schema was upgraded to `0023_backend_tables_rls`; no backend
table accessible to anon/authenticated remained without RLS. Live API health,
unauthenticated access rejection, same-origin refresh, static PWA assets, Google
sign-in and signed-in account/payment history were checked. No real payment was
created, approved, reversed or deleted as a deployment test.
