# Reviewer console

Run the Rust API, then `npm ci` and `npm run dev` in this directory. Open [local console](http://127.0.0.1:5173). The API authentication configuration selects managed browser sign-in or explicitly enabled development reviewer tokens. Development tokens stay in page memory; managed sessions use server-controlled cookies and CSRF protection.

The loopback Vite server forwards `/v1/` and `/auth/` to `http://127.0.0.1:8080`. This is a local development setup. Managed issuer/HTTPS production acceptance is separate work.

Approval filters combine connection, currency, inclusive integer minor-unit amount bounds and minimum recorded queue age. Amount filtering requires a currency. Historical unknown queue ages are labeled and excluded only when an age filter is active. Assigned-authority filtering awaits an explicit assignment model; connection grants still determine which rows a reviewer may see. Confirmation submits the unchanged server generation and digest.

Evidence search/exports and scoped operations use their own server authorization. Console visibility never grants permission. Run `npm run api:generate` after the OpenAPI contract changes; `npm run api:check` and `npm run build` validate generated types and the bundle. Browser behavior also requires verification.
