# Security Doctor — Knowledge Base

The distilled, battle-tested lessons behind every check. Each lesson: **principle**, **why** (the incident class that taught it), **detect** (how to find the gap in an arbitrary codebase — grep or live probe), **fix** (concrete pattern). Every pattern here came from a real production audit; adapt it to your own code rather than rebuilding from scratch.

**Assumed stack:** static/vanilla or Next.js client + Supabase (Postgres / PostgREST / GoTrue) + Vercel serverless `/api` + Stripe, with a browser-shipped **publishable/anon key**. Placeholders: `<app>_*` for table names, `<app>` for the product. Items marked ⚙ are stack-specific — adapt for non-Supabase/non-Vercel targets.

---

## (a) Database / RLS / Grants Lockdown

**The publishable/anon key is public — every anon grant is a public grant.**
- WHY: the anon key ships in the browser bundle; anyone reads it from page source and calls PostgREST/RPC directly, bypassing the UI. Anon-writable MFA backup codes would defeat 2FA; anon-readable claims exposed vendor PII.
- DETECT: pull the key from live `app.js`/page source, hit `GET/POST /rest/v1/<table>` and `/rest/v1/rpc/<fn>` directly. Never assume the UI is the only client.
- FIX: treat anon as an untrusted, fully-visible role. Every table/column/RPC needs an explicit grant decision.

**Column-level REVOKE is a silent no-op while a table-level GRANT exists.**
- WHY: Postgres column privileges do not subtract from table privileges. A first attempt "revoked" sensitive columns and changed nothing.
- DETECT: after a column revoke, probe the column with the anon key; if it still returns, the table grant is still there. Sweep `information_schema.column_privileges`.
- FIX: `REVOKE SELECT ON <table> FROM anon;` then `GRANT SELECT (col_a, col_b) ON <table> TO anon;`. Same for UPDATE — `REVOKE UPDATE ON <table>` does NOT remove separately-stored column-level UPDATE grants; sweep `column_privileges WHERE privilege_type='UPDATE'` too. Generate the migration from `pg_class`/`information_schema`, never a hand-typed table list (it drifts).

**`select=*` fails the WHOLE request under a column-level revoke — it does NOT trim to the allowed subset.**
- WHY: PostgREST denies the entire request if ANY named/expanded column is denied → clean `42501` on `select=*` while 134 of 140 columns stay individually readable. This false "42501 = protected" reading invalidated a CI guard and a "launch blocker cleared" report.
- DETECT: never assert lockdown with `select=*`. Probe **per column**. `select=id,secret_col` returning 42501 tells you `secret_col` is denied, not the table.
- FIX: audit column-by-column; capture the real allowlist from live traffic. Any client `select('*')` on a table with a revoked column must be rewritten to a named allowlist or it breaks when the revoke lands.

**Adding a column to an anon-read table breaks the app unless the same migration re-grants it.**
- WHY: an anon SELECT column-list grant does NOT auto-extend to `ADD COLUMN`. New columns 400 the signed-out app's full select, silently dropping it to a minimal fallback. Reflexive "just GRANT it" is how 58 columns leaked.
- DETECT: after any `ADD COLUMN` on an anon-read table, load the signed-out app and watch for 400s / fallback rendering.
- FIX: every new column on an anon-read table needs an explicit **allowlist-or-deny decision per column** in the same migration — never grant reflexively.

**`USING (true)` RLS (or no RLS at all) = world-readable/writable via the anon key.**
- WHY: a vendor-claims table with ZERO RLS gave full anon INSERT/UPDATE/DELETE/SELECT (create an `approved` claim on any listing, read every vendor's email/phone). Promo codes, user addresses, app config all shipped `using(true)`.
- DETECT: query `pg_policies` for `qual = 'true'`; per table compare anon-key read vs service-role read. Audit any table holding bearer-value data (codes, balances, tokens) or PII first.
- FIX: owner-scoped policies keyed on identity, not client-supplied fields. For write-sensitive objects, move creation server-side (service role) and ship **no INSERT policy for anyone**.

**Enabling RLS with a SELECT-only policy revokes the owner's own writes.**
- WHY: once RLS is on, every verb with no matching policy is DENIED. A "select to authenticated" pass would have killed check-ins, support threads, quote requests — the owners' own inserts.
- DETECT: for each table you're about to enable RLS on, enumerate every verb the app performs as that role; a policy must exist per verb.
- FIX: prefer **revoking anon grants** (per-role, reversible with one GRANT, never touches signed-in writes) over enabling RLS with partial policies. If you do enable RLS, write INSERT/UPDATE/DELETE policies alongside SELECT.

**Column-allowlist UPDATE grants are all-or-nothing per statement — one ungranted column takes the whole write down.**
- WHY: `grant update (username, top_5_spot_ids)` would break signup, because `update({username, email})` is ONE statement and the ungranted `email` fails the granted `username` with it.
- DETECT: grep the client for every write naming a to-be-revoked column (including signed-out paths).
- FIX: strict order — additive helper RPCs first → move all client call sites off the raw column (each with a `PGRST202` fallback so deploy order is free) → then the revoke.

**"Returns no rows" ≠ protected; "empty table" ≠ protected. Two separate questions.**
- WHY: a grant-readable column isn't a leak if RLS returns no rows; an empty table isn't safe if the grant is open (the first row written becomes readable — an empty-but-open MFA-codes table was exactly this). Conflating either produces a false all-clear.
- DETECT: ask both — (1) is the grant open? (2) does RLS actually filter rows? Compare anon-count vs **service-role-count**; a bare `[]` proves nothing. Classify each empty table individually (some empties are genuinely public).
- FIX: revoke the grant on empty-and-unguarded tables holding private data; leave genuinely-public empties.

**FK target trap: `user_id` must reference the app's own users table, not `auth.users`.**
- WHY: Supabase's table editor defaults new `user_id` FKs to `auth.users(id)`, but the app exposes `currentUser.id = <app>_users.id` (separate uuid linked via `auth_id`). Mismatch → every signed-in write `23503`, swallowed as a fake success toast.
- DETECT: query `information_schema` constraints; `references_table = users` (bare) points at `auth.users` — wrong.
- FIX: FK to `<app>_users(id)`. Audit claims/reviews/submissions/appeals/page_visits.

---

## (b) Privilege Escalation & Admin Gating

**SECURITY DEFINER RPCs are EXECUTABLE by `anon` by default — Postgres grants EXECUTE to PUBLIC.**
- WHY (critical, verified live): `promote_admin(text)`/`demote_admin(text)` were anon-callable. Full unauthenticated chain: read `profiles` (`USING(true)`) → get admin emails → `demote_admin` the owner → sign up → `promote_admin` yourself.
- DETECT: for every SECURITY DEFINER function, `POST /rest/v1/rpc/<fn>` with the anon key. `200` + the function's return = it RAN. Control: nonexistent RPC → `404 PGRST202`; missing grant → `42501`.
- FIX: `REVOKE EXECUTE ON FUNCTION <fn> FROM anon, public;` and pin `search_path` on every SECURITY DEFINER function.

**Resolve admin identity by an un-forgeable auth column, never by a client-writable field.**
- WHY (critical, verified against prod): admin endpoints looked up `<app>_users?email=eq.<verified-jwt-email>&select=is_admin`. The JWT check was fine; `email` is an ordinary text column. With anon INSERT on the users table, an attacker planted `{email:'victim@x', is_admin:true}` for an address with no account, then signed up on it — the signup trigger **adopted** the planted row (`set auth_id=new.id`) and never reset `is_admin`. Unauthenticated → full admin.
- DETECT: read the admin gate — does it match on `email`/`username`/any client-supplied column? Can anon INSERT into the users/profiles table (probe below)? Does the signup trigger reset privilege columns on adopted rows?
- FIX: resolve by `auth_id` (written by the signup trigger from `auth.users`, cannot be chosen or UPDATEd). Centralize in one helper (`whoIs()`/`adminGate()`). Precondition: verify EVERY admin row has `auth_id` populated — one null admin locks them out instantly.

**Anon INSERT on the users/profiles table is a privilege-escalation primitive even with a unique email constraint.**
- WHY: the unique constraint kills the duplicate-row variant but not the plant-before-signup variant.
- DETECT (safe probe): INSERT with an **existing primary key**. RLS/grant is evaluated before the unique check, so `42501` = revoked (safe), `23505` (duplicate key) = grant+RLS both allowed the write (open). No row is created. An empty `{}` payload is NOT inert — use a payload that hits NOT NULL (`23502`) if you can't use an existing PK.
- FIX: `REVOKE INSERT (is_admin), UPDATE (is_admin) ON <app>_users FROM authenticated, anon;` (zero-risk, closes escalation alone) then revoke table INSERT. A SECURITY DEFINER trigger must create the profile row server-side so removing the client grant doesn't break registration.

**The identity gate is only as good as the column the client cannot write.**
- WHY: even after switching to `auth_id`, while `authenticated` still held `UPDATE (is_admin)`, any signed-in user could PATCH `is_admin` on their own row and the gate faithfully returned true. **Hardening ≠ fix.**
- DETECT: probe `PATCH /rest/v1/<users>?id=eq.<self>` with `{is_admin:true}` as a signed-in non-admin.
- FIX: `REVOKE UPDATE (is_admin) ON <app>_users FROM authenticated, anon;`. Defense-in-depth: a `BEFORE UPDATE` trigger that raises on any privileged-column change (blocks even service role — see `references/fix-templates.md` privileged-column guard).

**Server-side admin re-check on every privileged endpoint — never trust a client "isAdmin" flag or a UI gate.**
- WHY: the modal/panel is UI; anyone with the password skips it in devtools or POSTs directly.
- DETECT: call each `/api/admin-*` route with a plain (non-admin, aal1) token — it must `403`.
- FIX: every admin route resolves the caller server-side and checks `is_admin` by `auth_id` (`requireAdminProfile()`).

**Verify a gate with a REAL 200/expected-success, not "not 403".** A malformed test payload returns 400 whether auth passed or failed — proves nothing. Use a valid payload; confirm the authorized path genuinely succeeds and the unauthorized path genuinely 403s.

**⚙ Non-Supabase equivalent:** the same laws hold anywhere — authorization decisions must key on a server-trusted identity claim (session/JWT sub verified server-side), privileged fields must be non-writable by the client, and every privileged route must re-check server-side. Only the mechanism (grants/RLS) is Postgres-specific.

---

## (c) Auth Flows (lockout, reset, enumeration, 2FA, sessions)

**Login-failure lockout as defense-in-depth + visibility; MUST fail OPEN.**
- WHY: brute-force/credential-stuffing visibility — but a guard outage must never block real sign-ins.
- DETECT: does the guard's outage branch return `{locked:false, degraded:true}` or block?
- FIX: GET-check / POST-record against `<app>_security_events`; lock at ~8 failures/15min, page the operator at 5 via the error pipeline. On any guard error, return not-locked. Honest scope: with a client SDK talking to Supabase directly, **Supabase's own auth rate limits are the hard wall** — this is signal + speed bumps.

**Revoke other sessions on password change / reset.** `signOut({scope:'others'})` after an in-app password change; `signOut({scope:'global'})` on reset (kills attacker sessions; supabase-js v2 default is global). A reset flow must actually let the user SET a new secret — a recovery link that signs in with no set-password screen is a dead end (real bug, months live).

**Password reset: dedicated standalone page, synchronous token capture, `detectSessionInUrl:false`.**
- WHY: an in-app `?auth=reset` sheet was unreliable — `PASSWORD_RECOVERY` race, Supabase stripping the query, native app opening links in Safari not the WebView.
- FIX: standalone `/reset` page: capture the recovery token from the URL hash synchronously → `setSession` (or `exchangeCodeForSession` for PKCE) → wipe token from URL → `no-referrer` + `noindex` → render the form only with a valid recovery session → `signOut()` on success. Whitelist the redirect URL in Supabase Auth → URL Configuration.

**Enumeration is a deliberate, documented decision — not an accident.** Decide per-app; document in code comments. Close it by returning one identical response for found/not-found; the recovery endpoint should use one identical error for every failure mode on purpose.

**2FA (TOTP): the SERVER gate is the security; the modal is UI. Gate at choke points, not login handlers.**
- FIX: server gate (`mfaGate(accessToken)`) requires `aal2` when the account has a verified factor; wire into every privileged endpoint. Client challenge fires on the BOOT path, not the sign-in handler.
- **Do NOT gate the whoami/identity endpoint** — it's the call that tells the panel you're an admin, which must happen BEFORE the panel can challenge. Gate it and the challenge never fires → permanent lockout.
- **Unenrolled accounts pass the gate** (so unenrolled admins aren't locked out) — but that's exactly what made the anon-admin-escalation chain work. The real fix is the identity column, not 2FA.
- Recovery codes are yours: 8 single-use, server-generated, sha256-salted with user_id, shown once. Recovery endpoint takes password AND one code, REMOVES the factor, never mints a session. Rate-limit 5/15min by email AND ip, **one identical error per failure mode**. Backup-code tables: RLS ON with **no policies** = service-role only.
- aal1 vs aal2: `signInWithPassword` and `/auth/v1/user` accept an **aal1** token — don't add a TOTP prompt to routes that don't enforce aal2.

**Supabase JS `navigator.locks` deadlocks auth across tab suspension on iOS — but a no-op lock is ALSO wrong.**
- WHY: iOS Safari holds a `navigator.locks` lock across suspension; on resume `getSession()`/`getUser()` hang forever. A fully no-op lock lets a background auto-refresh race a manual one → rotating refresh tokens invalidate each other → session silently dies, every read 401s.
- FIX: pass an **in-memory serializing lock** (mutual exclusion in-page, 10s ceiling, no `navigator.locks`) to `createClient`. Never call `getSession()`/`getUser()` on load/resume — decode the JWT straight from `localStorage` (`sb-<ref>-auth-token`, `atob(token.split('.')[1])`), `refreshSession({refresh_token})` only when `exp` is past. On `visibilitychange` resume call `refreshSession()` in a `Promise.race` timeout. Route auth errors (401/JWT/PGRST301) to sign-out, don't retry.

**Cross-subdomain session sharing: chunked cookie on the parent domain, byte-identical in every file.**
- WHY: `localStorage` is per-origin; a cookie caps ~4KB and an encoded session is ~2.7KB — overflow **silently truncates**, login "works" then vanishes next page.
- FIX: a `storage` adapter that CHUNKS across `key.0`/`key.1` behind a `__chunks:<n>` marker, reads fall back to `localStorage`, skips the cookie off the real domain. Must stay byte-identical across all copies or a session written by one side is unreadable by the other.

**Anti-bot signup: gate value behind email confirmation + server-side captcha.**
- WHY: ~53 bot accounts farmed 10 free credits each. A client captcha widget alone is useless — bots POST straight to the Supabase auth API with the anon key.
- FIX: (1) grant the signup bonus only from an `AFTER UPDATE OF email_confirmed_at` trigger with an idempotency boolean; profiles start at 0 credits. (2) Cloudflare Turnstile wired into ALL captcha-protected calls (signUp, signInWithPassword, resend, resetPasswordForEmail) AND enabled server-side in the Supabase dashboard — enable both together or all auth breaks.

---

## (d) CSP & Security Headers

**Ship CSP Report-Only first; flip to enforcing only when a byte-identical policy has logged zero real violations.**
- WHY: a blocking CSP missing one source does not degrade — the feature dies for 100% of users, silently. Report-Only can't break prod.
- FIX: run Report-Only across real traffic + drive the QA harness through every flow. Diff the enforced string against the proven report-only string (must be byte-identical). Swap header key `Content-Security-Policy-Report-Only` → `Content-Security-Policy` (one-word instant rollback). A report row under `disposition:"enforce"` now = a real break.

**Enumerate EVERY fetch-destination directive explicitly — a passing page load proves nothing about media/assets the user must click to reach.** Real gaps that each killed a feature when enforced:
- `connect-src` missing the custom API CNAME (`api.<app>.app`) and the Realtime `wss://`.
- `worker-src`/`child-src` missing `blob:` → **MapLibre GL builds workers from blob URLs, map dies for everyone.**
- `media-src` absent → `<audio>`/`<video>` fall back to `default-src`, Supabase-storage media silently blocked (killed all audio for 5 days; a same-origin splash video kept working and hid it).
- DETECT: the harness must run **`--headed`** (headless has no WebGL, never exercises the blob-worker path). Read the **console** (`grep "violates the following Content Security Policy"`), not the reports table — Chrome batches CSP reports with 17–55s lag. Fire a deliberate control (`fetch('https://control.example.net/x')`) into the same buffer and confirm it appears, or "zero violations" and "logging broken" are indistinguishable.
- FIX: explicitly enumerate `connect-src` (custom-domain REST + `wss://`), `worker-src 'self' blob:`, `child-src 'self' blob:`, `media-src 'self' data: blob: <storage-origin>`, `img-src`, `font-src`.

**`'unsafe-inline'` in `script-src` can only drop once EVERY inline script and inline handler is gone — partial work buys ZERO benefit.** Extract all inline `<script>` to files; convert inline `on*` to delegated `data-ev/data-fn` bound by one capture-phase dispatcher that resolves `data-fn` **by name** (bare-identifier check + eval/Function/fetch/open denylist), never as source. Verification traps: cached HTML keeps the old CSP header (cache-bust); DevTools-evaluated JS has its own CSP exemption (inject by having the PAGE create the element, confirm with a `securitypolicyviolation` listener).

**Baseline security headers on every response:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (+ CSP `frame-ancestors`), `Referrer-Policy`, `Permissions-Policy`, `Strict-Transport-Security` `includeSubDomains`, `base-uri`, `object-src 'none'`. HSTS is a Vercel default on custom domains.

**SRI + `crossorigin` on all CDN scripts; pin exact versions.** Floating `@2` tags mean an upstream change ships arbitrary code. Verify SRI in a real browser with a deliberately-wrong hash as the negative control; self-host where practical.

---

## (e) Probing / Verification Methodology

**`42501` is the ONLY trustworthy "grant is gone" signal — and it means two opposite things, so read the MESSAGE not the code.**
- `42501 "permission denied for table X"` = the GRANT is gone (safe).
- `42501 "new row violates row-level security policy"` = the grant is STILL there; only a policy refused THAT row. Scoring both as "blocked" hid ~12 writable tables.
- Codes that are NOT permission results: `400 PGRST204` ("column not found" — PostgREST's own check, before Postgres); `22P02` (id filter type wrong); `55000` (unwritable view); `23502` (NOT NULL — grant present, constraint hit); `23505` (duplicate — grant+RLS passed). Get real column names + id types from `GET /rest/v1/` with the SERVICE key + `Accept: application/openapi+json`.

**Never trust a scanner/probe/grep result without asserting it against a case whose answer you already know — and the control must span the failure mode.** A control that shares the broken assumption is decoration. Carry MULTIPLE controls spanning every id shape and both outcomes (a known-blocked uuid-id table, a known-blocked integer-id table, a known-OPEN insert). Report UNKNOWN rather than folding ambiguity into "open". No-match UPDATE/DELETE filters: `<col>=is.null&<col>=not.is.null` (type-agnostic, matches nothing), never a hard-coded uuid.

**PostgREST insert/`Prefer: return=representation` rolls back on insert-only tables → false "blocked".** `return=representation` SELECTs the row back after inserting, so on an insert-only table the whole transaction fails 42501 and rolls back — every insert-only table reads as blocked. Probe inserts WITHOUT `return=representation`, or cross-check against a table the live app is known to write.

**A test that skips itself when unconfigured is silently green.** `node:test` evaluates `skip:` at REGISTRATION before `before()` runs, so a reachability probe must be top-level await. Default URL + publishable key IN the test file so it can't skip itself; verify the guard FAILS before the fix (a guard that passes pre-fix is worthless). Invert `APPLIED` flags: if an unapplied-stage assertion starts passing, the suite FAILS.

**Guards must be pinned by occurrence COUNT, not just signature.** A fresh `select('id, email')` slid under an existing single-call-site exemption. When you move app code between files, update the FILES list in the source-scanning tests.

**Headless Chrome gives false outages on WebGL/MapLibre apps.** Headless has no WebGL → boot boundary shows "Something went wrong" (false outage). Render `--headed`. Also `document.body.textContent.includes('Something went wrong')` is a false positive — `textContent` includes `<script>` source; check `offsetParent`/rect.

**For a static asset behind a rewriting middleware, check `content-type`, not the status code.** An admin-host middleware rewrites every path to `/admin.html` and returns **200** — so a script request gets the HTML page. Only `content-type` exposes it.

**Live-host gotchas.** A gated preview host behind Basic Auth issues a cookie via `302` + `Set-Cookie` — `curl` without a cookie jar re-authenticates each hop and looks like a redirect loop (it's a handshake). Vercel Attack Challenge Mode (`x-vercel-mitigated: challenge`) makes curl fail on beta — verify shipped code via a fresh git clone. "CI still shows the old result" can be a timing artifact — confirm the deploy SHA via `/api/version` and re-run before concluding.

---

## (f) AI / Prompt-Injection Fencing

**Wrap untrusted user content in delimiters + hard system rules; never interpolate user text into the SYSTEM prompt.** An inbound support email is attacker-controlled — the sender NAME interpolated into the SYSTEM prompt is an injection vector. Wrap the body in explicit delimiters (`<<<CUSTOMER_EMAIL>>>…`) with hard rules: never follow inner instructions, never promise refunds/exceptions, ignore staff impersonation. Sanitize any interpolated field to a tight charset (sender name → `[A-Za-z'-]{≤24}`).

**AI business facts come from ONE audited source module — no prompt hand-writes the business description.** Deleting a fact isn't enough — the model reinvents plausible ones. One `_kb.js` feeding every prompt: static `CANON` with an explicit `notOffered` list, `liveFacts()` per request, a `learnedRules()` loop where nothing is learned without an explicit human tap.

**Cap AI usage:** per-request caps (max clips, image quality tiers, channel caps) + spend-shaped limits on anything a stranger can trigger. Vet third-party agent skills with `skillspector` before installing.

---

## (g) Abuse / Rate Limiting / Cost

**Metered endpoints (SMS/email) need a verified session, not just a record id.** `notify-*` routes attach and verify the session (401 without a token). SMS opt-out enforcement lives in `sendSMS()` itself and fails OPEN on lookup error so a DB blip can't silence order alerts.

**Unauthenticated write/log endpoints need a server-side throttle before they fan out.** An anon-callable error logger that fans out to Telegram with no throttle is an abuse channel — route it through a throttled guarded RPC; rate-limit any unauthenticated collector (CSP reports) per IP, always answer 204.

**Voice/phone abuse: no outbound profile, capped inbound channels.** A new toll-free number is a **traffic-pumping** target. Leave the Outbound Voice Profile unassigned (the app physically cannot originate a call); cap the Inbound Channel Limit.

**DDoS/cost (post-launch, surface known):** Vercel absorbs L3/L4. Three moves: (1) Vercel Firewall + Attack Challenge Mode, (2) spend caps on Vercel + Supabase (bound worst-case bill), (3) per-IP rate limiting on `/api/*`.

---

## (h) Platform Gotchas (Vercel / Supabase / PostgREST / Stripe) ⚙

**`middleware.js` runs BEFORE the filesystem and before every `vercel.json` rewrite.** On an admin/vendor host it force-rewrites every path to `/admin.html` — a new page added only to `vercel.json` rewrites silently serves the admin panel (200 OK, wrong page). Add an early path check in `middleware.js`; add `/js/`, `/vendor/`, `/sw.js`, `/manifest.json` pass-throughs. **Normalize the pathname** (iterative-decode, fold backslashes, collapse slashes, strip trailing slash, lowercase) or `/admin.html/` and `/%2fadmin.html` both serve the panel.

**Basic-Auth middleware gates ALL `/api` including crons and webhooks — bypass self-authenticated routes explicitly** (`return NextResponse.next()` for `/api/cron/*` and named webhook paths; they carry their own secret/signature). Read creds from env with no hardcoded fallback; unset password → whole site 401s (fail closed).

**PostgREST returns an ARRAY on success, an OBJECT on error — array-destructuring turns any 400 into an opaque 500.** `const [row] = await r.json()` on an error object throws `TypeError: not iterable`. `const rowsOf = v => Array.isArray(v)?v:[];` and log the parsed body on any write failure.

**PostgREST caps a response at 1000 rows regardless of `limit`.** Page with `Range` headers for full coverage. `limit=200,extra_col` is an invalid param that 500s the query.

**`encodeURIComponent` does NOT neutralize SQL `LIKE` metacharacters — PostgREST decodes `%25`→`%` and rewrites `*`→`%`.** User input in an `ilike.` position is an injection/enumeration vector; validate the alphabet (allow `[A-Za-z0-9.-]`, kill `% _ * \`).

**Vercel "sensitive" env vars are write-only — `vercel env pull` writes `""`.** Normal, not corruption. Keep a copy of local creds in your own secrets store outside the repo.

**Env-pasted secrets can carry an embedded newline mid-value; `.trim()` misses it.** A line-wrapped JWT survives `.trim()`, then `Headers.set` throws `invalid header value`. Normalize base64/JWT/hex env secrets with `.replace(/\s+/g,"")`.

**Stripe webhook API-version drift silently corrupts writes.** The webhook destination defaulted to a newer API version than the pinned SDK; `subscription.current_period_end` moved to `items.data[0].current_period_end` → `undefined` → NULL period_end. Use a defensive accessor; verify `charge.dispute.created/.closed` are handled.

**Payments integrity:** recompute pricing server-side (never trust a client amount); a price change = copy + a NEW immutable Stripe Price + the env var (all three); test secret on Preview only, live on Production; **destination charges make YOU merchant-of-record, liable for every chargeback** — handle `charge.dispute.created` (unhandled = auto-lose).

**Pre-launch test scaffolding is a live hole — remove before launch.** Unauthenticated test endpoints that spoof state (`git rm`), admin-only payout bypasses, hardcoded location overrides. Grep `TEST BYPASS`, `ADMIN LOCATION OVERRIDE`. Scope any QA bypass to a single account, never all admins.

**Supabase Storage matches `allowed_mime_types` EXACTLY.** `MediaRecorder` emits `audio/webm;codecs=opus` → 415. Strip the `;codecs=` parameter client-side; cap bucket sizes.

**Client-side gated UI must be JS-injected, not hardcoded markup hidden by a separate CSS file.** If the workspace syncs `index.html` without the sibling CSS/JS, hardcoded-then-hidden markup renders exposed. Create gated DOM in JS behind the flag.

---

## (i) Process Rules (the meta-laws)

- **Fail OPEN for availability guards, fail CLOSED for auth/access.** Lockout guards, SMS opt-out lookups, alert-config reads → not-blocked on error. Auth middleware with no password, cron secret checks, admin gates → deny. Decide per guard, make it visible (`degraded:true`).
- **A security probe that writes must write something the product cannot surface.** A "anon cannot write announcements" probe POSTed `is_active:true` → real announcements shown to every visitor. Probe payloads go in disabled/draft state; prefer probes that CANNOT write; add a residue check; service-role cleanup in the same run.
- **Verify live, against a known control, with the real signal.** `42501` (right message), anon-count vs service-count, real 200 not "not 403", `content-type` not status code, console not reports table, `--headed` not headless, cache-buster on header changes.
- **Empty ≠ protected; readable-column ≠ leaked.** Two independent questions (grant open? RLS filtering rows?) — per table, per column.
- **Per-column, not per-table.** PostgREST fails the whole request on any denied column → table-level checks give false all-clears.
- **Hardening ≠ fix.** State plainly which you shipped; don't mark the item closed on the hardening step.
- **A guard that passes before the fix is worthless.** Verify every new assertion FAILS against the unfixed state first. Wire tests into an actual CI job.
- **Live actions have real side effects — batch, don't iterate live.** Every rehearsal run sends REAL email; every probe against an open verb writes a real prod row. Diagnose against the service key directly; run the full live flow only to CONFIRM.
- **Don't over-verify.** One clean pass then ship; flag wasted time rather than creating it — balanced against never concluding presence/absence from a single look.
