# Security Doctor — The Checklist

The scored audit — 33 manual checks (verify by hand/probe) + a 6-tool **scanner layer** (domain 9, items 34–39; see `tooling.md`). Each item: what to verify, how to detect the gap (grep or live probe), and the fix-template number ([T#] in `fix-templates.md`). **Report a checkbox as ✅ only with file:line evidence or a live-probe/scanner result — never from "looks fine."** Status values: ✅ done · ❌ gap · ⚠️ partial/hardening-only · ⏭️ n/a (say why).

Items marked ⚙ are stack-specific (Supabase/Vercel) — translate the intent for other stacks; the underlying law (in `knowledge-base.md`) is portable.

## Transport & headers
1. **HSTS** — `curl -sI <prod-url> | grep -i strict-transport`. Vercel default on custom domains; flag only if a custom server strips it.
2. **Secure cookie flags** — every `Set-Cookie` carries `Secure; HttpOnly; SameSite`. Grep `Set-Cookie`, `cookies.set`. UI-hint cookies readable by JS may skip HttpOnly deliberately — note it, don't fail it.
3. **Security headers present** — `X-Content-Type-Options: nosniff`, `X-Frame-Options` (SAMEORIGIN if the app iframes itself, DENY otherwise), `Referrer-Policy`, `Permissions-Policy`, `base-uri`, `object-src 'none'`. `curl -sI` + read `vercel.json`/server config. [T10]
4. **CSP** — enforcing, no `unsafe-inline` in `script-src` where achievable; `report-uri` wired; a report row under `disposition:"enforce"` = a real regression. Report-Only → collect → enforce. [T10]

## Auth flows
5. **Sessions reset on password change** — `signOut({scope:'others'})` after in-app change; `{scope:'global'}` on emailed reset. Grep `updateUser`, `signOut`. Verify the reset flow actually OFFERS a set-new-password screen (`PASSWORD_RECOVERY` handler → password form → `updateUser({password})`). ⚠️ **Grep the LIVE-served JS, not a stale local checkout** — staleness makes "no `updateUser` anywhere" a false positive when the fix already shipped. [KB §c]
6. **Reset links expire + redirect allowlist** — Supabase default; verify the redirect allowlist covers app + beta hosts. Standalone `/reset` page, synchronous token capture, `detectSessionInUrl:false`. [KB §c]
7. **Failed-login lockout + reset throttling** — DB-backed counter, lock ~8/15min, throttle resets ~3/hr, page the owner at 5. **MUST fail OPEN.** [T7]
8. **User enumeration** — audit sign-in/reset/signup messages. Deliberate exposure (semi-public usernames) is a documented UX call — check code comments before "fixing." Email flows answer uniformly. [KB §c]
9. **2FA/MFA server gate** ⚙ — if 2FA exists, the SERVER gate is the security (aal2 on every privileged endpoint), not the modal. **Fail CLOSED.** Do NOT gate the whoami endpoint. Backup-code tables = RLS-on-no-policies + grants revoked. [T8]
10. **Session robustness** ⚙ — Supabase JS: in-memory serializing lock (not `navigator.locks`, not no-op), JWT decoded from localStorage on boot, `refreshSession` on foreground. Grep `createClient`, `getSession`, `getUser`. [KB §c]

## Payments (skip section if no payments — say so)
11. **Verify payment webhooks** — Stripe signature on every webhook route; other webhooks Ed25519/HMAC. Grep `constructEvent`, `verify`. Handle `charge.dispute.created/.closed` (unhandled dispute = auto-lose). [KB §h]
12. **Prices server-side** — client NEVER sends an amount; server derives price from the product/tier row. Grep checkout routes for `amount` in request bodies. Test key on Preview only, live on Production. [KB §h]

## AI surfaces (skip if no LLM)
13. **Prompt-injection fencing** — any route putting outside text (emails, SMS, transcripts, reviews, form fields) into an LLM must delimit it, label it untrusted DATA, forbid promises, ignore staff-impersonation. **Check interpolations into the SYSTEM prompt** (a sender name is a vector — sanitize to a tight charset). [T9]
14. **Cap AI usage** — per-request caps + spend-shaped limits on anything a stranger can trigger. Human-in-the-loop for money/credential/policy actions. [KB §f/g]

## Request hygiene
15. **Limit request size** ⚙ — Vercel's 4.5MB default counts; flag custom servers only.
16. **Sanitize before storing/rendering** — `esc()`/framework escaping on every user string reaching innerHTML; note `dangerouslySetInnerHTML`. React escapes by default. Grep `innerHTML`, `dangerouslySetInnerHTML`.
17. **Lock down CORS** — no `*` on credentialed routes; postMessage origins EXACT-match allowlists (never `endsWith('.domain')`). Grep `Access-Control-Allow-Origin`, `postMessage`, `origin`.
18. **Whitelist upload types** ⚙ — presigned uploads carry an enforced contentType; bucket MIME allowlist. Supabase Storage matches `allowed_mime_types` EXACTLY (strip `;codecs=`). [KB §h]

## Surface area
19. **Admin routes gated** — every admin page behind middleware + server-side role check (+2FA where it exists); no debug/test routes reachable without a role check. Middleware runs before filesystem; normalize the pathname. [T11]
20. **Server-side admin re-check** — every privileged endpoint resolves the caller server-side and checks role by an **un-forgeable auth column** (`auth_id`), never a client-writable field, never a client "isAdmin" flag. Verify with a real 200/403, not "not 403." [T5, KB §b]
21. **Remove pre-launch test scaffolding** — grep `TEST BYPASS`, `ADMIN LOCATION OVERRIDE`, unauthenticated test endpoints that spoof state, payout bypasses. `git rm` before launch.
22. **CSRF** ⚙ — mostly n/a for bearer-token APIs; REQUIRED if any state-changing endpoint authenticates via cookies alone.
23. **Directory listing** ⚙ — n/a on Vercel; check on any custom static host.

## Data & visibility (the Supabase core — often where the real gaps are)
24. **Anon write lockdown** ⚙ — anon role has no INSERT/UPDATE/DELETE except explicitly-granted analytics/feedback. Live-probe every table (send a REAL column value; read the 42501 MESSAGE). Catalog-generated revoke, not a typed list. [T1, T2]
25. **Column-level exposure** ⚙ — no bearer tokens / PII / push-subscription keys readable by anon on public-read tables. Probe PER COLUMN (`select=*` 42501 is the column trap). Table-level revoke + named re-grant. [T3]
26. **RLS on sensitive tables** ⚙ — no `USING(true)`; owner-scoped policies with `WITH CHECK`; service-role-only tables = RLS-on-no-policies + grants revoked. Query `pg_policies WHERE qual='true'`. [T4]
27. **SECURITY DEFINER RPC exposure** ⚙ — every DEFINER function revoked from `anon, public`, `search_path` pinned, `ALTER DEFAULT PRIVILEGES ... REVOKE EXECUTE ... FROM anon`. Probe `/rest/v1/rpc/<fn>` with the anon key. [T5]
28. **Privilege-escalation columns** ⚙ — `is_admin`/`banned`/`credit`/`points` not writable by `authenticated` or `anon` (column REVOKE); optional BEFORE-UPDATE guard trigger; anon INSERT on users/profiles table revoked. Probe `PATCH is_admin` as a signed-in non-admin. [T6, KB §b]
29. **Metered/unauthenticated endpoints throttled** — routes that email/SMS/spend need a verified session or a DB rate-limit; unauthenticated collectors (CSP, error log) throttled per IP, always 204. Grep `notify`, `send`, service-role routes. [T12]
30. **Log security events + alert** — auth bursts, 403s on fences, CSP reports flow into the app's error pipeline → owner alert. No pipeline = a gap on its own. [T12]

## Supply chain & CI
31. **No secrets in git history** — `gitleaks` with `fetch-depth: 0`; rotate anything found; `.gitleaks.toml` allowlists public-by-design keys.
32. **Dependency scan** — `npm audit --audit-level=high`; committed lockfile.
33. **Security tests wired into CI** — the anon-probe harness + source ratchet run in an actual CI job; every new assertion FAILS against the unfixed state first. [T2]

---
## Automated scanner layer (domain 9 — run alongside the manual checks; catches classes the checklist structurally can't. Full detail in `tooling.md`)
34. **Supply-chain malware** — Socket (behavioral) or OSV-Scanner on every dependency change. `npm audit` only knows disclosed CVEs; this catches typosquats / hijacked / malicious-install-script packages with no advisory yet. [Tooling §1]
35. **Deep SAST on own code** — Semgrep (`p/javascript p/nodejs p/owasp-top-ten` + stack rulesets) taint-tracks input→sink in your own routes. No SAST otherwise. [Tooling §2]
36. **Verified secrets** — TruffleHog `--only-verified` / `--results=verified,unknown` live-validates keys (a leaked service-role key bypasses all RLS). Layer on top of gitleaks, don't replace. [Tooling §3]
37. **Live DAST** — Nuclei (`-tags exposure,misconfiguration`) against every deployed host; the only *external* probe (exposed `.env`, DB-studio leak, headers-as-served). Own/authorized targets, weekly. [Tooling §4]
38. **CI / Actions hardening** — zizmor on `.github/workflows/`: unpinned actions (SHA-pin), `${{ github.event.* }}` injection, over-broad `GITHUB_TOKEN`, `persist-credentials`. Your CI holds prod secrets = attack surface. [Tooling §5]
39. **LLM red-team regression** — promptfoo redteam suite per tool-using agent route, so a prompt edit can't silently reopen the fencing. Turns manual fencing into a CI gate. [Tooling §6]

---
**Scoring output:** a table `item · status · evidence (file:line, live-probe, or scanner result)`, then the gap list in priority order (live-fire / unauthenticated-escalation first), then fixes. Small fixes: implement in the same pass. Big/destructive: propose first. Record 0-finding scanner runs as evidence — and verify each scanner actually ran (a skipped/errored scan reads identical to a clean one).

**The five traps that look like success:** (a) a test that passed because it never ran (empty body, skipped-when-unconfigured, `before()` skip-eval bug); (b) an error from the wrong layer (PGRST204/PGRST202/22P02 ≠ denied); (c) revoking a column while the table grant stands (silent no-op); (d) assuming a function is private from its name (read the code path); (e) fixing the DB before deploying the client change (deploy the query fix first).
