---
name: app-doctor
description: Security Doctor + Pre-App/Launch Checklist. Audit any web app's security against a battle-tested 39-point checklist (33 manual checks + a 6-tool automated scanner layer) AND its launch-readiness against a 4-domain pre-app checklist (legal/compliance, auth hardening extras, last-mile polish, day-one retention), report exactly what's missing with the fix for each gap, then implement the fixes. Covers anon/RLS lockdown, privilege-escalation, auth/2FA, CSP, prompt-injection, payments, and supply chain — plus a scanner layer (Semgrep SAST, TruffleHog verified secrets, Nuclei live DAST, zizmor CI hardening, Socket supply-chain malware, promptfoo LLM red-team). Trigger on "security audit", "security check", "is <app> safe/ready to launch", "harden <app>", "run the security checklist", "pre-launch check", "launch checklist", "pre-app check", "app doctor", or before launching any app/feature touching auth, payments, uploads, or AI. Stack-portable — deepest on Supabase + Vercel + Stripe.
---

# App Doctor (Security Doctor + Pre-App Checklist)

**What it does, in one loop:** point it at an app → it runs the checklist, verifying each item **in the code and against the live app** → it produces a **scored report of exactly what's missing and the fix for each gap** → it **implements the fixes** (small ones in the same pass; big/destructive ones proposed first).

Built to be reusable across any app. The knowledge is generalized from real production security audits — real incidents, real fixes. The deepest coverage assumes **static/vanilla or Next.js client + Supabase (Postgres/PostgREST/GoTrue) + Vercel serverless `/api` + Stripe** with a browser-shipped anon key; items marked ⚙ are stack-specific and the underlying laws are portable.

## The one law that drives everything
**The publishable/anon key ships in the client bundle — every permission the `anon` role holds is granted to the entire internet.** A missing GRANT fails closed; a missing RLS policy fails open. And: **verify, never infer** — a finding is real only when a live probe with the public key returned the denial code, not when code "looks admin-only." The five traps that fake success are in `references/checklist.md`; read them before reporting anything green.

## Reference files (load as needed — don't dump all into context)
- `references/checklist.md` — the 39-item scored checklist (33 manual + 6 scanner): what to verify, how to detect each gap (grep/probe/scan), and which fix template applies. **This is the audit spine.**
- `references/fix-templates.md` — 12 copy-paste-and-adapt fixes (SQL + JS), each with pitfalls and the failure mode it closes.
- `references/tooling.md` — the **scanner layer** (domain 9): Semgrep, TruffleHog, Nuclei, zizmor, Socket/OSV, promptfoo + audit-firm companion skills. Install + exact command + what class each catches that the manual pass can't. Load when running the automated pass or wiring CI.
- `references/knowledge-base.md` — the *why* behind every check: the incident class that taught it, grouped by theme. Read a section when a finding is subtle or the user asks why.
- `references/launch-checklist.md` — the **pre-app / launch-readiness pass** (domains 10–13): legal & compliance (privacy-policy disclosures incl. AI use + named processors, deletion promises, public buckets, testimonials, click-to-cancel, trial reminders, AI self-harm response), auth hardening extras (reset rate-limit, breached-password screening), the 20-minute last-mile polish sweep, and day-one retention (widget, pricing, share paths). Load for any launch/readiness request, or alongside the security pass before a launch.

## Workflow

### 0. Scope
Confirm the target app and its stack. Ask which surfaces are in play (auth? payments? uploads? AI/LLM? admin panel?) so you can skip inapplicable sections honestly rather than stretch them. If a third-party agent skill is about to be installed as part of the work, vet it first (a skill-scanning tool such as NVIDIA's `skillspector` is a good companion here).

### 1. Recon (build the map before judging)
- Identify prod + beta/preview hosts, the API routes (`api/**`), the DB tables and RPCs, the middleware, the client entry files.
- ⚠️ **The local checkout may be STALE** relative to what's deployed (many teams push from a separate clone or CI, so a working copy can lag the live branch). A code-read finding ("no `updateUser` anywhere") is a false positive if the fix already shipped. For any item you judge by grepping client code, **also grep the live-served bundle** (`curl -s <host>/js/app.js?v=<live-version>`) before calling it a gap — the served file is the truth, the working copy is a maybe. Reconcile against a fresh clone before ANY push.
- ⚙ Supabase: pull the anon/publishable key from live page source. Get real column names + id types from `GET /rest/v1/` with the SERVICE key + `Accept: application/openapi+json` (you need these to write valid probes).
- Load `references/checklist.md`.

### 2. Audit (verify every item — code + live)
Walk the checklist top to bottom. For each item:
- **Grep the code** for the pattern named in the checklist, AND
- **Live-probe** where the checklist says to (anon writes, DEFINER RPCs, `is_admin` PATCH, headers via `curl -sI`, CSP via the browser console `--headed`).
- Record status (✅/❌/⚠️/⏭️) **with evidence** — `file:line` or the exact probe result. Never mark ✅ from appearance.
- Probing rules that keep you honest (full detail in `knowledge-base.md` §e): read the 42501 MESSAGE not just the code; send a REAL column value (a `{}` PATCH proves nothing); a bare `[]` proves nothing; probe PER COLUMN; carry a known-blocked AND a known-open control; probe inserts without `return=representation`. **Every probe that writes must write something the product cannot surface** (draft/inactive state, or a constraint-violating payload that never creates a row) — and clean up.

**Run the scanner layer (domain 9 — `tooling.md`).** Alongside the manual checks, run the automated scanners that catch classes the checklist can't: **Semgrep** (SAST on the app's own code), **TruffleHog** `--only-verified` (secrets), **zizmor** (`.github/workflows/`) during the code pass; **Nuclei** (`-tags exposure,misconfiguration`, own/authorized hosts only) during the live pass; **Socket/OSV** at dependency review; **promptfoo** against tool-using LLM routes. Install one-liners + exact commands are in `tooling.md`. Record 0-finding runs as evidence, and confirm each scanner actually ran (a skipped/errored scan looks identical to a clean one). Treat a heuristic scanner's CRITICAL on a *security* skill/tool as a likely false positive — read the code before believing it.

For a large surface, fan out read-only sub-agents by section (DB/RLS, auth, CSP/headers, payments, AI, supply chain, scanner layer) and merge — but you own the merge and the live re-verification.

### 2b. Launch-readiness pass (when the ask is "ready to launch?", a launch is near, or the user asks for the pre-app checklist)
Load `references/launch-checklist.md` and walk domains 10–13 the same way — verify, don't infer: read the live privacy policy against the actual API hosts in the code; walk the cancel flow as a test subscriber; probe a deleted upload's storage URL; run the polish sweep against the live mobile viewport. Legal items are launch blockers; polish batches into one commit; retention items are recommendations. A pure security ask can skip this pass; a pure launch ask still runs the security spine's critical items (anon probes, privilege escalation) — an app is not "ready" if it's leaking.

### 3. Report (exactly what's missing + the fix)
Produce, in the final message:
1. **Scored table** — `item · status · evidence`.
1b. **The App Doctor Score — one number out of 100, always.** The score answers "how much of this was already set up before we walked in?" — an app that had nearly everything done scores high and hears so plainly; an app with a handful of greens scores low.

   **Weights (74 checks, 210 possible points):**
   - 🔴 **Critical — 5 pts each (14 items):** security #11 webhook signatures, #12 prices server-side, #13 prompt-injection fencing, #19 admin routes gated, #20 server-side admin re-check, #24 anon write lockdown, #25 column exposure, #26 RLS, #27 DEFINER RPC exposure, #28 escalation columns, #31 secrets in git; launch L1 privacy policy exists, L5 deletion honored, L6 no private data in public buckets. These are the exploitable-now / sue-now items.
   - 🟡 **Important — 3 pts each (40 items):** every other security item #1–33, the 6 scanner checks #34–39, launch L2–L4 + L7–L10, and A1–A5.
   - 🟢 **Polish — 1 pt each (20 items):** the domain-12 polish sweep (16) + domain-13 retention (4).

   **Formula:** `score = round(100 × points earned ÷ points applicable)`. ✅ = full points, ⚠️ = half, ❌ = zero. ⏭️ N/A items leave the denominator entirely — but N/A means *structurally inapplicable* (no payments → #11–12 out; no AI → #13, L10, #39 out), never "didn't get to it." A scoped audit scores only the domains actually walked and says so next to the number.

   **Honesty caps (the number must not flatter):**
   - Any open 🔴 security critical → score is **capped at 49**, whatever the arithmetic says.
   - No security criticals but an open 🔴 legal blocker (L1/L5/L6) → **capped at 69**.
   - When a cap bites, show both: `Score: 49 (capped — underlying 78) — 1 critical open`.

   **Bands:** **90–100** launch-ready, gaps are polish — tell them they barely needed the audit. **75–89** nearly there — one focused day closes it. **50–74** real gaps — the fix pass is the value. **≤49** not safe / not ready — criticals first, everything else after.

   Print it as the first line of the report: `🩺 App Doctor Score: NN/100 — <band> (NNN/NNN pts across NN applicable checks)`.
2. **Gap list in priority order** — unauthenticated privilege-escalation and live data leaks first, then auth/payment, then hardening. For each gap: one line on the risk, and the concrete fix (point at the fix-template number and paste the adapted SQL/code).
3. **The fix plan** — which gaps you'll implement now vs. which need a decision.

If the user was only *asking* whether the app is safe (not asking you to change it), stop here — the report is the deliverable.

### 4. Implement (fix what's safe to fix)
- **Small, reversible fixes** (add a header, revoke a grant with a known re-grant, wire a guard, add a probe test): implement in the same pass, following the fix templates.
- ⚙ Ordering constraints are load-bearing — deploy the client query fix BEFORE the column revoke; move call sites off a column with a `PGRST202` fallback before revoking; verify every new test assertion FAILS against the unfixed state first.
- **Destructive / broad / prod-affecting** (schema-wide revokes, RLS enablement, CSP enforce flip): propose with the exact migration, don't surprise. Ship CSP Report-Only first.
- Respect the repo's deploy policy (branch-and-PR vs direct push, beta channel vs prod). When in doubt, ask which target. Paste SQL inline in a ```sql block AND save it as a migration file.
- Preview any UI-affecting change; then **verify live** the fix actually landed (real signal, known control) and **don't over-verify** — one clean pass, then ship.

### 5. Prove it (leave a ratchet)
Where the stack supports it, leave the **anon-probe harness + source ratchet** ([T2]) wired into CI so the fix can't silently regress. A guard that passes before the fix is worthless — confirm it fails first. Add the cheap scanners to the same CI gate — **gitleaks + Semgrep (SARIF) + zizmor** on every push; **Nuclei** weekly / post-deploy; **promptfoo** on the agent routes (`tooling.md`). Each scanner in CI is a standing ratchet against the class it covers.

## Adapting to a non-Supabase / non-Vercel app
The checklist's intent is universal; only the mechanism changes. Authorization must key on a server-trusted identity claim (not a client field); privileged fields must be non-writable by the client; every privileged route re-checks server-side; untrusted content into an LLM gets fenced; secrets never reach the client or git history; CSP/headers ship enforcing after a report-only bake. Translate each ⚙ item to the target's equivalent (row security, grants, middleware) and keep the process laws in `knowledge-base.md §i` verbatim — they're stack-agnostic.
