---
name: security-doctor
description: Audit any web app's security against a battle-tested 33-point checklist, report exactly what's missing with the fix for each gap, then implement the fixes. Covers anon/RLS lockdown, privilege-escalation, auth/2FA, CSP, prompt-injection, payments, and supply chain. Trigger on "security audit", "security check", "is <app> safe to launch", "harden <app>", "run the security checklist", or before launching any app/feature touching auth, payments, uploads, or AI. Stack-portable — deepest on Supabase + Vercel + Stripe.
---

# Security Doctor

**What it does, in one loop:** point it at an app → it runs the checklist, verifying each item **in the code and against the live app** → it produces a **scored report of exactly what's missing and the fix for each gap** → it **implements the fixes** (small ones in the same pass; big/destructive ones proposed first).

Built to be reusable across any app. The knowledge is generalized from real production security audits — real incidents, real fixes. The deepest coverage assumes **static/vanilla or Next.js client + Supabase (Postgres/PostgREST/GoTrue) + Vercel serverless `/api` + Stripe** with a browser-shipped anon key; items marked ⚙ are stack-specific and the underlying laws are portable.

## The one law that drives everything
**The publishable/anon key ships in the client bundle — every permission the `anon` role holds is granted to the entire internet.** A missing GRANT fails closed; a missing RLS policy fails open. And: **verify, never infer** — a finding is real only when a live probe with the public key returned the denial code, not when code "looks admin-only." The five traps that fake success are in `references/checklist.md`; read them before reporting anything green.

## Reference files (load as needed — don't dump all into context)
- `references/checklist.md` — the 33-item scored checklist: what to verify, how to detect each gap (grep/probe), and which fix template applies. **This is the audit spine.**
- `references/fix-templates.md` — 12 copy-paste-and-adapt fixes (SQL + JS), each with pitfalls and the failure mode it closes.
- `references/knowledge-base.md` — the *why* behind every check: the incident class that taught it, grouped by theme. Read a section when a finding is subtle or the user asks why.

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

For a large surface, fan out read-only sub-agents by section (DB/RLS, auth, CSP/headers, payments, AI, supply chain) and merge — but you own the merge and the live re-verification.

### 3. Report (exactly what's missing + the fix)
Produce, in the final message:
1. **Scored table** — `item · status · evidence`.
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
Where the stack supports it, leave the **anon-probe harness + source ratchet** ([T2]) wired into CI so the fix can't silently regress. A guard that passes before the fix is worthless — confirm it fails first.

## Adapting to a non-Supabase / non-Vercel app
The checklist's intent is universal; only the mechanism changes. Authorization must key on a server-trusted identity claim (not a client field); privileged fields must be non-writable by the client; every privileged route re-checks server-side; untrusted content into an LLM gets fenced; secrets never reach the client or git history; CSP/headers ship enforcing after a report-only bake. Translate each ⚙ item to the target's equivalent (row security, grants, middleware) and keep the process laws in `knowledge-base.md §i` verbatim — they're stack-agnostic.
