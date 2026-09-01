# Launch Checklist — the pre-app / launch-readiness pass (domains 10–13)

Companion to `checklist.md` (the 39-point security spine). Where that file asks "can this app be hacked?", this one asks "is this app *ready* — legally, functionally, and commercially?" Run it before any launch, App Store submission, or paid-tier go-live; run the relevant domain after big feature drops. Score items ✅/❌/⚠️/⏭️ with evidence, same as the security pass.

Sources: distilled from creator checklists (@murphmaxxing legal, @haydenschmitty auth, @yatesvids polish, @chris.raroque retention) cross-checked against real production launch work. Treat any third-party dollar-liability figures as scare numbers, not statutes — the *items* are sound.

---

## Domain 10 — Legal & compliance (the "don't get sued" pass)

**L1. Privacy policy exists and is linked** from the app, the marketing site footer, and the App Store listing. Apple rejects without one; regulators fine without one.
**L2. The policy says what you actually collect** — accounts, reviews, photos, location, analytics events. Generic template text that doesn't match reality is worse than none.
**L3. AI use is disclosed** — if any surface sends user content to an LLM (support chat, agents, generation features), the policy must say so and name the class of provider.
**L4. Third-party processors are named** — list every service user data touches (typ.: Supabase, Stripe, Vercel, Resend, Telnyx, Meta Pixel/CAPI, OpenAI/Anthropic, analytics). Detect: grep the codebase for API hosts and compare against the policy's list.
**L5. Deletion promises are honored** — if the product promises upload/account deletion, verify the storage object and DB rows actually go away (probe: delete a test upload, then fetch its storage URL — a 200 is a finding). Apple also requires in-app account deletion for apps with accounts.
**L6. No private data in public storage buckets** — public-read is fine for content that is meant to be public; it is a finding for anything user-private. Detect ⚙: list Supabase buckets, check `public` flag against what each holds; probe an unauthenticated object fetch.
**L7. No fabricated testimonials/reviews on marketing surfaces** — FTC territory. Every quote on the site must trace to a real person who said it. Detect: read the marketing site, ask the owner for provenance of each testimonial.
**L8. Cancellation is as easy as signup** (click-to-cancel) — a subscriber must be able to cancel in-app / via a Stripe billing-portal link without emailing support. Detect: walk the cancel path as a test subscriber.
**L9. Free trials / auto-renewals send a pre-charge reminder** — if a trial converts to paid, a reminder email/notification must fire before the first charge. Stripe: `send_upcoming_invoice` / trial-ending webhook → email.
**L10. AI chat surfaces have a self-harm/crisis response** — any user-facing chatbot needs a canned, escalating response for self-harm or crisis content (and it belongs in the KB/guardrail file with the injection fence, so red-team it alongside).

## Domain 11 — Auth hardening extras (adds to checklist.md's auth domain)

**A1. Password-reset endpoint is rate-limited** — login usually gets rate limits; the reset endpoint is the one that ships without them. ⚙ Supabase GoTrue has defaults — verify they're not lifted, and that any custom reset route (the app's own `/api` wrapper) has its own limiter. Also verify the reset FLOW dead-ends nowhere (a reset email that lands on a page that can't set a password is a launch blocker).
**A2. Breached-password screening** — ⚙ Supabase Auth → "leaked password protection" (HaveIBeenPwned) toggle ON, plus a minimum client-side strength rule (length + not-common). Detect: try signing up with `password123`.
**A3. Session token storage reviewed** — supabase-js defaults to localStorage; with an enforced CSP and no XSS surface this is an accepted risk, but *record it as a decision*, don't let it be an accident. Migrating to httpOnly-cookie auth is only worth it for high-value targets.
**A4. Server-side authorization everywhere** (already checklist.md's core — cross-reference, don't re-audit): client-side admin checks are decoration; every privileged route re-checks on the server.
**A5. 2FA proportional to stakes** — admin/vendor/money-touching accounts: required. Consumer review accounts: optional, don't add friction.

## Domain 12 — Launch polish sweep (the 20-minute last-mile pass)

Run this list against EACH live surface (app + marketing site), mobile viewport first. Most items are one-line fixes; batch them.

1. No horizontal scroll on any page (`overflow-x: clip`, not `hidden` — hidden breaks position:sticky)
2. No broken links (crawl internal links; check footer links specifically)
3. Mobile menu works
4. Favicon present (and OG card — see the OG memories)
5. Page titles are real (no "Vite App" / "Untitled")
6. Meta descriptions on indexable pages
7. Custom 404 page
8. Copyright year current (or use a dynamic year)
9. Images compressed (and cache-busted when replaced)
10. No dead/broken buttons
11. Every form has a success state AND an error state
12. No placeholder/lorem text anywhere
13. No unused nav items
14. No mobile overflow; every page mobile-optimized
15. Logo clicks to home
16. Phone numbers are `tel:` links; emails are `mailto:` links
17. (per-stack extras for iOS web: input-zoom fix, safe-area insets, dvh-based modals)

## Domain 13 — Day-one retention & commercial readiness

**R1. Home-screen widget ships WITH the iOS app, not after** — creator-reported +25% week-1 retention (small sample, right direction). The widget must show *glanceable changing state* (e.g., live status, prices near you, or a streak), never a static logo shortcut. Capacitor: native WidgetKit extension.
**R2. Pricing sanity** — don't launch underpriced; annual plan with a visible save-%; trials without upfront card where acquisition matters.
**R3. Push permission asked in context** (after a value moment, not on first open).
**R4. The "share to a friend" path exists** — share card / deep link per key object (spot, review, vendor).

---

## Field lessons (from running this pass on real apps)

- **Legal links must be absolute when app and site live on different subdomains.** A signup page on `app.<domain>` linking relative `/privacy.html` 404s silently — the policy "exists" and is still unreachable from the exact page that needs it. Probe the link from the served page, not the repo.
- **A shared password `minlength` bump can lock out existing users.** Raising the floor on a password input reused by BOTH signup and sign-in blocks legacy accounts (shorter passwords) from signing in at the HTML-validation layer. Raise it for signup only; sign-in keeps the old floor and users upgrade via reset.
- **Auth-user CASCADE never reaches storage objects.** `admin.deleteUser` cleans DB rows with `ON DELETE CASCADE`, but uploaded files (and rows with `ON DELETE SET NULL`) silently orphan. Account deletion must explicitly wipe the user's storage prefix and SET-NULL tables first — then probe a deleted upload's public URL (a 200 is a finding).
- **Every separately-billed add-on needs its own cancel affordance.** A base-plan cancel flow doesn't satisfy click-to-cancel for an add-on that is its own subscription; put a manage/cancel button (billing-portal link is enough) in the add-on's own UI.
- **A crisis guardrail belongs in the shared prompt source.** Add it to the one guardrails array/KB every customer-facing AI surface inherits (email, SMS, chat, voice) — per-route additions drift.
- **Re-verify "known open" gaps before fixing them.** A remembered bug may have been fixed since (a remembered "broken reset flow" turned out to be already fixed in production). The served bundle is the truth; diff it against the repo before writing a finding OR a fix.

## How this pass reports

Same as the security pass: scored table per domain, gaps in priority order (legal blockers → auth extras → retention → polish), each gap with its concrete fix. Legal items (L1–L10) are launch **blockers** for a paid or App Store product; polish items batch into one cleanup commit; R-items are roadmap recommendations, not blockers — say which is which.
