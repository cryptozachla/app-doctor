# Security Doctor — The Scanner Layer

The 33 manual checks are things you verify by hand or by live probe. This layer is the **automated scanners** that catch whole CLASSES the manual pass structurally can't see: supply-chain malware, your own code's taint paths, live external exposure, and CI-workflow attack surface. Run them as part of every audit; wire the cheap ones into CI as a ratchet.

**They complement, never replace, the checklist** — and a scanner result still obeys *verify, never infer*: read the findings, carry a known control, and **never trust a CRITICAL from a heuristic scanner without reading the code** — a security *tool* and a security *threat* share vocabulary, so scanners routinely flag a security skill's own threat-catalog or defensive docs as malicious. (Seen in practice: a skill-scanner rated a top-tier audit firm's Semgrep runner CRITICAL because its SKILL.md said *"never auto-execute commands that modify…"* — the scanner matched the safety guidance as the threat.)

## The six scanners

### 1 · Supply-chain malware — Socket / OSV-Scanner
**Gap:** `npm audit` only knows *disclosed CVEs*. It catches zero typosquats, hijacked-maintainer packages, or malicious install scripts — the packages with no advisory the day they land. This is the single class conventional SCA is structurally blind to.
- **Socket** (behavioral, GitHub App) — flags a dependency that reads env, opens network, or runs install scripts. Install the GitHub App → it comments on PRs. Deepest on the JS ecosystem.
- **OSV-Scanner** (CLI) — `osv-scanner scan --recursive .` — advisory + malicious-package feed; covers Python `requirements.txt` / Go too.
Run on every dependency change.

### 2 · Deep SAST on your own code — Semgrep CE
**Gap:** nothing in the manual pass scans *your own code* semantically. Semgrep taint-tracks user input → sink: an unsanitized param into a DB `.rpc()`/raw SQL, `dangerouslySetInnerHTML`, an SSRF `fetch`, a route missing its auth check.
```bash
pipx install semgrep
semgrep --config p/javascript --config p/nodejs --config p/owasp-top-ten \
  --exclude vendor --exclude node_modules <src dirs>
```
Add `p/python`, `p/react`, `p/typescript`, `p/jwt`, `p/secrets`, `p/sql-injection` as the stack warrants. `--sarif -o out.sarif` for CI. Registry rulesets work out of the box; tune false positives over time.

### 3 · Verified secrets — TruffleHog
**Gap:** a regex secret scanner (gitleaks) tells you a string *looks* like a key — noise (rotated keys, examples, test values). TruffleHog **live-verifies** — it logs into the provider to confirm the key still works — turning "500 hits to triage" into "3 that actually work, rotate these." It also scans surfaces gitleaks doesn't: Docker images, cloud buckets, CI logs, a built mobile bundle.
```bash
brew install trufflehog
trufflehog filesystem <dir> --results=verified,unknown
trufflehog git <repo-url> --only-verified
```
Keep gitleaks for the fast full-history regex sweep; add TruffleHog as the verification layer on top. A leaked service-role / admin key bypasses ALL row-security work — this is the backstop.

### 4 · Live DAST — Nuclei
**Gap:** every manual check is static / config-time. Nuclei is the only *external* probe of the DEPLOYED app — exposed `.env`, exposed DB-studio / admin consoles, backup files, default creds, known-CVE fingerprints, and headers/CSP verified **as served from the edge** (not just as configured).
```bash
brew install nuclei
nuclei -u https://<host> -tags exposure,misconfiguration \
  -severity low,medium,high,critical -rate-limit 20
```
Own infra / authorized targets only. Run weekly or post-deploy, not per-commit. `-sarif-export` to fail CI.

### 5 · CI / GitHub Actions hardening — zizmor
**Gap:** once you run security IN CI, your CI *is* attack surface — it holds prod secrets. zizmor is SAST for workflow YAML: unpinned actions (tag not SHA — the supply-chain-poisoning class), expression injection via `${{ github.event.* }}`, over-broad `GITHUB_TOKEN`, credential persistence on checkout.
```bash
pipx install zizmor
zizmor .github/workflows/
```
**Fix pattern:** pin every `uses:` to a full commit SHA; set job-level `permissions:` least-privilege; add `persist-credentials: false` to `actions/checkout`; never splice `github.event` text into a `run:` block (assign to an `env:` var first).

### 6 · LLM red-team — promptfoo
**Gap:** prompt-injection fencing is written once and never regression-tested. promptfoo turns "I fenced it" into a repeatable gate: it re-runs a jailbreak / injection / tool-abuse suite against your LLM ROUTE (system prompt + fences + tools) every deploy, so a prompt-template edit can't silently reopen the hole. It tests the *application*, which is what ships.
```bash
npm i -g promptfoo   # or: npx promptfoo@latest redteam run
```
Write a redteam config per LLM endpoint. Scope to **tool-using agent routes** (where injection → tool abuse is the real risk); overkill for a one-shot summarizer.

## Companion agent skills (audit-firm methodology)
Installable skills that add process the checklist doesn't have. Vet any third-party skill before install (a skill-scanner such as NVIDIA `skillspector`), but **read the code on any CRITICAL for a security skill** — false positives are the norm there.
- **`differential-review`** (Trail of Bits) — security review of a git diff / PR; catches per-change regressions where the checklist audits whole-app state.
- **`static-analysis` / semgrep** (Trail of Bits) — a fuller SAST pipeline (semgrep + CodeQL + SARIF merge) than a single semgrep pass.
- **`agentic-actions-auditor`** (Trail of Bits) — audits AI-agent GitHub Actions for attacker input reaching the agent in CI; pairs with zizmor.

## Where each fits the run
- **Code pass:** Semgrep + TruffleHog + zizmor.
- **Live pass:** Nuclei against every deployed host.
- **Dependency review:** Socket / OSV.
- **AI routes:** promptfoo.
- **Ratchet (CI, every push):** gitleaks + Semgrep + zizmor + the anon-probe harness. Nuclei weekly. promptfoo on the agent routes.

A scanner that finds nothing is a *result*, not a formality — record it (0 findings from Semgrep/TruffleHog/Nuclei is evidence the manual hardening held). And apply the same honesty as the rest of the audit: verify the scanner actually ran (a skipped/errored scan reads identical to a clean one).
