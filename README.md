# SE4030 — Secure Software Development — Assignment

Securing an existing open-source MERN application: identifying and fixing
vulnerabilities, and adding an OAuth 2.0 / OpenID Connect sign-in flow.

---

## 1. Submission details

> **ACTION REQUIRED — fill these four fields in before you submit.**
> They are the only placeholders left in this repository.

| Field | Value |
|---|---|
| **Member name** | Amila Devin Senarathne |
| **Index number** | `<<YOUR INDEX NUMBER>>` |
| **GitHub — original project** | https://github.com/TheLordA/Instagram-Clone |
| **GitHub — modified project** | https://github.com/amila1998/SE4030-Assignment---Instagram-Clone-master |
| **YouTube video (≤ 20 min)** | `<<YOUTUBE LINK>>` |

### About the original project

| | |
|---|---|
| Name | Instagram-Clone (MERN Stack) |
| Author | Anass Ferrak ("TheLordA") |
| Repository | https://github.com/TheLordA/Instagram-Clone |
| Last upstream commit | `ddc1b1e` — **9 March 2022** (semester starts 1 July 2026, so this predates it by over four years) |
| Licence | ISC |
| Stack | MongoDB, Express.js, React.js, Node.js |

It is a general-purpose social application (posts, likes, comments,
follow/unfollow, bookmarks, image upload, password reset). It is **not** a
deliberately vulnerable teaching application — it is a real project with 130+
stars whose flaws are genuine mistakes, not planted exercises.

---

## 2. What was done

| Deliverable | Status |
|---|---|
| ≥ 7 distinct vulnerabilities identified | **12 found** |
| Vulnerabilities fixed | **12 fixed**, one commit each |
| Black-box + white-box tooling | npm audit, Semgrep (community + custom rules), manual review, runtime probes |
| OAuth 2.0 / OIDC feature | **Sign in with Google** — Authorization Code + PKCE |
| Commit history with detailed messages | Every fix is its own commit with full rationale |
| Report | [`REPORT.md`](REPORT.md) / `REPORT.pdf` |

### Vulnerabilities fixed

| ID | Vulnerability | OWASP | Severity |
|---|---|---|---|
| VULN-01 | Unauthenticated user-search endpoint (mass PII disclosure) | A01 | High |
| VULN-02 | Password-reset tokens leaked via `GET /user/:id` → account takeover | A01 / A02 | **Critical** |
| VULN-03 | NoSQL operator injection in all authentication queries | A03 | **Critical** |
| VULN-04 | Regex injection + ReDoS in user search | A03 | High |
| VULN-05 | JWTs never expired; no algorithm pinning; weak signing key | A07 / A02 | High |
| VULN-06 | Password reset never saved the password; plaintext tokens; enumeration; no password policy | A07 | High |
| VULN-07 | No rate limiting anywhere (brute force, mail bombing) | A07 | High |
| VULN-08 | Unrestricted file upload; no input validation or bounds | A04 / A03 | High |
| VULN-09 | Raw DB errors and stack traces returned; missing security headers | A05 | Medium |
| VULN-10 | 32 vulnerable server dependencies (app unrunnable on supported Node) | A06 | High |
| VULN-11 | HTTP 200 on auth failure silently disabled the new rate limiter | A07 | High |
| VULN-12 | 200 vulnerable client dependencies; unpinned GitHub dependency; no client CSP | A06 / A03 | High |

Full analysis of each — including impact, exploit path, fix and residual risk
— is in [`REPORT.md`](REPORT.md).

### Measured results

| Metric | Before | After |
|---|---|---|
| Server dependency advisories | 32 (2 critical, 17 high) | **0** |
| Client dependency advisories | 200 (18 critical, 59 high) | **26** — all build-toolchain only, none shipped |
| Custom Semgrep findings | 17 | **0** |
| Runtime security checks | — | **30 / 30 passing** |
| OAuth flow checks | — | **23 / 23 passing** |

---

## 3. Repository layout

```
├── README.md                    this file
├── REPORT.md / REPORT.pdf       the vulnerability report
├── OAUTH.md                     OAuth design, setup and rationale
├── SECURITY.md                  security policy
├── client/                      React SPA
├── server/                      Express API
└── security/
    ├── semgrep-rules.yml        custom Semgrep ruleset (7 rules)
    ├── verify-fixes.js          30 runtime checks of the fixes
    ├── verify-oauth.js          23 checks of the OAuth flow
    └── reports/                 raw before/after tool output
```

---

## 4. Running the application

### Prerequisites
- Node.js 18+ (verified on Node 25)
- MongoDB — or Docker: `docker run -d -p 27017:27017 mongo:7`

### Server

```bash
cd server
npm install
cp .env.sample .env      # then edit .env, see below
npm start                # http://localhost:5000
```

`server/.env` must contain a real `JWT_SECRET` — **the server refuses to
start without one of at least 32 characters** (VULN-05). Generate one with:

```bash
openssl rand -base64 48
```

### Client

```bash
cd client
npm install
npm start                # http://localhost:3000
```

### Google sign-in (optional)

Follow [`OAUTH.md`](OAUTH.md) §5 to create Google credentials and fill in the
four `GOOGLE_*` / `CLIENT_OAUTH_SUCCESS_URL` variables. Without them the app
runs normally and the Google routes return a clear `503`.

---

## 5. Reproducing the security work

```bash
# White-box: custom Semgrep rules (needs Docker)
docker run --rm -v "$(pwd):/src" semgrep/semgrep \
  semgrep --config /src/security/semgrep-rules.yml \
  --exclude=node_modules --no-git-ignore /src

# White-box: dependency scanning
cd server && npm audit
cd client && npm audit

# Black-box: runtime checks against the running API
node security/verify-fixes.js     # 30 checks
node security/verify-oauth.js     # 23 checks
```

> Restart the API before re-running `verify-fixes.js` — its final check
> deliberately exhausts the rate limiter, so a back-to-back run starts
> already throttled.

---

## 6. Reviewing the commit history

Each vulnerability is a single, self-contained commit whose message states
the OWASP category, CWE, severity, how it was found, the exploit path, the
fix, and how the fix was verified.

```bash
git log --oneline                      # overview
git log --grep="VULN-02" -p            # one vulnerability end to end
git show <commit>                      # full rationale + diff
```

The first commit is the **unmodified upstream code**, so every change in this
repository is attributable to a specific security finding.

---

## 7. Acknowledgements

Original application © Anass Ferrak ("TheLordA"), used under its ISC licence.
All security analysis, fixes and the OAuth implementation in this repository
are the assignment work. Images used by the original project belong to their
respective creators.
