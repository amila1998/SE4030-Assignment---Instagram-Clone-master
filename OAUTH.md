# Google OAuth 2.0 / OpenID Connect — Sign in with Google

This document describes the OAuth feature added to the application for
SE4030, how to configure it, and why it is built the way it is.

---

## 1. What was added

The upstream application authenticated users in exactly one way: an email
address and a password checked against a bcrypt hash, in exchange for a JWT.

This adds a **second, independent sign-in method** — *Sign in with Google* —
using the **OAuth 2.0 Authorization Code grant with PKCE**, and Google's
**OpenID Connect** identity layer to learn who the user is.

The existing password flow is deliberately **not removed**. Accounts created
before Google sign-in existed continue to work, and a user can link both
methods to one account.

---

## 2. Why this grant type

| Grant | Why not |
|---|---|
| **Implicit** | Deprecated by RFC 9700 (OAuth 2.0 Security BCP). Returns tokens in the URL fragment, where they reach browser history, `Referer` headers and logs. |
| **Resource Owner Password Credentials** | Deprecated. Would require this application to handle the user's *Google* password directly — the exact thing OAuth exists to prevent. |
| **Client Credentials** | Authenticates a service, not a person. There is no user identity to obtain. |
| **Authorization Code + PKCE** | ✅ Chosen. The code arrives over the front channel and is redeemed over a server-to-server back channel, so no token is ever exposed to the browser. PKCE binds the code to the client that began the flow. |

**PKCE (RFC 7636)** matters even though this is a confidential client with a
client secret. It defends against authorization-code interception: an attacker
who somehow obtains the `code` still cannot redeem it, because they do not
have the `code_verifier`, which never leaves this server. Only the `S256`
challenge method is used — `plain` offers no protection against an observer.

---

## 3. The flow as implemented

```
 Browser                    This API                     Google
    │                          │                            │
    │  1. click "Sign in       │                            │
    │     with Google"         │                            │
    │ ───── GET /auth/google ──▶                            │
    │                          │ generate state + PKCE      │
    │                          │ verifier; store verifier   │
    │                          │ SERVER-SIDE; set httpOnly  │
    │                          │ state cookie               │
    │ ◀──── 302 + Set-Cookie ──│                            │
    │                          │                            │
    │  2. ─────────── redirect to Google w/ code_challenge ─▶│
    │                          │                            │
    │  3. user consents on Google's own page                │
    │                          │                            │
    │ ◀───────────── 302 back with ?code&state ─────────────│
    │                          │                            │
    │ ─ GET /auth/google/      │                            │
    │   callback?code&state ──▶│                            │
    │                          │ verify state == cookie     │
    │                          │ (constant-time), consume   │
    │                          │ the stored auth request    │
    │                          │                            │
    │                          │ 4. POST code +             │
    │                          │    code_verifier ─────────▶│  BACK CHANNEL
    │                          │ ◀──── id_token + access ───│
    │                          │                            │
    │                          │ 5. verify id_token         │
    │                          │    signature against       │
    │                          │    Google's JWKS; check    │
    │                          │    iss / aud / exp         │
    │                          │                            │
    │                          │ 6. find-or-create user by  │
    │                          │    Google `sub`            │
    │                          │                            │
    │                          │ 7. sign OUR application    │
    │                          │    JWT; store it against   │
    │                          │    a one-time code         │
    │ ◀─ 302 /oauth/callback?code=<one-time>                │
    │                          │                            │
    │ 8. POST /auth/google/    │                            │
    │    exchange {code} ─────▶│ single-use lookup          │
    │ ◀──── { token, user } ───│                            │
    │                          │                            │
    │ 9. store JWT, redirect to the feed                    │
```

### Why step 7–8 instead of redirecting with the JWT

The obvious shortcut is `redirect(client + "?token=" + jwt)`. That places a
live session token in a URL, and URLs are written to browser history, proxy
and server access logs, and `Referer` headers on any subsequent outbound
request.

Instead the API mints an **opaque, single-use, 60-second code**. The SPA
redeems it over POST and it is deleted on first use. The JWT itself never
appears in a URL. The callback screen also strips the code from the address
bar with `history.replaceState` immediately on load.

---

## 4. Security properties

| Control | Where | Purpose |
|---|---|---|
| `state` parameter | `oauth.controller.js` | CSRF — an attacker cannot forge a callback we accept |
| `state` mirrored in an httpOnly cookie | `start` | Binds the callback to the browser that began the flow |
| Constant-time state comparison | `callback` | `crypto.timingSafeEqual`, so the check cannot be probed by timing |
| Single-use authorization request | `oauthStore.js` | A replayed callback finds nothing and fails |
| PKCE `S256` | `createPkcePair` | An intercepted code cannot be redeemed |
| `code_verifier` never leaves the server | `oauthStore.js` | The whole basis of PKCE |
| ID token signature verified | `verifyIdToken` | Against Google's JWKS — never decode-and-trust |
| `iss` / `aud` / `exp` validated | `verifyIdToken` | Rejects tokens minted for another application |
| `email_verified` required | `callback` | Prevents takeover via an unverified Google address |
| Linked on `sub`, not email | `callback` | `sub` is immutable; email addresses can be reassigned |
| Google tokens not reused as sessions | `callback` | We mint our own JWT with our own expiry and claims |
| One-time exchange code | `exchange` | Keeps the JWT out of URLs, history and logs |
| Rate limited | `oauth.route.js` | Same `authLimiter` as the other credential endpoints |
| No password created for Google users | `user.model.js` | A generated password would be a credential that protects nothing |

---

## 5. Configuration

### 5.1 Create the Google credentials

1. Go to <https://console.cloud.google.com/apis/credentials>
2. Create a project (or select one).
3. Configure the **OAuth consent screen**:
   - User type: **External**
   - Fill in app name and support email
   - Scopes: `openid`, `.../auth/userinfo.email`, `.../auth/userinfo.profile`
   - While the app is in *Testing*, add your own Google account under
     **Test users**, or sign-in will be refused.
4. **Create credentials → OAuth client ID**
   - Application type: **Web application**
   - **Authorised redirect URI**:
     `http://localhost:5000/auth/google/callback`

   This must match `GOOGLE_REDIRECT_URI` *exactly* — Google compares the
   full string, including scheme, port and trailing slash.
5. Copy the **Client ID** and **Client secret**.

### 5.2 Configure the server

In `server/.env`:

```bash
GOOGLE_CLIENT_ID="<your client id>.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="<your client secret>"
GOOGLE_REDIRECT_URI="http://localhost:5000/auth/google/callback"
CLIENT_OAUTH_SUCCESS_URL="http://localhost:3000/oauth/callback"
```

If any of these are missing the API returns **503** with an explanatory
message rather than failing obscurely, and the rest of the application
continues to work normally.

> **Never commit `server/.env`.** It is covered by `.gitignore`. The client
> secret is a credential: anyone holding it can impersonate this application
> to Google.

### 5.3 Run it

```bash
docker run -d -p 27017:27017 mongo:7   # database
cd server && npm install && npm start  # API  on :5000
cd client && npm install && npm start  # SPA  on :3000
```

Open <http://localhost:3000/login> and click **Sign in with Google**.

---

## 6. Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/auth/google` | Begin the flow; 302 to Google with a PKCE challenge |
| `GET` | `/auth/google/callback` | Google's redirect target; exchanges the code |
| `POST` | `/auth/google/exchange` | SPA redeems its one-time code for the app JWT |

---

## 7. Data model

Three schema changes in `server/models/user.model.js`:

- **`GoogleId`** — Google's `sub` claim. `unique` + `sparse`, so many local
  accounts can exist without it while those that have it stay unique.
- **`AuthProvider`** — `"local"`, `"google"` or `"hybrid"`.
- **`Password`** — now conditionally required (only when
  `AuthProvider === "local"`). A Google-only account has no local password,
  so there is no local credential to brute-force.

`signin` rejects a Google-only account with the *same* generic
"Invalid Email or Password" message used for a wrong password, so the
endpoint does not disclose which sign-in method an address uses.

---

## 8. Verification

`security/verify-oauth.js` runs 23 automated checks against a running server:
the grant type, PKCE method and challenge format, requested scopes, state
cookie flags, constant-time CSRF rejection, replay rejection, exchange-code
validation and per-request freshness.

```bash
node security/verify-oauth.js
# RESULT: 23 passed, 0 failed
```

These cover everything that does not require a live Google credential.
Completing a real consent-screen sign-in is demonstrated in the video.

---

## 9. Known limitations

1. **In-memory state store.** `utils/oauthStore.js` uses process-local `Map`s,
   so in-flight logins do not survive a restart and are not shared across
   instances. A multi-node deployment needs Redis or a database-backed store.
   Correct and secret-safe for a single-instance deployment.
2. **No refresh-token handling.** Google's refresh token is not requested or
   stored, because the application only needs identity at sign-in, not ongoing
   API access on the user's behalf. Requesting offline access would mean
   storing a long-lived credential for no benefit.
3. **The application JWT still lives in `localStorage`,** matching the
   existing password flow. An httpOnly cookie would be stronger against XSS;
   changing it touches every authenticated request in the client and is
   recorded as accepted residual risk in the report rather than rushed.
