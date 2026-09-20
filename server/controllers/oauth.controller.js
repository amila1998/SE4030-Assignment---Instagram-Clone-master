/**
 * Google OAuth 2.0 / OpenID Connect - Authorization Code grant with PKCE.
 *
 * Flow implemented here:
 *
 *   GET  /auth/google
 *        Generates `state` (CSRF) and a PKCE `code_verifier`, stores both
 *        server-side, mirrors `state` into an httpOnly cookie, and redirects
 *        the browser to Google with `code_challenge`.
 *
 *   GET  /auth/google/callback
 *        Google redirects back with `code` and `state`. We verify `state`
 *        against BOTH the cookie and the server store, exchange the code for
 *        tokens over the back channel using the `code_verifier`, verify the
 *        ID token's signature and claims, then find-or-create the local user.
 *        Rather than putting the application JWT in the redirect URL, we mint
 *        a one-time exchange code and redirect with that.
 *
 *   POST /auth/google/exchange
 *        The SPA posts the one-time code and receives the application JWT
 *        plus the user profile. The code is deleted on first use.
 */

const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");

const User = require("../models/user.model");
const { signOptions } = require("../config/jwt.config");
const {
	GOOGLE_AUTH_ENDPOINT,
	GOOGLE_TOKEN_ENDPOINT,
	GOOGLE_SCOPES,
	AUTH_REQUEST_TTL_MS,
	EXCHANGE_CODE_TTL_MS,
	getConfig,
	isConfigured,
} = require("../config/oauth.config");
const {
	putAuthRequest,
	takeAuthRequest,
	putExchangeCode,
	takeExchangeCode,
} = require("../utils/oauthStore");

const STATE_COOKIE = "g_oauth_state";

/** base64url encoding, per RFC 7636 section 4.2 (no padding, URL-safe). */
const base64url = (buffer) =>
	buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/**
 * PKCE S256 challenge: BASE64URL(SHA256(code_verifier)).
 *
 * The "plain" method is also permitted by the spec but offers no protection
 * against an attacker who can observe the authorization request, so S256 is
 * the only method used here.
 */
const createPkcePair = () => {
	const codeVerifier = base64url(crypto.randomBytes(32));
	const codeChallenge = base64url(crypto.createHash("sha256").update(codeVerifier).digest());
	return { codeVerifier, codeChallenge };
};

const notConfigured = (res) =>
	res.status(503).json({
		error:
			"Google sign-in is not configured on this server. " +
			"Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI and " +
			"CLIENT_OAUTH_SUCCESS_URL - see OAUTH.md.",
	});

/**
 * Step 1 - begin the flow.
 */
exports.start = (req, res) => {
	if (!isConfigured()) return notConfigured(res);
	const { clientId, redirectUri } = getConfig();

	// `state` defends the callback against CSRF: an attacker cannot forge a
	// callback that we will accept, because they cannot predict this value or
	// set the cookie it is compared against.
	const state = base64url(crypto.randomBytes(32));
	const { codeVerifier, codeChallenge } = createPkcePair();

	// The verifier stays here. It is never sent to the browser and never
	// appears in a URL.
	putAuthRequest(state, { codeVerifier }, AUTH_REQUEST_TTL_MS);

	// Mirror `state` into an httpOnly cookie so the callback can confirm that
	// the browser completing the flow is the same one that started it.
	res.cookie(STATE_COOKIE, state, {
		httpOnly: true, // not readable from JavaScript
		sameSite: "lax", // must survive the top-level redirect back from Google
		secure: process.env.NODE_ENV === "production", // HTTPS-only in production
		maxAge: AUTH_REQUEST_TTL_MS,
		path: "/auth/google",
	});

	const params = new URLSearchParams({
		client_id: clientId,
		redirect_uri: redirectUri,
		response_type: "code",
		scope: GOOGLE_SCOPES.join(" "),
		state,
		code_challenge: codeChallenge,
		code_challenge_method: "S256",
		// Ask for a fresh account chooser rather than silently reusing a
		// session, so the user is always aware which account they are linking.
		prompt: "select_account",
	});

	return res.redirect(`${GOOGLE_AUTH_ENDPOINT}?${params.toString()}`);
};

/**
 * Step 2 - handle Google's redirect, exchange the code, issue our own JWT.
 */
exports.callback = async (req, res) => {
	if (!isConfigured()) return notConfigured(res);
	const { clientId, clientSecret, redirectUri, clientSuccessUrl } = getConfig();

	const fail = (reason, detail) => {
		console.error("[oauth callback]", reason, detail || "");
		res.clearCookie(STATE_COOKIE, { path: "/auth/google" });
		// Send a generic reason to the SPA; the detail stays in the log.
		return res.redirect(`${clientSuccessUrl}?error=${encodeURIComponent(reason)}`);
	};

	// Google reports user-side failures (e.g. consent denied) in `error`.
	if (req.query.error) {
		return fail("access_denied", req.query.error);
	}

	const { code, state } = req.query;
	if (typeof code !== "string" || typeof state !== "string") {
		return fail("invalid_request", "missing code or state");
	}

	// --- CSRF checks -----------------------------------------------------
	const cookieState = req.cookies ? req.cookies[STATE_COOKIE] : undefined;
	if (!cookieState) {
		return fail("invalid_state", "state cookie missing");
	}
	// Constant-time comparison so the check cannot be probed by timing.
	const a = Buffer.from(String(cookieState));
	const b = Buffer.from(String(state));
	if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
		return fail("invalid_state", "state cookie does not match callback state");
	}

	// Single-use: consumes the stored request, so a replayed callback fails.
	const authRequest = takeAuthRequest(state);
	if (!authRequest) {
		return fail("invalid_state", "unknown or expired authorization request");
	}
	res.clearCookie(STATE_COOKIE, { path: "/auth/google" });

	try {
		// --- Back-channel token exchange ---------------------------------
		// Sent server-to-server. The code_verifier proves we are the same
		// client that started the flow (PKCE), and the client_secret
		// authenticates this confidential client.
		const tokenResponse = await fetch(GOOGLE_TOKEN_ENDPOINT, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code,
				client_id: clientId,
				client_secret: clientSecret,
				redirect_uri: redirectUri,
				code_verifier: authRequest.codeVerifier,
			}),
		});

		if (!tokenResponse.ok) {
			const body = await tokenResponse.text();
			return fail("token_exchange_failed", `${tokenResponse.status} ${body}`);
		}

		const tokens = await tokenResponse.json();
		if (!tokens.id_token) {
			return fail("token_exchange_failed", "no id_token in response");
		}

		// --- ID token verification ---------------------------------------
		// Never trust an ID token without verifying it. `verifyIdToken`
		// checks the RS256 signature against Google's published JWKS, and
		// validates `iss`, `aud` and `exp`. Decoding the payload without
		// verification - which a lot of tutorial code does - would let anyone
		// mint an identity by crafting a token.
		const oauthClient = new OAuth2Client(clientId);
		const ticket = await oauthClient.verifyIdToken({
			idToken: tokens.id_token,
			audience: clientId,
		});
		const payload = ticket.getPayload();

		// Google may return an unverified address if the account was never
		// confirmed. Accepting it would allow account takeover by registering
		// a Google account against someone else's email.
		if (!payload.email || payload.email_verified !== true) {
			return fail("email_not_verified", payload.email);
		}

		// --- Find or create the local user -------------------------------
		// `sub` is Google's stable, immutable user id. Email addresses can be
		// reassigned, so `sub` is the correct join key.
		let user = await User.findOne({ GoogleId: payload.sub });

		if (!user) {
			// Link to an existing password account with the same verified
			// email, rather than creating a duplicate identity.
			user = await User.findOne({ Email: payload.email });
			if (user) {
				user.GoogleId = payload.sub;
				user.AuthProvider = user.Password ? "hybrid" : "google";
				await user.save();
			} else {
				user = await new User({
					Name: payload.name || payload.email.split("@")[0],
					Email: payload.email,
					GoogleId: payload.sub,
					AuthProvider: "google",
					// No Password: this account has no local credential to
					// guess. The schema makes Password conditional on the
					// provider.
				}).save();
			}
		}

		// --- Issue OUR token ---------------------------------------------
		// Google's tokens are not reused as session tokens. We mint the same
		// application JWT the password flow issues, with the same expiry,
		// algorithm and issuer/audience binding from VULN-05.
		const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, signOptions);

		// --- Hand back via a one-time code --------------------------------
		// The JWT is deliberately NOT placed in the redirect URL. Query
		// strings land in browser history, server logs and `Referer` headers.
		// The SPA redeems this opaque, single-use, 60-second code instead.
		const exchangeCode = base64url(crypto.randomBytes(32));
		putExchangeCode(
			exchangeCode,
			{
				token,
				user: {
					_id: user._id,
					Name: user.Name,
					Email: user.Email,
					Followers: user.Followers,
					Following: user.Following,
					Bookmarks: user.Bookmarks,
				},
			},
			EXCHANGE_CODE_TTL_MS
		);

		return res.redirect(`${clientSuccessUrl}?code=${exchangeCode}`);
	} catch (err) {
		return fail("oauth_failed", err && err.message);
	}
};

/**
 * Step 3 - the SPA redeems the one-time code for the application JWT.
 */
exports.exchange = (req, res) => {
	if (!isConfigured()) return notConfigured(res);

	const { code } = req.body;
	if (typeof code !== "string" || code.length === 0) {
		return res.status(400).json({ error: "An exchange code is required." });
	}

	const entry = takeExchangeCode(code);
	if (!entry) {
		return res.status(400).json({ error: "This sign-in code is invalid or has expired." });
	}

	return res.json({ token: entry.token, user: entry.user });
};
