/**
 * Verification of the Google OAuth 2.0 / OIDC implementation.
 *
 * These checks exercise the parts of the flow that do NOT require a real
 * Google credential: the authorization request this server builds, and the
 * CSRF / replay defences on the callback. Completing a real sign-in needs
 * live Google client credentials and a human at the consent screen, which is
 * demonstrated in the video rather than automated here.
 *
 * Usage:  node security/verify-oauth.js
 */

const crypto = require("crypto");

const BASE = process.env.API_BASE || "http://localhost:5000";

let passed = 0;
let failed = 0;

const check = (description, condition, detail) => {
	if (condition) {
		passed++;
		console.log(`  PASS  ${description}`);
	} else {
		failed++;
		console.log(`  FAIL  ${description}`);
		if (detail !== undefined) console.log("        got:", JSON.stringify(detail));
	}
};

const section = (title) => console.log(`\n${title}\n${"-".repeat(title.length)}`);

const base64url = (buffer) =>
	buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const run = async () => {
	section("Authorization request (GET /auth/google)");

	// `redirect: manual` so we can inspect the 302 rather than following it
	// out to Google.
	const start = await fetch(BASE + "/auth/google", { redirect: "manual" });
	check("returns a redirect", start.status === 302 || start.status === 303, start.status);

	const location = start.headers.get("location") || "";
	check("redirects to Google's authorization endpoint",
		location.startsWith("https://accounts.google.com/o/oauth2/v2/auth"), location.slice(0, 80));

	const url = new URL(location);
	const q = url.searchParams;

	check("response_type is 'code' (Authorization Code grant)", q.get("response_type") === "code", q.get("response_type"));
	check("code_challenge_method is S256 (PKCE)", q.get("code_challenge_method") === "S256", q.get("code_challenge_method"));
	check("a code_challenge is present", !!q.get("code_challenge"), q.get("code_challenge"));
	check("a state parameter is present", !!q.get("state"), q.get("state"));
	check("openid scope is requested (OIDC)", (q.get("scope") || "").includes("openid"), q.get("scope"));
	check("email scope is requested", (q.get("scope") || "").includes("email"), q.get("scope"));
	check("redirect_uri is registered and explicit", !!q.get("redirect_uri"), q.get("redirect_uri"));

	// The code_challenge must be a base64url SHA-256 digest: 43 chars, no
	// padding, and crucially NOT the verifier itself (which would be the
	// insecure "plain" method).
	const challenge = q.get("code_challenge") || "";
	check("code_challenge is a 43-char base64url SHA-256 digest",
		challenge.length === 43 && /^[A-Za-z0-9_-]+$/.test(challenge), challenge);

	section("State cookie (CSRF binding)");
	const setCookie = start.headers.get("set-cookie") || "";
	check("a state cookie is set", setCookie.includes("g_oauth_state"), setCookie);
	check("state cookie is HttpOnly", /httponly/i.test(setCookie), setCookie);
	check("state cookie is SameSite=Lax", /samesite=lax/i.test(setCookie), setCookie);

	// The cookie value must equal the state in the URL, or the callback's
	// comparison is meaningless.
	const cookieMatch = /g_oauth_state=([^;]+)/.exec(setCookie);
	check("state cookie value matches the state parameter",
		!!cookieMatch && cookieMatch[1] === q.get("state"));

	section("Callback CSRF and replay defences");

	// No state cookie at all.
	const noCookie = await fetch(
		`${BASE}/auth/google/callback?code=abc&state=${encodeURIComponent(q.get("state"))}`,
		{ redirect: "manual" }
	);
	const noCookieLoc = noCookie.headers.get("location") || "";
	check("callback without the state cookie is rejected",
		noCookieLoc.includes("error=invalid_state"), noCookieLoc);

	// Cookie present but not matching the callback's state parameter.
	const forgedState = base64url(crypto.randomBytes(32));
	const mismatch = await fetch(
		`${BASE}/auth/google/callback?code=abc&state=${encodeURIComponent(forgedState)}`,
		{ redirect: "manual", headers: { Cookie: `g_oauth_state=${q.get("state")}` } }
	);
	const mismatchLoc = mismatch.headers.get("location") || "";
	check("callback with a mismatched state is rejected",
		mismatchLoc.includes("error=invalid_state"), mismatchLoc);

	// Matching cookie and state, but a value this server never issued: the
	// server-side store lookup must still fail.
	const unknown = await fetch(
		`${BASE}/auth/google/callback?code=abc&state=${encodeURIComponent(forgedState)}`,
		{ redirect: "manual", headers: { Cookie: `g_oauth_state=${forgedState}` } }
	);
	const unknownLoc = unknown.headers.get("location") || "";
	check("callback with an unknown authorization request is rejected",
		unknownLoc.includes("error=invalid_state"), unknownLoc);

	// Google reporting a user-side failure.
	const denied = await fetch(`${BASE}/auth/google/callback?error=access_denied`, {
		redirect: "manual",
	});
	const deniedLoc = denied.headers.get("location") || "";
	check("consent denial is passed back to the client as access_denied",
		deniedLoc.includes("error=access_denied"), deniedLoc);

	section("Exchange endpoint (POST /auth/google/exchange)");

	const bogus = await fetch(BASE + "/auth/google/exchange", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ code: "not-a-real-code" }),
	});
	const bogusJson = await bogus.json();
	check("an unknown exchange code is rejected with 400", bogus.status === 400, bogusJson);

	const missing = await fetch(BASE + "/auth/google/exchange", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({}),
	});
	check("a missing exchange code is rejected with 400", missing.status === 400);

	// A non-string code must not reach the store lookup (NoSQL-style guard).
	const wrongType = await fetch(BASE + "/auth/google/exchange", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ code: { $ne: null } }),
	});
	check("a non-string exchange code is rejected with 400", wrongType.status === 400);

	section("Freshness");
	// Two authorization requests must not reuse state or PKCE material.
	const second = await fetch(BASE + "/auth/google", { redirect: "manual" });
	const secondQ = new URL(second.headers.get("location")).searchParams;
	check("a second request uses a different state", secondQ.get("state") !== q.get("state"));
	check("a second request uses a different code_challenge",
		secondQ.get("code_challenge") !== q.get("code_challenge"));

	console.log(`\n${"=".repeat(60)}`);
	console.log(`RESULT: ${passed} passed, ${failed} failed`);
	console.log("=".repeat(60));
	process.exit(failed === 0 ? 0 : 1);
};

run().catch((err) => {
	console.error("Verification run failed:", err);
	process.exit(1);
});
