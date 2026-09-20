/**
 * Google OAuth 2.0 / OpenID Connect configuration.
 *
 * Grant type: Authorization Code with PKCE (RFC 7636).
 *
 * Why this grant:
 *   - The Implicit grant is deprecated by the OAuth 2.0 Security Best
 *     Current Practice (RFC 9700). It returns tokens in the URL fragment,
 *     where they land in browser history, `Referer` headers and logs.
 *   - The Resource Owner Password Credentials grant is also deprecated and
 *     would require this application to handle Google passwords directly,
 *     which is the whole thing OAuth exists to avoid.
 *   - Authorization Code returns a single-use code over the front channel
 *     and exchanges it for tokens over a server-to-server back channel, so
 *     no token ever touches the browser URL.
 *   - PKCE binds that code to the specific client that started the flow. An
 *     attacker who intercepts the code cannot redeem it without the
 *     `code_verifier`, which never leaves this server.
 */

const GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

// OpenID Connect scopes. `openid` requests an ID token; `email` and
// `profile` are the minimum needed to create a local account. Nothing more
// is requested - least privilege applies to scopes too.
const GOOGLE_SCOPES = ["openid", "email", "profile"];

// How long an in-flight authorization request stays valid. The user has to
// complete the Google consent screen within this window.
const AUTH_REQUEST_TTL_MS = 10 * 60 * 1000; // 10 minutes

// How long the one-time code handed back to the SPA stays valid. The client
// redeems it immediately on page load, so this is deliberately tight.
const EXCHANGE_CODE_TTL_MS = 60 * 1000; // 1 minute

const getConfig = () => {
	const clientId = process.env.GOOGLE_CLIENT_ID;
	const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
	const redirectUri = process.env.GOOGLE_REDIRECT_URI;
	const clientSuccessUrl = process.env.CLIENT_OAUTH_SUCCESS_URL;

	return { clientId, clientSecret, redirectUri, clientSuccessUrl };
};

/**
 * Google sign-in is optional: the application still runs without it, and the
 * existing email/password flow is untouched. Routes check this and return a
 * clear 503 rather than failing with an opaque error from Google.
 */
const isConfigured = () => {
	const { clientId, clientSecret, redirectUri, clientSuccessUrl } = getConfig();
	return Boolean(clientId && clientSecret && redirectUri && clientSuccessUrl);
};

module.exports = {
	GOOGLE_AUTH_ENDPOINT,
	GOOGLE_TOKEN_ENDPOINT,
	GOOGLE_SCOPES,
	AUTH_REQUEST_TTL_MS,
	EXCHANGE_CODE_TTL_MS,
	getConfig,
	isConfigured,
};
