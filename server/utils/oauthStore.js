/**
 * Short-lived server-side state for the OAuth flow.
 *
 * Two separate stores:
 *
 *  1. Authorization requests, keyed by `state`. Holds the PKCE
 *     `code_verifier` for an in-flight login. The verifier MUST stay on the
 *     server - that is the entire point of PKCE.
 *
 *  2. Exchange codes, keyed by a random opaque value. Holds the application
 *     JWT that the SPA will collect in a single POST, so the JWT never
 *     travels in a redirect URL.
 *
 * Both are single-use and time-limited.
 *
 * LIMITATION (recorded in the report): these are in-process Maps, so they do
 * not survive a restart and are not shared between instances. A multi-node
 * deployment needs Redis or a database-backed store. For a single-instance
 * deployment this is correct and keeps the secrets out of the browser.
 */

const authRequests = new Map();
const exchangeCodes = new Map();

const now = () => Date.now();

/**
 * Drop expired entries. Called on every write, which is sufficient at this
 * scale and avoids a background timer that would keep the process alive.
 */
const sweep = (store) => {
	const t = now();
	for (const [key, value] of store) {
		if (value.expiresAt <= t) store.delete(key);
	}
};

const putAuthRequest = (state, data, ttlMs) => {
	sweep(authRequests);
	authRequests.set(state, { ...data, expiresAt: now() + ttlMs });
};

/**
 * Retrieve and immediately delete. Single-use: replaying a `state` value
 * cannot drive a second token exchange.
 */
const takeAuthRequest = (state) => {
	const entry = authRequests.get(state);
	if (!entry) return null;
	authRequests.delete(state);
	if (entry.expiresAt <= now()) return null;
	return entry;
};

const putExchangeCode = (code, data, ttlMs) => {
	sweep(exchangeCodes);
	exchangeCodes.set(code, { ...data, expiresAt: now() + ttlMs });
};

const takeExchangeCode = (code) => {
	const entry = exchangeCodes.get(code);
	if (!entry) return null;
	exchangeCodes.delete(code);
	if (entry.expiresAt <= now()) return null;
	return entry;
};

module.exports = {
	putAuthRequest,
	takeAuthRequest,
	putExchangeCode,
	takeExchangeCode,
};
