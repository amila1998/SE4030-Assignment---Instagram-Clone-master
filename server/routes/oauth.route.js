/**
 * Google OAuth 2.0 / OpenID Connect routes.
 *
 * These are intentionally public - they ARE the authentication mechanism, so
 * requiring an existing session would be circular. They are rate limited for
 * the same reason the other credential endpoints are (VULN-07).
 */

const controller = require("../controllers/oauth.controller");
const { authLimiter } = require("../middleware/rateLimit.middleware");

module.exports = (app) => {
	// Step 1: redirect the user to Google with a PKCE challenge.
	app.get("/auth/google", authLimiter, controller.start);

	// Step 2: Google redirects back here with an authorization code.
	app.get("/auth/google/callback", authLimiter, controller.callback);

	// Step 3: the SPA redeems its one-time code for the application JWT.
	app.post("/auth/google/exchange", authLimiter, controller.exchange);
};
