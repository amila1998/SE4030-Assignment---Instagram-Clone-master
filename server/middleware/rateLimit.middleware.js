/**
 * Rate-limiting middleware.
 *
 * SECURITY (VULN-07): the original application applied no rate limiting of
 * any kind, so `/signin`, `/reset-pwd` and `/new-pwd` could be driven at the
 * full speed of the network. Two tiers are defined here: a strict limiter for
 * credential-handling endpoints and a broad limiter for everything else.
 */

const rateLimit = require("express-rate-limit");

const WINDOW_MS = 15 * 60 * 1000; // 15 minutes

/**
 * Strict limiter for endpoints that accept or issue credentials.
 *
 * `skipSuccessfulRequests` means a legitimate user who signs in correctly
 * does not consume budget, so the limit is felt almost exclusively by
 * password-guessing traffic.
 */
const authLimiter = rateLimit({
	windowMs: WINDOW_MS,
	max: 10,
	skipSuccessfulRequests: true,
	standardHeaders: true, // RateLimit-* headers (RFC draft)
	legacyHeaders: false, // drop the deprecated X-RateLimit-* headers
	message: {
		error: "Too many attempts from this IP. Please try again in 15 minutes.",
	},
});

/**
 * Even stricter limiter for password-reset requests. Each accepted request
 * sends an email, so an unbounded endpoint is both an enumeration tool and a
 * way to use the application as a mail bomb against a third party.
 */
const passwordResetLimiter = rateLimit({
	windowMs: 60 * 60 * 1000, // 1 hour
	max: 5,
	standardHeaders: true,
	legacyHeaders: false,
	message: {
		error: "Too many password reset requests from this IP. Please try again later.",
	},
});

/**
 * Broad limiter applied to the whole API as a backstop against scraping and
 * cheap application-level denial of service. Set high enough that normal
 * browsing of the feed is unaffected.
 */
const globalLimiter = rateLimit({
	windowMs: WINDOW_MS,
	max: 500,
	standardHeaders: true,
	legacyHeaders: false,
	message: {
		error: "Too many requests from this IP. Please slow down.",
	},
});

module.exports = { authLimiter, passwordResetLimiter, globalLimiter };
