/**
 *
 * @author Anass Ferrak aka " TheLordA " <ferrak.anass@gmail.com>
 * GitHub repo: https://github.com/TheLordA/Instagram-Clone
 *
 */

const express = require("express");
const morgan = require("morgan");
const cors = require("cors");
const compression = require("compression");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
// OAUTH: needed to read the httpOnly `state` cookie on the Google callback.
const cookieParser = require("cookie-parser");

const connectDB = require("./config/db.config");

/**
 * -------------- GENERAL SETUP ----------------
 */

// Gives us access to variables set in the .env file via `process.env.VARIABLE_NAME` syntax
require("dotenv").config();

// SECURITY (VULN-05): refuse to start with a missing, placeholder or
// low-entropy JWT signing key. Failing at boot is far safer than discovering
// at first login that every token in circulation is forgeable.
const { assertSecretIsStrong } = require("./config/jwt.config");
assertSecretIsStrong();

// Connection to DB
connectDB();

// Create the Express application object
const app = express();

// SECURITY (VULN-09): disable the framework fingerprint BEFORE any route or
// middleware can emit a response. The original code called this AFTER the
// routes were registered and immediately before app.listen(), which still
// worked by accident, but placing it here makes the ordering intentional
// rather than incidental.
app.disable("x-powered-by");

// Compress the HTTP response sent back to a client
app.use(compression()); //Compress all routes

// SECURITY (VULN-09): configure Helmet explicitly rather than relying on the
// bare defaults. The API serves JSON only, so the CSP can be maximally
// restrictive - there is no legitimate reason for a response from this origin
// to load a script, a frame or an object.
app.use(
	helmet({
		contentSecurityPolicy: {
			useDefaults: false,
			directives: {
				defaultSrc: ["'none'"],
				frameAncestors: ["'none'"], // clickjacking
				baseUri: ["'none'"],
				formAction: ["'none'"],
				scriptSrc: ["'none'"],
				objectSrc: ["'none'"],
			},
		},
		// Send the Referer header only to same-origin destinations, so that
		// resource ids in URLs do not leak to third parties.
		referrerPolicy: { policy: "no-referrer" },
		// HSTS is only meaningful over TLS; enable it when NODE_ENV=production,
		// where the app is expected to sit behind HTTPS.
		hsts:
			process.env.NODE_ENV === "production"
				? { maxAge: 31536000, includeSubDomains: true, preload: true }
				: false,
		crossOriginResourcePolicy: { policy: "same-site" },
	})
);

// SECURITY (VULN-09): request logging. "dev" is a terse development format;
// production uses "combined". Either way the Authorization header is never
// part of these formats, so bearer tokens do not reach the log.
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// SECURITY (VULN-09): the allowed origin was hard-coded to
// http://localhost:3000, so any real deployment would either break or be
// "fixed" by someone setting origin:true - which reflects ANY origin and,
// together with credentials:true, disables the same-origin policy for this
// API entirely. Read it from configuration instead, defaulting to the
// development origin, and reject unknown origins explicitly.
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || "http://localhost:3000")
	.split(",")
	.map((o) => o.trim())
	.filter(Boolean);

app.use(
	cors({
		origin: (origin, callback) => {
			// Requests with no Origin header (curl, same-origin, server-to-server)
			// are not subject to the browser same-origin policy.
			if (!origin) return callback(null, true);
			if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
			return callback(new Error(`Origin ${origin} is not allowed by CORS.`));
		},
		credentials: true,
		methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
		allowedHeaders: ["Content-Type", "Authorization"],
	})
);

// Parsers
// SECURITY (VULN-08): the body limit was 50 MB, so any unauthenticated
// caller could make the server buffer 50 MB of JSON per request - trivial
// memory-exhaustion DoS. Images are capped at 5 MB decoded (see
// utils/imageUpload.js); 8 MB here leaves room for base64's ~33% inflation
// plus the surrounding JSON fields.
app.use(express.json({ limit: "8mb" }));
app.use(express.urlencoded({ extended: true, limit: "8mb" }));

// OAUTH: parses the short-lived, httpOnly `state` cookie used to bind the
// Google callback to the browser that started the flow (CSRF defence).
app.use(cookieParser());

// SECURITY (VULN-03): strip any key beginning with "$" or containing "."
// from req.body / req.params / req.query before it can reach a Mongoose
// query. This is the application-wide backstop against NoSQL operator
// injection; individual controllers additionally coerce their inputs to
// primitives so that a single missed middleware is not fatal.
app.use(
	mongoSanitize({
		replaceWith: "_",
		onSanitize: ({ req, key }) => {
			console.warn(`[security] stripped NoSQL operator from ${key} on ${req.method} ${req.path}`);
		},
	})
);

// SECURITY (VULN-07): rate limiting keys on the client IP, so how Express
// derives that IP decides whether the limiter can be bypassed.
//
//   - `trust proxy` left false (the default): req.ip is the socket address.
//     Correct when the app is exposed directly, as it is in development.
//   - `trust proxy` set to true: Express takes the LEFT-MOST value of the
//     client-supplied X-Forwarded-For header, which an attacker can set
//     freely - rotating it defeats the limiter entirely.
//
// So this must be an explicit deployment decision, never a blanket `true`.
// Set TRUST_PROXY to the exact number of reverse proxies in front of the
// app (e.g. "1" behind a single nginx or load balancer).
if (process.env.TRUST_PROXY) {
	const hops = Number(process.env.TRUST_PROXY);
	if (!Number.isInteger(hops) || hops < 0) {
		throw new Error("TRUST_PROXY must be a non-negative integer (the number of proxy hops).");
	}
	app.set("trust proxy", hops);
} else {
	app.set("trust proxy", false);
}

// Broad backstop limiter for the whole API. The stricter per-endpoint
// limiters are attached in routes/auth.route.js.
const { globalLimiter } = require("./middleware/rateLimit.middleware");
app.use(globalLimiter);

/**
 * -------------- ROUTES ----------------
 */
require("./routes/auth.route")(app);
// OAUTH: Google sign-in (Authorization Code + PKCE). Mounted alongside the
// existing email/password routes rather than replacing them, so accounts
// created before Google sign-in existed continue to work.
require("./routes/oauth.route")(app);
require("./routes/post.route")(app);
require("./routes/user.route")(app);

/**
 * -------------- ERROR HANDLING ----------------
 */

// SECURITY (VULN-09): an explicit 404 for unmatched routes. Without it,
// Express falls through to its default handler, which renders an HTML error
// page containing the request path - an unnecessary reflection of user input
// from a JSON API.
app.use((req, res) => {
	res.status(404).json({ error: "Not found." });
});

// SECURITY (VULN-09): centralised error handler. Express's default handler
// returns the full stack trace whenever NODE_ENV is not "production",
// disclosing absolute file paths, dependency versions and internal structure.
// Log the detail server-side; return a generic message to the caller.
//
// eslint-disable-next-line no-unused-vars -- Express identifies the error
// handler by its four-parameter arity, so `next` must stay in the signature.
app.use((err, req, res, next) => {
	console.error("[unhandled]", err);

	// Surface CORS rejections as 403 rather than a generic 500.
	if (err && typeof err.message === "string" && err.message.includes("not allowed by CORS")) {
		return res.status(403).json({ error: "Origin not allowed." });
	}
	// Body parser rejections (oversized or malformed payloads).
	if (err && err.type === "entity.too.large") {
		return res.status(413).json({ error: "Request body is too large." });
	}
	if (err && err.type === "entity.parse.failed") {
		return res.status(400).json({ error: "Request body is not valid JSON." });
	}

	return res.status(500).json({ error: "An unexpected error occurred." });
});

/**
 * -------------- SERVER ----------------
 */

// Specify the PORT which will the server running on
const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
	console.log(`Server is running in ${process.env.NODE_ENV} mode, under port ${PORT}.`);
});
