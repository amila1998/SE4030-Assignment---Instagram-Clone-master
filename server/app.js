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

// Compress the HTTP response sent back to a client
app.use(compression()); //Compress all routes

// Use Helmet to protect against well known vulnerabilities
app.use(helmet());

// use Morgan dep in dev mode
app.use(morgan("dev"));

// Set up cors to allow us to accept requests from our client
app.use(
	cors({
		origin: "http://localhost:3000", // <-- location of the react app were connecting to
		credentials: true,
	})
);

// Parsers
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true }));

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
require("./routes/post.route")(app);
require("./routes/user.route")(app);

/**
 * -------------- SERVER ----------------
 */

// Specify the PORT which will the server running on
const PORT = process.env.PORT || 3001;

// Disabling Powered by tag
app.disable("x-powered-by");

app.listen(PORT, () => {
	console.log(`Server is running in ${process.env.NODE_ENV} mode, under port ${PORT}.`);
});
