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
