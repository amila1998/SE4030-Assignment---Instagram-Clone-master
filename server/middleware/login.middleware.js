/**
 *
 * @author Anass Ferrak aka " TheLordA " <ferrak.anass@gmail.com>
 * GitHub repo: https://github.com/TheLordA/Instagram-Clone
 *
 */

const jwt = require("jsonwebtoken");

const User = require("../models/user.model");
const { verifyOptions } = require("../config/jwt.config");

module.exports = async (req, res, next) => {
	const { authorization } = req.headers;
	if (!authorization) {
		return res.status(401).json({ error: "You must be logged In." });
	}

	// SECURITY (VULN-05): require the "Bearer " scheme instead of using
	// String.replace(), which previously accepted a bare token and any
	// number of malformed prefixes.
	if (!authorization.startsWith("Bearer ")) {
		return res.status(401).json({ error: "Malformed Authorization header." });
	}
	const token = authorization.slice("Bearer ".length).trim();
	if (!token) {
		return res.status(401).json({ error: "Malformed Authorization header." });
	}

	let payload;
	try {
		// SECURITY (VULN-05): `verifyOptions` pins algorithms to ["HS256"] and
		// enforces the issuer/audience claims. Without algorithm pinning the
		// library honours the `alg` value inside the attacker-controlled token
		// header, which is the basis of algorithm-confusion attacks.
		payload = jwt.verify(token, process.env.JWT_SECRET, verifyOptions);
	} catch (err) {
		// Distinguish an expired session from a forged one for the client,
		// without disclosing which signature check failed.
		const expired = err.name === "TokenExpiredError";
		return res.status(401).json({
			error: expired ? "Your session has expired. Please sign in again." : "Invalid session.",
		});
	}

	try {
		const userdata = await User.findById(payload._id);

		// SECURITY (VULN-05): the original code called next() from inside the
		// .then() without checking for null and without a .catch(). A token
		// belonging to a deleted account therefore set `req.user = null` and
		// let the request continue into controllers that immediately
		// dereference `req.user._id`. Reject instead.
		if (!userdata) {
			return res.status(401).json({ error: "Invalid session." });
		}

		// We make user data accessible
		req.user = userdata;
		return next();
	} catch (err) {
		console.error("[auth middleware]", err);
		return res.status(500).json({ error: "Unable to verify the session." });
	}
};
