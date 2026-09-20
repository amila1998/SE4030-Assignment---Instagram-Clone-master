/**
 * Centralised JWT configuration.
 *
 * SECURITY (VULN-05): the original code called `jwt.sign(payload, secret)`
 * with no options and `jwt.verify(token, secret, cb)` with no options. That
 * produced tokens which never expired and which were validated against
 * whatever algorithm the token's own header claimed. Both the signing and
 * the verification side now share the constants below so they cannot drift
 * apart.
 */

// Pin the algorithm on both sides. Without this, `jsonwebtoken` will honour
// the `alg` header inside the attacker-supplied token, which is the root of
// the classic algorithm-confusion family of attacks (e.g. downgrading an
// RS256 deployment to HS256 and signing with the public key).
const JWT_ALGORITHM = "HS256";

// Short-lived access tokens. A stolen token is only useful for this long.
const JWT_EXPIRES_IN = "1h";

// Binding the issuer and audience means a token minted by some other service
// that happens to share the secret cannot be replayed against this API.
const JWT_ISSUER = "instagram-clone-api";
const JWT_AUDIENCE = "instagram-clone-client";

// Minimum acceptable entropy for an HS256 signing key. HS256 keys shorter
// than the 256-bit output of SHA-256 weaken the HMAC, and short human-chosen
// secrets are offline-brute-forceable against any captured token.
const MIN_SECRET_LENGTH = 32;

/**
 * Fail fast at start-up rather than at first login. A server that boots with
 * a missing or weak signing key is not safe to serve traffic, and silently
 * defaulting the secret (as many tutorials do) is how placeholder values
 * reach production.
 */
const assertSecretIsStrong = () => {
	const secret = process.env.JWT_SECRET;

	if (!secret) {
		throw new Error(
			"JWT_SECRET is not set. Refusing to start: tokens cannot be signed securely without it."
		);
	}
	if (secret.length < MIN_SECRET_LENGTH) {
		throw new Error(
			`JWT_SECRET is too short (${secret.length} chars). ` +
				`Use at least ${MIN_SECRET_LENGTH} characters of high-entropy random data, ` +
				`e.g. \`openssl rand -base64 48\`.`
		);
	}
	// Reject the placeholder shipped in .env.sample so a copied sample file
	// cannot become a real signing key.
	if (/put ur jwt secret here/i.test(secret)) {
		throw new Error("JWT_SECRET is still the placeholder value from .env.sample.");
	}
};

const signOptions = {
	algorithm: JWT_ALGORITHM,
	expiresIn: JWT_EXPIRES_IN,
	issuer: JWT_ISSUER,
	audience: JWT_AUDIENCE,
};

const verifyOptions = {
	algorithms: [JWT_ALGORITHM],
	issuer: JWT_ISSUER,
	audience: JWT_AUDIENCE,
};

module.exports = {
	JWT_ALGORITHM,
	JWT_EXPIRES_IN,
	JWT_ISSUER,
	JWT_AUDIENCE,
	MIN_SECRET_LENGTH,
	assertSecretIsStrong,
	signOptions,
	verifyOptions,
};
