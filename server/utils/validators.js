/**
 * Shared input-validation helpers.
 *
 * Kept in one module so that every entry point which accepts a password or a
 * piece of user-authored text applies the same rule. Duplicated, slightly
 * divergent validation is a common source of bypasses.
 */

// SECURITY (VULN-06): the original application accepted any non-empty string
// as a password, including "a". bcrypt cost does not help when the plaintext
// is trivially guessable, so a baseline policy is enforced at the boundary.
const PASSWORD_MIN_LENGTH = 10;
const PASSWORD_MAX_LENGTH = 128; // bcrypt truncates past 72 bytes; also a DoS bound

/**
 * Validate a candidate password against the policy.
 * @returns {string|null} an error message, or null when the password is fine.
 */
const validatePassword = (password) => {
	if (typeof password !== "string") {
		return "Password must be a string.";
	}
	if (password.length < PASSWORD_MIN_LENGTH) {
		return `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`;
	}
	if (password.length > PASSWORD_MAX_LENGTH) {
		return `Password must be at most ${PASSWORD_MAX_LENGTH} characters long.`;
	}
	// Require a mix of character classes. This is deliberately modest: NIST
	// SP 800-63B favours length over composition rules, and the length
	// minimum above is doing most of the work here.
	if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
		return "Password must contain a lowercase letter, an uppercase letter and a digit.";
	}
	return null;
};

module.exports = {
	PASSWORD_MIN_LENGTH,
	PASSWORD_MAX_LENGTH,
	validatePassword,
};
