/**
 *
 * @author Anass Ferrak aka " TheLordA " <ferrak.anass@gmail.com>
 * GitHub repo: https://github.com/TheLordA/Instagram-Clone
 *
 */

const controller = require("../controllers/auth.controller");

// SECURITY (VULN-07): every credential-handling route is rate limited.
const { authLimiter, passwordResetLimiter } = require("../middleware/rateLimit.middleware");

module.exports = (app) => {
	// Route to handle SignUp requests
	app.post("/signup", authLimiter, controller.signup);

	// Route to handle SignIn requests
	app.post("/signin", authLimiter, controller.signin);

	// Route to handle Reset Passwords requests
	// Stricter limit: each accepted request sends an email.
	app.post("/reset-pwd", passwordResetLimiter, controller.resetPwd);

	// Route to handle Create New Passwords requests
	app.post("/new-pwd", authLimiter, controller.newPwd);
};
