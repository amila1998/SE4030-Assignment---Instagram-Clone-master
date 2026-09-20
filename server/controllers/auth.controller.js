/**
 *
 * @author Anass Ferrak aka " TheLordA " <ferrak.anass@gmail.com>
 * GitHub repo: https://github.com/TheLordA/Instagram-Clone
 *
 */

const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
// const sgMail = require("@sendgrid/mail");

// sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const User = require("../models/user.model");
const { signOptions } = require("../config/jwt.config");
const { validatePassword } = require("../utils/validators");

// bcrypt work factor. 12 keeps the original setting explicit and shared.
const BCRYPT_COST = 12;

// SECURITY (VULN-06): reset links are short-lived. 10 minutes matches the
// wording of the email template the upstream project ships.
const RESET_TOKEN_TTL_MS = 10 * 60 * 1000;

// SECURITY (VULN-06): one fixed reply for every password-reset request, so
// the endpoint cannot be used to discover which email addresses have
// accounts.
const GENERIC_RESET_RESPONSE =
	"If that email address has an account, a reset link has been sent to it.";

// SECURITY (VULN-06): only the digest of a reset token is persisted. The raw
// token exists solely in the email sent to the account owner.
const hashResetToken = (token) => crypto.createHash("sha256").update(token).digest("hex");

// SignUp Controller
exports.signup = (req, res) => {
	// SECURITY (VULN-03): same operator-injection guard as `signin`. Without
	// it, `{"email": {"$ne": null}}` makes the duplicate-account lookup match
	// an unrelated user and reject every registration attempt.
	const { name, email, password } = req.body;
	if (typeof name !== "string" || typeof email !== "string" || typeof password !== "string") {
		return res.status(400).json({ error: "Name, email and password must be strings." });
	}
	// Verifying if one of the fields is Empty
	if (!name || !password || !email) {
		return res.json({ error: "Please submit all required field" });
	}
	// SECURITY (VULN-06): the application previously accepted any non-empty
	// password, including a single character.
	const policyError = validatePassword(password);
	if (policyError) {
		return res.status(400).json({ error: policyError });
	}
	// Else we search the user with the credentials submitted
	User.findOne({ Email: email })
		.then((savedUser) => {
			// Verify if the user exist in the DB
			if (savedUser) {
				return res.json({ error: "This Email Is Already Used !" });
			}
			// We Hash the pwd before save into DB, more the number is high more it's more secure
			bcrypt.hash(password, BCRYPT_COST).then((hashedPwd) => {
				const user = new User({
					Name: name,
					Email: email,
					Password: hashedPwd,
				});
				// We save our new user to DB
				user.save()
					.then((user) => {
						// // after saving the user into DB we send a confirmation email
						// const email = {
						// 	from: "no-reply@insta-clone.com",
						// 	to: user.Email,
						// 	subject: "Your account has been created successfully",
						// 	html: "<h1>Welcome to InstaClone</h1>",
						// };
						// sgMail.send(email);
						res.json({ message: "Saved successfully " });
					})
					.catch((err) => {
						console.log(err);
					});
			});
		})
		.catch((err) => {
			console.log(err);
		});
};

// SignIn Controller
exports.signin = (req, res) => {
	// SECURITY (VULN-03): reject non-string credentials outright rather than
	// coercing them. `{"email": {"$ne": null}}` would otherwise reach
	// Mongoose as a query operator and match an arbitrary account instead of
	// performing the intended equality comparison.
	const { email, password } = req.body;
	if (typeof email !== "string" || typeof password !== "string") {
		return res.status(400).json({ error: "Email and password must be strings." });
	}
	// Verification for an empty field
	if (!email || !password) {
		return res.json({ error: "Please provide Email or Password" });
	}
	// Check if email exist in our DB
	// `Password` is `select: false` on the schema (VULN-02), so it has to be
	// requested explicitly here - this is the only place that needs it.
	User.findOne({ Email: email })
		.select("+Password")
		.then((savedUser) => {
			if (!savedUser) {
				return res.json({ error: "Invalid Email or Password" });
			}
			bcrypt.compare(password, savedUser.Password).then((doMatch) => {
				if (doMatch) {
					// SECURITY (VULN-05): sign with an explicit algorithm, a short
					// expiry and issuer/audience binding. Previously this call
					// passed no options at all, minting tokens that never expired.
					const token = jwt.sign(
						{ _id: savedUser._id },
						process.env.JWT_SECRET,
						signOptions
					);
					// retrieve the user info details and send it to the front
					const { _id, Name, Email, Followers, Following, Bookmarks } = savedUser;
					res.json({ token, user: { _id, Name, Email, Followers, Following, Bookmarks } });
				} else {
					return res.json({
						error: "Invalid Email or Password",
					});
				}
			});
		})
		.catch((err) => {
			console.log(err);
		});
};

// Reset Password Controller
exports.resetPwd = (req, res) => {
	// SECURITY (VULN-03): `{"email": {"$ne": null}}` here previously matched
	// the first user in the collection and stamped a reset token onto that
	// account - an attacker-triggered reset against a victim chosen by the
	// database, not by the requester.
	const { email } = req.body;
	if (typeof email !== "string") {
		return res.status(400).json({ error: "Email must be a string." });
	}
	crypto.randomBytes(32, (err, buffer) => {
		if (err) {
			console.error("[resetPwd] failed to generate reset token", err);
			return res.status(500).json({ error: GENERIC_RESET_RESPONSE });
		}
		const token = buffer.toString("hex");
		User.findOne({ Email: email }).then((user) => {
			// SECURITY (VULN-06): always return the same response whether or not
			// the address is registered. The old "No User exists with that
			// email" reply turned this endpoint into an account-existence
			// oracle for any address an attacker cared to test.
			if (!user) {
				return res.json({ message: GENERIC_RESET_RESPONSE });
			}

			// SECURITY (VULN-06): store only a SHA-256 digest of the token. The
			// raw token goes to the user's mailbox and is never persisted, so
			// read access to the database (backup, injection, insider) no
			// longer yields usable reset credentials.
			user.ResetToken = hashResetToken(token);
			user.ExpirationToken = Date.now() + RESET_TOKEN_TTL_MS;
			user.save().then((result) => {
				// this section will be fully functional after adding the SendGrid API Key
				// in order to use this feature
				// the following is an example of Email template

				// const email = {
				// 	from: "no-reply@insta-clone.com",
				// 	to: user.Email,
				// 	subject: "Password Reset",
				// 	html: `
				//      <p>A request has been made to change the password of your account </p>
				// 	 <h5>click on this <a href="http://localhost:3000/reset/${token}">link</a> to reset your password</h5>
				// 	 <p> Or copy and paste the following link :</p>
				// 	 <h5>"http://localhost:3000/reset/${token}"</h5>
				// 	 <h5>The link is only valid for 10min</h5>
				// 	 <h5>If you weren't the sender of that request , you can just ignore the message</h5>
				//      `,
				// };
				// sgMail.send(email);

				res.json({ message: GENERIC_RESET_RESPONSE });
			});
		});
	});
};

// New Password Controller
exports.newPwd = (req, res) => {
	// SECURITY (VULN-03): the reset token is matched directly against the
	// database, so a non-string here is the most dangerous injection in the
	// application: `{"token": {"$ne": null}}` matched ANY user that happened
	// to have a live reset token and handed the caller that account.
	const Password = req.body.password;
	const Token = req.body.token;
	if (typeof Password !== "string" || typeof Token !== "string") {
		return res.status(400).json({ error: "Token and password must be strings." });
	}
	// SECURITY (VULN-06): enforce the password policy on reset as well as on
	// sign-up. Validating in only one of the two paths lets an attacker (or a
	// user) route around the policy entirely.
	const policyError = validatePassword(Password);
	if (policyError) {
		return res.status(400).json({ error: policyError });
	}

	// SECURITY (VULN-06): look the token up by its digest, because only the
	// digest is stored. `ResetToken` is `select: false` (VULN-02) so it must
	// be requested explicitly for the clearing assignment below to persist.
	User.findOne({
		ResetToken: hashResetToken(Token),
		ExpirationToken: { $gt: Date.now() },
	})
		.select("+ResetToken +ExpirationToken")
		.then((user) => {
			if (!user) {
				return res.status(422).json({ error: "Session expired ! Try Again with a new Request" });
			}
			bcrypt.hash(Password, BCRYPT_COST).then((HashPwd) => {
				// SECURITY (VULN-06): the original line was `user.password = ...`
				// (lower-case p). The schema field is `Password`, so Mongoose
				// discarded the assignment and the reset silently completed
				// WITHOUT ever changing the password, while still consuming the
				// token. Users who reset after a suspected compromise kept their
				// old, compromised credentials and had no way to tell.
				user.Password = HashPwd;

				// Single-use: clear the token so a captured reset link cannot be
				// replayed within its validity window.
				user.ResetToken = undefined;
				user.ExpirationToken = undefined;
				user.save().then((result) => {
					res.json({ message: "Password Updated successfully" });
				});
			});
		})
		.catch((err) => {
			console.log(err);
		});
};
