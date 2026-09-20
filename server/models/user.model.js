/**
 *
 * @author Anass Ferrak aka " TheLordA " <ferrak.anass@gmail.com>
 * GitHub repo: https://github.com/TheLordA/Instagram-Clone
 *
 */

const mongoose = require("mongoose");
const { ObjectId } = mongoose.Schema.Types;

const userSchema = new mongoose.Schema({
	Name: {
		type: String,
		required: true,
	},
	Email: {
		type: String,
		required: true,
	},
	// SECURITY (VULN-02): secret-bearing fields are marked `select: false`
	// so they are excluded from every query by default and must be opted
	// into explicitly with `.select("+Field")`. Previously these fields
	// were returned by any query that did not remember to project them
	// away, which leaked live password-reset tokens to other users.
	// OAUTH: a Google-authenticated account has no local password. Making
	// `Password` unconditionally required would force us to invent one, and a
	// generated-then-discarded password is a credential that exists, can be
	// guessed, and protects nothing. Requiring it only for local accounts
	// means a Google account has no local credential at all.
	Password: {
		type: String,
		required: function () {
			return this.AuthProvider === "local";
		},
		select: false,
	},

	// OAUTH: Google's `sub` claim - a stable, immutable identifier for the
	// Google account. Email addresses can be reassigned between people, so
	// `sub` rather than `Email` is the correct key to link identities on.
	// `sparse` allows many documents without this field while still enforcing
	// uniqueness among those that have it.
	GoogleId: {
		type: String,
		unique: true,
		sparse: true,
		index: true,
	},

	// Which credential(s) can sign this account in:
	//   "local"  - email + password only
	//   "google" - Google only, no local password
	//   "hybrid" - an existing password account that later linked Google
	AuthProvider: {
		type: String,
		enum: ["local", "google", "hybrid"],
		default: "local",
	},
	ResetToken: { type: String, select: false },
	ExpirationToken: { type: Date, select: false },
	Photo: {
		type: Buffer,
	},
	PhotoType: {
		type: String,
	},
	Followers: [{ type: ObjectId, ref: "User" }],
	Following: [{ type: ObjectId, ref: "User" }],
	Bookmarks: [{ type: ObjectId, ref: "Post" }],
});

// Create a model from our schema
module.exports = mongoose.model("User", userSchema);
