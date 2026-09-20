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
	Password: {
		type: String,
		required: true,
		select: false,
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
