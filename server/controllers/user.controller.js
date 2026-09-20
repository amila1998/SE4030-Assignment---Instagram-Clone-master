/**
 *
 * @author Anass Ferrak aka " TheLordA " <ferrak.anass@gmail.com>
 * GitHub repo: https://github.com/TheLordA/Instagram-Clone
 *
 */
const mongoose = require("mongoose");

const Post = require("../models/post.model");
const User = require("../models/user.model");
const { validateEncodedImage } = require("../utils/imageUpload");

// SECURITY (VULN-08): reject malformed ObjectIds at the boundary.
const isValidObjectId = (id) => typeof id === "string" && mongoose.Types.ObjectId.isValid(id);

// SECURITY (VULN-09): `Photo` defaults to the STRING "no photo" in the post
// schema, so the old unguarded `item.Photo.toString("base64")` produced
// garbage for image-less posts. One guarded serialiser, used by every
// handler here, also keeps the returned field list explicit.
const serializePost = (item) => ({
	_id: item._id,
	PostedBy: item.PostedBy,
	Title: item.Title,
	Body: item.Body,
	Photo: Buffer.isBuffer(item.Photo) ? item.Photo.toString("base64") : null,
	PhotoType: item.PhotoType || null,
	Likes: item.Likes,
	Comments: item.Comments,
	createdAt: item.createdAt,
});

// Bound profile and bookmark listings for the same reason as the feeds.
const PROFILE_PAGE_SIZE = 50;

exports.user = async (req, res) => {
	// SECURITY (VULN-02): use an explicit allow-list projection rather than
	// the old `.select("-Password")` deny-list. A deny-list silently leaks
	// every field someone forgets to add to it - which is exactly how the
	// live `ResetToken` / `ExpirationToken` values ended up in this
	// response and made one-click account takeover possible.
	// SECURITY (VULN-08): validate the route parameter before querying.
	if (!isValidObjectId(req.params.id)) {
		return res.status(400).json({ error: "A valid user id is required." });
	}
	try {
		const user = await User.findOne({ _id: req.params.id }).select(
			"_id Name Email Photo PhotoType Followers Following"
		);
		if (!user) {
			return res.status(404).json({ error: "User not found." });
		}

		const result = await Post.find({ PostedBy: req.params.id })
			.populate("PostedBy", "_id Name")
			.sort("-createdAt")
			.limit(PROFILE_PAGE_SIZE);

		return res.json({ user, posts: result.map(serializePost) });
	} catch (err) {
		// SECURITY (VULN-09): log the detail, return a generic message.
		console.error("[user]", err);
		return res.status(500).json({ error: "Unable to load the profile." });
	}
};

exports.follow = async (req, res) => {
	// SECURITY (VULN-08): validate the target id, and use $addToSet rather
	// than $push. With $push, replaying the same follow request appended a
	// duplicate entry every time, letting one caller grow another user's
	// Followers array without bound until the 16 MB BSON document limit broke
	// that user's profile permanently.
	if (!isValidObjectId(req.body.followId)) {
		return res.status(400).json({ error: "A valid followId is required." });
	}
	if (req.body.followId === req.user._id.toString()) {
		return res.status(400).json({ error: "You cannot follow yourself." });
	}
	try {
		const target = await User.findByIdAndUpdate(
			req.body.followId,
			{ $addToSet: { Followers: req.user._id } },
			{ new: true }
		);
		if (!target) {
			return res.status(404).json({ error: "User not found." });
		}

		const result = await User.findByIdAndUpdate(
			req.user._id,
			{ $addToSet: { Following: req.body.followId } },
			{ new: true }
		).select("_id Name Email Photo PhotoType Followers Following Bookmarks");

		return res.json(result);
	} catch (err) {
		// SECURITY (VULN-09): log the detail, return a generic message.
		console.error("[follow]", err);
		return res.status(500).json({ error: "Unable to complete the request." });
	}
};

exports.unfollow = async (req, res) => {
	// SECURITY (VULN-08): validate the target id before it reaches Mongoose.
	if (!isValidObjectId(req.body.unfollowId)) {
		return res.status(400).json({ error: "A valid unfollowId is required." });
	}
	try {
		const target = await User.findByIdAndUpdate(
			req.body.unfollowId,
			{ $pull: { Followers: req.user._id } },
			{ new: true }
		);
		if (!target) {
			return res.status(404).json({ error: "User not found." });
		}

		const result = await User.findByIdAndUpdate(
			req.user._id,
			{ $pull: { Following: req.body.unfollowId } },
			{ new: true }
		).select("_id Name Email Photo PhotoType Followers Following Bookmarks");

		return res.json(result);
	} catch (err) {
		console.error("[unfollow]", err);
		return res.status(500).json({ error: "Unable to complete the request." });
	}
};

exports.bookmarks = async (req, res) => {
	try {
		// The original read `user[0].Bookmarks` from a .find() result without
		// checking that the array was non-empty, which threw on any request
		// whose session pointed at a deleted account.
		const user = await User.findById(req.user._id).select("_id Bookmarks");
		if (!user) {
			return res.status(404).json({ error: "User not found." });
		}

		const result = await Post.find({ _id: { $in: user.Bookmarks } })
			.populate("PostedBy", "_id Name")
			.limit(PROFILE_PAGE_SIZE);

		return res.json({ bookmark: result.map(serializePost) });
	} catch (err) {
		console.error("[bookmarks]", err);
		return res.status(500).json({ error: "Unable to load bookmarks." });
	}
};

exports.bookmarkPost = (req, res) => {
	// SECURITY (VULN-08): validate the id and use $addToSet so that repeated
	// bookmarking of the same post cannot grow the array without bound.
	if (!isValidObjectId(req.body.postId)) {
		return res.status(400).json({ error: "A valid postId is required." });
	}
	User.findByIdAndUpdate(
		req.user._id,
		{
			$addToSet: { Bookmarks: req.body.postId },
		},
		{ new: true }
	)
		.select("-Password")
		.then((result) => {
			res.json(result);
		})
		.catch((err) => {
			console.error("[bookmark]", err);
			return res.status(500).json({ error: "Unable to update bookmarks." });
		});
};

exports.removeBookmark = (req, res) => {
	// SECURITY (VULN-08): validate the id before it reaches Mongoose.
	if (!isValidObjectId(req.body.postId)) {
		return res.status(400).json({ error: "A valid postId is required." });
	}
	User.findByIdAndUpdate(
		req.user._id,
		{
			$pull: { Bookmarks: req.body.postId },
		},
		{ new: true }
	)
		.select("-Password")
		.then((result) => {
			res.json(result);
		})
		.catch((err) => {
			console.error("[bookmark]", err);
			return res.status(500).json({ error: "Unable to update bookmarks." });
		});
};

// Just Wrote the logic of it but not yet tested and the client implementation doesn't exist yet
exports.updatePicture = (req, res) => {
	// SECURITY (VULN-08): the profile picture went through exactly the same
	// unvalidated path as post images - an arbitrary client-supplied blob and
	// an arbitrary client-declared MIME type, written straight to the user
	// document. It now uses the same content-sniffing validator, so the
	// stored type always reflects the real bytes.
	const image = validateEncodedImage(req.body.Photo, req.body.PhotoType);
	if (!image.ok) {
		return res.status(400).json({ error: image.error });
	}

	User.findByIdAndUpdate(
		req.user._id,
		{ $set: { Photo: image.buffer, PhotoType: image.mimeType } },
		{ new: true }
	)
		.select("_id Name Email Photo PhotoType Followers Following")
		.then((result) => {
			res.json(result);
		})
		.catch((err) => {
			console.error("[updatePicture]", err);
			return res.status(500).json({ error: "Unable to update the profile picture." });
		});
};

// SECURITY (VULN-04): escape every character that carries meaning inside a
// regular expression, so caller input is matched literally instead of being
// executed as a pattern.
const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// An empty or absent pattern used to match every user in the collection.
// Require a minimum prefix length so that search cannot be used to walk the
// entire user base, and cap the length so the generated regex stays small.
const MIN_SEARCH_LENGTH = 3;
const MAX_SEARCH_LENGTH = 64;
const MAX_SEARCH_RESULTS = 20;

exports.userSearch = (req, res) => {
	const { pattern } = req.body;

	// Reject non-strings outright (NoSQL operator injection guard, VULN-03).
	if (typeof pattern !== "string") {
		return res.status(400).json({ error: "Search pattern must be a string." });
	}

	const term = pattern.trim();
	if (term.length < MIN_SEARCH_LENGTH) {
		return res
			.status(400)
			.json({ error: `Search pattern must be at least ${MIN_SEARCH_LENGTH} characters.` });
	}
	if (term.length > MAX_SEARCH_LENGTH) {
		return res.status(400).json({ error: "Search pattern is too long." });
	}

	// Anchored, fully escaped, case-insensitive prefix match. Because the
	// input is escaped it can no longer contain quantifiers, so catastrophic
	// backtracking is not reachable.
	const safePattern = new RegExp("^" + escapeRegExp(term), "i");

	User.find({ Email: { $regex: safePattern } })
		.select("_id Email Name")
		.limit(MAX_SEARCH_RESULTS)
		.then((user) => {
			res.json({ user });
		})
		.catch((err) => {
			console.error("[userSearch]", err);
			return res.status(500).json({ error: "Unable to complete the search." });
		});
};
