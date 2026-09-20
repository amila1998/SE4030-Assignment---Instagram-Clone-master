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

exports.user = (req, res) => {
	// SECURITY (VULN-02): use an explicit allow-list projection rather than
	// the old `.select("-Password")` deny-list. A deny-list silently leaks
	// every field someone forgets to add to it - which is exactly how the
	// live `ResetToken` / `ExpirationToken` values ended up in this
	// response and made one-click account takeover possible.
	// SECURITY (VULN-08): validate the route parameter before querying.
	if (!isValidObjectId(req.params.id)) {
		return res.status(400).json({ error: "A valid user id is required." });
	}
	User.findOne({ _id: req.params.id })
		.select("_id Name Email Photo PhotoType Followers Following")
		.then((user) => {
			Post.find({ PostedBy: req.params.id })
				.populate("PostedBy", "_id Name")
				.exec((err, result) => {
					if (err) return res.status(422).json();
					const posts = [];
					result.map((item) => {
						posts.push({
							_id: item._id,
							Title: item.Title,
							Body: item.Body,
							Photo: item.Photo.toString("base64"),
							PhotoType: item.PhotoType,
							Likes: item.Likes,
							Comments: item.Comments,
							Followers: item.Followers,
							Following: item.Following,
						});
					});
					res.json({ user, posts });
				});
		})
		.catch((err) => {
			return res.status(404).json({ Error: "User not found" });
		});
};

exports.follow = (req, res) => {
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
	User.findByIdAndUpdate(
		req.body.followId,
		{
			$addToSet: { Followers: req.user._id },
		},
		{
			new: true,
		},
		(err, result) => {
			if (err) {
				return res.status(422).json({ error: err });
			}
			User.findByIdAndUpdate(
				req.user._id,
				{
					$addToSet: { Following: req.body.followId },
				},
				{ new: true }
			)
				.select("-Password")
				.then((result) => {
					res.json(result);
				})
				.catch((err) => {
					return res.status(422).json({ error: err });
				});
		}
	);
};

exports.unfollow = (req, res) => {
	// SECURITY (VULN-08): validate the target id before it reaches Mongoose.
	if (!isValidObjectId(req.body.unfollowId)) {
		return res.status(400).json({ error: "A valid unfollowId is required." });
	}
	User.findByIdAndUpdate(
		req.body.unfollowId,
		{
			$pull: { Followers: req.user._id },
		},
		{
			new: true,
		},
		(err, result) => {
			if (err) {
				return res.status(422).json({ error: err });
			}
			User.findByIdAndUpdate(
				req.user._id,
				{
					$pull: { Following: req.body.unfollowId },
				},
				{ new: true }
			)
				.select("-Password")
				.then((result) => {
					res.json(result);
				})
				.catch((err) => {
					return res.status(422).json({ error: err });
				});
		}
	);
};

exports.bookmarks = (req, res) => {
	User.find({ _id: req.user._id })
		.select("-Password")
		.then((user) => {
			const data = user[0].Bookmarks;
			Post.find({ _id: { $in: data } })
				.populate("PostedBy", "_id Name")
				.then((result) => {
					let bookmark = [];
					result.map((item) => {
						bookmark.push({
							_id: item._id,
							PostedBy: item.PostedBy,
							Title: item.Title,
							Body: item.Body,
							Photo: item.Photo.toString("base64"),
							PhotoType: item.PhotoType,
							Likes: item.Likes,
							Comments: item.Comments,
						});
					});
					res.json({ bookmark });
				})
				.catch((err) => console.log(err));
		})
		.catch((err) => {
			return res.status(404).json({ Error: "User not found" });
		});
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
			return res.json({ error: err });
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
			return res.json({ error: err });
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
