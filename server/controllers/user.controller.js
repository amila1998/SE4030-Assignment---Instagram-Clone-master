/**
 *
 * @author Anass Ferrak aka " TheLordA " <ferrak.anass@gmail.com>
 * GitHub repo: https://github.com/TheLordA/Instagram-Clone
 *
 */
const Post = require("../models/post.model");
const User = require("../models/user.model");

exports.user = (req, res) => {
	// SECURITY (VULN-02): use an explicit allow-list projection rather than
	// the old `.select("-Password")` deny-list. A deny-list silently leaks
	// every field someone forgets to add to it - which is exactly how the
	// live `ResetToken` / `ExpirationToken` values ended up in this
	// response and made one-click account takeover possible.
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
	User.findByIdAndUpdate(
		req.body.followId,
		{
			$push: { Followers: req.user._id },
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
					$push: { Following: req.body.followId },
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
	User.findByIdAndUpdate(
		req.user._id,
		{
			$push: { Bookmarks: req.body.postId },
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
	User.findByIdAndUpdate(
		req.user._id,
		{ $set: { Photo: req.body.Photo, PhotoType: req.body.PhotoType } },
		{ new: true },
		(err, result) => {
			if (err) {
				return res.status(422).json({ error: "pic canot post" });
			}
			res.json(result);
		}
	);
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
