/**
 *
 * @author Anass Ferrak aka " TheLordA " <ferrak.anass@gmail.com>
 * GitHub repo: https://github.com/TheLordA/Instagram-Clone
 *
 */

const mongoose = require("mongoose");

const Post = require("../models/post.model");
const { validateEncodedImage } = require("../utils/imageUpload");

// SECURITY (VULN-08): bound every piece of user-authored text. Unbounded
// fields let a single request write an arbitrarily large document, which is
// both a storage-exhaustion vector and a way to make every subsequent feed
// response enormous for all other users.
const TITLE_MAX_LENGTH = 150;
const BODY_MAX_LENGTH = 2200; // matches Instagram's own caption limit
const COMMENT_MAX_LENGTH = 1000;

// SECURITY (VULN-09): the feed endpoints previously returned EVERY matching
// post, with the full base64 image inlined in each one. A growing database
// therefore turned a single authenticated GET into an ever-larger response -
// uncontrolled resource consumption on both the server and the client. Cap
// the page size until real cursor pagination is implemented.
const FEED_PAGE_SIZE = 50;

const validateText = (value, label, maxLength) => {
	if (typeof value !== "string") return `${label} must be a string.`;
	const trimmed = value.trim();
	if (trimmed.length === 0) return `${label} is required.`;
	if (trimmed.length > maxLength) return `${label} must be at most ${maxLength} characters.`;
	return null;
};

// SECURITY (VULN-08): reject malformed ObjectIds before they reach Mongoose.
// An invalid id otherwise produces a CastError whose message was echoed to
// the caller (see VULN-09) and, in the callback-style handlers below, was
// easy to mishandle.
const isValidObjectId = (id) => typeof id === "string" && mongoose.Types.ObjectId.isValid(id);

/**
 * Single serialisation shape for a post.
 *
 * Every handler previously rebuilt this object by hand, and each one called
 * `item.Photo.toString("base64")` unguarded. The schema defaults `Photo` to
 * the STRING "no photo" rather than a Buffer, so any post saved without an
 * image made the whole feed request throw. Centralising the shape fixes that
 * once and keeps the field allow-list in a single place.
 */
const serializePost = (item) => ({
	_id: item._id,
	Title: item.Title,
	Body: item.Body,
	PostedBy: item.PostedBy,
	Photo: Buffer.isBuffer(item.Photo) ? item.Photo.toString("base64") : null,
	PhotoType: item.PhotoType || null,
	Likes: item.Likes,
	Comments: item.Comments,
	createdAt: item.createdAt,
});

exports.allPost = async (req, res) => {
	try {
		const data = await Post.find()
			.populate("PostedBy", "_id Name")
			.populate("Comments.PostedBy", "_id Name")
			.sort("-createdAt")
			.limit(FEED_PAGE_SIZE);
		return res.json({ posts: data.map(serializePost) });
	} catch (err) {
		console.error("[allPost]", err);
		return res.status(500).json({ error: "Unable to load posts." });
	}
};

exports.subPost = async (req, res) => {
	try {
		const data = await Post.find({ PostedBy: { $in: req.user.Following } })
			.populate("PostedBy", "_id Name")
			.populate("Comments.PostedBy", "_id Name")
			.sort("-createdAt")
			.limit(FEED_PAGE_SIZE);
		return res.json({ posts: data.map(serializePost) });
	} catch (err) {
		console.error("[subPost]", err);
		return res.status(500).json({ error: "Unable to load posts." });
	}
};

exports.myPost = async (req, res) => {
	try {
		const data = await Post.find({ PostedBy: req.user._id })
			.populate("PostedBy", "_id Name")
			.populate("Comments.PostedBy", "_id Name")
			.sort("-createdAt")
			.limit(FEED_PAGE_SIZE);
		return res.json({ posts: data.map(serializePost) });
	} catch (err) {
		console.error("[myPost]", err);
		return res.status(500).json({ error: "Unable to load posts." });
	}
};

exports.createPost = (req, res) => {
	const { title, body, photoEncode, photoType } = req.body;

	// SECURITY (VULN-08): validate the text fields as strings and bound their
	// length. Previously any type and any length was accepted and written
	// straight to the database.
	const titleError = validateText(title, "Title", TITLE_MAX_LENGTH);
	if (titleError) return res.status(400).json({ error: titleError });

	const bodyError = validateText(body, "Body", BODY_MAX_LENGTH);
	if (bodyError) return res.status(400).json({ error: bodyError });

	// SECURITY (VULN-08): the image is sniffed from its own bytes; the
	// client-declared type is not trusted. This also fixes the ReferenceError
	// below, where the original code read an undeclared `photoEncoded`
	// instead of the destructured `photoEncode` and so threw on every call.
	const image = validateEncodedImage(photoEncode, photoType);
	if (!image.ok) {
		return res.status(400).json({ error: image.error });
	}

	const post = new Post({
		Title: title.trim(),
		Body: body.trim(),
		// Bind the post to the authenticated user's id only. Assigning the
		// whole `req.user` document here relied on Mongoose casting and
		// risked persisting fields that were never meant to be embedded.
		PostedBy: req.user._id,
		Photo: image.buffer,
		PhotoType: image.mimeType,
	});

	post.save()
		.then((result) => {
			res.status(201).json({ message: "Post created successfully", _id: result._id });
		})
		.catch((err) => {
			console.error("[createPost]", err);
			return res.status(500).json({ error: "Unable to create the post." });
		});
};

exports.like = async (req, res) => {
	// SECURITY (VULN-08): reject malformed ids before they reach Mongoose.
	if (!isValidObjectId(req.body.postId)) {
		return res.status(400).json({ error: "A valid postId is required." });
	}
	try {
		// $addToSet, not $push: repeated like requests previously appended a
		// duplicate entry per call, growing the Likes array without bound.
		const result = await Post.findByIdAndUpdate(
			req.body.postId,
			{ $addToSet: { Likes: req.user._id } },
			{ new: true }
		)
			.populate("PostedBy", "_id Name")
			.populate("Comments.PostedBy", "_id Name");

		if (!result) return res.status(404).json({ error: "Post not found." });
		return res.json(serializePost(result));
	} catch (err) {
		// SECURITY (VULN-09): log the detail, return a generic message.
		console.error("[like]", err);
		return res.status(500).json({ error: "Unable to like the post." });
	}
};

exports.unlike = async (req, res) => {
	// SECURITY (VULN-08): reject malformed ids before they reach Mongoose.
	if (!isValidObjectId(req.body.postId)) {
		return res.status(400).json({ error: "A valid postId is required." });
	}
	try {
		const result = await Post.findByIdAndUpdate(
			req.body.postId,
			{ $pull: { Likes: req.user._id } },
			{ new: true }
		)
			.populate("PostedBy", "_id Name")
			.populate("Comments.PostedBy", "_id Name");

		if (!result) return res.status(404).json({ error: "Post not found." });
		return res.json(serializePost(result));
	} catch (err) {
		console.error("[unlike]", err);
		return res.status(500).json({ error: "Unable to unlike the post." });
	}
};

exports.comment = async (req, res) => {
	// SECURITY (VULN-08): validate the comment text and the target post id.
	// The original handler pushed `req.body.text` of any type and any length
	// into the Comments array.
	const textError = validateText(req.body.text, "Comment", COMMENT_MAX_LENGTH);
	if (textError) return res.status(400).json({ error: textError });

	if (!isValidObjectId(req.body.postId)) {
		return res.status(400).json({ error: "A valid postId is required." });
	}

	try {
		const comment = { Text: req.body.text.trim(), PostedBy: req.user._id };
		const result = await Post.findByIdAndUpdate(
			req.body.postId,
			{ $push: { Comments: comment } },
			{ new: true }
		)
			.populate("Comments.PostedBy", "_id Name")
			.populate("PostedBy", "_id Name");

		if (!result) return res.status(404).json({ error: "Post not found." });
		return res.json(serializePost(result));
	} catch (err) {
		console.error("[comment]", err);
		return res.status(500).json({ error: "Unable to add the comment." });
	}
};

exports.deletePost = async (req, res) => {
	if (!isValidObjectId(req.params.postId)) {
		return res.status(400).json({ error: "A valid postId is required." });
	}
	try {
		const post = await Post.findById(req.params.postId).populate("PostedBy", "_id");
		if (!post) {
			return res.status(404).json({ error: "Post not found." });
		}

		// SECURITY (VULN-09): the original handler checked ownership but had
		// NO else branch - a non-owner's request simply fell off the end of
		// the function, so the response was never sent and the client hung
		// until it timed out. Deny explicitly with 403.
		if (post.PostedBy._id.toString() !== req.user._id.toString()) {
			return res.status(403).json({ error: "You can only delete your own posts." });
		}

		await post.deleteOne();
		return res.json({ _id: post._id });
	} catch (err) {
		console.error("[deletePost]", err);
		return res.status(500).json({ error: "Unable to delete the post." });
	}
};
