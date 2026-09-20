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

exports.allPost = (req, res) => {
	Post.find()
		.populate("PostedBy", "_id Name")
		.populate("Comments.PostedBy", "_id Name")
		.sort("-createdAt")
		.then((data) => {
			let posts = [];
			data.map((item) => {
				posts.push({
					_id: item._id,
					Title: item.Title,
					Body: item.Body,
					PostedBy: item.PostedBy,
					Photo: item.Photo.toString("base64"),
					PhotoType: item.PhotoType,
					Likes: item.Likes,
					Comments: item.Comments,
				});
			});
			res.json({ posts });
		})
		.catch((err) => {
			console.log(err);
		});
};

exports.subPost = (req, res) => {
	Post.find({ PostedBy: { $in: req.user.Following } })
		.populate("PostedBy", "_id Name")
		.populate("Comments.PostedBy", "_id Name")
		.sort("-createdAt")
		.then((data) => {
			let posts = [];
			data.map((item) => {
				posts.push({
					_id: item._id,
					Title: item.Title,
					Body: item.Body,
					PostedBy: item.PostedBy,
					Photo: item.Photo.toString("base64"),
					PhotoType: item.PhotoType,
					Likes: item.Likes,
					Comments: item.Comments,
				});
			});
			res.json({ posts });
		})
		.catch((err) => {
			console.log(err);
		});
};

exports.myPost = (req, res) => {
	Post.find({ PostedBy: req.user._id })
		.populate("PostedBy", "_id Name")
		.populate("Comments.PostedBy", "_id Name")
		.sort("-createdAt")
		.then((data) => {
			let posts = [];
			data.map((item) => {
				posts.push({
					id: item._id,
					title: item.Title,
					body: item.body,
					//postedBy: item.PostedBy,
					photo: item.Photo.toString("base64"),
					photoType: item.PhotoType,
					likes: item.Likes,
					Comments: item.Comments,
				});
			});
			res.json({ posts });
		})
		.catch((err) => {
			console.log(err);
		});
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

exports.like = (req, res) => {
	// SECURITY (VULN-08): reject malformed ids before they reach Mongoose.
	if (!isValidObjectId(req.body.postId)) {
		return res.status(400).json({ error: "A valid postId is required." });
	}
	Post.findByIdAndUpdate(
		req.body.postId,
		{
			$push: { Likes: req.user._id },
		},
		{ new: true }
	)
		.populate("PostedBy", "_id Name")
		.populate("Comments.PostedBy", "_id Name")
		.exec((err, result) => {
			if (err) return res.status(422).json({ Error: err });
			else {
				res.json({
					_id: result._id,
					Title: result.Title,
					Body: result.Body,
					PostedBy: result.PostedBy,
					Photo: result.Photo.toString("base64"),
					PhotoType: result.PhotoType,
					Likes: result.Likes,
					Comments: result.Comments,
				});
			}
		});
};

exports.unlike = (req, res) => {
	// SECURITY (VULN-08): reject malformed ids before they reach Mongoose.
	if (!isValidObjectId(req.body.postId)) {
		return res.status(400).json({ error: "A valid postId is required." });
	}
	Post.findByIdAndUpdate(
		req.body.postId,
		{
			$pull: { Likes: req.user._id },
		},
		{ new: true }
	)
		.populate("PostedBy", "_id Name")
		.populate("Comments.PostedBy", "_id Name")
		.exec((err, result) => {
			if (err) return res.status(422).json({ Error: err });
			else {
				console.log(result);
				res.json({
					_id: result._id,
					Title: result.Title,
					Body: result.Body,
					PostedBy: result.PostedBy,
					Photo: result.Photo.toString("base64"),
					PhotoType: result.PhotoType,
					Likes: result.Likes,
					Comments: result.Comments,
				});
			}
		});
};

exports.comment = (req, res) => {
	// SECURITY (VULN-08): validate the comment text and the target post id.
	// The original handler pushed `req.body.text` of any type and any length
	// into the Comments array.
	const textError = validateText(req.body.text, "Comment", COMMENT_MAX_LENGTH);
	if (textError) return res.status(400).json({ error: textError });

	if (!isValidObjectId(req.body.postId)) {
		return res.status(400).json({ error: "A valid postId is required." });
	}

	const comment = { Text: req.body.text.trim(), PostedBy: req.user._id };
	Post.findByIdAndUpdate(
		req.body.postId,
		{
			$push: { Comments: comment },
		},
		{ new: true }
	)
		.populate("Comments.PostedBy", "_id Name")
		.populate("PostedBy", "_id Name")
		.exec((err, result) => {
			if (err) return res.status(422).json({ Error: err });
			else {
				res.json({
					_id: result._id,
					Title: result.Title,
					Body: result.Body,
					PostedBy: result.PostedBy,
					Photo: result.Photo.toString("base64"),
					PhotoType: result.PhotoType,
					Likes: result.Likes,
					Comments: result.Comments,
				});
			}
		});
};

exports.deletePost = (req, res) => {
	Post.findOne({ _id: req.params.postId })
		.populate("PostedBy", "_id")
		.exec((err, post) => {
			if (err || !post) return res.status(422).json({ Error: err });
			if (post.PostedBy._id.toString() === req.user._id.toString()) {
				post.remove()
					.then((result) => {
						res.json(result._id);
					})
					.catch((err) => console.log(err));
			}
		});
};
