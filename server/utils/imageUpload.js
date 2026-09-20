/**
 * Image upload validation.
 *
 * SECURITY (VULN-08): the original application accepted an arbitrary base64
 * blob together with a client-declared `photoType`, stored both verbatim, and
 * echoed them back to every viewer inside a `data:` URI. Nothing checked what
 * the bytes actually were, how large they were, or whether the declared type
 * was true.
 *
 * The defence here is content sniffing: the declared type is ignored for
 * trust purposes and the real type is derived from the file's magic bytes.
 * A declared type is only accepted when it agrees with what the bytes say.
 */

// 5 MB of decoded image data. Base64 inflates by ~33%, so this corresponds to
// roughly 6.7 MB on the wire.
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;

/**
 * Magic-byte signatures for the formats we are willing to store and serve.
 * SVG is deliberately NOT included: it is an XML document that can carry
 * <script>, so serving user-supplied SVG from the application's origin is a
 * stored-XSS primitive.
 */
const SIGNATURES = [
	{ mime: "image/jpeg", bytes: [0xff, 0xd8, 0xff] },
	{ mime: "image/png", bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
	{ mime: "image/gif", bytes: [0x47, 0x49, 0x46, 0x38] }, // "GIF8"
];

const ALLOWED_MIME_TYPES = SIGNATURES.map((s) => s.mime).concat("image/webp");

const startsWith = (buffer, bytes) =>
	buffer.length >= bytes.length && bytes.every((b, i) => buffer[i] === b);

/**
 * WebP is a RIFF container: "RIFF" <4-byte size> "WEBP".
 */
const isWebp = (buffer) =>
	buffer.length >= 12 &&
	buffer.toString("ascii", 0, 4) === "RIFF" &&
	buffer.toString("ascii", 8, 12) === "WEBP";

/**
 * Determine the true MIME type of a buffer from its content.
 * @returns {string|null} the detected type, or null if unrecognised.
 */
const sniffMimeType = (buffer) => {
	for (const sig of SIGNATURES) {
		if (startsWith(buffer, sig.bytes)) return sig.mime;
	}
	if (isWebp(buffer)) return "image/webp";
	return null;
};

/**
 * Validate a base64-encoded image submitted by a client.
 *
 * @param {unknown} photoEncoded base64 payload from the request body
 * @param {unknown} declaredType the client-supplied MIME type
 * @returns {{ok: true, buffer: Buffer, mimeType: string} | {ok: false, error: string}}
 */
const validateEncodedImage = (photoEncoded, declaredType) => {
	if (typeof photoEncoded !== "string" || photoEncoded.length === 0) {
		return { ok: false, error: "An image is required." };
	}

	// Cheap length check before allocating the decoded buffer, so an
	// oversized payload is rejected without spending the memory.
	const approxDecodedBytes = Math.floor((photoEncoded.length * 3) / 4);
	if (approxDecodedBytes > MAX_IMAGE_BYTES) {
		return { ok: false, error: "Image exceeds the 5 MB limit." };
	}

	// Accept an optional data-URI prefix, then require strict base64 so that
	// arbitrary text cannot be smuggled through Buffer.from's lenient parser.
	const payload = photoEncoded.replace(/^data:[^;]+;base64,/, "");
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(payload)) {
		return { ok: false, error: "Image is not valid base64." };
	}

	let buffer;
	try {
		buffer = Buffer.from(payload, "base64");
	} catch (err) {
		return { ok: false, error: "Image is not valid base64." };
	}

	if (buffer.length === 0) {
		return { ok: false, error: "An image is required." };
	}
	if (buffer.length > MAX_IMAGE_BYTES) {
		return { ok: false, error: "Image exceeds the 5 MB limit." };
	}

	// The authoritative check: what are these bytes, really?
	const actualType = sniffMimeType(buffer);
	if (!actualType) {
		return {
			ok: false,
			error: "Unsupported image format. Allowed: JPEG, PNG, GIF, WebP.",
		};
	}

	// If the client declared a type, it must agree with the content. We store
	// the SNIFFED type either way, never the declared one.
	if (typeof declaredType === "string" && declaredType.length > 0) {
		const normalised = declaredType.trim().toLowerCase();
		if (!ALLOWED_MIME_TYPES.includes(normalised)) {
			return { ok: false, error: "Unsupported image type." };
		}
		if (normalised !== actualType) {
			return { ok: false, error: "Declared image type does not match the file content." };
		}
	}

	return { ok: true, buffer, mimeType: actualType };
};

module.exports = {
	MAX_IMAGE_BYTES,
	ALLOWED_MIME_TYPES,
	sniffMimeType,
	validateEncodedImage,
};
