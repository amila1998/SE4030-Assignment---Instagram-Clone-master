/**
 * Runtime verification of the SE4030 security fixes.
 *
 * Black-box: talks to the running API over HTTP exactly as an attacker
 * would. Each check states the vulnerability it covers, the request that
 * exploited it before the fix, and the behaviour now expected.
 *
 * Usage:
 *   1. start MongoDB            docker run -d -p 27017:27017 mongo:7
 *   2. start the API            cd server && npm start
 *   3. node security/verify-fixes.js
 */

const BASE = process.env.API_BASE || "http://localhost:5000";

let passed = 0;
let failed = 0;

const post = async (path, body, token) => {
	const res = await fetch(BASE + path, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			...(token ? { Authorization: "Bearer " + token } : {}),
		},
		body: JSON.stringify(body),
	});
	let json = null;
	try {
		json = await res.json();
	} catch (e) {
		/* non-JSON response */
	}
	return { status: res.status, json, headers: res.headers };
};

const put = async (path, body, token) => {
	const res = await fetch(BASE + path, {
		method: "PUT",
		headers: {
			"Content-Type": "application/json",
			...(token ? { Authorization: "Bearer " + token } : {}),
		},
		body: JSON.stringify(body),
	});
	let json = null;
	try {
		json = await res.json();
	} catch (e) {
		/* non-JSON response */
	}
	return { status: res.status, json, headers: res.headers };
};

const get = async (path, token) => {
	const res = await fetch(BASE + path, {
		headers: token ? { Authorization: "Bearer " + token } : {},
	});
	let json = null;
	try {
		json = await res.json();
	} catch (e) {
		/* non-JSON response */
	}
	return { status: res.status, json, headers: res.headers };
};

const check = (vuln, description, condition, detail) => {
	if (condition) {
		passed++;
		console.log(`  PASS  [${vuln}] ${description}`);
	} else {
		failed++;
		console.log(`  FAIL  [${vuln}] ${description}`);
		if (detail !== undefined) console.log("        got:", JSON.stringify(detail));
	}
};

const section = (title) => console.log(`\n${title}\n${"-".repeat(title.length)}`);

const run = async () => {
	const stamp = Date.now();
	const email = `probe_${stamp}@example.com`;
	const strongPassword = "CorrectHorse1Battery";

	section("VULN-06  Password policy");
	const weak = await post("/signup", { name: "Probe", email, password: "a" });
	check("VULN-06", "single-character password is rejected", weak.status === 400, weak.json);

	const good = await post("/signup", { name: "Probe", email, password: strongPassword });
	check(
		"VULN-06",
		"policy-compliant password is accepted",
		good.status === 200 || good.status === 201,
		good.json
	);

	section("VULN-03  NoSQL operator injection");
	const inj = await post("/signin", { email: { $ne: null }, password: strongPassword });
	check("VULN-03", "signin with {$ne:null} email is rejected", inj.status === 400, inj.json);

	const injReset = await post("/new-pwd", { token: { $ne: null }, password: strongPassword });
	check(
		"VULN-03",
		"new-pwd with {$ne:null} token is rejected",
		injReset.status === 400,
		injReset.json
	);

	section("VULN-05  JWT hardening");
	const login = await post("/signin", { email, password: strongPassword });
	check("VULN-05", "valid credentials return a token", !!(login.json && login.json.token), login.json);

	const token = login.json && login.json.token;
	let claims = null;
	if (token) {
		claims = JSON.parse(Buffer.from(token.split(".")[1], "base64").toString());
		const header = JSON.parse(Buffer.from(token.split(".")[0], "base64").toString());
		check("VULN-05", "token carries an exp claim", typeof claims.exp === "number", claims);
		check("VULN-05", "token algorithm is HS256", header.alg === "HS256", header);
		check("VULN-05", "token carries the expected issuer", claims.iss === "instagram-clone-api", claims);
		check(
			"VULN-05",
			"token carries the expected audience",
			claims.aud === "instagram-clone-client",
			claims
		);
	}

	const forged = await get("/allpost", "not.a.real.token");
	check("VULN-05", "a forged token is rejected with 401", forged.status === 401, forged.json);

	const noScheme = await get("/allpost", undefined);
	check("VULN-05", "a missing Authorization header is rejected", noScheme.status === 401, noScheme.json);

	section("VULN-01  Authentication on user search");
	const anon = await post("/users-research", { pattern: "probe" });
	check("VULN-01", "user search without a token returns 401", anon.status === 401, anon.json);

	section("VULN-04  Regex injection in user search");
	if (token) {
		const wildcard = await post("/users-research", { pattern: ".*probe" }, token);
		const users = (wildcard.json && wildcard.json.user) || [];
		check(
			"VULN-04",
			"wildcard pattern '.*probe' is matched literally, not as a regex",
			wildcard.status === 200 && users.length === 0,
			wildcard.json
		);

		const tooShort = await post("/users-research", { pattern: "a" }, token);
		check("VULN-04", "single-character search is rejected", tooShort.status === 400, tooShort.json);

		const legit = await post("/users-research", { pattern: "probe_" + stamp }, token);
		check(
			"VULN-04",
			"legitimate prefix search still works",
			legit.status === 200 && ((legit.json && legit.json.user) || []).length === 1,
			legit.json
		);
	}

	section("VULN-02  Reset-token exposure");
	if (token && login.json.user) {
		await post("/reset-pwd", { email });
		const profile = await get("/user/" + login.json.user._id, token);
		const body = JSON.stringify(profile.json || {});
		check(
			"VULN-02",
			"GET /user/:id does not expose ResetToken",
			!body.includes("ResetToken"),
			profile.json && profile.json.user
		);
		check(
			"VULN-02",
			"GET /user/:id does not expose Password",
			!body.includes("Password"),
			profile.json && profile.json.user
		);
	}

	section("VULN-06  Account enumeration on password reset");
	const known = await post("/reset-pwd", { email });
	const unknown = await post("/reset-pwd", { email: `absent_${stamp}@example.com` });
	check(
		"VULN-06",
		"known and unknown addresses get identical responses",
		JSON.stringify(known.json) === JSON.stringify(unknown.json),
		{ known: known.json, unknown: unknown.json }
	);

	section("VULN-08  Upload validation and input bounds");
	if (token) {
		const htmlAsImage = Buffer.from("<html><script>alert(1)</script></html>").toString("base64");
		const spoof = await post(
			"/createpost",
			{ title: "t", body: "b", photoEncode: htmlAsImage, photoType: "image/png" },
			token
		);
		check("VULN-08", "HTML bytes declared as image/png are rejected", spoof.status === 400, spoof.json);

		const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>').toString(
			"base64"
		);
		const svgRes = await post(
			"/createpost",
			{ title: "t", body: "b", photoEncode: svg, photoType: "image/svg+xml" },
			token
		);
		check("VULN-08", "SVG upload is rejected", svgRes.status === 400, svgRes.json);

		const longTitle = await post(
			"/createpost",
			{ title: "x".repeat(500), body: "b", photoEncode: "", photoType: "image/png" },
			token
		);
		check("VULN-08", "over-long title is rejected", longTitle.status === 400, longTitle.json);

		const badId = await put("/like", { postId: "not-an-objectid" }, token);
		check("VULN-08", "malformed ObjectId is rejected with 400", badId.status === 400, badId.json);
	}

	section("VULN-09  Security headers and error handling");
	const headRes = await get("/allpost", token);
	const h = headRes.headers;
	check("VULN-09", "X-Powered-By is not disclosed", !h.get("x-powered-by"), h.get("x-powered-by"));
	check(
		"VULN-09",
		"Content-Security-Policy is set",
		!!h.get("content-security-policy"),
		h.get("content-security-policy")
	);
	check(
		"VULN-09",
		"X-Content-Type-Options is nosniff",
		h.get("x-content-type-options") === "nosniff",
		h.get("x-content-type-options")
	);
	check(
		"VULN-09",
		"X-Frame-Options / frame-ancestors set (clickjacking)",
		!!h.get("x-frame-options") ||
			(h.get("content-security-policy") || "").includes("frame-ancestors"),
		h.get("x-frame-options")
	);
	check(
		"VULN-09",
		"Referrer-Policy is set",
		!!h.get("referrer-policy"),
		h.get("referrer-policy")
	);

	const notFound = await get("/definitely-not-a-route", token);
	check("VULN-09", "unknown route returns JSON 404, not an HTML stack", notFound.status === 404, notFound.json);

	if (token) {
		const badDelete = await fetch(BASE + "/deletepost/not-an-objectid", {
			method: "DELETE",
			headers: { Authorization: "Bearer " + token },
		});
		check("VULN-09", "malformed delete id returns 400 and does not hang", badDelete.status === 400);
	}

	section("VULN-07  Rate limiting");
	// authLimiter allows 10 FAILED attempts per 15 minutes.
	let limited = false;
	let seen = 0;
	for (let i = 0; i < 14; i++) {
		const r = await post("/signin", { email, password: "WrongPassword123" });
		seen++;
		if (r.status === 429) {
			limited = true;
			break;
		}
	}
	check("VULN-07", `repeated failed logins are throttled (429 after ${seen} attempts)`, limited);

	console.log(`\n${"=".repeat(60)}`);
	console.log(`RESULT: ${passed} passed, ${failed} failed`);
	console.log("=".repeat(60));
	// Set the exit code and let the event loop drain naturally. Calling
	// process.exit() here races Node's teardown of undici's keep-alive
	// sockets on Windows and prints a spurious libuv assertion AFTER the
	// results, which reads like a failure but is not one.
	process.exitCode = failed === 0 ? 0 : 1;
};

run().catch((err) => {
	console.error("Verification run failed:", err);
	process.exitCode = 1;
});

/**
 * NOTE ON RE-RUNNING
 *
 * The rate-limit check at the end deliberately exhausts the auth limiter's
 * budget (10 failed attempts per 15 minutes, keyed on client IP). A second
 * run inside that window therefore starts already throttled and will report
 * failures for checks that are in fact working.
 *
 * Restart the API before re-running, which resets the in-memory counters:
 *   1. stop the server, then `npm start` again
 *   2. node security/verify-fixes.js
 */
