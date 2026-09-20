/**
 *
 * @author Anass Ferrak aka " TheLordA " <ferrak.anass@gmail.com>
 * GitHub repo: https://github.com/TheLordA/Instagram-Clone
 *
 */

const loginmiddleware = require("../middleware/login.middleware");
const controller = require("../controllers/user.controller");

module.exports = (app) => {
	// Getting the user details by id
	app.get("/user/:id", loginmiddleware, controller.user);

	// Follow a user
	app.put("/follow", loginmiddleware, controller.follow);

	// UnFollow a user
	app.put("/unfollow", loginmiddleware, controller.unfollow);

	// Retrieve all Bookmarks
	app.get("/bookmarks", loginmiddleware, controller.bookmarks);

	// Bookmark a post
	app.put("/bookmark-post", loginmiddleware, controller.bookmarkPost);

	// Remove a bookmark
	app.put("/remove-bookmark", loginmiddleware, controller.removeBookmark);

	// Update the profile picture
	// Just Wrote the logic of it but not yet tested and the client implementation doesn't exist yet
	app.put("/update-picture", loginmiddleware, controller.updatePicture);

	// Search for a user by email
	// SECURITY (VULN-01): this route previously had no authentication
	// middleware, so any anonymous caller could enumerate every account in
	// the database. It now requires a valid session like every other
	// non-auth endpoint.
	app.post("/users-research", loginmiddleware, controller.userSearch);
};
