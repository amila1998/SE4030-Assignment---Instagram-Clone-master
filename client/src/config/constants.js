/**
 *
 * @author Anass Ferrak aka " TheLordA " <an.ferrak@gmail.com>
 * GitHub repo: https://github.com/TheLordA/Instagram-Web-App-MERN-Stack-Clone
 *
 */

/**
 *  This File will Contains all Constants Used in the whole
 *  Client Code In order to make it more Cleaner
 */

// OAUTH / SECURITY: the API base URL was hard-coded as
// `http://localhost:5000` on every endpoint below, so the client could only
// ever talk to a local dev server and a deployment would need a source edit.
// Read it from the environment (CRA exposes REACT_APP_* at build time) and
// fall back to the original value for local development.
export const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:5000";

// This is the config used in order to send
// our token with Axios requests
export const config = (jwt) => {
	return {
		headers: {
			Authorization: "Bearer " + jwt,
		},
	};
};

/**
 * EndPoints of the API used in the code
 */

// CreatePost Screen
export const CREATE_POST_URL = `${API_BASE}/createpost`;

// Home Screen
export const ALL_POST_URL = `${API_BASE}/allpost`;

// Login Screen
export const LOGIN_URL = `${API_BASE}/signin`;

// NewPassword Screen
export const NEW_PWD_URL = `${API_BASE}/new-pwd`;

// Profile Screen
export const MY_POST_URL = `${API_BASE}/mypost`;
export const MY_BOOKMARKS_URL = `${API_BASE}/bookmarks`;

// ResetPassword Screen
export const RESET_PWD_URL = `${API_BASE}/reset-pwd`;

// SignUp Screen
export const SIGNUP_URL = `${API_BASE}/signup`;

// SubscribePosts Screen
export const SUB_POST_URL = `${API_BASE}/subspost`;

/**
 * OAUTH - Google sign-in (Authorization Code + PKCE).
 *
 * GOOGLE_AUTH_URL is a full-page navigation, not an XHR: the browser must be
 * redirected to Google's consent screen, so this is used with
 * `window.location.href` rather than axios.
 *
 * GOOGLE_EXCHANGE_URL is where the SPA redeems the one-time code it receives
 * on the callback route for the application JWT.
 */
export const GOOGLE_AUTH_URL = `${API_BASE}/auth/google`;
export const GOOGLE_EXCHANGE_URL = `${API_BASE}/auth/google/exchange`;
