/**
 * OAUTH - landing page for the Google sign-in redirect.
 *
 * The API deliberately does NOT put the application JWT in this URL. Query
 * strings are written to browser history, proxy logs and `Referer` headers,
 * so a token placed there outlives the request that carried it.
 *
 * Instead the API redirects here with a single-use, 60-second `code`, which
 * this screen immediately POSTs to /auth/google/exchange to obtain the JWT.
 * The code is then stripped from the address bar so it does not linger in
 * history even for its short lifetime.
 */

import React, { useContext, useEffect, useRef, useState } from "react";
import { useHistory, useLocation, Link } from "react-router-dom";
import axios from "axios";

import AuthenticationContext from "../contexts/auth/Auth.context";
import { FETCH_USER_DATA } from "../contexts/types.js";
import { GOOGLE_EXCHANGE_URL } from "../config/constants";

import Container from "@material-ui/core/Container";
import CircularProgress from "@material-ui/core/CircularProgress";
import Typography from "@material-ui/core/Typography";
import Alert from "@material-ui/lab/Alert";
import Box from "@material-ui/core/Box";

// Map the API's error codes onto messages fit to show a user. The server
// sends a short code and keeps the detail in its own log.
const ERROR_MESSAGES = {
	access_denied: "You cancelled the Google sign-in.",
	invalid_state: "The sign-in request could not be verified. Please try again.",
	invalid_request: "The sign-in request was incomplete. Please try again.",
	token_exchange_failed: "Google could not complete the sign-in. Please try again.",
	email_not_verified: "Your Google account does not have a verified email address.",
	oauth_failed: "Something went wrong during sign-in. Please try again.",
};

const OAuthCallback = () => {
	const { dispatch } = useContext(AuthenticationContext);
	const history = useHistory();
	const location = useLocation();

	const [error, setError] = useState(null);

	// React 18's StrictMode double-invokes effects in development. The
	// exchange code is single-use, so a second POST would always fail and
	// show a spurious error. This guard makes the redemption run once.
	const redeemed = useRef(false);

	useEffect(() => {
		if (redeemed.current) return;
		redeemed.current = true;

		const params = new URLSearchParams(location.search);
		const oauthError = params.get("error");
		const code = params.get("code");

		// Remove the code from the address bar immediately, so it is not kept
		// in browser history.
		window.history.replaceState({}, document.title, window.location.pathname);

		if (oauthError) {
			setError(ERROR_MESSAGES[oauthError] || ERROR_MESSAGES.oauth_failed);
			return;
		}
		if (!code) {
			setError("No sign-in code was provided.");
			return;
		}

		axios
			.post(GOOGLE_EXCHANGE_URL, { code })
			.then((res) => {
				const data = res.data;
				// Stored the same way the password flow stores it, so the rest
				// of the application is unchanged by how the user signed in.
				localStorage.setItem("jwt", data.token);
				localStorage.setItem("user", JSON.stringify(data.user));
				dispatch({ type: FETCH_USER_DATA, payload: data.user });
				history.replace("/");
			})
			.catch((err) => {
				setError(
					(err.response && err.response.data && err.response.data.error) ||
						"Could not complete the sign-in. Please try again."
				);
			});
	}, [dispatch, history, location.search]);

	return (
		<Container maxWidth="xs">
			<Box
				display="flex"
				flexDirection="column"
				alignItems="center"
				justifyContent="center"
				minHeight="60vh"
				textAlign="center"
			>
				{error ? (
					<>
						<Alert variant="outlined" severity="error">
							{error}
						</Alert>
						<Box mt={3}>
							<Link to="/login" style={{ textDecoration: "none" }}>
								Back to sign in
							</Link>
						</Box>
					</>
				) : (
					<>
						<CircularProgress />
						<Box mt={3}>
							<Typography variant="body1">Completing your Google sign-in…</Typography>
						</Box>
					</>
				)}
			</Box>
		</Container>
	);
};

export default OAuthCallback;
