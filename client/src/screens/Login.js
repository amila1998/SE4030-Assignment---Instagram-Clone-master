/**
 *
 * @author Anass Ferrak aka " TheLordA " <ferrak.anass@gmail.com>
 * GitHub repo: https://github.com/TheLordA/Instagram-Clone
 *
 */

import React, { useState, useContext } from "react";
import { Link, useHistory } from "react-router-dom";
import AuthenticationContext from "../contexts/auth/Auth.context";
import { FETCH_USER_DATA } from "../contexts/types.js";
import { LOGIN_URL, GOOGLE_AUTH_URL } from "../config/constants";
import Copyright from "../components/Copyight";
import { EmailRegex } from "../utils/regex";
import axios from "axios";
// Material-UI Components
import Button from "@material-ui/core/Button";
import CssBaseline from "@material-ui/core/CssBaseline";
import TextField from "@material-ui/core/TextField";
import Grid from "@material-ui/core/Grid";
import Box from "@material-ui/core/Box";
import Typography from "@material-ui/core/Typography";
import { makeStyles } from "@material-ui/core/styles";
import Container from "@material-ui/core/Container";
import Alert from "@material-ui/lab/Alert";
import Divider from "@material-ui/core/Divider";
// OAUTH: Google mark for the sign-in button (react-icons is already a dep).
import { FcGoogle } from "react-icons/fc";

// General Styles
const useStyles = makeStyles((theme) => ({
	Logo: {
		fontFamily: "Grand Hotel, cursive",
		margin: "0px 0px 20px 0px",
	},
	paper: {
		marginTop: "50px",
		display: "flex",
		flexDirection: "column",
		alignItems: "center",
	},
	image: {
		backgroundSize: "cover",
		backgroundColor: "#fafafa",
		backgroundImage: "url(https://source.unsplash.com/random)",
		backgroundRepeat: "no-repeat",
		backgroundPosition: "center",
		height: "100vh",
	},
	form: {
		width: "100%", // Fix IE 11 issue.
		marginTop: theme.spacing(1),
	},
	submit: {
		margin: theme.spacing(2, 0, 2),
	},
	divider: {
		margin: theme.spacing(1, 0, 2),
	},
	googleButton: {
		margin: theme.spacing(0, 0, 2),
		textTransform: "none",
	},
}));

const Login = () => {
	const { dispatch } = useContext(AuthenticationContext);

	const history = useHistory();
	const classes = useStyles();

	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [formatValidation, setFormatValidation] = useState(false);
	const [authValidation, setAuthValidation] = useState(false);
	// SECURITY (VULN-07): the alert text is now driven by the server, so a
	// rate-limit message ("too many attempts") can be distinguished from a
	// plain credential failure.
	const [authMessage, setAuthMessage] = useState("Invalid given Email/Password — check it out!");

	const handleInputChanges = (e) => {
		switch (e.target.name) {
			case "email":
				setEmail(e.target.value);
				break;
			case "password":
				setPassword(e.target.value);
				break;
			default:
				break;
		}
	};

	// OAUTH: a full-page navigation, not an XHR. The browser has to land on
	// Google's consent screen, and the httpOnly `state` cookie the API sets
	// must be stored by the browser as part of that top-level navigation.
	const handleGoogleSignIn = () => {
		window.location.href = GOOGLE_AUTH_URL;
	};

	const handlePostData = () => {
		// the Regex email validation was token from : https://emailregex.com/
		if (EmailRegex.test(email)) {
			axios.post(LOGIN_URL, { password, email })
				.then((res) => {
					const data = res.data;
					if (data.error) {
						setFormatValidation(false);
						setAuthValidation(true);
					} else {
						// we store our generated token in order to use it to access protected endpoints
						localStorage.setItem("jwt", data.token);
						// we also store the user details
						localStorage.setItem("user", JSON.stringify(data.user));
						dispatch({ type: FETCH_USER_DATA, payload: data.user });
						// we redirect the user to home page
						history.push("/");
					}
				})
				.catch((err) => {
					// SECURITY (VULN-07): the API now returns 401 for bad
					// credentials and 429 when the rate limiter trips, instead
					// of 200 with an error field. axios rejects on those, so the
					// message is read from err.response here.
					setFormatValidation(false);
					setAuthValidation(true);
					if (err.response && err.response.status === 429) {
						setAuthMessage(
							(err.response.data && err.response.data.error) ||
								"Too many attempts. Please try again later."
						);
					} else {
						setAuthMessage("Invalid email or password.");
					}
				});
		} else {
			setAuthValidation(false);
			setFormatValidation(true);
		}
	};

	return (
		<Grid container>
			<Grid className={classes.image} item sm={4} md={6} />
			<Grid item xs={12} sm={8} md={6}>
				<Container component="main" maxWidth="xs">
					<CssBaseline />
					<div className={classes.paper}>
						<Typography className={classes.Logo} variant="h2" gutterBottom>
							Instagram Clone
						</Typography>
						{formatValidation ? (
							<Alert variant="outlined" severity="error">
								Invalid Email format — check it out!
							</Alert>
						) : null}
						{authValidation ? (
							<Alert variant="outlined" severity="error">
								{authMessage}
							</Alert>
						) : null}
						<form className={classes.form} noValidate>
							<TextField
								variant="outlined"
								margin="normal"
								required
								fullWidth
								id="email"
								label="Email Address"
								name="email"
								// autoComplete="email"
								autoFocus
								value={email}
								onChange={handleInputChanges}
							/>
							<TextField
								variant="outlined"
								margin="normal"
								required
								fullWidth
								name="password"
								label="Password"
								type="password"
								autoComplete="current-password"
								value={password}
								onChange={handleInputChanges}
							/>

							<Button
								fullWidth
								variant="outlined"
								color="primary"
								className={classes.submit}
								disabled={email !== "" && password !== "" ? false : true}
								onClick={handlePostData}
							>
								Sign In
							</Button>
							<Divider className={classes.divider} />

							{/* OAUTH: sign in with Google (Authorization Code + PKCE) */}
							<Button
								fullWidth
								variant="outlined"
								className={classes.googleButton}
								startIcon={<FcGoogle />}
								onClick={handleGoogleSignIn}
							>
								Sign in with Google
							</Button>

							<Grid container>
								<Grid item xs>
									<Link to="/reset" style={{ textDecoration: "none" }}>
										Forgot password?
									</Link>
								</Grid>
								<Grid item>
									<Link to="/signup" style={{ textDecoration: "none" }}>
										{"Don't have an account? Sign Up"}
									</Link>
								</Grid>
							</Grid>
						</form>
					</div>
					<Box mt={8}>
						<Copyright />
					</Box>
				</Container>
			</Grid>
		</Grid>
	);
};

export default Login;
