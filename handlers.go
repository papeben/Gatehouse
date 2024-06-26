package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/skip2/go-qrcode"
)

func HandleMain(response http.ResponseWriter, request *http.Request) { // Create main listener function

	var (
		validSession bool   = false
		userId       string = "Unauth"
		userEmail    string = "-"
	)

	handler := functionalURIs[request.Method][strings.ToLower(request.URL.Path)] // Load handler associated with URI from functionalURIs map
	tokenCookie, tokenError := request.Cookie(sessionCookieName)

	if tokenError == nil {
		validSession, userId, userEmail = IsValidSessionWithInfo(tokenCookie.Value)
		if !validSession {
			log(3, fmt.Sprintf("Client %s presented an invalid session token", request.RemoteAddr))
			http.SetCookie(response, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
		}
	}
	if handler != nil {
		handler.(func(http.ResponseWriter, *http.Request))(response, request) // If handler function set, use it to handle http request
	} else if !validSession && requireAuthentication {
		http.Redirect(response, request, path.Join("/", functionalPath, "login"), http.StatusSeeOther)
	} else if requireEmailConfirm && validSession && PendingEmailApproval(tokenCookie.Value) {
		http.Redirect(response, request, "/"+functionalPath+"/confirmemail", http.StatusSeeOther)
	} else {
		proxy.ServeHTTP(response, request)
	}

	log(4, fmt.Sprintf("%s(%s) (%s) %s %d %s %s", userId, userEmail, request.RemoteAddr, request.Proto, request.ContentLength, request.Method, request.RequestURI))
}

func HandleLogin(response http.ResponseWriter, request *http.Request) {
	var innerForm = []GatehouseFormElement{}

	if allowUsernameLogin {
		innerForm = append(
			innerForm,
			FormCreateDivider(),
			FormCreateTextInput("username", "Username"),
			FormCreatePasswordInput("password", "Password"),
		)
	}

	if allowPasswordReset && allowUsernameLogin {
		innerForm = append(innerForm,
			FormCreateSmallLink("/"+functionalPath+"/forgot", "Forgot my password..."),
		)
	}

	if allowUsernameLogin {
		innerForm = append(
			innerForm,
			FormCreateSubmitInput("signin", "Sign In"),
			FormCreateDivider(),
		)
	}

	if allowRegistration {
		innerForm = append(innerForm,
			FormCreateButtonLink("/"+functionalPath+"/register", "Create an Account"),
			FormCreateDivider(),
		)
	}

	var loginPage GatehouseForm = GatehouseForm{ // Define login page
		appName + " - Sign in",
		"Sign In",
		"/" + functionalPath + "/submit/login",
		"POST",
		innerForm,
		[]OIDCButton{
			// {"Sign In with Google", "/" + functionalPath + "/static/icons/google.png", "#fff", "#000", "/" + functionalPath + "/auth/google"},
			// {"Sign In with Microsoft Account", "/" + functionalPath + "/static/icons/microsoft.png", "#fff", "#000", "/" + functionalPath + "/auth/microsoft"},
			// {"Sign In with Apple ID", "/" + functionalPath + "/static/icons/apple.png", "#fff", "#000", "/" + functionalPath + "/auth/apple"},
		},
		functionalPath,
	}

	err := formTemplate.Execute(response, loginPage)
	if err != nil {
		panic(err)
	}
}

func HandleLogout(response http.ResponseWriter, request *http.Request) {
	http.SetCookie(response, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})

	var innerform = []GatehouseFormElement{}

	innerform = append(
		innerform,
		FormCreateDivider(),
		FormCreateHint("You have signed out."),
		FormCreateButtonLink("/", "Back to site"),
		FormCreateDivider(),
		FormCreateButtonLink("/"+functionalPath+"/login", "Sign In"),
	)

	if allowRegistration {
		innerform = append(innerform, FormCreateButtonLink("/"+functionalPath+"/register", "Create an Account"))
	}

	var logoutPage = GatehouseForm{ // Define login page
		appName + " - Sign Out",
		"Goodbye",
		"",
		"",
		innerform,
		[]OIDCButton{},
		functionalPath,
	}

	err := formTemplate.Execute(response, logoutPage)
	if err != nil {
		panic(err)
	}
}

func HandleForgotPassword(response http.ResponseWriter, request *http.Request) {
	err := formTemplate.Execute(response, forgotPasswordPage)
	if err != nil {
		panic(err)
	}
}

func HandleRecoveryCode(response http.ResponseWriter, request *http.Request) {
	var (
		userID string
	)
	mfaCookie, err := request.Cookie(mfaCookieName)
	if err != nil {
		http.Redirect(response, request, "/"+functionalPath+"/login", http.StatusSeeOther)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_mfa WHERE mfa_session = ? AND used = 0 AND type = 'totp'", tablePrefix), mfaCookie.Value).Scan(&userID)
		if err == sql.ErrNoRows {
			http.Redirect(response, request, "/"+functionalPath+"/login", http.StatusSeeOther)
		} else if err != nil {
			panic(err)
		} else {
			err := formTemplate.Execute(response, mfaRecoveryCodePage)
			if err != nil {
				panic(err)
			}
		}
	}
}

func HandleConfirmEmail(response http.ResponseWriter, request *http.Request) {
	err := formTemplate.Execute(response, confirmEmailPage)
	if err != nil {
		panic(err)
	}
}

func HandleRegister(response http.ResponseWriter, request *http.Request) {
	if allowRegistration {
		err := formTemplate.Execute(response, registrationPage)
		if err != nil {
			panic(err)
		}
	} else {
		err := formTemplate.Execute(response, disabledFeaturePage)
		if err != nil {
			panic(err)
		}
	}

}

func HandleConfirmEmailCode(response http.ResponseWriter, request *http.Request) {
	emailCode := request.URL.Query().Get("c")
	if ConfirmEmailCode(emailCode) {
		err := formTemplate.Execute(response, confirmedEmailPage)
		if err != nil {
			panic(err)
		}
	} else {
		response.WriteHeader(400)
		err := formTemplate.Execute(response, linkExpired)
		if err != nil {
			panic(err)
		}
	}
}

func HandlePasswordResetCode(response http.ResponseWriter, request *http.Request) {
	resetCode := request.URL.Query().Get("c")
	if resetCode != "" && IsValidResetCode(resetCode) {
		customResetPage := resetPage
		customResetPage.FormAction += fmt.Sprintf("?c=%s", resetCode)
		err := formTemplate.Execute(response, customResetPage)
		if err != nil {
			panic(err)
		}
	} else {
		err := formTemplate.Execute(response, linkExpired)
		if err != nil {
			panic(err)
		}
	}
}

func HandleResendConfirmation(response http.ResponseWriter, request *http.Request) {
	tokenCookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		http.Redirect(response, request, path.Join("/", functionalPath, "login"), http.StatusSeeOther)
	} else if IsValidSession(tokenCookie.Value) && PendingEmailApproval(tokenCookie.Value) && ResendConfirmationEmail(tokenCookie.Value) {
		err := formTemplate.Execute(response, resendConfirmationPage)
		if err != nil {
			panic(err)
		}
	} else if IsValidSession(tokenCookie.Value) && !PendingEmailApproval(tokenCookie.Value) {
		http.Redirect(response, request, "/", http.StatusSeeOther)
	} else {
		response.WriteHeader(400)
		err := formTemplate.Execute(response, linkExpired)
		if err != nil {
			panic(err)
		}
	}
}

func HandleIsUsernameTaken(response http.ResponseWriter, request *http.Request) {
	if !IsValidNewUsername(strings.ToLower(request.URL.Query().Get("u"))) {
		response.WriteHeader(400)
		fmt.Fprint(response, `Username taken.`)
	} else {
		response.WriteHeader(200)
		fmt.Fprint(response, `Username available.`)
	}
}

func HandleAddMFA(response http.ResponseWriter, request *http.Request) {
	sessionCookie, err := request.Cookie(sessionCookieName)
	validSession := false
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	if !allowMobileMFA {
		err = formTemplate.Execute(response, disabledFeaturePage)
		if err != nil {
			panic(err)
		}
	} else if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var (
			userID          string
			username        string
			email           string
			mfaType         string
			mfaStoredSecret *string
			mfaSecret       string
			png             []byte
		)

		err = db.QueryRow(fmt.Sprintf("SELECT user_id, email, username, mfa_type, mfa_secret FROM %s_sessions INNER JOIN %s_accounts ON id = user_id WHERE session_token = ?", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &email, &username, &mfaType, &mfaStoredSecret)
		if err != nil && err == sql.ErrNoRows {
			response.WriteHeader(403)
			fmt.Fprint(response, `Unauthorized.`)
		} else if err != nil {
			panic(err)
		} else if mfaType == "token" {
			response.WriteHeader(400)
			fmt.Fprint(response, `Token MFA already configured.`)
		} else {
			if mfaStoredSecret == nil {
				mfaSecret = GenerateOTPSecret()
				_, err = db.Exec(fmt.Sprintf("UPDATE %s_accounts SET mfa_secret = ? WHERE id = ?", tablePrefix), mfaSecret, userID)
				if err != nil {
					panic(err)
				}
			} else {
				mfaSecret = *mfaStoredSecret
			}
			otpUrl := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", appName, email, mfaSecret, appName)
			png, err = qrcode.Encode(otpUrl, qrcode.Medium, 256)
			if err != nil {
				panic(err)
			}
			png64 := base64.StdEncoding.EncodeToString(png)

			var enrolPage GatehouseForm = GatehouseForm{ // Define forgot password page
				appName + " - OTP Token",
				"Setup Authenticator",
				"/" + functionalPath + "/submit/validatemfa",
				"POST",
				[]GatehouseFormElement{
					FormCreateDivider(),
					FormCreateHint("To set up a OTP token, scan this QR code with a compatible authenticator app."),
					FormCreateQR(png64),
					FormCreateHint("Once added, enter the current code into the text box and confirm."),
					FormCreateTextInput("otp", "123456"),
					FormCreateSubmitInput("submit", "Confirm"),
					FormCreateDivider(),
				},
				[]OIDCButton{},
				functionalPath,
			}
			err = formTemplate.Execute(response, enrolPage)
			if err != nil {
				panic(err)
			}
		}
	}
}

func HandleElevateSession(response http.ResponseWriter, request *http.Request) {
	sessionCookie, err := request.Cookie(sessionCookieName)
	validSession := false
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	target := request.URL.Query().Get("t")

	if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	} else if target == "" {
		response.WriteHeader(400)
		fmt.Fprintf(response, "Target required.")
	} else if !listContains(elevatedRedirectPages, target) {
		response.WriteHeader(400)
		fmt.Fprintf(response, "Invalid target.")
	} else {
		var editedPage GatehouseForm = elevateSessionPage
		editedPage.FormAction = path.Join("/", functionalPath, fmt.Sprintf("/submit/elevate?t=%s", target))
		err := formTemplate.Execute(response, editedPage)
		if err != nil {
			panic(err)
		}
	}
}

func HandleRemoveMFA(response http.ResponseWriter, request *http.Request) {
	var (
		validSession         bool = false
		validCriticalSession bool = false
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession = IsValidCriticalSession(critialSessionCookie.Value)
	}

	if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	} else if !validCriticalSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "elevate?t=removemfa"), http.StatusSeeOther)
	} else {
		err := formTemplate.Execute(response, mfaRemovePage)
		if err != nil {
			panic(err)
		}
	}
}

func HandleManage(response http.ResponseWriter, request *http.Request) {
	var (
		validSession bool = false
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	if !validSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "login"), http.StatusSeeOther)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var (
			userID         string = ""
			email          string = ""
			emailConfirmed bool   = false
			mfaType        string = ""
			dashButtons    []GatehouseFormElement
		)
		err = db.QueryRow(fmt.Sprintf("SELECT user_id, email, email_confirmed, mfa_type FROM %s_sessions INNER JOIN %s_accounts ON id = user_id WHERE session_token = ? AND critical = 0", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &email, &emailConfirmed, &mfaType)
		if err != nil {
			panic(err)
		}

		if email == "" && allowEmailChange {
			dashButtons = append(dashButtons, FormCreateButtonLink(path.Join("/", functionalPath, "changeemail"), "Add Email Address"))
		} else if allowEmailChange {
			dashButtons = append(dashButtons, FormCreateButtonLink(path.Join("/", functionalPath, "changeemail"), "Change Email Address"))
		}

		if allowUsernameChange {
			dashButtons = append(dashButtons, FormCreateButtonLink(path.Join("/", functionalPath, "changeusername"), "Change Username"))
		}

		if mfaType == "email" && allowMobileMFA {
			dashButtons = append(dashButtons, FormCreateButtonLink(path.Join("/", functionalPath, "addmfa"), "Add MFA Device"))
		} else if mfaType == "token" {
			dashButtons = append(dashButtons, FormCreateButtonLink(path.Join("/", functionalPath, "removemfa"), "Remove MFA Device"))
		}

		dashButtons = append(
			dashButtons,
			FormCreateButtonLink(path.Join("/", functionalPath, "logout"), "Sign Out"),
			FormCreateDivider(),
		)

		if allowDeleteAccount {
			dashButtons = append(
				dashButtons,
				FormCreateHint("Danger Area"),
				FormCreateDangerButtonLink(path.Join("/", functionalPath, "deleteaccount"), "Delete Account"),
			)
		}

		var dashboardPage GatehouseForm = GatehouseForm{
			appName + " - Manage Account",
			"Manage Account",
			"/",
			"GET",
			dashButtons,
			[]OIDCButton{},
			functionalPath,
		}
		err = dashTemplate.Execute(response, dashboardPage)
		if err != nil {
			panic(err)
		}
	}
}

func HandleChangeEmail(response http.ResponseWriter, request *http.Request) {
	var (
		validSession         bool = false
		validCriticalSession bool = false
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession = IsValidCriticalSession(critialSessionCookie.Value)
	}

	if !allowEmailChange {
		err := formTemplate.Execute(response, disabledFeaturePage)
		if err != nil {
			panic(err)
		}
	} else if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	} else if !validCriticalSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "elevate?t=changeemail"), http.StatusSeeOther)
	} else {
		err := formTemplate.Execute(response, emailChangePage)
		if err != nil {
			panic(err)
		}
	}
}

func HandleChangeUsername(response http.ResponseWriter, request *http.Request) {
	var (
		userId               string
		validSession         bool = false
		validCriticalSession bool = false
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession = IsValidCriticalSession(critialSessionCookie.Value)
	}

	if !allowUsernameChange {
		err := formTemplate.Execute(response, disabledFeaturePage)
		if err != nil {
			panic(err)
		}
	} else if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	} else if !validCriticalSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "elevate?t=changeusername"), http.StatusSeeOther)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_accounts INNER JOIN %s_sessions ON user_id = id WHERE session_token = ? AND username_changed < CURRENT_TIMESTAMP - INTERVAL 30 DAY", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userId)
		if err == sql.ErrNoRows {
			err = formTemplate.Execute(response, usernameChangeBlockedPage)
			if err != nil {
				panic(err)
			}
		} else if err != nil {
			panic(err)
		} else {
			err = formTemplate.Execute(response, usernameChangePage)
			if err != nil {
				panic(err)
			}
		}

	}
}

func HandleDeleteAccount(response http.ResponseWriter, request *http.Request) {
	var (
		validSession         bool = false
		validCriticalSession bool = false
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession = IsValidCriticalSession(critialSessionCookie.Value)
	}

	if !allowDeleteAccount {
		err := formTemplate.Execute(response, disabledFeaturePage)
		if err != nil {
			panic(err)
		}
	} else if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	} else if !validCriticalSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "elevate?t=deleteaccount"), http.StatusSeeOther)
	} else {
		err := formTemplate.Execute(response, deleteAccountPage)
		if err != nil {
			panic(err)
		}
	}
}

//////////////////////////////////////////////////////////////////////////////
// Form Submissions

func HandleSubLogin(response http.ResponseWriter, request *http.Request) {
	var (
		username       string = strings.ToLower(request.FormValue("username"))
		password       string = request.FormValue("password")
		userID         string
		email          string
		emailConfirmed bool
		passwordHash   string
		mfaType        string
	)
	if !allowUsernameLogin {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Feature Disabled.`)
	} else if username == "" || password == "" {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid registration details.`)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT id, email, email_confirmed, password, mfa_type FROM %s_accounts WHERE username = ?", tablePrefix), username).Scan(&userID, &email, &emailConfirmed, &passwordHash, &mfaType)
		if err == sql.ErrNoRows {
			http.Redirect(response, request, path.Join("/", functionalPath, "/login?error=invalid"), http.StatusSeeOther)
		} else if err != nil {
			panic(err)
		} else if !CheckPasswordHash(password, passwordHash) {
			http.Redirect(response, request, path.Join("/", functionalPath, "/login?error=invalid"), http.StatusSeeOther)
		} else if allowMobileMFA && (mfaType == "token" || mfaType == "email" && emailConfirmed) {
			// Begin multifactor session
			sessionToken := GenerateMfaSessionToken()
			cookie := http.Cookie{Name: mfaCookieName, Value: sessionToken, SameSite: http.SameSiteLaxMode, Secure: false, Path: "/"}
			http.SetCookie(response, &cookie)

			if mfaType == "email" {
				mfaToken := GenerateRandomNumbers(6)
				_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_mfa (mfa_session, type, user_id, token) VALUES (?, ?, ?, ?)", tablePrefix), sessionToken, "email", userID, mfaToken)
				if err != nil {
					panic(err)
				}
				var body bytes.Buffer
				err = emailTemplate.Execute(&body, struct {
					Title    string
					Username string
					Message  string
					HasLink  bool
					Link     string
					AppName  string
				}{
					Title:    "OTP Token",
					Username: username,
					Message:  fmt.Sprintf("Your OTP code for %s is: %s", appName, mfaToken),
					HasLink:  false,
					Link:     "",
					AppName:  appName,
				})
				if err != nil {
					panic(err)
				}

				err = sendMail(strings.ToLower(email), "Sign In - OTP", body.String())
				if err != nil {
					fmt.Println(err)
					fmt.Println("Error sending email to " + email + ". Placing MFA code below:")
					fmt.Println(mfaToken)
				}

				err = formTemplate.Execute(response, mfaEmailPage)
				if err != nil {
					panic(err)
				}
			} else {
				_, err := db.Exec(fmt.Sprintf("INSERT INTO %s_mfa (mfa_session, type, user_id, token) VALUES (?, ?, ?, ?)", tablePrefix), sessionToken, "totp", userID, "")
				if err != nil {
					panic(err)
				}
				err = formTemplate.Execute(response, mfaTokenPage)
				if err != nil {
					panic(err)
				}
			}
		} else {
			AuthenticateRequestor(response, request, userID)
		}

	}
}

func HandleSubRegister(response http.ResponseWriter, request *http.Request) {
	username := strings.ToLower(request.FormValue("newUsername"))
	email := strings.ToLower(request.FormValue("email"))
	password := request.FormValue("password")
	passwordConfirm := request.FormValue("passwordConfirm")

	if !allowRegistration {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Feature Disabled.`)
	} else if !IsValidNewUsername(username) {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid Username.`)
	} else if !IsValidNewEmail(email) {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid email.`)
	} else if !IsValidPassword(password) {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid Password.`)
	} else if password != passwordConfirm {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Passwords did not match.`)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()
		userID := GenerateUserID()
		_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id, username, email, password) VALUES (?, ?, ?, ?)", tablePrefix), userID, username, email, HashPassword(password))
		if err != nil {
			panic(err)
		}
		SendEmailConfirmationCode(userID, email, username)
		AuthenticateRequestor(response, request, userID)
	}
}

func HandleSubResetRequest(response http.ResponseWriter, request *http.Request) {
	email := request.FormValue("email")
	if !allowPasswordReset {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Feature Disabled.`)
	} else if ResetPasswordRequest(email) {
		err := formTemplate.Execute(response, resetSentPage)
		if err != nil {
			panic(err)
		}
	} else {
		err := formTemplate.Execute(response, resetNotSentPage)
		if err != nil {
			panic(err)
		}
	}
}

func HandleSubReset(response http.ResponseWriter, request *http.Request) {
	code := request.URL.Query().Get("c")
	password := request.FormValue("password")
	passwordConfirm := request.FormValue("passwordConfirm")

	if code != "" && IsValidPassword(password) && password == passwordConfirm {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var userID string
		err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_resets WHERE reset_token = ? AND used = 0", tablePrefix), code).Scan(&userID)
		if err == sql.ErrNoRows {
			response.WriteHeader(403)
			fmt.Fprint(response, `403 - Unauthorized.`)
		} else if err != nil {
			panic(err)
		} else {
			_, err = db.Exec(fmt.Sprintf("UPDATE %s_resets INNER JOIN %s_accounts ON user_id = id SET password = ?, used = 1 WHERE reset_token = ?", tablePrefix, tablePrefix), HashPassword(password), code)
			if err != nil {
				panic(err)
			}
			err := formTemplate.Execute(response, resetSuccessPage)
			if err != nil {
				panic(err)
			}
		}
	} else {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid request.`)
	}
}

func HandleSubOTP(response http.ResponseWriter, request *http.Request) {
	var (
		otpInput       string = request.FormValue("token")
		mfaType        string
		mfaStoredToken string
		mfaSecret      *string
		userID         string
	)
	mfaSession, err := request.Cookie(mfaCookieName)

	if err != nil {
		response.WriteHeader(400)
		fmt.Fprint(response, `Invalid request.`)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT user_id, token, mfa_type, mfa_secret FROM %s_mfa INNER JOIN %s_accounts ON user_id = id WHERE mfa_session = ? AND created > CURRENT_TIMESTAMP - INTERVAL 1 HOUR AND used = 0", tablePrefix, tablePrefix), mfaSession.Value).Scan(&userID, &mfaStoredToken, &mfaType, &mfaSecret)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		} else if err == sql.ErrNoRows {
			response.WriteHeader(400)
			fmt.Fprint(response, `Invalid request.`)
		} else if mfaType == "email" && mfaStoredToken == otpInput {
			AuthenticateRequestor(response, request, userID)
		} else if mfaType == "token" {
			otp, _ := GenerateOTP(*mfaSecret, 30)
			if otp == otpInput {
				AuthenticateRequestor(response, request, userID)
			} else {
				http.Redirect(response, request, "/"+functionalPath+"/login?error=invalid", http.StatusSeeOther)
			}
		} else {
			http.Redirect(response, request, "/"+functionalPath+"/login?error=invalid", http.StatusSeeOther)
		}

		_, err = db.Exec(fmt.Sprintf("UPDATE %s_mfa SET used = 1 WHERE mfa_session = ?", tablePrefix), mfaSession.Value)
		if err != nil {
			panic(err)
		}
	}
}

func HandleSubMFAValidate(response http.ResponseWriter, request *http.Request) {
	var (
		submitOtp    string = request.FormValue("otp")
		mfaSecret    string
		userID       string
		validSession bool = false
	)
	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	if !allowMobileMFA {
		err = formTemplate.Execute(response, disabledFeaturePage)
		if err != nil {
			panic(err)
		}
	} else if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT id, mfa_secret FROM %s_accounts INNER JOIN %s_sessions ON id = user_id WHERE session_token = ? AND mfa_type = 'email' AND mfa_secret IS NOT NULL", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &mfaSecret)
		if err == sql.ErrNoRows {
			response.WriteHeader(400)
			fmt.Fprint(response, `Invalid Request.`)
		} else if err != nil {
			panic(err)
		} else {
			otp, err := GenerateOTP(mfaSecret, 30)
			if err != nil {
				panic(err)
			} else if otp == submitOtp {
				_, err := db.Exec(fmt.Sprintf("UPDATE %s_accounts SET mfa_type = 'token' WHERE id = ?", tablePrefix), userID)
				if err != nil {
					panic(err)
				}

				var recoveryCodes string = ""
				for i := 0; i < 12; i++ {
					recoveryCode := GenerateRandomNumbers(8)
					recoveryCodes = recoveryCodes + "<br>" + recoveryCode
					_, err = db.Exec(fmt.Sprintf("INSERT IGNORE INTO %s_recovery (user_id, code) VALUES (?, ?)", tablePrefix), userID, recoveryCode)
					if err != nil {
						panic(err)
					}
				}

				var mfaValidatedPage GatehouseForm = GatehouseForm{ // Define forgot password page
					appName + " - MFA Validated",
					"Success",
					"/",
					"GET",
					[]GatehouseFormElement{
						FormCreateDivider(),
						FormCreateHint("Your OTP code was validated successfully! You are now able to sign in with your authenticator OTP in the future."),
						FormCreateDivider(),
						FormCreateHint("Your recovery codes:"),
						FormCreateHint(recoveryCodes),
						FormCreateDivider(),
						FormCreateButtonLink("/"+functionalPath+"/manage", "Back to Dashboard"),
						FormCreateDivider(),
					},
					[]OIDCButton{},
					functionalPath,
				}

				err = formTemplate.Execute(response, mfaValidatedPage)
				if err != nil {
					panic(err)
				}
			} else {
				response.WriteHeader(400)
				err = formTemplate.Execute(response, mfaFailedPage)
				if err != nil {
					panic(err)
				}
			}
		}
	}
}

func HandleSubElevate(response http.ResponseWriter, request *http.Request) {
	var (
		password     string = request.FormValue("password")
		passwordHash string
		userID       string
		validSession bool = false
	)
	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	target := request.URL.Query().Get("t")

	if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	} else if target == "" {
		response.WriteHeader(400)
		fmt.Fprintf(response, "Target required.")
	} else if !listContains(elevatedRedirectPages, target) {
		response.WriteHeader(400)
		fmt.Fprintf(response, "Invalid target.")
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT id, password FROM %s_accounts INNER JOIN %s_sessions ON id = user_id WHERE session_token = ?", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &passwordHash)
		if err != nil {
			panic(err)
		}

		if !CheckPasswordHash(password, passwordHash) {
			http.Redirect(response, request, "/"+functionalPath+fmt.Sprintf("/elevate?error=invalid&t=%s", target), http.StatusSeeOther)
		} else {
			elevatedSessionToken := GenerateSessionToken()
			_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_sessions (session_token, user_id, critical) VALUES (?, ?, 1)", tablePrefix), elevatedSessionToken, userID)
			if err != nil {
				panic(err)
			}
			cookie := http.Cookie{Name: criticalCookieName, Value: elevatedSessionToken, SameSite: http.SameSiteStrictMode, Secure: false, Path: "/"}
			http.SetCookie(response, &cookie)
			http.Redirect(response, request, path.Join("/", functionalPath, target), http.StatusSeeOther)
		}
	}
}

func HandleSubRemoveMFA(response http.ResponseWriter, request *http.Request) {
	var (
		validSession         bool = false
		validCriticalSession bool = false
		mfaType              string
		sessionUserID        string
		criticalUserID       string
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession = IsValidCriticalSession(critialSessionCookie.Value)
	}

	if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	} else if !validCriticalSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "elevate?t=removemfa"), http.StatusSeeOther)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT id, mfa_type FROM %s_accounts INNER JOIN %s_sessions ON id = user_id WHERE session_token = ? AND critical = 0", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&sessionUserID, &mfaType)
		if err != nil {
			panic(err)
		}
		err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_accounts INNER JOIN %s_sessions ON id = user_id WHERE session_token = ? AND critical = 1", tablePrefix, tablePrefix), critialSessionCookie.Value).Scan(&criticalUserID)
		if err != nil {
			panic(err)
		}

		if sessionUserID != criticalUserID {
			response.WriteHeader(500)
			fmt.Fprint(response, `Undefined error.`)
		} else if mfaType != "token" {
			response.WriteHeader(400)
			fmt.Fprint(response, `MFA Device not registered`)
		} else {
			_, err = db.Exec(fmt.Sprintf("UPDATE %s_accounts SET mfa_type = 'email', mfa_secret = NULL WHERE id = ?", tablePrefix), sessionUserID)
			if err != nil {
				panic(err)
			}
			err = formTemplate.Execute(response, mfaRemovedPage)
			if err != nil {
				panic(err)
			}
		}
	}
}

func HandleSubEmailChange(response http.ResponseWriter, request *http.Request) {
	var (
		validSession         bool = false
		validCriticalSession bool = false
		userID               string
		username             string
		email                string
	)

	email = strings.ToLower(request.FormValue("newemail"))

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession = IsValidCriticalSession(critialSessionCookie.Value)
	}

	if !allowEmailChange {
		response.WriteHeader(400)
		fmt.Fprint(response, `Feature disabled.`)
	} else if !validSession || !validCriticalSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	} else if !IsValidNewEmail(email) {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid email.`)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT user_id, username FROM %s_accounts INNER JOIN %s_sessions ON user_id = id WHERE session_token = ?", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &username)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		} else if err == sql.ErrNoRows {
			response.WriteHeader(400)
			fmt.Fprint(response, `Invalid request.`)
		} else {
			_, err = db.Exec(fmt.Sprintf("UPDATE %s_accounts SET email = ?, email_confirmed = 0, email_resent = 0 WHERE id = ?", tablePrefix), email, userID)
			if err != nil {
				panic(err)
			}
		}

		SendEmailConfirmationCode(userID, email, username)
		err = formTemplate.Execute(response, confirmEmailPage)
		if err != nil {
			panic(err)
		}
	}
}

func HandleSubUsernameChange(response http.ResponseWriter, request *http.Request) {
	var (
		validSession         bool = false
		validCriticalSession bool = false
		userID               string
		username             string
	)

	username = strings.ToLower(request.FormValue("newUsername"))

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession = IsValidCriticalSession(critialSessionCookie.Value)
	}

	if !allowUsernameChange {
		response.WriteHeader(400)
		fmt.Fprint(response, `Feature disabled.`)
	} else if !validSession || !validCriticalSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	} else if !IsValidNewUsername(username) {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid username.`)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_accounts INNER JOIN %s_sessions ON user_id = id WHERE session_token = ? AND username_changed < CURRENT_TIMESTAMP - INTERVAL 30 DAY", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		} else if err == sql.ErrNoRows {
			response.WriteHeader(400)
			fmt.Fprint(response, `Invalid request.`)
		} else {
			_, err = db.Exec(fmt.Sprintf("UPDATE %s_accounts SET username = ?, username_changed = CURRENT_TIMESTAMP WHERE id = ? AND username_changed < CURRENT_TIMESTAMP - INTERVAL 30 DAY", tablePrefix), username, userID)
			if err != nil {
				panic(err)
			}

			// SendEmailConfirmationCode(userID, email, username)
			err = formTemplate.Execute(response, confirmedUsernameChangePage)
			if err != nil {
				panic(err)
			}
		}
	}
}

func HandleSubDeleteAccount(response http.ResponseWriter, request *http.Request) {
	var (
		validSession         bool = false
		validCriticalSession bool = false
		userID               string
		username             string
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession = IsValidSession(sessionCookie.Value)
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession = IsValidCriticalSession(critialSessionCookie.Value)
	}
	if !allowDeleteAccount {
		response.WriteHeader(400)
		fmt.Fprint(response, `Feature Disabled.`)
	} else if !validSession || !validCriticalSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT user_id, username FROM %s_accounts INNER JOIN %s_sessions ON user_id = id WHERE session_token = ?", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &username)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		} else if err == sql.ErrNoRows {
			response.WriteHeader(400)
			fmt.Fprint(response, `Invalid request.`)
		} else {
			_, err = db.Exec(fmt.Sprintf("DELETE FROM %s_accounts WHERE id = ?", tablePrefix), userID)
			if err != nil {
				panic(err)
			}
		}

		err = formTemplate.Execute(response, deletedAccountPage)
		if err != nil {
			panic(err)
		}
	}
}

func HandleSubRecoveryCode(response http.ResponseWriter, request *http.Request) {
	var (
		userID        string
		recoveryToken string = request.FormValue("token")
	)
	mfaCookie, err := request.Cookie(mfaCookieName)
	if err != nil {
		http.Redirect(response, request, "/"+functionalPath+"/login", http.StatusSeeOther)
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_mfa INNER JOIN %s_recovery ON %s_mfa.user_id = %s_recovery.user_id INNER JOIN %s_accounts ON id = %s_recovery.user_id WHERE mfa_session = ? AND %s_mfa.used = 0 AND type = 'totp' AND %s_mfa.created > CURRENT_TIMESTAMP - INTERVAL 1 HOUR AND code = ?", tablePrefix, tablePrefix, tablePrefix, tablePrefix, tablePrefix, tablePrefix, tablePrefix, tablePrefix), mfaCookie.Value, recoveryToken).Scan(&userID)
		if err == sql.ErrNoRows {
			http.Redirect(response, request, "/"+functionalPath+"/login?error=invalid", http.StatusSeeOther)
		} else if err != nil {
			panic(err)
		} else {
			_, err = db.Exec(fmt.Sprintf("UPDATE %s_recovery SET used = 1 WHERE user_id = ? AND code = ?", tablePrefix), userID, recoveryToken)
			if err != nil {
				panic(err)
			}
			AuthenticateRequestor(response, request, userID)
		}
	}
}
