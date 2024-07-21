package main

import (
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
		validSession   bool   = false
		userId         string = "Unauth"
		userEmail      string = "-"
		emailConfirmed bool   = false
		proxied        string = "Proxied"
	)
	sessionCookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		validSession = false
	} else {
		validSession, userId, userEmail, emailConfirmed, err = IsValidSessionWithInfo(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	handler := functionalURIs[request.Method][strings.ToLower(request.URL.Path)] // Load handler associated with URI from functionalURIs map
	if handler != nil {
		handler.(func(http.ResponseWriter, *http.Request))(response, request) // If handler function set, use it to handle http request
		proxied = "Served"
	} else if requireEmailConfirm && validSession && !emailConfirmed {
		http.Redirect(response, request, "/"+functionalPath+"/confirmemail", http.StatusSeeOther)
		proxied = "Redirected"
	} else if requireAuthentication && !validSession && !sliceContainsPath(publicPageList, request.URL.Path) {
		http.Redirect(response, request, path.Join("/", functionalPath, "login"), http.StatusSeeOther)
		proxied = "Redirected"
	} else if request.URL.Path == "/" && sliceContainsPath(publicPageList, "//") {
		proxy.ServeHTTP(response, request)
	} else {
		proxy.ServeHTTP(response, request)
	}

	logMessage(4, fmt.Sprintf("%s(%s) (%s) %s %s %d %s %s", userId, userEmail, request.RemoteAddr, proxied, request.Proto, request.ContentLength, request.Method, request.RequestURI))
}

func sliceContainsPath(slice []string, path string) bool {
	for _, val := range slice {
		if val == path {
			return true
		} else if len(val) > 2 && string(val[len(val)-1]) == "/" && len(path) > len(val) && path[0:len(val)] == val {
			return true
		}
	}
	return false
}

func HandleLogin(response http.ResponseWriter, request *http.Request) {
	var validSession = false
	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
		}
	}
	if validSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "manage"), http.StatusSeeOther)
		return
	}

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

	ServePage(response, loginPage)
}

func HandleLogout(response http.ResponseWriter, request *http.Request) {
	sessionToken, err := request.Cookie(sessionCookieName)
	if err != nil {
		response.WriteHeader(410)
		ServePage(response, linkExpired)
		return
	}

	_, err = db.Exec(fmt.Sprintf("DELETE FROM %s_sessions WHERE session_token = ?", tablePrefix), sessionToken.Value)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
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

	var logoutPage = GatehouseForm{
		appName + " - Sign Out",
		"Goodbye",
		"",
		"",
		innerform,
		[]OIDCButton{},
		functionalPath,
	}

	ServePage(response, logoutPage)
}

func HandleForgotPassword(response http.ResponseWriter, request *http.Request) {
	if !allowPasswordReset {
		response.WriteHeader(410)
		ServePage(response, disabledFeaturePage)
		return
	}
	ServePage(response, forgotPasswordPage)
}

func HandleRecoveryCode(response http.ResponseWriter, request *http.Request) {
	if !allowMobileMFA {
		response.WriteHeader(410)
		ServePage(response, disabledFeaturePage)
		return
	}
	var (
		userID string
	)
	mfaCookie, err := request.Cookie(mfaCookieName)
	if err != nil {
		http.Redirect(response, request, "/"+functionalPath+"/login", http.StatusSeeOther)
		return
	}

	err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_mfa WHERE mfa_session = ? AND used = 0 AND type = 'totp'", tablePrefix), mfaCookie.Value).Scan(&userID)
	if err == sql.ErrNoRows {
		http.Redirect(response, request, "/"+functionalPath+"/login", http.StatusSeeOther)
	} else if err != nil {
		ServeErrorPage(response, err)
	} else {
		ServePage(response, mfaRecoveryCodePage)
	}

}

func HandleConfirmEmail(response http.ResponseWriter, request *http.Request) {
	ServePage(response, confirmEmailPage)
}

func HandleRegister(response http.ResponseWriter, request *http.Request) {
	if !allowRegistration {
		response.WriteHeader(410)
		ServePage(response, disabledFeaturePage)
		return
	}

	ServePage(response, registrationPage)
}

func HandleConfirmEmailCode(response http.ResponseWriter, request *http.Request) {
	emailCode := request.URL.Query().Get("c")
	validCode, err := ConfirmEmailCode(emailCode)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	if !validCode {
		response.WriteHeader(410)
		ServePage(response, linkExpired)
		return
	}
	ServePage(response, confirmedEmailPage)
}

func HandlePasswordResetCode(response http.ResponseWriter, request *http.Request) {
	resetCode := request.URL.Query().Get("c")
	validResetCode, err := IsValidResetCode(resetCode)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	if !validResetCode {
		response.WriteHeader(410)
		ServePage(response, linkExpired)
		return
	}
	customResetPage := resetPage
	customResetPage.FormAction += fmt.Sprintf("?c=%s", resetCode)
	ServePage(response, customResetPage)
}

func HandleResendConfirmation(response http.ResponseWriter, request *http.Request) {
	tokenCookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		http.Redirect(response, request, path.Join("/", functionalPath, "login"), http.StatusSeeOther)
		return
	}
	var (
		validSession bool = false
		pendingEmail bool = false
	)
	validSession, err = IsValidSession(tokenCookie.Value)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	pendingEmail, err = PendingEmailApproval(tokenCookie.Value)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	if !validSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "login"), http.StatusSeeOther)
		return
	}
	if !pendingEmail {
		response.WriteHeader(410)
		ServePage(response, linkExpired)
		return
	}
	emailSent, err := ResendConfirmationEmail(tokenCookie.Value)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	if emailSent {
		ServePage(response, resendConfirmationPage)
	} else {
		response.WriteHeader(410)
		ServePage(response, linkExpired)
	}
}

func HandleIsUsernameTaken(response http.ResponseWriter, request *http.Request) {
	isValid, err := IsValidNewUsername(strings.ToLower(request.URL.Query().Get("u")))
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	if !isValid {
		response.WriteHeader(400)
		fmt.Fprint(response, `Username taken.`)
	} else {
		response.WriteHeader(200)
		fmt.Fprint(response, `Username available.`)
	}
}

func HandleAddMFA(response http.ResponseWriter, request *http.Request) {
	if !allowMobileMFA {
		response.WriteHeader(410)
		ServePage(response, disabledFeaturePage)
		return
	}

	validSession := false
	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}
	if !validSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "/login"), http.StatusSeeOther)
		return
	}

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
	if err == sql.ErrNoRows {
		http.Redirect(response, request, path.Join("/", functionalPath, "/login"), http.StatusSeeOther)
		return
	} else if err != nil {
		ServeErrorPage(response, err)
		logMessage(1, err.Error())
		return
	} else if mfaType == "token" {
		response.WriteHeader(400)
		fmt.Fprint(response, `Token MFA already configured.`)
		return
	}

	if mfaStoredSecret == nil {
		mfaSecret = GenerateOTPSecret()
		_, err = db.Exec(fmt.Sprintf("UPDATE %s_accounts SET mfa_secret = ? WHERE id = ?", tablePrefix), mfaSecret, userID)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	} else {
		mfaSecret = *mfaStoredSecret
	}

	otpUrl := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", appName, email, mfaSecret, appName)
	png, err = qrcode.Encode(otpUrl, qrcode.Medium, 256)
	if err != nil {
		ServeErrorPage(response, err)
		logMessage(1, fmt.Sprintf("Failed to encode QRCode: %s", otpUrl))
		return
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
	ServePage(response, enrolPage)

}

func HandleElevateSession(response http.ResponseWriter, request *http.Request) {
	sessionCookie, err := request.Cookie(sessionCookieName)
	validSession := false
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	target := request.URL.Query().Get("t")

	if !validSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "/login"), http.StatusSeeOther)
		return
	}
	if target == "" {
		response.WriteHeader(400)
		fmt.Fprintf(response, "Target required.")
		return
	}
	if !listContains(elevatedRedirectPages, target) {
		response.WriteHeader(400)
		fmt.Fprintf(response, "Invalid target.")
		return
	}

	var editedPage GatehouseForm = elevateSessionPage
	editedPage.FormAction = path.Join("/", functionalPath, fmt.Sprintf("/submit/elevate?t=%s", target))
	ServePage(response, editedPage)
}

func HandleRemoveMFA(response http.ResponseWriter, request *http.Request) {
	if !allowMobileMFA {
		response.WriteHeader(410)
		ServePage(response, disabledFeaturePage)
		return
	}
	var (
		validSession         bool = false
		validCriticalSession bool = false
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession, err = IsValidCriticalSession(critialSessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	if !validSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "/login"), http.StatusSeeOther)
	} else if !validCriticalSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "elevate?t=removemfa"), http.StatusSeeOther)
	} else {
		ServePage(response, mfaRemovePage)
	}
}

func HandleManage(response http.ResponseWriter, request *http.Request) {
	var validSession bool = false

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	if !validSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "login"), http.StatusSeeOther)
		return
	}

	var (
		userID         string = ""
		email          string = ""
		emailConfirmed bool   = false
		mfaType        string = ""
		dashButtons    []GatehouseFormElement
	)
	err = db.QueryRow(fmt.Sprintf("SELECT user_id, email, email_confirmed, mfa_type FROM %s_sessions INNER JOIN %s_accounts ON id = user_id WHERE session_token = ? AND critical = 0", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &email, &emailConfirmed, &mfaType)
	if err == sql.ErrNoRows {
		http.Redirect(response, request, path.Join("/", functionalPath, "login"), http.StatusSeeOther)
		return
	} else if err != nil {
		ServeErrorPage(response, err)
		return
	}

	// Account info options
	if allowEmailChange || allowUsernameChange {
		dashButtons = append(
			dashButtons,
			FormCreateDivider(),
			FormCreateHint("Account Details"),
		)
	}

	if email == "" && allowEmailChange {
		dashButtons = append(dashButtons, FormCreateButtonLink(path.Join("/", functionalPath, "changeemail"), "Add Email Address"))
	} else if allowEmailChange {
		dashButtons = append(dashButtons, FormCreateButtonLink(path.Join("/", functionalPath, "changeemail"), "Change Email Address"))
	}

	if allowUsernameChange {
		dashButtons = append(dashButtons, FormCreateButtonLink(path.Join("/", functionalPath, "changeusername"), "Change Username"))
	}

	if allowAvatarChange {
		dashButtons = append(dashButtons, FormCreateButtonLink(path.Join("/", functionalPath, "changeavatar"), "Change Avatar"))
	}

	// Security options

	if allowMobileMFA || allowSessionRevoke {
		dashButtons = append(
			dashButtons,
			FormCreateDivider(),
			FormCreateHint("Account Security"),
		)
	}

	if mfaType == "email" && allowMobileMFA {
		dashButtons = append(dashButtons, FormCreateButtonLink(path.Join("/", functionalPath, "addmfa"), "Add MFA Device"))
	} else if mfaType == "token" {
		dashButtons = append(dashButtons, FormCreateButtonLink(path.Join("/", functionalPath, "removemfa"), "Remove MFA Device"))
	}

	dashButtons = append(
		dashButtons,
		FormCreateButtonLink(path.Join("/", functionalPath, "logout"), "Sign Out"),
	)

	if allowSessionRevoke {
		dashButtons = append(
			dashButtons,
			FormCreateButtonLink(path.Join("/", functionalPath, "revokesessions"), "Sign Out All Devices"),
		)
	}

	if allowDeleteAccount {
		dashButtons = append(
			dashButtons,
			FormCreateDivider(),
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
		logMessage(1, fmt.Sprintf("Error rendering dashboard page: %s", err.Error()))
		ServeErrorPage(response, err)
	}

}

func HandleChangeEmail(response http.ResponseWriter, request *http.Request) {
	if !allowEmailChange {
		response.WriteHeader(410)
		ServePage(response, disabledFeaturePage)
		return
	}

	var validSession bool = false
	var validCriticalSession bool = false
	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}
	if !validSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "/login"), http.StatusSeeOther)
		return
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession, err = IsValidCriticalSession(critialSessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}
	if !validCriticalSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "elevate?t=changeemail"), http.StatusSeeOther)
		return
	}

	ServePage(response, emailChangePage)
}

func HandleChangeUsername(response http.ResponseWriter, request *http.Request) {
	if !allowUsernameChange {
		response.WriteHeader(410)
		ServePage(response, disabledFeaturePage)
		return
	}
	var (
		userId               string
		validSession         bool = false
		validCriticalSession bool = false
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}
	if !validSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "/login"), http.StatusSeeOther)
		return
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession, err = IsValidCriticalSession(critialSessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}
	if !validCriticalSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "elevate?t=changeusername"), http.StatusSeeOther)
		return
	}

	err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_accounts INNER JOIN %s_sessions ON user_id = id WHERE session_token = ? AND username_changed < CURRENT_TIMESTAMP - INTERVAL 30 DAY", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userId)
	if err == sql.ErrNoRows {
		ServePage(response, usernameChangeBlockedPage)
	} else if err != nil {
		ServeErrorPage(response, err)
		return
	} else {
		ServePage(response, usernameChangePage)
	}

}

func HandleChangeAvatar(response http.ResponseWriter, request *http.Request) {
	if !allowAvatarChange {
		response.WriteHeader(410)
		ServePage(response, disabledFeaturePage)
		return
	}

	var (
		validSession bool = false
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}
	if !validSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "/login"), http.StatusSeeOther)
		return
	}

	ServePage(response, avatarChangePage)
}

func HandleDeleteAccount(response http.ResponseWriter, request *http.Request) {
	if !allowDeleteAccount {
		response.WriteHeader(410)
		ServePage(response, disabledFeaturePage)
		return
	}
	var (
		validSession         bool = false
		validCriticalSession bool = false
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}
	if !validSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "/login"), http.StatusSeeOther)
		return
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession, err = IsValidCriticalSession(critialSessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}
	if !validCriticalSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "elevate?t=deleteaccount"), http.StatusSeeOther)
		return
	}
	ServePage(response, deleteAccountPage)
}

func HandleSessionRevoke(response http.ResponseWriter, request *http.Request) {
	if !allowSessionRevoke {
		response.WriteHeader(410)
		ServePage(response, disabledFeaturePage)
		return
	}
	var validSession bool = false

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}
	if !validSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "/login"), http.StatusSeeOther)
		return
	}
	var sessionRevokePage = GatehouseForm{
		appName + " - Sign Out All Devices",
		"Sign Out All Devices",
		"/" + functionalPath + "/submit/revokesessions",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Are you sure you wish to sign out all devices?"),
			FormCreateDivider(),
			FormCreateDangerSubmitInput("submit", "Sign Out"),
			FormCreateDivider(),
			FormCreateHint("Changed your mind?"),
			FormCreateButtonLink("/"+functionalPath+"/manage", "Cancel"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	ServePage(response, sessionRevokePage)
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
		response.WriteHeader(410)
		fmt.Fprint(response, `410 - Feature Disabled.`)
		return
	}
	if username == "" || password == "" {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Credentials Not Provided.`)
		return
	}

	err := db.QueryRow(fmt.Sprintf("SELECT id, email, email_confirmed, password, mfa_type FROM %s_accounts WHERE username = ?", tablePrefix), username).Scan(&userID, &email, &emailConfirmed, &passwordHash, &mfaType)
	if err == sql.ErrNoRows {
		http.Redirect(response, request, path.Join("/", functionalPath, "/login?error=invalid"), http.StatusSeeOther)
		return
	} else if err != nil {
		ServeErrorPage(response, err)
		return
	}

	if !CheckPasswordHash(password, passwordHash) {
		http.Redirect(response, request, path.Join("/", functionalPath, "/login?error=invalid"), http.StatusSeeOther)
		return
	}

	if !allowMobileMFA {
		AuthenticateRequestor(response, request, userID)
		return
	}

	if mfaType == "email" && !emailConfirmed {
		AuthenticateRequestor(response, request, userID)
		return
	}

	// Begin multifactor session
	sessionToken, err := GenerateMfaSessionToken()
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	cookie := http.Cookie{Name: mfaCookieName, Value: sessionToken, SameSite: http.SameSiteStrictMode, Secure: false, Path: "/"}
	http.SetCookie(response, &cookie)

	if mfaType == "email" {
		mfaToken := GenerateRandomNumbers(6)
		_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_mfa (mfa_session, type, user_id, token) VALUES (?, ?, ?, ?)", tablePrefix), sessionToken, "email", userID, mfaToken)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}

		err = sendMail(
			strings.ToLower(email),
			"Sign In - OTP",
			username,
			fmt.Sprintf("Your OTP code for %s is: %s", appName, mfaToken),
			"",
			"<b>If you did not request this action, please change your password immediately.</b>",
		)

		if err != nil {
			ServeErrorPage(response, err)
			logMessage(2, fmt.Sprintf("User %s was not sent their email MFA code: %s", userID, err.Error()))
		} else {
			ServePage(response, mfaEmailPage)
		}

	} else if mfaType == "token" {
		_, err := db.Exec(fmt.Sprintf("INSERT INTO %s_mfa (mfa_session, type, user_id, token) VALUES (?, ?, ?, ?)", tablePrefix), sessionToken, "totp", userID, "")
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
		ServePage(response, mfaTokenPage)
	} else {
		ServeErrorPage(response, nil)
		logMessage(1, fmt.Sprintf("Unrecognised MFA type in database: %s", mfaType))
	}
}

func HandleSubRegister(response http.ResponseWriter, request *http.Request) {
	username := strings.ToLower(request.FormValue("newUsername"))
	email := strings.ToLower(request.FormValue("email"))
	password := request.FormValue("password")
	passwordConfirm := request.FormValue("passwordConfirm")

	if !allowRegistration {
		response.WriteHeader(410)
		fmt.Fprint(response, `410 - Feature Disabled.`)
		return
	}
	validUsername, err := IsValidNewUsername(username)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	if !validUsername {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid Username.`)
		return
	}
	validEmail, err := IsValidNewEmail(email)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	if !validEmail {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid email.`)
		return
	}
	if !IsValidPassword(password) {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid Password.`)
		return
	}
	if password != passwordConfirm {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Passwords did not match.`)
		return
	}
	userID, err := GenerateUserID()
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id, username, email, password) VALUES (?, ?, ?, ?)", tablePrefix), userID, username, email, HashPassword(password))
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	err = SendEmailConfirmationCode(userID, email, username)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	AuthenticateRequestor(response, request, userID)

}

func HandleSubResetRequest(response http.ResponseWriter, request *http.Request) {
	email := request.FormValue("email")
	if !allowPasswordReset {
		response.WriteHeader(410)
		fmt.Fprint(response, `410 - Feature Disabled.`)
		return
	}
	emailExists, err := ResetPasswordRequest(email)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	if !emailExists {
		ServePage(response, resetNotSentPage)
	}
	ServePage(response, resetSentPage)
}

func HandleSubReset(response http.ResponseWriter, request *http.Request) {
	if !allowPasswordReset {
		response.WriteHeader(410)
		fmt.Fprint(response, `410 - Feature Disabled.`)
		return
	}

	code := request.URL.Query().Get("c")
	password := request.FormValue("password")
	passwordConfirm := request.FormValue("passwordConfirm")

	if code == "" || !IsValidPassword(password) || password != passwordConfirm {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid request.`)
		return
	}

	var userID string
	err := db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_resets WHERE reset_token = ? AND used = 0", tablePrefix), code).Scan(&userID)
	if err == sql.ErrNoRows {
		response.WriteHeader(403)
		fmt.Fprint(response, `403 - Unauthorized.`)
		return
	} else if err != nil {
		ServeErrorPage(response, err)
		return
	}

	_, err = db.Exec(fmt.Sprintf("UPDATE %s_resets INNER JOIN %s_accounts ON user_id = id SET password = ?, used = 1 WHERE reset_token = ?", tablePrefix, tablePrefix), HashPassword(password), code)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	ServePage(response, resetSuccessPage)

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
		return
	}

	err = db.QueryRow(fmt.Sprintf("SELECT user_id, token, mfa_type, mfa_secret FROM %s_mfa INNER JOIN %s_accounts ON user_id = id WHERE mfa_session = ? AND created > CURRENT_TIMESTAMP - INTERVAL 1 HOUR AND used = 0", tablePrefix, tablePrefix), mfaSession.Value).Scan(&userID, &mfaStoredToken, &mfaType, &mfaSecret)
	if err == sql.ErrNoRows {
		response.WriteHeader(400)
		fmt.Fprint(response, `Invalid request.`)
		return
	} else if err != nil {
		ServeErrorPage(response, err)
		return
	}

	if mfaType == "email" && mfaStoredToken == otpInput {
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
		logMessage(1, err.Error())
	}

}

func HandleSubMFAValidate(response http.ResponseWriter, request *http.Request) {
	if !allowMobileMFA {
		response.WriteHeader(410)
		ServePage(response, disabledFeaturePage)
		return
	}

	var (
		submitOtp    string = request.FormValue("otp")
		mfaSecret    string
		userID       string
		email        string
		username     string
		validSession bool = false
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}
	if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
		return
	}

	err = db.QueryRow(fmt.Sprintf("SELECT id, mfa_secret, email, username FROM %s_accounts INNER JOIN %s_sessions ON id = user_id WHERE session_token = ? AND mfa_type = 'email' AND mfa_secret IS NOT NULL", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &mfaSecret, &email, &username)
	if err == sql.ErrNoRows {
		response.WriteHeader(400)
		fmt.Fprint(response, `Invalid Request.`)
		return
	} else if err != nil {
		ServeErrorPage(response, err)
		return
	}

	otp, err := GenerateOTP(mfaSecret, 30)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	if otp != submitOtp {
		response.WriteHeader(400)
		ServePage(response, mfaFailedPage)
		return
	}

	_, err = db.Exec(fmt.Sprintf("UPDATE %s_accounts SET mfa_type = 'token' WHERE id = ?", tablePrefix), userID)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	var recoveryCodes string = ""
	for i := 0; i < 12; i++ {
		recoveryCode := GenerateRandomNumbers(8)
		recoveryCodes = recoveryCodes + "<br>" + recoveryCode
		_, err = db.Exec(fmt.Sprintf("INSERT IGNORE INTO %s_recovery (user_id, code) VALUES (?, ?)", tablePrefix), userID, recoveryCode)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	var mfaValidatedPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - MFA Validated",
		"Success",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Your MFA device was successfully registered. You are now able to sign in with your authenticator OTP in the future."),
			FormCreateDivider(),
			FormCreateHint("In the event you lose your MFA device, a recovery code can be used instead."),
			FormCreateHint("Your recovery codes:"),
			FormCreateHint(recoveryCodes),
			FormCreateHint("Ensure these are recorded somewhere safe."),
			FormCreateDivider(),
			FormCreateButtonLink("/"+functionalPath+"/manage", "Back to Dashboard"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	ServePage(response, mfaValidatedPage)
	if enableMFAAlerts {
		err = sendMail(email, "MFA Device Added", username, "You have successfully added an MFA device to your account.", "", "")
		if err != nil {
			logMessage(3, fmt.Sprintf("User %s was not sent MFA added email.", userID))
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
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}
	if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
		return
	}

	target := request.URL.Query().Get("t")
	if target == "" {
		response.WriteHeader(400)
		fmt.Fprintf(response, "Target required.")
		return
	}
	if !listContains(elevatedRedirectPages, target) {
		response.WriteHeader(400)
		fmt.Fprintf(response, "Invalid target.")
		return
	}

	err = db.QueryRow(fmt.Sprintf("SELECT id, password FROM %s_accounts INNER JOIN %s_sessions ON id = user_id WHERE session_token = ?", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &passwordHash)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	if !CheckPasswordHash(password, passwordHash) {
		http.Redirect(response, request, "/"+functionalPath+fmt.Sprintf("/elevate?error=invalid&t=%s", target), http.StatusSeeOther)
		return
	}

	elevatedSessionToken, err := GenerateSessionToken()
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_sessions (session_token, user_id, critical) VALUES (?, ?, 1)", tablePrefix), elevatedSessionToken, userID)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	cookie := http.Cookie{Name: criticalCookieName, Value: elevatedSessionToken, SameSite: http.SameSiteStrictMode, Secure: false, Path: "/"}
	http.SetCookie(response, &cookie)
	http.Redirect(response, request, path.Join("/", functionalPath, target), http.StatusSeeOther)
}

func HandleSubRemoveMFA(response http.ResponseWriter, request *http.Request) {
	var (
		validSession         bool = false
		validCriticalSession bool = false
		mfaType              string
		username             string
		email                string
		sessionUserID        string
		criticalUserID       string
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession, err = IsValidCriticalSession(critialSessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
		return
	}

	if !validCriticalSession {
		http.Redirect(response, request, path.Join("/", functionalPath, "elevate?t=removemfa"), http.StatusSeeOther)
		return
	}

	err = db.QueryRow(fmt.Sprintf("SELECT id, mfa_type FROM %s_accounts INNER JOIN %s_sessions ON id = user_id WHERE session_token = ? AND critical = 0", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&sessionUserID, &mfaType)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	err = db.QueryRow(fmt.Sprintf("SELECT id, email, username FROM %s_accounts INNER JOIN %s_sessions ON id = user_id WHERE session_token = ? AND critical = 1", tablePrefix, tablePrefix), critialSessionCookie.Value).Scan(&criticalUserID, &email, &username)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	if sessionUserID != criticalUserID {
		response.WriteHeader(500)
		fmt.Fprint(response, `Undefined error.`)
		logMessage(3, fmt.Sprintf("User (%s) attempted to use another user's (%s) elevated session token.", sessionUserID, criticalUserID))
		return
	}

	if mfaType != "token" {
		response.WriteHeader(400)
		fmt.Fprint(response, `MFA Device not registered`)
		return
	}

	_, err = db.Exec(fmt.Sprintf("UPDATE %s_accounts SET mfa_type = 'email', mfa_secret = NULL WHERE id = ?", tablePrefix), sessionUserID)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	ServePage(response, mfaRemovedPage)
	if enableMFAAlerts {
		err = sendMail(email, "MFA Device Removed", username, "You have successfully removed an MFA device to your account.", "", "If you did not request this action, change your password immediately.")
		if err != nil {
			logMessage(3, fmt.Sprintf("User %s was not sent MFA removed email.", sessionUserID))
		}
	}

}

func HandleSubEmailChange(response http.ResponseWriter, request *http.Request) {
	if !allowEmailChange {
		response.WriteHeader(410)
		fmt.Fprint(response, `Feature disabled.`)
		return
	}

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
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession, err = IsValidCriticalSession(critialSessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	if !validSession || !validCriticalSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
		return
	}
	validEmail, err := IsValidNewEmail(email)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	if !validEmail {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid email.`)
		return
	}
	err = db.QueryRow(fmt.Sprintf("SELECT user_id, username FROM %s_accounts INNER JOIN %s_sessions ON user_id = id WHERE session_token = ?", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &username)
	if err == sql.ErrNoRows {
		response.WriteHeader(400)
		fmt.Fprint(response, `Invalid request.`)
		return
	} else if err != nil {
		ServeErrorPage(response, err)
		return
	}
	_, err = db.Exec(fmt.Sprintf("UPDATE %s_accounts SET email = ?, email_confirmed = 0, email_resent = 0 WHERE id = ?", tablePrefix), email, userID)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	err = SendEmailConfirmationCode(userID, email, username)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	ServePage(response, confirmEmailPage)

}

func HandleSubUsernameChange(response http.ResponseWriter, request *http.Request) {
	if !allowUsernameChange {
		response.WriteHeader(410)
		fmt.Fprint(response, `Feature disabled.`)
		return
	}

	var (
		validSession         bool = false
		validCriticalSession bool = false
		userID               string
		username             string
		email                string
	)

	username = strings.ToLower(request.FormValue("newUsername"))

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession, err = IsValidCriticalSession(critialSessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	if !validSession || !validCriticalSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
		return
	}
	validUsername, err := IsValidNewUsername(username)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}
	if !validUsername {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid username.`)
		return
	}

	err = db.QueryRow(fmt.Sprintf("SELECT user_id, email FROM %s_accounts INNER JOIN %s_sessions ON user_id = id WHERE session_token = ? AND username_changed < CURRENT_TIMESTAMP - INTERVAL 30 DAY", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &email)
	if err == sql.ErrNoRows {
		response.WriteHeader(400)
		fmt.Fprint(response, `Invalid request.`)
		return
	} else if err != nil {
		ServeErrorPage(response, err)
		return
	}

	_, err = db.Exec(fmt.Sprintf("UPDATE %s_accounts SET username = ?, username_changed = CURRENT_TIMESTAMP WHERE id = ? AND username_changed < CURRENT_TIMESTAMP - INTERVAL 30 DAY", tablePrefix), username, userID)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	ServePage(response, confirmedUsernameChangePage)
	err = sendMail(email, "Username Changed", username, "Your username has been changed successfully. You will be able to change your username again after 30 days.", "", "If you did not perform this action, please change your password immediately.")
	if err != nil {
		logMessage(3, fmt.Sprintf("User %s was not notified of username change.", username))
	}

}

func HandleSubDeleteAccount(response http.ResponseWriter, request *http.Request) {
	if !allowDeleteAccount {
		response.WriteHeader(410)
		fmt.Fprint(response, `Feature Disabled.`)
		return
	}

	var (
		validSession         bool = false
		validCriticalSession bool = false
		userID               string
		username             string
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	critialSessionCookie, err := request.Cookie(criticalCookieName)
	if err == nil {
		validCriticalSession, err = IsValidCriticalSession(critialSessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	if !validSession || !validCriticalSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
		return
	}

	err = db.QueryRow(fmt.Sprintf("SELECT user_id, username FROM %s_accounts INNER JOIN %s_sessions ON user_id = id WHERE session_token = ?", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &username)
	if err == sql.ErrNoRows {
		response.WriteHeader(400)
		fmt.Fprint(response, `Invalid request.`)
	} else if err != nil {
		ServeErrorPage(response, err)
		return
	}

	_, err = db.Exec(fmt.Sprintf("DELETE FROM %s_accounts WHERE id = ?", tablePrefix), userID)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	ServePage(response, deletedAccountPage)

}

func HandleSubRecoveryCode(response http.ResponseWriter, request *http.Request) {
	if !allowMobileMFA {
		response.WriteHeader(410)
		ServePage(response, disabledFeaturePage)
		return
	}
	var (
		userID        string
		recoveryToken string = request.FormValue("token")
	)
	mfaCookie, err := request.Cookie(mfaCookieName)
	if err != nil {
		http.Redirect(response, request, "/"+functionalPath+"/login", http.StatusSeeOther)
		return
	}

	err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_mfa INNER JOIN %s_recovery ON %s_mfa.user_id = %s_recovery.user_id INNER JOIN %s_accounts ON id = %s_recovery.user_id WHERE mfa_session = ? AND %s_mfa.used = 0 AND type = 'totp' AND %s_mfa.created > CURRENT_TIMESTAMP - INTERVAL 1 HOUR AND code = ?", tablePrefix, tablePrefix, tablePrefix, tablePrefix, tablePrefix, tablePrefix, tablePrefix, tablePrefix), mfaCookie.Value, recoveryToken).Scan(&userID)
	if err == sql.ErrNoRows {
		http.Redirect(response, request, "/"+functionalPath+"/login?error=invalid", http.StatusSeeOther)
		return
	} else if err != nil {
		ServeErrorPage(response, err)
		return
	}

	_, err = db.Exec(fmt.Sprintf("UPDATE %s_recovery SET used = 1 WHERE user_id = ? AND code = ?", tablePrefix), userID, recoveryToken)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	AuthenticateRequestor(response, request, userID)

}

func HandleSubSessionRevoke(response http.ResponseWriter, request *http.Request) {
	if !allowSessionRevoke {
		response.WriteHeader(410)
		fmt.Fprint(response, `Feature Disabled.`)
		return
	}

	var (
		validSession bool = false
		userID       string
	)

	sessionCookie, err := request.Cookie(sessionCookieName)
	if err == nil {
		validSession, err = IsValidSession(sessionCookie.Value)
		if err != nil {
			ServeErrorPage(response, err)
			return
		}
	}

	if !validSession {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
		return
	}

	err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_accounts INNER JOIN %s_sessions ON user_id = id WHERE session_token = ?", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID)
	if err == sql.ErrNoRows {
		response.WriteHeader(400)
		fmt.Fprint(response, `Invalid request.`)
		return
	} else if err != nil {
		ServeErrorPage(response, err)
		return
	}

	_, err = db.Exec(fmt.Sprintf("DELETE FROM %s_sessions WHERE user_id = ?", tablePrefix), userID)
	if err != nil {
		ServeErrorPage(response, err)
		return
	}

	var logoutPage = GatehouseForm{
		appName + " - Sign Out",
		"Signed Out All Devices",
		"",
		"",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("You have signed out all devices."),
			FormCreateButtonLink("/", "Back to site"),
			FormCreateDivider(),
			FormCreateButtonLink("/"+functionalPath+"/login", "Sign In"),
		},
		[]OIDCButton{},
		functionalPath,
	}

	http.SetCookie(response, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	ServePage(response, logoutPage)

}
