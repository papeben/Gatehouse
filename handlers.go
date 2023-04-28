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

func HandleLogin(response http.ResponseWriter, request *http.Request) {
	err := formTemplate.Execute(response, loginPage)
	if err != nil {
		panic(err)
	}
}

func HandleLogout(response http.ResponseWriter, request *http.Request) {
	http.SetCookie(response, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
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

func HandleConfirmEmail(response http.ResponseWriter, request *http.Request) {
	err := formTemplate.Execute(response, confirmEmailPage)
	if err != nil {
		panic(err)
	}
}

func HandleRegister(response http.ResponseWriter, request *http.Request) {
	err := formTemplate.Execute(response, registrationPage)
	if err != nil {
		panic(err)
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
		err := formTemplate.Execute(response, linkExpired)
		if err != nil {
			panic(err)
		}
	}
}

func HandleIsUsernameTaken(response http.ResponseWriter, request *http.Request) {
	if !IsValidNewUsername(request.URL.Query().Get("u")) {
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
	if !validSession {
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
	if username == "" || password == "" {
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
		} else {
			passwordValid := CheckPasswordHash(password, passwordHash)
			if !passwordValid {
				http.Redirect(response, request, path.Join("/", functionalPath, "/login?error=invalid"), http.StatusSeeOther)
			} else if mfaEnabled == "TRUE" && (mfaType == "token" || mfaType == "email" && emailConfirmed) {
				// Begin multifactor session
				sessionToken := GenerateMfaSessionToken()
				cookie := http.Cookie{Name: mfaCookieName, Value: sessionToken, SameSite: http.SameSiteLaxMode, Secure: false, Path: "/"}
				http.SetCookie(response, &cookie)
				db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
				if err != nil {
					panic(err)
				}
				defer db.Close()

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
						Title:    "MFA Token",
						Username: username,
						Message:  fmt.Sprintf("Your MFA code for %s is: %s", appName, mfaToken),
						HasLink:  false,
						Link:     "",
						AppName:  appName,
					})
					if err != nil {
						panic(err)
					}

					err = sendMail(strings.ToLower(email), "Password Reset Request", body.String())
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
					_, err := db.Exec(fmt.Sprintf("INSERT INTO %s_mfa (mfa_session, type, user_id, token) VALUES (?, ?, ?, ?)", tablePrefix), sessionToken, "email", userID, "")
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
}

func HandleSubRegister(response http.ResponseWriter, request *http.Request) {
	username := strings.ToLower(request.FormValue("newUsername"))
	email := strings.ToLower(request.FormValue("email"))
	password := request.FormValue("password")
	passwordConfirm := request.FormValue("passwordConfirm")

	if IsValidNewUsername(username) && IsValidNewEmail(email) && IsValidPassword(password) && password == passwordConfirm { // Test registration input validity
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
	} else {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid registration details.`)
	}
}

func HandleSubResetRequest(response http.ResponseWriter, request *http.Request) {
	email := request.FormValue("email")
	if ResetPasswordRequest(email) {
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
	if ResetSubmission(request) {
		err := formTemplate.Execute(response, resetSuccessPage)
		if err != nil {
			panic(err)
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
		mfaSecret      string
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

		_, err = db.Exec(fmt.Sprintf("UPDATE %s_mfa SET used = 1 WHERE mfa_session = ?", tablePrefix), mfaSession.Value)
		if err != nil {
			panic(err)
		}

		err = db.QueryRow(fmt.Sprintf("SELECT user_id, token, mfa_type, mfa_secret FROM %s_mfa INNER JOIN %s_accounts ON user_id = id WHERE mfa_session = ? AND created > CURRENT_TIMESTAMP - INTERVAL 1 HOUR AND used = 0", tablePrefix, tablePrefix), mfaSession.Value).Scan(&userID, &mfaStoredToken, &mfaType, &mfaSecret)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		} else if err == sql.ErrNoRows {
			response.WriteHeader(400)
			fmt.Fprint(response, `Invalid request.`)
		} else if mfaType == "email" && mfaStoredToken == otpInput {
			AuthenticateRequestor(response, request, userID)
		} else if mfaType == "token" {
			otp, _ := GenerateOTP(mfaSecret, 30)
			if otp == otpInput {
				AuthenticateRequestor(response, request, userID)
			} else {
				http.Redirect(response, request, "/"+functionalPath+"/login?error=invalid", http.StatusSeeOther)
			}
		} else {
			http.Redirect(response, request, "/"+functionalPath+"/login?error=invalid", http.StatusSeeOther)
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

	if !validSession {
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
				err = formTemplate.Execute(response, mfaValidatedPage)
				if err != nil {
					panic(err)
				}
			} else {
				err = formTemplate.Execute(response, mfaFailedPage)
				if err != nil {
					panic(err)
				}
			}
		}
	}
}
