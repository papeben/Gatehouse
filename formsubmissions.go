package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

func RegisterSubmission(response http.ResponseWriter, request *http.Request) {
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

func LoginSubmission(response http.ResponseWriter, request *http.Request) {
	var (
		username       string = strings.ToLower(request.FormValue("username"))
		password       string = request.FormValue("password")
		userID         string
		email          string
		emailConfirmed bool
		passwordHash   string
		mfaType        string
	)
	if username != "" {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT id, email, email_confirmed, password, mfa_type FROM %s_accounts WHERE username = ?", tablePrefix), username).Scan(&userID, &email, &emailConfirmed, &passwordHash, &mfaType)
		if err != nil && err == sql.ErrNoRows {
			http.Redirect(response, request, "/"+functionalPath+"/login?error=invalid", http.StatusSeeOther)
		} else if err != nil && err != sql.ErrNoRows {
			panic(err)
		} else if err == nil {
			passwordValid := CheckPasswordHash(password, passwordHash)
			if !passwordValid {
				http.Redirect(response, request, "/"+functionalPath+"/login?error=invalid", http.StatusSeeOther)
			} else if mfaEnabled == "TRUE" && mfaType == "email" && emailConfirmed {
				MfaSession(response, request, userID, username, email, mfaType)
			} else if mfaEnabled == "TRUE" && mfaType == "email" && !emailConfirmed {
				AuthenticateRequestor(response, request, userID)
			} else if mfaEnabled == "TRUE" && mfaType == "token" {
				MfaSession(response, request, userID, username, email, mfaType)
			} else {
				AuthenticateRequestor(response, request, userID)
			}
		}
	}

}

func IsValidNewUsername(username string) bool {
	match, _ := regexp.MatchString("^[a-zA-Z0-9\\-_]{1,32}$", username)
	if match {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var userID string
		err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_accounts WHERE username = ?", tablePrefix), username).Scan(&userID)
		if err != nil {
			if err == sql.ErrNoRows {
				return true
			} else {
				panic(err)
			}
		} else {
			return false
		}
	} else {
		return false
	}
}

func IsValidNewEmail(email string) bool {
	match, _ := regexp.MatchString(`^[\w!#$%&'*+/=?^_{|}~-]+(\.[\w!#$%&'*+/=?^_{|}~-]+)*@[a-zA-Z0-9]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,})$`, email)
	if match {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var userID string
		err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_accounts WHERE email = ?", tablePrefix), strings.ToLower(email)).Scan(&userID)
		if err != nil {
			if err == sql.ErrNoRows {
				return true
			} else {
				panic(err)
			}
		} else {
			return false
		}
	} else {
		return false
	}
}

func IsValidPassword(password string) bool {
	// Check length
	if len(password) < 8 {
		return false
	}

	// Check for uppercase letter
	hasUppercase := false
	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUppercase = true
			break
		}
	}
	if !hasUppercase {
		return false
	}

	// Check for numeric digit
	hasDigit := false
	for _, char := range password {
		if unicode.IsDigit(char) {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return false
	}

	// Password meets all criteria
	return true
}

func MfaSubmission(response http.ResponseWriter, request *http.Request) {
	var (
		mfaToken       string = request.FormValue("token")
		mfaType        string
		mfaStoredToken string
		mfaSecret      string
		userID         string
	)
	mfaSession, err := request.Cookie(mfaCookieName)

	if err == nil {
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
		} else if mfaType == "email" && mfaStoredToken == mfaToken {
			AuthenticateRequestor(response, request, userID)
		} else if mfaType == "token" {
			otp, _ := GenerateOTP(mfaSecret, 30)
			if otp == mfaToken {
				AuthenticateRequestor(response, request, userID)
			} else {
				http.Redirect(response, request, "/"+functionalPath+"/login?error=invalid", http.StatusSeeOther)
			}
		} else {
			http.Redirect(response, request, "/"+functionalPath+"/login?error=invalid", http.StatusSeeOther)
		}

		if err == nil {
			_, err = db.Exec(fmt.Sprintf("UPDATE %s_mfa SET used = 1 WHERE mfa_session = ?", tablePrefix), mfaSession.Value)
			if err != nil {
				panic(err)
			}
		}
	} else {
		response.WriteHeader(400)
		fmt.Fprint(response, `Invalid request.`)
	}
}

func MfaValidate(response http.ResponseWriter, request *http.Request) {
	var (
		submitOtp string = request.FormValue("otp")
		mfaSecret string
		userID    string
	)
	sessionCookie, err := request.Cookie(sessionCookieName)

	if err == nil {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT id, mfa_secret FROM %s_accounts INNER JOIN %s_sessions ON id = user_id WHERE session_token = ?", tablePrefix, tablePrefix), sessionCookie.Value).Scan(&userID, &mfaSecret)
		if err == nil {
			otp, err := GenerateOTP(mfaSecret, 30)
			if err != nil {
				panic(err)
			}
			if otp == submitOtp {
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
		} else if err == sql.ErrNoRows {
			response.WriteHeader(403)
			fmt.Fprint(response, `Unauthorized.`)
		} else {
			panic(err)
		}
	} else {
		response.WriteHeader(403)
		fmt.Fprint(response, `Unauthorized.`)
	}
}
