package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
)

func GenerateUserID() string {
	newID := GenerateRandomString(8)

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var userID string
	err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_accounts WHERE id = ?", tablePrefix), strings.ToLower(newID)).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return newID
		} else {
			panic(err)
		}
	} else {
		return GenerateUserID()
	}
}

func GenerateSessionToken() string {
	newToken := GenerateRandomString(64)

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var userID string
	err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_sessions WHERE session_token = ?", tablePrefix), newToken).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return newToken
		} else {
			panic(err)
		}
	} else {
		return GenerateSessionToken()
	}
}

func GeneratEmailConfirmationToken() string {
	newToken := GenerateRandomString(32)

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var userID string
	err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_confirmations WHERE confirmation_token = ?", tablePrefix), newToken).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return strings.ToLower(newToken)
		} else {
			panic(err)
		}
	} else {
		return GeneratEmailConfirmationToken()
	}
}

func AuthenticateRequestor(response http.ResponseWriter, request *http.Request, userID string) {
	token := GenerateSessionToken()

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_sessions (session_token, user_id) VALUES (?, ?)", tablePrefix), token, userID)
	if err != nil {
		panic(err)
	}

	cookie := http.Cookie{Name: sessionCookieName, Value: token, SameSite: http.SameSiteLaxMode, Secure: false, Path: "/"}
	http.SetCookie(response, &cookie)
	http.Redirect(response, request, "/", http.StatusSeeOther)
}

func IsValidSession(request *http.Request) bool {
	tokenCookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		return false
	} else {

		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var userID string
		var emailConfirmed int
		err = db.QueryRow(fmt.Sprintf("SELECT user_id, email_confirmed FROM %s_sessions INNER JOIN %s_accounts ON id = user_id WHERE session_token = ?", tablePrefix, tablePrefix), tokenCookie.Value).Scan(&userID, &emailConfirmed)
		if err != nil {
			if err == sql.ErrNoRows {
				return false
			} else {
				panic(err)
			}
		} else {
			if requireEmailConfirm == "TRUE" && emailConfirmed == 0 {
				return false
			} else {
				return true
			}
		}
	}
}

func PendingEmailApproval(request *http.Request) bool {
	tokenCookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		return false
	} else {

		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var emailConfirmed bool
		err = db.QueryRow(fmt.Sprintf("SELECT email_confirmed FROM %s_accounts INNER JOIN %s_sessions ON id = user_id WHERE session_token = ?", tablePrefix, tablePrefix), tokenCookie.Value).Scan(&emailConfirmed)
		if err != nil {
			if err == sql.ErrNoRows {
				return false
			} else {
				panic(err)
			}
		} else {
			if emailConfirmed {
				return false
			} else {
				return true
			}
		}
	}
}

func ConfirmEmailCode(code string) bool {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var isTokenUsed bool
	err = db.QueryRow(fmt.Sprintf("SELECT used FROM %s_confirmations WHERE confirmation_token = ?", tablePrefix), code).Scan(&isTokenUsed)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		} else {
			panic(err)
		}
	} else {
		if isTokenUsed {
			return false
		} else {
			_, err := db.Exec(fmt.Sprintf("UPDATE %s_accounts INNER JOIN %s_confirmations ON user_id = id SET email_confirmed = 1, used = 1 WHERE confirmation_token = ?", tablePrefix, tablePrefix), code)
			if err != nil {
				panic(err)
			}
			return true
		}
	}
}

func SendEmailConfirmationCode(userID string, email string) {
	code := GeneratEmailConfirmationToken()
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()
	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_confirmations (confirmation_token, user_id) VALUES (?, ?)", tablePrefix), code, userID)
	if err != nil {
		panic(err)
	}
	// Email code
	fmt.Println(code)
}
