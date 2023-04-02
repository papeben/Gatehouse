package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
)

func RegisterSubmission(response http.ResponseWriter, request *http.Request) {
	username := request.FormValue("newUsername")
	email := request.FormValue("email")
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

		authenticateRequestor(response, request, userID)

	} else {

		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid registration details.`)

	}
}

func LoginSubmission(response http.ResponseWriter, request *http.Request) {
	var (
		username     string = request.FormValue("username")
		password     string = request.FormValue("password")
		userID       string
		passwordHash string
		isValid      bool = false
	)
	if username != "" {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		err = db.QueryRow(fmt.Sprintf("SELECT id, password FROM %s_accounts WHERE username = ?", tablePrefix), username).Scan(&userID, &passwordHash)
		if err == nil && CheckPasswordHash(password, passwordHash) {
			isValid = true
		} else if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
	}

	if isValid {
		authenticateRequestor(response, request, userID)
	} else {
		http.Redirect(response, request, "/"+functionalPath+"/login?error=invalid", http.StatusSeeOther)
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
	_, err := mail.ParseAddress(email)
	if err == nil {
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
	return true
}