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
	err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_sessions WHERE session_token = ?", tablePrefix), strings.ToLower(newToken)).Scan(&userID)
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

func authenticateRequestor(response http.ResponseWriter, request *http.Request, userID string) {
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
