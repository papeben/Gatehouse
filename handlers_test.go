package main

import (
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
	InitDatabase()
	LoadTemplates()
	LoadFuncionalURIs()
}

func TestRegistrationFlow(t *testing.T) {
	requireAuthentication = true
	requireEmailConfirm = true
	mfaEnabled = true
	username := GenerateRandomString(8)
	email := username + "@testing.local"
	password := "aG00dPasswrd4Te5t"
	sessionToken := ""

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		t.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	t.Run("Redirect unauthenticated users to login", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusSeeOther {
			fmt.Println(recorder.Body)
			t.Errorf("Expected redirect, got %v", recorder.Code)
		}
	})

	t.Run("Get register page", func(t *testing.T) {
		req, err := http.NewRequest("GET", path.Join("/"+functionalPath+"/register"), nil)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			fmt.Println(recorder.Body)
			t.Errorf("Expected ok, got %v", recorder.Code)
		}
	})

	t.Run("Submit registration data", func(t *testing.T) {
		form := url.Values{}
		form.Add("newUsername", username)
		form.Add("email", email)
		form.Add("password", password)
		form.Add("passwordConfirm", password)
		req, err := http.NewRequest("POST", path.Join("/", functionalPath, "submit", "register"), strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			t.Fatal(err)
		}

		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusSeeOther {
			fmt.Println(recorder.Body)
			t.Errorf("Expected redirect, got %v", recorder.Code)
		}
	})

	t.Run("Get confirmation page", func(t *testing.T) {
		req, err := http.NewRequest("GET", path.Join("/"+functionalPath+"/confirmemail"), nil)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			fmt.Println(recorder.Body)
			t.Errorf("Expected %v, got %v", http.StatusOK, recorder.Code)
		}
	})

	t.Run("Confirm email address", func(t *testing.T) {
		var (
			code string
			used bool
		)
		err = db.QueryRow(fmt.Sprintf("SELECT confirmation_token, used FROM %s_confirmations INNER JOIN %s_accounts ON user_id = id WHERE username = ?", tablePrefix, tablePrefix), strings.ToLower(username)).Scan(&code, &used)
		if err != nil {
			t.Fatal(err)
		}
		if used {
			t.Errorf("Confirmation code recorded as already used")
		}

		// Test confirmation link
		req, err := http.NewRequest("GET", path.Join("/", functionalPath, "confirmcode?c="+code), nil)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			fmt.Println(recorder.Body)
			t.Errorf("Expected OK, got %v", recorder.Code)
		}

		err = db.QueryRow(fmt.Sprintf("SELECT confirmation_token, used FROM %s_confirmations INNER JOIN %s_accounts ON user_id = id WHERE username = ?", tablePrefix, tablePrefix), strings.ToLower(username)).Scan(&code, &used)
		if err != nil {
			t.Fatal(err)
		}
		if !used {
			t.Errorf("Confirmation code should have been marked as used")
		}

		// Test confirmation link has expired
		req, err = http.NewRequest("GET", path.Join("/", functionalPath, "confirmcode?c="+code), nil)
		if err != nil {
			t.Fatal(err)
		}
		recorder = httptest.NewRecorder()
		handler = http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusBadRequest {
			fmt.Println(recorder.Body)
			t.Errorf("Expected OK, got %v", recorder.Code)
		}
	})

	t.Run("Sign in with new credentials and email OTP", func(t *testing.T) {

		// Submit login
		form := url.Values{}
		form.Add("username", username)
		form.Add("password", password)
		req, err := http.NewRequest("POST", path.Join("/", functionalPath, "submit", "login"), strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			t.Fatal(err)
		}

		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			fmt.Println(recorder.Body)
			t.Errorf("Expected ok, got %v", recorder.Code)
		}

		// Get OTP from database
		mfaSession := recorder.Result().Cookies()[0].Value
		var token string
		err = db.QueryRow(fmt.Sprintf("SELECT token FROM %s_mfa WHERE mfa_session = ?", tablePrefix), mfaSession).Scan(&token)
		if err != nil {
			t.Fatal(err)
		}

		// Send OTP
		form = url.Values{}
		form.Add("token", token)
		req, err = http.NewRequest("POST", path.Join("/", functionalPath, "submit", "mfa"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(recorder.Result().Cookies()[0])

		recorder = httptest.NewRecorder()
		handler = http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusSeeOther {
			fmt.Println(recorder.Body)
			t.Errorf("Expected redirect, got %v", recorder.Code)
		}

		returnedCookies := recorder.Result().Cookies()
		if len(returnedCookies) != 1 || returnedCookies[0].Name != sessionCookieName {
			fmt.Println(recorder.Body)
			t.Errorf("Expected a sesson cookie, but didn't get one")
		} else {
			sessionToken = returnedCookies[0].Value
		}
	})

	t.Run("Register MFA Token Device", func(t *testing.T) {

		// get Add-MFA page
		req, err := http.NewRequest("GET", path.Join("/", functionalPath, "addmfa"), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})

		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			fmt.Println(recorder.Body)
			t.Errorf("Expected OK, got %v", recorder.Code)
		}

		// Get generated MFA secret
		var mfaSecret string
		err = db.QueryRow(fmt.Sprintf("SELECT mfa_secret FROM %s_accounts INNER JOIN %s_sessions ON user_id = id WHERE session_token = ?", tablePrefix, tablePrefix), sessionToken).Scan(&mfaSecret)
		if err != nil {
			t.Fatal(err)
		}

		// Send incorrect token to validation
		form := url.Values{}
		form.Add("otp", "123456")
		req, err = http.NewRequest("POST", path.Join("/", functionalPath, "submit", "validatemfa"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		recorder = httptest.NewRecorder()
		handler = http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusBadRequest {
			fmt.Println(recorder.Body)
			t.Errorf("Expected bad request, got %v", recorder.Code)
		}

		// Send correct token to validation
		form = url.Values{}
		otp, err := GenerateOTP(mfaSecret, 30)
		if err != nil {
			t.Fatal(err)
		}
		form.Add("otp", otp)
		req, err = http.NewRequest("POST", path.Join("/", functionalPath, "submit", "validatemfa"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		recorder = httptest.NewRecorder()
		handler = http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			fmt.Println(recorder.Body)
			t.Errorf("Expected %v got %v", http.StatusOK, recorder.Code)
		}

		// Send correct token to again
		form = url.Values{}
		otp, err = GenerateOTP(mfaSecret, 30)
		if err != nil {
			t.Fatal(err)
		}
		form.Add("otp", otp)
		req, err = http.NewRequest("POST", path.Join("/", functionalPath, "submit", "validatemfa"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		recorder = httptest.NewRecorder()
		handler = http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusBadRequest {
			fmt.Println(recorder.Body)
			t.Errorf("Expected %v got %v", http.StatusBadRequest, recorder.Code)
		}

		// Add MFA page should now be unavailable
		req, err = http.NewRequest("GET", path.Join("/", functionalPath, "addmfa"), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})

		recorder = httptest.NewRecorder()
		handler = http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusBadRequest {
			fmt.Println(recorder.Body)
			t.Errorf("Expected %v got %v", http.StatusBadRequest, recorder.Code)
		}

	})

	t.Run("Sign in with new credentials and device OTP", func(t *testing.T) {

		// Submit login
		form := url.Values{}
		form.Add("username", username)
		form.Add("password", password)
		req, err := http.NewRequest("POST", path.Join("/", functionalPath, "submit", "login"), strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			t.Fatal(err)
		}

		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			fmt.Println(recorder.Body)
			t.Errorf("Expected ok, got %v", recorder.Code)
		}

		// Get generated MFA secret
		var mfaSecret string
		err = db.QueryRow(fmt.Sprintf("SELECT mfa_secret FROM %s_accounts INNER JOIN %s_sessions ON user_id = id WHERE session_token = ?", tablePrefix, tablePrefix), sessionToken).Scan(&mfaSecret)
		if err != nil {
			t.Fatal(err)
		}

		// Send OTP

		form = url.Values{}
		otp, err := GenerateOTP(mfaSecret, 30)
		if err != nil {
			t.Fatal(err)
		}
		form.Add("token", otp)
		req, err = http.NewRequest("POST", path.Join("/", functionalPath, "submit", "mfa"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(recorder.Result().Cookies()[0])

		recorder = httptest.NewRecorder()
		handler = http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusSeeOther {
			fmt.Println(recorder.Body)
			t.Errorf("Expected redirect, got %v", recorder.Code)
		}

		returnedCookies := recorder.Result().Cookies()
		if len(returnedCookies) != 1 || returnedCookies[0].Name != sessionCookieName {
			fmt.Println(recorder.Body)
			t.Errorf("Expected a sesson cookie, but didn't get one")
		} else {
			sessionToken = returnedCookies[0].Value
		}
	})

	t.Run("Sign out", func(t *testing.T) {

		req, err := http.NewRequest("GET", path.Join("/", functionalPath, "logout"), nil)
		if err != nil {
			t.Fatal(err)
		}

		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			fmt.Println(recorder.Body)
			t.Errorf("Expected ok, got %v", recorder.Code)
		}

		returnedCookies := recorder.Result().Cookies()
		if len(returnedCookies) != 1 || returnedCookies[0].Name != sessionCookieName {
			t.Errorf("Expected a session cookie, but didn't get one")
		} else if returnedCookies[0].Value != "" {
			t.Errorf("Expected a blank session cookie, but it had a value.")
		} else if returnedCookies[0].MaxAge != -1 {
			t.Errorf("Expected a MaxAge of -1")
		}
	})

}
