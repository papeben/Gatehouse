package main

import (
	"bytes"
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

type formFields struct {
	field string
	value string
}

func init() {
	rand.Seed(time.Now().UnixNano())
	InitDatabase(1)
	LoadTemplates()
	LoadFuncionalURIs()
	initProxy()
}

func sendGetRequest(path string, withValidSession bool, withValidCriticalSession bool, withValidMFASession bool, emailVerified bool) (int, *bytes.Buffer) {
	var (
		userId string
	)
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return 0, nil
	}

	if withValidSession || withValidMFASession || withValidCriticalSession || emailVerified {
		userId = createDummyUser()
	}
	if withValidSession {
		sessionToken := createDummySession(userId)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken, SameSite: http.SameSiteStrictMode, Secure: false, Path: "/"})
	}
	if withValidCriticalSession {
		elevatedSessionToken := createDummyElevatedSession(userId)
		req.AddCookie(&http.Cookie{Name: criticalCookieName, Value: elevatedSessionToken, SameSite: http.SameSiteStrictMode, Secure: false, Path: "/"})
	}
	if withValidMFASession {
		mfaSessionToken := createDummyMFASession(userId)
		req.AddCookie(&http.Cookie{Name: mfaCookieName, Value: mfaSessionToken, SameSite: http.SameSiteStrictMode, Secure: false, Path: "/"})
	}
	if emailVerified {
		validateDummyEmail(userId)
	}

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(HandleMain)
	handler.ServeHTTP(recorder, req)
	return recorder.Code, recorder.Body
}

func sendPostRequest(path string, sessionToken string, elevatedToken string, MFAToken string, formValues []formFields) (int, *bytes.Buffer) {
	form := url.Values{}
	for _, v := range formValues {
		form.Add(v.field, v.value)
	}

	req, err := http.NewRequest("POST", path, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if sessionToken != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken, SameSite: http.SameSiteStrictMode, Secure: false, Path: "/"})
	}
	if elevatedToken != "" {
		req.AddCookie(&http.Cookie{Name: criticalCookieName, Value: elevatedToken, SameSite: http.SameSiteStrictMode, Secure: false, Path: "/"})
	}
	if MFAToken != "" {
		req.AddCookie(&http.Cookie{Name: mfaCookieName, Value: MFAToken, SameSite: http.SameSiteStrictMode, Secure: false, Path: "/"})
	}

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(HandleMain)
	handler.ServeHTTP(recorder, req)
	return recorder.Code, recorder.Body
}

func createDummyUser() string {
	userId := GenerateRandomString(8)
	username := GenerateRandomString(16)
	password := GenerateRandomString(16)
	email := GenerateRandomString(16) + "@testing.local"

	tempDb, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer tempDb.Close()

	_, err = tempDb.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id, username, email, password, username_changed) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP - INTERVAL 31 DAY)", tablePrefix), userId, username, email, HashPassword(password))
	if err != nil {
		panic(err)
	}

	return userId
}

func createDummySession(userId string) string {
	tempDb, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer tempDb.Close()

	token := GenerateRandomString(64)
	_, err = tempDb.Exec(fmt.Sprintf("INSERT INTO %s_sessions (session_token, user_id) VALUES (?, ?)", tablePrefix), token, userId)
	if err != nil {
		panic(err)
	}
	return token
}

func createDummyMFASession(userId string) string {
	tempDb, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer tempDb.Close()

	mfaToken := GenerateRandomNumbers(6)
	mfaSessionToken := GenerateRandomString(32)

	_, err = tempDb.Exec(fmt.Sprintf("INSERT INTO %s_mfa (mfa_session, type, user_id, token) VALUES (?, ?, ?, ?)", tablePrefix), mfaSessionToken, "totp", userId, mfaToken)
	if err != nil {
		panic(err)
	}
	return mfaSessionToken
}

func createDummyElevatedSession(userId string) string {
	tempDb, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer tempDb.Close()

	elevatedSessionToken := GenerateRandomString(64)
	_, err = tempDb.Exec(fmt.Sprintf("INSERT INTO %s_sessions (session_token, user_id, critical) VALUES (?, ?, 1)", tablePrefix), elevatedSessionToken, userId)
	if err != nil {
		panic(err)
	}
	return elevatedSessionToken
}

func validateDummyEmail(userId string) {
	tempDb, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer tempDb.Close()

	_, err = tempDb.Exec(fmt.Sprintf("UPDATE %s_accounts SET email_confirmed = 1 WHERE id = ?", tablePrefix), userId)
	if err != nil {
		panic(err)
	}
}

func TestRegistrationFlow(t *testing.T) {
	requireAuthentication = true
	requireEmailConfirm = true
	allowMobileMFA = true
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

	t.Run("Test new username", func(t *testing.T) {
		req, err := http.NewRequest("GET", path.Join("/"+functionalPath+"/usernametaken?u="+username), nil)
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

		returnedCookies := recorder.Result().Cookies()
		if len(returnedCookies) != 1 || returnedCookies[0].Name != sessionCookieName {
			fmt.Println(recorder.Body)
			t.Errorf("Expected a sesson cookie, but didn't get one")
		} else {
			sessionToken = returnedCookies[0].Value
		}
	})

	t.Run("Get confirmation page", func(t *testing.T) {
		req, err := http.NewRequest("GET", path.Join("/"+functionalPath+"/confirmemail"), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			fmt.Println(recorder.Body)
			t.Errorf("Expected %v, got %v", http.StatusOK, recorder.Code)
		}
	})

	t.Run("Get resend page", func(t *testing.T) {
		req, err := http.NewRequest("GET", path.Join("/"+functionalPath+"/resendconfirmation"), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			fmt.Println(recorder.Body)
			t.Errorf("Expected %v, got %v", http.StatusOK, recorder.Code)
		}
	})

	t.Run("Get resend page again", func(t *testing.T) {
		req, err := http.NewRequest("GET", path.Join("/"+functionalPath+"/resendconfirmation"), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusGone {
			fmt.Println(recorder.Body)
			t.Errorf("Expected %v, got %v", http.StatusBadRequest, recorder.Code)
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

		if recorder.Code != http.StatusGone {
			fmt.Println(recorder.Body)
			t.Errorf("Expected Gone, got %v", recorder.Code)
		}
	})

	t.Run("Test username is now unavailable", func(t *testing.T) {
		req, err := http.NewRequest("GET", path.Join("/"+functionalPath+"/usernametaken?u="+username), nil)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusBadRequest {
			fmt.Println(recorder.Body)
			t.Errorf("Expected %v, got %v", http.StatusBadRequest, recorder.Code)
		}
	})

	t.Run("Get login page", func(t *testing.T) {
		req, err := http.NewRequest("GET", path.Join("/"+functionalPath+"/login"), nil)
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

	t.Run("Get forgot password page", func(t *testing.T) {
		req, err := http.NewRequest("GET", path.Join("/"+functionalPath+"/forgot"), nil)
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

	t.Run("Send reset request", func(t *testing.T) {

		var mfaSecret string
		err = db.QueryRow(fmt.Sprintf("SELECT mfa_secret FROM %s_accounts INNER JOIN %s_sessions ON user_id = id WHERE session_token = ?", tablePrefix, tablePrefix), sessionToken).Scan(&mfaSecret)
		if err != nil {
			t.Fatal(err)
		}
		// Submit login
		form := url.Values{}
		form.Add("email", email)
		req, err := http.NewRequest("POST", path.Join("/", functionalPath, "submit", "resetrequest"), strings.NewReader(form.Encode()))
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
	})

	t.Run("Use reset link", func(t *testing.T) {
		var resetToken string
		err = db.QueryRow(fmt.Sprintf("SELECT reset_token FROM %s_accounts INNER JOIN %s_resets ON user_id = id WHERE email = ?", tablePrefix, tablePrefix), strings.ToLower(email)).Scan(&resetToken)
		if err != nil {
			t.Fatal(err)
		}

		req, err := http.NewRequest("GET", path.Join("/"+functionalPath+"/resetpassword?c="+resetToken), nil)
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

	t.Run("Submit invalid password reset", func(t *testing.T) {
		var resetToken string
		err = db.QueryRow(fmt.Sprintf("SELECT reset_token FROM %s_accounts INNER JOIN %s_resets ON user_id = id WHERE email = ?", tablePrefix, tablePrefix), strings.ToLower(email)).Scan(&resetToken)
		if err != nil {
			t.Fatal(err)
		}

		form := url.Values{}
		form.Add("password", password)
		form.Add("passwordConfirm", password+"mismatch")
		req, err := http.NewRequest("POST", path.Join("/", functionalPath, "submit", "reset?c="+resetToken), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusBadRequest {
			fmt.Println(recorder.Body)
			t.Errorf("Expected %v, got %v", http.StatusBadRequest, recorder.Code)
		}
	})

	t.Run("Submit invalid reset code", func(t *testing.T) {
		resetToken, err := GenerateResetToken()
		if err != nil {
			panic(err)
		}

		form := url.Values{}
		form.Add("password", password)
		form.Add("passwordConfirm", password)
		req, err := http.NewRequest("POST", path.Join("/", functionalPath, "submit", "reset?c="+resetToken), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusForbidden {
			fmt.Println(recorder.Body)
			t.Errorf("Expected %v, got %v", http.StatusForbidden, recorder.Code)
		}
	})

	t.Run("Submit password reset", func(t *testing.T) {
		var resetToken string
		err = db.QueryRow(fmt.Sprintf("SELECT reset_token FROM %s_accounts INNER JOIN %s_resets ON user_id = id WHERE email = ?", tablePrefix, tablePrefix), strings.ToLower(email)).Scan(&resetToken)
		if err != nil {
			t.Fatal(err)
		}

		form := url.Values{}
		form.Add("password", password)
		form.Add("passwordConfirm", password)
		req, err := http.NewRequest("POST", path.Join("/", functionalPath, "/submit", "reset?c="+resetToken), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(HandleMain)
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			fmt.Println(recorder.Body)
			t.Errorf("Expected %v, got %v", http.StatusOK, recorder.Code)
		}
	})

	t.Run("Sign out", func(t *testing.T) {

		req, err := http.NewRequest("GET", path.Join("/", functionalPath, "logout"), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})

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

func TestRegistrationPermutations(t *testing.T) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		t.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	emails := []struct {
		value   string
		isValid bool
	}{
		{"", false},                // empty string
		{"user@example.com", true}, // simple email
		// {"user-123@example.com", true},       // email with hyphen
		// {"user.123@example.com", true},       // email with period
		// {"user@subdomain.example.com", true}, // email with subdomain
		// {"user@.example.com", false},         // empty subdomain
		// {"user@example._com", false},         // underscore in TLD
		// {"user@.com", false},                 // empty subdomain and TLD
		// {"user@example.coffee.", false},      // trailing period in TLD
		// {"user@123.123.123.123", false},      // IP address instead of domain
		// {"user@example..com", false},         // double period in domain
		// {"user@-example.com", false},         // hyphen at start of domain
		// {"user@example.com.", false},         // trailing period in domain
		// {"user@example.com-", false},         // hyphen at end of domain
	}

	usernames := []struct {
		value   string
		isValid bool
	}{
		{"username123", true},
		// {"_user_123", true},
		// {"user.name", false},
		// {"user!@#", false},
		// {"username_with_a_very_long_name_that_is_more_than_50_characters_long", false},
		// {"漢字123_", false},
		// {"u͈̥̩̦̤̟̯̜̱̰̺̹͇s̛̈̉̾͑̽̓̂͊ͬ̈͆̑̈́͜e̛ͥ̅͆ͣ̄̆̒ͧͮ̄ͨ̌͝͠r͑ͥ̇ͨ̑͆̅͋̏̏ͤ̏̓̿͏̵n̓ͥͩ͆̋̈́̉ͯ͊̉ͥ̃ͨ̽͊͠a̵͑̔ͤ͆̑̏͂̏̏ͥ̏͗̈͌͏͏m̐͊ͦ̿ͤ̂̋ͧ̆̈́̉ͨͣ͗͆͘͞eͭͫ̒͛ͩ̆̿̈ͧ̽͒̾̄͌̈̚͟", false},
		// {"user🔑name", false},
	}

	passwords := []struct {
		value   string
		isValid bool
	}{
		{"Password123", true},
		// {"pa$$w0rd", false},
		// {"12345678", false},
		// {"LongPasswordWith123", true},
		// {"passwordwithnouppercaseornum", false},
		// {"🔑EmojiPassword123👍", true},
		// {"⚡️UnusualCharPassword123~`!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?¿¡", true},
		// {"ALLCAPSNOLOWERORNUMBER", false},
		// {"漢字123_", false},
		// {"u͈̥̩̦̤̟̯̜̱̰̺̹͇s̛̈̉̾͑̽̓̂͊ͬ̈͆̑̈́͜e̛ͥ̅͆ͣ̄̆̒ͧͮ̄ͨ̌͝͠r͑ͥ̇ͨ̑͆̅͋̏̏ͤ̏̓̿͏̵n̓ͥͩ͆̋̈́̉ͯ͊̉ͥ̃ͨ̽͊͠a̵͑̔ͤ͆̑̏͂̏̏ͥ̏͗̈͌͏͏m̐͊ͦ̿ͤ̂̋ͧ̆̈́̉ͨͣ͗͆͘͞eͭͫ̒͛ͩ̆̿̈ͧ̽͒̾̄͌̈̚͟", false},
		{"", false},
	}

	for _, email := range emails {
		for _, username := range usernames {
			for _, password := range passwords {
				t.Run(fmt.Sprintf("Registering '%s' '%s' '%s'", email.value, username.value, password.value), func(t *testing.T) {
					prefix := GenerateRandomString(4)
					expectedSuccess := true
					if !email.isValid || !username.isValid || !password.isValid {
						expectedSuccess = false
					}
					form := url.Values{}
					form.Add("newUsername", fmt.Sprintf("%s%s", prefix, username.value))
					form.Add("email", fmt.Sprintf("%s%s", prefix, email.value))
					form.Add("password", password.value)
					form.Add("passwordConfirm", password.value)
					req, err := http.NewRequest("POST", path.Join("/", functionalPath, "submit", "register"), strings.NewReader(form.Encode()))
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					if err != nil {
						t.Fatal(err)
					}

					recorder := httptest.NewRecorder()
					handler := http.HandlerFunc(HandleMain)
					handler.ServeHTTP(recorder, req)

					returnedCookies := recorder.Result().Cookies()
					if expectedSuccess {
						if recorder.Code != http.StatusSeeOther {
							fmt.Println(recorder.Body)
							t.Errorf("Expected redirect, got %v", recorder.Code)
						}
						if len(returnedCookies) != 1 || returnedCookies[0].Name != sessionCookieName {
							fmt.Println(recorder.Body)
							t.Errorf("Expected a sesson cookie, but didn't get one")
						}
					} else {
						if recorder.Code != http.StatusBadRequest {
							fmt.Println(recorder.Body)
							t.Errorf("Expected bad request, got %v", recorder.Code)
						}
						if len(returnedCookies) != 0 {
							fmt.Println(recorder.Body)
							t.Errorf("Expected no sesson cookie, but got one")
						}
					}
				})
			}
		}
	}
}

func TestPageRequests(t *testing.T) {
	var reqPermutations = []struct {
		path                string
		withSession         bool
		withCriticalSession bool
		withMFASession      bool
		emailVerified       bool
		expectedCode        int
	}{
		{"/", false, false, false, false, 303},
		{"/", true, false, false, false, 303},
		{"/", true, false, false, true, 200},
		{"/gatehouse/login", true, false, false, true, 303},
		{"/gatehouse/login", false, false, false, false, 200},
		{"/gatehouse/register", true, false, false, true, 200},
		{"/gatehouse/register", false, false, false, true, 200},
		{"/gatehouse/forgot", true, false, false, true, 200},
		{"/gatehouse/forgot", false, false, false, false, 200},
		{"/gatehouse/confirmemail", true, false, false, true, 200},
		{"/gatehouse/confirmemail", false, false, false, false, 200},
		{"/gatehouse/confirmcode", true, false, false, true, 410},
		{"/gatehouse/confirmcode", false, false, false, false, 410},
		{"/gatehouse/resetpassword", true, false, false, true, 410},
		{"/gatehouse/resetpassword", false, false, false, false, 410},
		{"/gatehouse/resendconfirmation", true, false, false, false, 200},
		{"/gatehouse/resendconfirmation", false, false, false, false, 303},
		{"/gatehouse/usernametaken?u=uhafiauywfgbiauwf", false, false, false, false, 200},
		{"/gatehouse/usernametaken?u=uhafiauywfgbiauwf", true, false, false, false, 200},
		{"/gatehouse/usernametaken", false, false, false, false, 400},
		{"/gatehouse/addmfa", true, false, false, true, 200},
		{"/gatehouse/addmfa", true, false, false, false, 200},
		{"/gatehouse/addmfa", false, false, false, false, 303},
		{"/gatehouse/removemfa", true, false, false, true, 303},
		{"/gatehouse/removemfa", true, false, false, false, 303},
		{"/gatehouse/removemfa", false, false, false, false, 303},
		{"/gatehouse/removemfa", true, true, false, false, 200},
		{"/gatehouse/elevate", false, false, false, false, 303},
		{"/gatehouse/elevate", true, false, false, true, 400},
		{"/gatehouse/elevate?t=removemfa", true, true, false, false, 200},
		{"/gatehouse/elevate?t=removemfa", true, false, false, true, 200},
		{"/gatehouse/elevate?t=removemfa", false, false, false, false, 303},
		{"/gatehouse/elevate?t=notarealfunc", true, false, false, true, 400},
		{"/gatehouse/manage", false, false, false, false, 303},
		{"/gatehouse/manage", true, false, false, false, 200},
		{"/gatehouse/manage", true, false, false, true, 200},
		{"/gatehouse/changeemail", false, false, false, false, 303},
		{"/gatehouse/changeemail", true, false, false, false, 303},
		{"/gatehouse/changeemail", true, true, false, false, 200},
		{"/gatehouse/changeusername", false, false, false, false, 303},
		{"/gatehouse/changeusername", true, false, false, true, 303},
		{"/gatehouse/changeusername", true, true, false, true, 200},
		{"/gatehouse/changeavatar", true, false, false, true, 200},
		{"/gatehouse/changeavatar", false, false, false, true, 303},
		{"/gatehouse/deleteaccount", false, false, false, false, 303},
		{"/gatehouse/deleteaccount", true, false, false, true, 303},
		{"/gatehouse/deleteaccount", true, true, false, true, 200},
		{"/gatehouse/recoverycode", false, false, false, false, 303},
		{"/gatehouse/recoverycode", true, false, false, true, 303},
		{"/gatehouse/recoverycode", true, false, true, true, 200},
		{"/gatehouse/revokesessions", false, false, false, false, 303},
		{"/gatehouse/revokesessions", true, false, false, true, 200},
		{"/gatehouse/logout", false, false, false, false, 410},
	}

	var responseCode int
	for _, p := range reqPermutations {
		t.Run(fmt.Sprintf("GET page %s", p.path), func(t *testing.T) {
			responseCode, _ = sendGetRequest(p.path, p.withSession, p.withCriticalSession, p.withMFASession, p.emailVerified)
			if responseCode != p.expectedCode {
				t.Errorf("Requesting path '%s' returned code %v when %v was expected. Session: %t, Critical: %t, MFA: %t, Email: %t", p.path, responseCode, p.expectedCode, p.withSession, p.withCriticalSession, p.withMFASession, p.emailVerified)
			}
		})
	}
}

func TestPageDatabaseFailure(t *testing.T) {
	var reqPermutations = []struct {
		path                string
		withSession         bool
		withCriticalSession bool
		withMFASession      bool
		emailVerified       bool
		expectedCode        int
	}{
		{"/", false, false, false, false, 303},
		{"/", true, false, false, false, 500},
		{"/gatehouse/login", true, false, false, true, 500},
		{"/gatehouse/login", false, false, false, false, 200},
		{"/gatehouse/register", true, false, false, true, 500},
		{"/gatehouse/register", false, false, false, true, 200},
		{"/gatehouse/forgot", true, false, false, true, 500},
		{"/gatehouse/forgot", false, false, false, false, 200},
		{"/gatehouse/confirmemail", true, false, false, true, 500},
		{"/gatehouse/confirmemail", false, false, false, false, 200},
		{"/gatehouse/confirmcode", true, false, false, true, 500},
		{"/gatehouse/confirmcode", false, false, false, false, 500},
		{"/gatehouse/resetpassword", true, false, false, true, 500},
		{"/gatehouse/resetpassword", false, false, false, false, 500},
		{"/gatehouse/resendconfirmation", true, false, false, false, 500},
		{"/gatehouse/resendconfirmation", false, false, false, false, 303},
		{"/gatehouse/usernametaken?u=uhafiauywfgbiauwf", false, false, false, false, 500},
		{"/gatehouse/usernametaken?u=uhafiauywfgbiauwf", true, false, false, false, 500},
		{"/gatehouse/usernametaken", false, false, false, false, 400},
		{"/gatehouse/addmfa", true, false, false, true, 500},
		{"/gatehouse/addmfa", true, false, false, false, 500},
		{"/gatehouse/addmfa", false, false, false, false, 303},
		{"/gatehouse/removemfa", true, false, false, true, 500},
		{"/gatehouse/removemfa", true, false, false, false, 500},
		{"/gatehouse/removemfa", false, false, false, false, 303},
		{"/gatehouse/removemfa", true, true, false, false, 500},
		{"/gatehouse/elevate", false, false, false, false, 303},
		{"/gatehouse/elevate", true, false, false, true, 500},
		{"/gatehouse/elevate?t=removemfa", true, true, false, false, 500},
		{"/gatehouse/elevate?t=removemfa", true, false, false, true, 500},
		{"/gatehouse/elevate?t=removemfa", false, false, false, false, 303},
		{"/gatehouse/elevate?t=notarealfunc", true, false, false, true, 500},
		{"/gatehouse/manage", false, false, false, false, 303},
		{"/gatehouse/manage", true, false, false, false, 500},
		{"/gatehouse/manage", true, false, false, true, 500},
		{"/gatehouse/changeemail", false, false, false, false, 303},
		{"/gatehouse/changeemail", true, false, false, false, 500},
		{"/gatehouse/changeemail", true, true, false, false, 500},
		{"/gatehouse/changeusername", false, false, false, false, 303},
		{"/gatehouse/changeusername", true, false, false, true, 500},
		{"/gatehouse/changeusername", true, true, false, true, 500},
		{"/gatehouse/changeavatar", true, false, false, true, 500},
		{"/gatehouse/deleteaccount", false, false, false, false, 303},
		{"/gatehouse/deleteaccount", true, false, false, true, 500},
		{"/gatehouse/deleteaccount", true, true, false, true, 500},
		{"/gatehouse/recoverycode", false, false, false, false, 303},
		{"/gatehouse/recoverycode", true, false, false, true, 500},
		{"/gatehouse/recoverycode", true, false, true, true, 500},
		{"/gatehouse/revokesessions", false, false, false, false, 303},
		{"/gatehouse/revokesessions", true, false, false, true, 500},
		{"/gatehouse/logout", true, false, false, true, 500},
	}

	db.Close()

	var responseCode int
	for _, p := range reqPermutations {
		t.Run(fmt.Sprintf("GET page %s", p.path), func(t *testing.T) {
			responseCode, _ = sendGetRequest(p.path, p.withSession, p.withCriticalSession, p.withMFASession, p.emailVerified)
			if responseCode != p.expectedCode {
				t.Errorf("Requesting path '%s' returned code %v when %v was expected. Session: %t, Critical: %t, MFA: %t, Email: %t", p.path, responseCode, p.expectedCode, p.withSession, p.withCriticalSession, p.withMFASession, p.emailVerified)
			}
		})
	}

	var err error
	db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}

}

func TestDisabledFeatureRequests(t *testing.T) {
	var reqPermutations = []struct {
		path                string
		withSession         bool
		withCriticalSession bool
		withMFASession      bool
		emailVerified       bool
		expectedCode        int
	}{
		{"/gatehouse/register", true, false, false, true, 410},
		{"/gatehouse/forgot", true, false, false, true, 410},
		{"/gatehouse/resetpassword", true, false, false, true, 410},
		{"/gatehouse/addmfa", true, false, false, true, 410},
		{"/gatehouse/removemfa", true, false, false, true, 410},
		{"/gatehouse/changeemail", false, false, false, false, 410},
		{"/gatehouse/changeusername", false, false, false, false, 410},
		{"/gatehouse/changeavatar", false, false, false, false, 410},
		{"/gatehouse/deleteaccount", false, false, false, false, 410},
		{"/gatehouse/recoverycode", false, false, false, false, 410},
		{"/gatehouse/revokesessions", false, false, false, false, 410},
	}

	allowRegistration = false
	allowUsernameLogin = false
	allowPasswordReset = false
	allowMobileMFA = false
	allowUsernameChange = false
	allowEmailChange = false
	allowDeleteAccount = false
	allowSessionRevoke = false
	allowAvatarChange = false

	var responseCode int
	for _, p := range reqPermutations {
		t.Run(fmt.Sprintf("GET page %s", p.path), func(t *testing.T) {
			responseCode, _ = sendGetRequest(p.path, p.withSession, p.withCriticalSession, p.withMFASession, p.emailVerified)
			if responseCode != p.expectedCode {
				t.Errorf("Requesting path '%s' returned code %v when %v was expected. Session: %t, Critical: %t, MFA: %t, Email: %t", p.path, responseCode, p.expectedCode, p.withSession, p.withCriticalSession, p.withMFASession, p.emailVerified)
			}
		})
	}

	allowRegistration = envWithDefaultBool("ALLOW_REGISTRATION", true)
	allowUsernameLogin = envWithDefaultBool("ALLOW_USERNAME_LOGIN", true)
	allowPasswordReset = envWithDefaultBool("ALLOW_PASSWORD_RESET", true)
	allowMobileMFA = envWithDefaultBool("ALLOW_MOBILE_MFA", true)
	allowUsernameChange = envWithDefaultBool("ALLOW_USERNAME_CHANGE", true)
	allowEmailChange = envWithDefaultBool("ALLOW_EMAIL_CHANGE", true)
	allowDeleteAccount = envWithDefaultBool("ALLOW_DELETE_ACCOUNT", true)
	allowSessionRevoke = envWithDefaultBool("ALLOW_SESSION_REVOKE", true)
	allowAvatarChange = envWithDefaultBool("ALLOW_AVATAR_CHANGE", true)
}

func TestPostRequests(t *testing.T) {

	userId := GenerateRandomString(8)
	username := GenerateRandomString(16)
	password := "ThisIsAQualityPassword123"
	email := GenerateRandomString(16) + "@testing.local"
	sessionToken := createDummySession(userId)
	mfaSession := createDummyMFASession(userId)
	elevatedSession := createDummyElevatedSession(userId)
	validateDummyEmail(userId)

	_, err := db.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id, username, email, password) VALUES (?, ?, ?, ?)", tablePrefix), userId, username, email, HashPassword(password))
	if err != nil {
		panic(err)
	}

	deletedUserId := GenerateRandomString(8)
	deletedUsername := GenerateRandomString(16)
	deletedPassword := "ThisIsAQualityPassword123"
	deletedEmail := GenerateRandomString(16) + "@testing.local"
	deletedSessionToken := createDummySession(deletedUserId)
	deletedElevatedSession := createDummyElevatedSession(deletedUserId)
	validateDummyEmail(deletedUserId)

	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id, username, email, password) VALUES (?, ?, ?, ?)", tablePrefix), deletedUserId, deletedUsername, deletedEmail, HashPassword(deletedPassword))
	if err != nil {
		panic(err)
	}

	var reqPermutations = []struct {
		path          string
		sessionToken  string
		elevatedToken string
		MFAToken      string
		expectedCode  int
		formValues    []formFields
	}{
		{"/gatehouse/submit/login", "", "", "", 303, []formFields{{"username", username}, {"password", password}}},
		{"/gatehouse/submit/login", "", "", "", 400, []formFields{{"username", ""}, {"password", password}}},
		{"/gatehouse/submit/login", "", "", "", 400, []formFields{{"username", username}, {"password", ""}}},
		{"/gatehouse/submit/login", "", "", "", 303, []formFields{{"username", username}, {"password", "NotCorrectPW"}}},
		{"/gatehouse/submit/login", "", "", "", 303, []formFields{{"username", username}, {"password", "NotCorrectPW"}}},
		{"/gatehouse/submit/register", "", "", "", 400, []formFields{{"newUsername", GenerateRandomString(8)}, {"password", ""}, {"passwordConfirm", ""}, {"email", GenerateRandomString(16) + "@testing.local"}}},
		{"/gatehouse/submit/register", "", "", "", 400, []formFields{{"newUsername", GenerateRandomString(8)}, {"password", password}, {"passwordConfirm", "NotMatching"}, {"email", GenerateRandomString(16) + "@testing.local"}}},
		{"/gatehouse/submit/register", "", "", "", 400, []formFields{{"newUsername", GenerateRandomString(8)}, {"password", password}, {"passwordConfirm", password}, {"email", GenerateRandomString(16) + "@invalid"}}},
		{"/gatehouse/submit/register", "", "", "", 303, []formFields{{"newUsername", GenerateRandomString(8)}, {"password", password}, {"passwordConfirm", password}, {"email", GenerateRandomString(16) + "@testing.local"}}},
		{"/gatehouse/submit/mfa", "", "", mfaSession, 303, []formFields{{"token", "123456"}}},
		{"/gatehouse/submit/validatemfa", sessionToken, "", "", 400, []formFields{{"otp", "123456"}}},
		{"/gatehouse/submit/elevate?t=changeusername", sessionToken, "", "", 303, []formFields{{"password", password}}},
		{"/gatehouse/submit/elevate?t=changeusername", sessionToken, "", "", 303, []formFields{{"password", password}}},
		{"/gatehouse/submit/removemfa", sessionToken, elevatedSession, "", 400, []formFields{{"password", password}}},
		{"/gatehouse/submit/changeemail", sessionToken, elevatedSession, "", 200, []formFields{{"newemail", GenerateRandomString(16) + "@testing.local"}}},
		{"/gatehouse/submit/changeusername", sessionToken, elevatedSession, "", 400, []formFields{{"newUsername", "invalid%username"}}},
		{"/gatehouse/submit/changeusername", sessionToken, elevatedSession, "", 400, []formFields{{"newUsername", GenerateRandomString(8)}}},
		{"/gatehouse/submit/recoverycode", "", "", mfaSession, 303, []formFields{{"token", "123456"}}},
		{"/gatehouse/submit/revokesessions", sessionToken, elevatedSession, "", 200, []formFields{{"token", "123456"}}},
		{"/gatehouse/submit/deleteaccount", deletedSessionToken, deletedElevatedSession, "", 200, []formFields{}},
	}

	var responseCode int
	for _, p := range reqPermutations {
		t.Run(fmt.Sprintf("POST page %s", p.path), func(t *testing.T) {
			responseCode, _ = sendPostRequest(p.path, p.sessionToken, p.elevatedToken, p.MFAToken, p.formValues)
			if responseCode != p.expectedCode {
				t.Errorf("Requesting path '%s' returned code %v when %v was expected.", p.path, responseCode, p.expectedCode)
			}
		})
	}
}

func TestPostDatabaseFailure(t *testing.T) {

	userId := GenerateRandomString(8)
	username := GenerateRandomString(16)
	password := "ThisIsAQualityPassword123"
	email := GenerateRandomString(16) + "@testing.local"
	sessionToken := createDummySession(userId)
	mfaSession := createDummyMFASession(userId)
	elevatedSession := createDummyElevatedSession(userId)
	validateDummyEmail(userId)

	_, err := db.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id, username, email, password) VALUES (?, ?, ?, ?)", tablePrefix), userId, username, email, HashPassword(password))
	if err != nil {
		panic(err)
	}

	db.Close()

	var reqPermutations = []struct {
		path          string
		sessionToken  string
		elevatedToken string
		MFAToken      string
		expectedCode  int
		formValues    []formFields
	}{
		{"/gatehouse/submit/login", sessionToken, "", "", 500, []formFields{{"username", username}, {"password", password}}},
		{"/gatehouse/submit/register", sessionToken, "", "", 500, []formFields{{"newUsername", GenerateRandomString(8)}, {"password", password}, {"passwordConfirm", password}, {"email", GenerateRandomString(16) + "@testing.local"}}},
		{"/gatehouse/submit/mfa", sessionToken, "", mfaSession, 500, []formFields{{"token", "123456"}}},
		{"/gatehouse/submit/validatemfa", sessionToken, "", "", 500, []formFields{{"otp", "123456"}}},
		{"/gatehouse/submit/elevate?t=changeusername", sessionToken, "", "", 500, []formFields{{"password", password}}},
		{"/gatehouse/submit/elevate?t=changeusername", sessionToken, "", "", 500, []formFields{{"password", password}}},
		{"/gatehouse/submit/removemfa", sessionToken, elevatedSession, "", 500, []formFields{{"password", password}}},
		{"/gatehouse/submit/changeemail", sessionToken, elevatedSession, "", 500, []formFields{{"newemail", GenerateRandomString(16) + "@testing.local"}}},
		{"/gatehouse/submit/changeusername", sessionToken, elevatedSession, "", 500, []formFields{{"newUsername", GenerateRandomString(8)}}},
		{"/gatehouse/submit/recoverycode", "", "", mfaSession, 500, []formFields{{"token", "123456"}}},
		{"/gatehouse/submit/revokesessions", sessionToken, elevatedSession, "", 500, []formFields{{"token", "123456"}}},
		{"/gatehouse/submit/deleteaccount", sessionToken, elevatedSession, "", 500, []formFields{}},
	}

	var responseCode int
	for _, p := range reqPermutations {
		t.Run(fmt.Sprintf("POST page %s", p.path), func(t *testing.T) {
			responseCode, _ = sendPostRequest(p.path, p.sessionToken, p.elevatedToken, p.MFAToken, p.formValues)
			if responseCode != p.expectedCode {
				t.Errorf("Requesting path '%s' returned code %v when %v was expected.", p.path, responseCode, p.expectedCode)
			}
		})
	}

	db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
}

func TestPostDisabledFeatures(t *testing.T) {

	userId := GenerateRandomString(8)
	username := GenerateRandomString(16)
	password := "ThisIsAQualityPassword123"
	email := GenerateRandomString(16) + "@testing.local"
	sessionToken := createDummySession(userId)
	mfaSession := createDummyMFASession(userId)
	elevatedSession := createDummyElevatedSession(userId)
	validateDummyEmail(userId)

	allowRegistration = false
	allowUsernameLogin = false
	allowPasswordReset = false
	allowMobileMFA = false
	allowUsernameChange = false
	allowEmailChange = false
	allowDeleteAccount = false
	allowSessionRevoke = false

	_, err := db.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id, username, email, password) VALUES (?, ?, ?, ?)", tablePrefix), userId, username, email, HashPassword(password))
	if err != nil {
		panic(err)
	}

	var reqPermutations = []struct {
		path          string
		sessionToken  string
		elevatedToken string
		MFAToken      string
		expectedCode  int
		formValues    []formFields
	}{
		{"/gatehouse/submit/login", "", "", "", 410, []formFields{{"username", username}, {"password", password}}},
		{"/gatehouse/submit/register", "", "", "", 410, []formFields{{"newUsername", GenerateRandomString(8)}, {"password", password}, {"passwordConfirm", password}, {"email", GenerateRandomString(16) + "@testing.local"}}},
		{"/gatehouse/submit/mfa", "", "", mfaSession, 303, []formFields{{"token", "123456"}}},
		{"/gatehouse/submit/validatemfa", sessionToken, "", "", 410, []formFields{{"otp", "123456"}}},
		{"/gatehouse/submit/changeemail", sessionToken, elevatedSession, "", 410, []formFields{{"newemail", GenerateRandomString(16) + "@testing.local"}}},
		{"/gatehouse/submit/changeusername", sessionToken, elevatedSession, "", 410, []formFields{{"newUsername", GenerateRandomString(8)}}},
		{"/gatehouse/submit/recoverycode", "", "", mfaSession, 410, []formFields{{"token", "123456"}}},
		{"/gatehouse/submit/revokesessions", sessionToken, elevatedSession, "", 410, []formFields{{"token", "123456"}}},
		{"/gatehouse/submit/deleteaccount", sessionToken, elevatedSession, "", 410, []formFields{}},
		{"/gatehouse/submit/resetrequest", "", "", "", 410, []formFields{{"email", email}}},
		{"/gatehouse/submit/reset", "", "", "", 410, []formFields{{"password", password}, {"password", password}}},
	}

	var responseCode int
	for _, p := range reqPermutations {
		t.Run(fmt.Sprintf("POST page %s", p.path), func(t *testing.T) {
			responseCode, _ = sendPostRequest(p.path, p.sessionToken, p.elevatedToken, p.MFAToken, p.formValues)
			if responseCode != p.expectedCode {
				t.Errorf("Requesting path '%s' returned code %v when %v was expected.", p.path, responseCode, p.expectedCode)
			}
		})
	}

	allowRegistration = envWithDefaultBool("ALLOW_REGISTRATION", true)
	allowUsernameLogin = envWithDefaultBool("ALLOW_USERNAME_LOGIN", true)
	allowPasswordReset = envWithDefaultBool("ALLOW_PASSWORD_RESET", true)
	allowMobileMFA = envWithDefaultBool("ALLOW_MOBILE_MFA", true)
	allowUsernameChange = envWithDefaultBool("ALLOW_USERNAME_CHANGE", true)
	allowEmailChange = envWithDefaultBool("ALLOW_EMAIL_CHANGE", true)
	allowDeleteAccount = envWithDefaultBool("ALLOW_DELETE_ACCOUNT", true)
	allowSessionRevoke = envWithDefaultBool("ALLOW_SESSION_REVOKE", true)
}
