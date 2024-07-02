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

func init() {
	rand.Seed(time.Now().UnixNano())
	InitDatabase(1)
	LoadTemplates()
	LoadFuncionalURIs()
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

	fmt.Println(req.Cookies())
	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(HandleMain)
	handler.ServeHTTP(recorder, req)
	return recorder.Code, recorder.Body
}

func createDummyUser() string {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	userId, _ := GenerateUserID()
	username := GenerateRandomString(16)
	password := GenerateRandomString(16)
	email := GenerateRandomString(16) + "@testing.local"

	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id, username, email, password) VALUES (?, ?, ?, ?)", tablePrefix), userId, username, email, HashPassword(password))
	if err != nil {
		panic(err)
	}

	return userId
}

func createDummySession(userId string) string {
	token, _ := GenerateSessionToken()
	_, err := db.Exec(fmt.Sprintf("INSERT INTO %s_sessions (session_token, user_id) VALUES (?, ?)", tablePrefix), token, userId)
	if err != nil {
		panic(err)
	}
	return token
}

func createDummyMFASession(userId string) string {
	mfaToken := GenerateRandomNumbers(6)
	mfaSessionToken, err := GenerateMfaSessionToken()
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_mfa (mfa_session, type, user_id, token) VALUES (?, ?, ?, ?)", tablePrefix), mfaSessionToken, "totp", userId, mfaToken)
	if err != nil {
		panic(err)
	}
	return mfaSessionToken
}

func createDummyElevatedSession(userId string) string {
	elevatedSessionToken, _ := GenerateSessionToken()
	_, err := db.Exec(fmt.Sprintf("INSERT INTO %s_sessions (session_token, user_id, critical) VALUES (?, ?, 1)", tablePrefix), elevatedSessionToken, userId)
	if err != nil {
		panic(err)
	}
	return elevatedSessionToken
}

func validateDummyEmail(userId string) {
	_, err := db.Exec(fmt.Sprintf("UPDATE %s_accounts SET email_confirmed = 1 WHERE id = ?", tablePrefix), userId)
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

		if recorder.Code != http.StatusBadRequest {
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

		if recorder.Code != http.StatusBadRequest {
			fmt.Println(recorder.Body)
			t.Errorf("Expected OK, got %v", recorder.Code)
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
		{"/gatehouse/login", true, false, false, true, 200},
		{"/gatehouse/login", false, false, false, false, 200},
		{"/gatehouse/register", true, false, false, true, 200},
		{"/gatehouse/register", false, false, false, true, 200},
		{"/gatehouse/forgot", true, false, false, true, 200},
		{"/gatehouse/forgot", false, false, false, false, 200},
		{"/gatehouse/confirmemail", true, false, false, true, 200},
		{"/gatehouse/confirmemail", false, false, false, false, 200},
		{"/gatehouse/confirmcode", true, false, false, true, 400},
		{"/gatehouse/confirmcode", false, false, false, false, 400},
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
		{"/gatehouse/deleteaccount", false, false, false, false, 303},
		{"/gatehouse/deleteaccount", true, false, false, true, 303},
		{"/gatehouse/deleteaccount", true, true, false, true, 200},
		{"/gatehouse/recoverycode", false, false, false, false, 303},
		{"/gatehouse/recoverycode", true, false, false, true, 303},
		{"/gatehouse/recoverycode", true, false, true, true, 200},
		{"/gatehouse/revokesessions", false, false, false, false, 303},
		{"/gatehouse/revokesessions", true, false, false, true, 200},
	}

	var responseCode int
	for _, p := range reqPermutations {
		t.Run(fmt.Sprintf("Submit password reset %s", p.path), func(t *testing.T) {
			responseCode, _ = sendGetRequest(p.path, p.withSession, p.withCriticalSession, p.withMFASession, p.emailVerified)
			if responseCode != p.expectedCode {
				t.Errorf("Requesting path '%s' returned code %v when %v was expected. Session: %t, Critical: %t, MFA: %t, Email: %t", p.path, responseCode, p.expectedCode, p.withSession, p.withCriticalSession, p.withMFASession, p.emailVerified)
			}
		})
	}
}
