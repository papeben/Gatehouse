package main

import (
	"database/sql"
	"fmt"
	"math/rand"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func init() {
	rand.Seed(time.Now().UnixNano())
	InitDatabase(1)
}

func TestIsValidSession(t *testing.T) {
	// Set up the database connection
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		t.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	// Test with a valid session token
	sessionToken, err := GenerateSessionToken()
	if err != nil {
		panic(err)
	}
	userId, err := GenerateUserID()
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id) VALUES (?)", tablePrefix), userId)
	if err != nil {
		t.Fatalf("Error inserting user into database: %v", err)
	}
	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_sessions (session_token, user_id) VALUES (?, ?)", tablePrefix), sessionToken, userId)
	if err != nil {
		t.Fatalf("Error inserting session token into database: %v", err)
	}
	valid, _ := IsValidSession(sessionToken)
	if !valid {
		t.Errorf("Expected IsValidSession to return true for valid session token %s, but it returned false", sessionToken)
	}

	// Test with an invalid session token
	sessionToken, err = GenerateSessionToken()
	if err != nil {
		panic(err)
	}
	valid, _ = IsValidSession(sessionToken)
	if valid {
		t.Errorf("Expected IsValidSession to return false for invalid session token %s, but it returned true", sessionToken)
	}
}

func TestPendingEmailApproval(t *testing.T) {
	// Set up the database connection
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		t.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	// Insert a test user with email unconfirmed
	email := "test@example.com"
	userId, err := GenerateUserID()
	if err != nil {
		panic(err)
	}
	session, err := GenerateSessionToken()
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id, email, email_confirmed) VALUES (?, ?, false)", tablePrefix), userId, email)
	if err != nil {
		t.Fatalf("Error inserting test user into database: %v", err)
	}

	// Insert a session for the test user
	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_sessions (user_id, session_token) VALUES (?, ?)", tablePrefix), userId, session)
	if err != nil {
		t.Fatalf("Error inserting session for test user: %v", err)
	}

	// Check that PendingEmailApproval returns true for the test user's session
	pending, _ := PendingEmailApproval(session)
	if !pending {
		t.Errorf("Expected PendingEmailApproval to return true for session with unconfirmed email, but it returned false")
	}

	// Confirm the test user's email
	_, err = db.Exec(fmt.Sprintf("UPDATE %s_accounts SET email_confirmed = true WHERE email = ?", tablePrefix), email)
	if err != nil {
		t.Fatalf("Error confirming test user's email: %v", err)
	}

	// Check that PendingEmailApproval returns false for the test user's session after email confirmation
	pending, _ = PendingEmailApproval(session)
	if pending {
		t.Errorf("Expected PendingEmailApproval to return false for session with confirmed email, but it returned true")
	}
}

func TestConfirmEmailCode(t *testing.T) {
	// open database connection
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		t.Fatalf("Error opening database connection: %s", err)
	}
	defer db.Close()

	// insert test data
	code, err := GenerateEmailConfirmationToken()
	if err != nil {
		panic(err)
	}
	userId, err := GenerateUserID()
	if err != nil {
		panic(err)
	}
	email := "testing@example.local"

	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id, email, email_confirmed) VALUES (?, ?, false)", tablePrefix), userId, email)
	if err != nil {
		t.Fatalf("Error inserting test user into database: %v", err)
	}

	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_confirmations (confirmation_token, user_id) VALUES (?, ?)", tablePrefix), code, userId)
	if err != nil {
		t.Fatalf("Error inserting test data: %s", err)
	}

	// call the function
	result, _ := ConfirmEmailCode(code)

	// check the result
	if !result {
		t.Error("Expected ConfirmEmailCode to return true, but it returned false")
	}

	// call the function again
	result, _ = ConfirmEmailCode(code)

	// check the result
	if result {
		t.Error("Expected ConfirmEmailCode to return false, but it returned true")
	}

	// check the database state after the function call
	var isTokenUsed bool
	err = db.QueryRow(fmt.Sprintf("SELECT used FROM %s_confirmations WHERE confirmation_token = ?", tablePrefix), code).Scan(&isTokenUsed)
	if err != nil {
		t.Fatalf("Error checking database state: %s", err)
	}
	if !isTokenUsed {
		t.Error("Expected confirmation token to be marked as used, but it was not")
	}
}

func TestSendEmailConfirmationCode(t *testing.T) {
	LoadTemplates()
	t.Run("should send only one confirmation email to test@testing.local", func(t *testing.T) {
		userId, err := GenerateUserID()
		if err != nil {
			panic(err)
		}
		SendEmailConfirmationCode(userId, "test@testing.local", "test")
	})
}

func TestResetPasswordRequest(t *testing.T) {
	LoadTemplates()
	t.Run("Sending email to registered user test@testing.local", func(t *testing.T) {
		// Set up the database connection
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			t.Fatalf("Error connecting to database: %v", err)
		}
		defer db.Close()

		// Insert a test user with email unconfirmed
		email := "test@example.local"
		username := "testingreset"
		userId, err := GenerateUserID()
		if err != nil {
			panic(err)
		}
		_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id, username, email) VALUES (?, ?, ?)", tablePrefix), userId, username, email)
		if err != nil {
			t.Fatalf("Error inserting test user into database: %v", err)
		}
		result, _ := ResetPasswordRequest(email)
		if !result {
			t.Error("Reset email failed to send.")
		}
	})

	t.Run("don't send main to unregistered user unregistered@testing.local", func(t *testing.T) {
		email := "unregistered@example.local"
		result, _ := ResetPasswordRequest(email)
		if result {
			t.Error("Shouldn't have sent to unregistered email address.")
		}
	})
}

func TestIsValidResetCode(t *testing.T) {
	// open database connection
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		t.Fatalf("Error opening database connection: %s", err)
	}
	defer db.Close()

	// insert test data
	code, err := GenerateResetToken()
	if err != nil {
		panic(err)
	}
	userID, err := GenerateUserID()
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_resets (reset_token, user_id, used) VALUES (?, ?, ?)", tablePrefix), code, userID, false)
	if err != nil {
		t.Fatalf("Error inserting test data: %s", err)
	}

	// call the function with a valid code
	result, _ := IsValidResetCode(code)

	// check the result
	if !result {
		t.Error("Expected IsValidResetCode to return true, but it returned false")
	}

	// call the function with an invalid code
	invalidCode, err := GenerateResetToken()
	if err != nil {
		panic(err)
	}
	result, _ = IsValidResetCode(invalidCode)

	// check the result
	if result {
		t.Error("Expected IsValidResetCode to return false, but it returned true")
	}
}

func TestUsernamePermutations(t *testing.T) {
	tests := []struct {
		username string
		expected bool
	}{
		{"", false},
		{"123456789012345678901234567890123", false},
		{"abc-def_123", true},
		{"abc😊def", false},
		{"abcédef", false},
		{"abcdefghijklmno-pqrst_0123456789", true},
		{"abcdefghijklmnopqrstuvwxyz_012345", false},
		{"Jämjö123XYZ", false},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Username '%s'", test.username), func(t *testing.T) {

			actual, _ := IsValidNewUsername(test.username)
			if actual != test.expected {
				t.Errorf("Expected IsValidNewUsername('%s') to be %v, but got %v", test.username, test.expected, actual)
			}
		})
	}
}

func TestEmailPermutations(t *testing.T) {
	tests := []struct {
		email    string
		expected bool
	}{
		{"", false},                          // empty string
		{"user+123@example.com", true},       // email with plus sign
		{"us_er.123@example.com", true},      // email with period
		{"user@subdomain.example.com", true}, // email with subdomain
		{"user@example..com", false},         // double period in domain
		{"user@.example.com", false},         // empty subdomain
		{"user@example-.com", false},         // hyphen at end of domain
		{"user@example._com", false},         // underscore in TLD
		{"user@.com", false},                 // empty subdomain and TLD
		{"user@.example.", false},            // empty TLD
		{"user@example.coffee.", false},      // trailing period in TLD
		{"user@123.123.123.123", false},      // IP address instead of domain
		{"user@example..com", false},         // double period in domain
		{"user@.example.com", false},         // empty subdomain
		{"user@-example.com", false},         // hyphen at start of domain
		{"user@example.com.", false},         // trailing period in domain
		{"user@example..com", false},         // double period in domain
		{"user@example.com-", false},         // hyphen at end of domain
		{"existinguser@example.com", false},  // hyphen at end of domain
	}

	// open database connection
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		t.Fatalf("Error opening database connection: %s", err)
	}

	// Insert test user
	userId, err := GenerateUserID()
	if err != nil {
		panic(err)
	}
	email := "existinguser@example.com"
	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_accounts (id, email) VALUES (?, ?)", tablePrefix), userId, email)
	if err != nil {
		t.Fatalf("Error inserting test user into database: %v", err)
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Email '%s'", test.email), func(t *testing.T) {

			actual, _ := IsValidNewEmail(test.email)
			if actual != test.expected {
				t.Errorf("Expected IsValidNewEmail('%s') to be %v, but got %v", test.email, test.expected, actual)
			}
		})
	}
}

func TestIsValidPassword(t *testing.T) {
	// test cases
	testCases := []struct {
		password string
		expected bool
	}{
		{"abc123XYZ", true},   // valid password
		{"12345678", false},   // too short
		{"abcdefgh", false},   // no numbers
		{"ABCDEFGH", false},   // no lowercase letters
		{"123abcde", false},   // no uppercase letters
		{"12abcde", false},    // no uppercase letters and too short
		{"!@#$%^&*", false},   // no letters
		{"abcDEFGH1", true},   // valid password
		{"测试abc123XYZ", true}, // valid password with Chinese characters
		{"abc🔑123XYZ", true},  // valid password with emoji
		{"Jämjö123XYZ", true}, // valid password with Swedish characters
	}

	// iterate over test cases
	for _, testCase := range testCases {
		// call the function with the password
		result := IsValidPassword(testCase.password)

		// check the result
		if result != testCase.expected {
			t.Errorf("For password '%s', expected %t but got %t", testCase.password, testCase.expected, result)
		}
	}
}
