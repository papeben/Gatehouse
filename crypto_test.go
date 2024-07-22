package main

import (
	"database/sql"
	"encoding/base32"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHashPassword(t *testing.T) {
	password := "password123"
	hashed := HashPassword(password)
	if hashed == password {
		t.Errorf("HashPassword(%v) = %v; expected different hash", password, hashed)
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "password123"
	hashed := HashPassword(password)
	if !CheckPasswordHash(password, hashed) {
		t.Errorf("CheckPasswordHash(%v, %v) = false; expected true", password, hashed)
	}
}

func TestGenerateRandomString(t *testing.T) {
	length := 10
	str := GenerateRandomString(length)
	if len(str) != length {
		t.Errorf("GenerateRandomString(%v) returned a string with length %v; expected length %v", length, len(str), length)
	}
}

func TestGenerateRandomNumbers(t *testing.T) {
	length := 10
	result := GenerateRandomNumbers(length)

	// Check the length of the generated string
	if len(result) != length {
		t.Errorf("Generated string has incorrect length. Expected %d, got %d", length, len(result))
	}

	// Check that the generated string only contains digits
	for _, char := range result {
		if char < '0' || char > '9' {
			t.Errorf("Generated string contains invalid character %c", char)
		}
	}
}

func TestGenerateOTPSecret(t *testing.T) {
	secret := GenerateOTPSecret()

	_, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Errorf("GenerateOTPSecret() produced an invalid secret key: %v", err)
	}

	if len(secret) != 16 {
		t.Errorf("GenerateOTPSecret() produced a secret key with length %d, expected 16", len(secret))
	}
}

func TestGenerateOTP(t *testing.T) {
	secret := GenerateOTPSecret()

	// Generate an OTP for the current time step
	otp, err := GenerateOTP(secret, 1)
	if err != nil {
		t.Errorf("GenerateOTP() returned an error: %v", err)
	}

	if len(otp) != 6 {
		t.Errorf("GenerateOTP() produced an OTP with length %d, expected 6", len(otp))
	}

	// Wait for one time step
	time.Sleep(1 * time.Second)

	otp2, err := GenerateOTP(secret, 1)
	if err != nil {
		t.Errorf("GenerateOTP() returned an error: %v", err)
	}

	if otp == otp2 {
		t.Errorf("GenerateOTP() produced the same OTP for two different time steps")
	}
}

func TestGenerateUserID(t *testing.T) {
	// Set up the database connection
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		t.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	// Test generating a new user ID
	newID, err := GenerateUserID()
	if err != nil {
		panic(err)
	}
	if len(newID) != 8 {
		t.Errorf("Generated ID has incorrect length. Expected 8, got %d", len(newID))
	}
	var userID string
	err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_accounts WHERE id = ?", tablePrefix), strings.ToLower(newID)).Scan(&userID)
	if err != nil {
		if err != sql.ErrNoRows {
			t.Errorf("Error querying database: %v", err)
		}
	} else {
		t.Errorf("Generated ID already exists in database: %s", userID)
	}
}

func TestGenerateSessionToken(t *testing.T) {
	t.Run("should generate unique session token", func(t *testing.T) {
		token, err := GenerateSessionToken()
		if err != nil {
			panic(err)
		}
		if token == "" {
			t.Errorf("expected non-empty session token, but got %q", token)
		}

		if len(token) != 64 {
			t.Errorf("expected 64 character session token, but got %q", token)
		}

	})
}

func TestGenerateResetToken(t *testing.T) {
	t.Run("should generate unique reset token", func(t *testing.T) {
		token, err := GenerateResetToken()
		if err != nil {
			panic(err)
		}
		if token == "" {
			t.Errorf("expected non-empty token, but got %q", token)
		}

		if len(token) != 32 {
			t.Errorf("expected 32 character token, but got %q", token)
		}

	})
}

func TestGenerateMfaSessionToken(t *testing.T) {
	t.Run("should generate unique sesson token", func(t *testing.T) {
		token, err := GenerateMfaSessionToken()
		if err != nil {
			panic(err)
		}
		if token == "" {
			t.Errorf("expected non-empty token, but got %q", token)
		}

		if len(token) != 32 {
			t.Errorf("expected 32 character token, but got %q", token)
		}

	})
}

func TestGenerateConfirmationToken(t *testing.T) {
	t.Run("should generate unique confirmation token", func(t *testing.T) {
		token, err := GenerateEmailConfirmationToken()
		if err != nil {
			panic(err)
		}
		if token == "" {
			t.Errorf("expected non-empty token, but got %q", token)
		}

		if len(token) != 32 {
			t.Errorf("expected 32 character token, but got %q", token)
		}

	})
}
