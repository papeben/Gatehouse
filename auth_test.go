package main

import (
	"math/rand"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func init() {
	rand.Seed(time.Now().UnixNano())
	InitDatabase()
}

func TestGenerateUserID(t *testing.T) {
	t.Run("should generate unique user id", func(t *testing.T) {
		userID := GenerateUserID()
		if userID == "" {
			t.Errorf("expected non-empty user id, but got %q", userID)
		}

		if len(userID) != 8 {
			t.Errorf("expected 8 character user id, but got %q", userID)
		}

	})
}

func TestGenerateSessionToken(t *testing.T) {
	t.Run("should generate unique session token", func(t *testing.T) {
		token := GenerateSessionToken()
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
		token := GenerateResetToken()
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
		token := GenerateEmailConfirmationToken()
		if token == "" {
			t.Errorf("expected non-empty token, but got %q", token)
		}

		if len(token) != 32 {
			t.Errorf("expected 32 character token, but got %q", token)
		}

	})
}
