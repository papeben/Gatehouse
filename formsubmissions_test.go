package main

import (
	"fmt"
	"testing"
)

func TestUsernamePermutations(t *testing.T) {
	tests := []struct {
		username string
		expected bool
	}{
		{"", false},
		{"123456789012345678901234567890123", false},
		{"ABC-def_123", true},
		{"abc-def_123", true},
		{"abc_def_123", true},
		{"abc-def-123", true},
		{"abc-def_!23", false},
		{"abc😊def", false},
		{"abcédef", false},
		{"abcdefghijklmno-pqrst_0123456789", true},
		{"abc_def-123", true},
		{"abc_def-123_", true},
		{"ABC_DEF-123_", true},
		{"Abc_def-123", true},
		{"a-b-c_d-e-f_1-2-3", true},
		{"abcdefghijklmnopqrstuvwxyz_012345", false},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Username '%s'", test.username), func(t *testing.T) {

			actual := IsValidNewUsername(test.username)
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
		{"user@example.com", true},           // simple email
		{"user123@example.com", true},        // email with numbers
		{"user-123@example.com", true},       // email with hyphen
		{"user_123@example.com", true},       // email with underscore
		{"user+123@example.com", true},       // email with plus sign
		{"user.123@example.com", true},       // email with period
		{"user@subdomain.example.com", true}, // email with subdomain
		{"user@example.co.uk", true},         // email with country code TLD
		{"user@example.local", true},         // email with non-standard TLD
		{"user@example.technology", true},    // email with new gTLD
		{"user@example.coffee", true},        // email with non-standard TLD
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
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Email '%s'", test.email), func(t *testing.T) {

			actual := IsValidNewEmail(test.email)
			if actual != test.expected {
				t.Errorf("Expected IsValidNewEmail('%s') to be %v, but got %v", test.email, test.expected, actual)
			}
		})
	}
}
