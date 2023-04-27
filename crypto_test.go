package main

import (
	"encoding/base32"
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
	otp, err := GenerateOTP(secret, 30)
	if err != nil {
		t.Errorf("GenerateOTP() returned an error: %v", err)
	}

	if len(otp) != 6 {
		t.Errorf("GenerateOTP() produced an OTP with length %d, expected 6", len(otp))
	}

	// Wait for one time step
	time.Sleep(30 * time.Second)

	otp2, err := GenerateOTP(secret, 30)
	if err != nil {
		t.Errorf("GenerateOTP() returned an error: %v", err)
	}

	if otp == otp2 {
		t.Errorf("GenerateOTP() produced the same OTP for two different time steps")
	}
}
