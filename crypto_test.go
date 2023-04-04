package main

import (
	"testing"
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
