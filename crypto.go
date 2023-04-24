package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		panic(err)
	}
	return string(bytes)
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateRandomString(length int) string {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetLength := big.NewInt(int64(len(charset)))
	bytes := make([]byte, length)

	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			panic(err)
		}

		bytes[i] = charset[num.Int64()]
	}

	return string(bytes)
}

func GenerateRandomNumbers(length int) string {
	charset := "0123456789"
	charsetLength := big.NewInt(int64(len(charset)))
	bytes := make([]byte, length)

	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			panic(err)
		}

		bytes[i] = charset[num.Int64()]
	}

	return string(bytes)
}

func GenerateOTP(secret string, timeStep int64) (string, error) {
	// Decode the secret key from base32
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to decode secret key: %v", err)
	}

	// Calculate the number of time steps that have elapsed since the Unix epoch
	now := time.Now().Unix()
	timeStepCount := uint64(now / timeStep)

	// Convert the time step count to a byte array in big-endian order
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, timeStepCount)

	// Generate an HMAC-SHA1 hash using the secret key and time step count
	hash := hmac.New(sha1.New, key)
	hash.Write(counterBytes)
	sum := hash.Sum(nil)

	// Calculate the offset into the hash to use as the starting point for the OTP
	offset := sum[len(sum)-1] & 0x0f

	// Extract a 4-byte integer from the hash starting at the given offset
	value := binary.BigEndian.Uint32(sum[offset:])

	// Truncate the integer to a 6-digit value and return it as a string
	otp := fmt.Sprintf("%06d", value%1000000)
	return otp, nil
}

func GenerateOTPSecret() string {
	// Generate a random secret key
	secret := make([]byte, 10)
	_, err := rand.Read(secret)
	if err != nil {
		panic(err)
	}
	secretBase32 := base32.StdEncoding.EncodeToString(secret)
	return secretBase32
}
