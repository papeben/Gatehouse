package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" /* #nosec G505 */
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		logMessage(0, fmt.Sprintf("Failed to generate BCRYPT hash of password string: %s", err.Error()))
		logMessage(5, fmt.Sprintf("Password string: %s", password))
		os.Exit(1)
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
			logMessage(0, fmt.Sprintf("Failed to generate random number: %s", err.Error()))
			os.Exit(1)
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
			logMessage(0, fmt.Sprintf("Failed to generate random number: %s", err.Error()))
			os.Exit(1)
		}

		bytes[i] = charset[num.Int64()]
	}

	return string(bytes)
}

func GenerateOTP(secret string, timestep int64) (string, error) {
	// decode the base32 secret into bytes
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	// calculate the number of time steps since Unix epoch (Jan 1 1970 00:00:00 UTC)
	steps := time.Now().Unix() / timestep

	// convert the steps to a byte array in big-endian format
	msg := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		msg[i] = byte(steps & 0xff)
		steps >>= 8
	}

	// calculate the HMAC-SHA1 hash of the message using the secret key
	h := hmac.New(sha1.New, key)
	h.Write(msg)
	hash := h.Sum(nil)

	// truncate the hash to a 4-byte value
	offset := hash[len(hash)-1] & 0xf
	code := (int(hash[offset])&0x7f)<<24 |
		(int(hash[offset+1])&0xff)<<16 |
		(int(hash[offset+2])&0xff)<<8 |
		(int(hash[offset+3]) & 0xff)
	code = int(math.Mod(float64(code), math.Pow10(6)))

	// convert the code to a string with leading zeros if necessary
	codeStr := strconv.Itoa(code)
	for len(codeStr) < 6 {
		codeStr = "0" + codeStr
	}

	return codeStr, nil
}

func GenerateOTPSecret() string {
	// Generate a random secret key
	secret := make([]byte, 10)
	_, err := rand.Read(secret)
	if err != nil {
		logMessage(0, fmt.Sprintf("Failed to read bytes: %s", err.Error()))
		os.Exit(1)
	}
	secretBase32 := base32.StdEncoding.EncodeToString(secret)
	return secretBase32
}

func GenerateUserID() (string, error) {
	newID := GenerateRandomString(8)

	var userID string
	err := db.QueryRow(fmt.Sprintf("SELECT id FROM %s_accounts WHERE id = ?", tablePrefix), strings.ToLower(newID)).Scan(&userID)
	if err == sql.ErrNoRows {
		return newID, nil
	} else if err != nil {
		return "", err
	} else {
		newID, err = GenerateUserID()
		return newID, err
	}
}

func GenerateAvatarID() (string, error) {
	newID := GenerateRandomString(16)

	var avatarID string
	err := db.QueryRow(fmt.Sprintf("SELECT avatar_id FROM %s_avatars WHERE avatar_id = ?", tablePrefix), strings.ToLower(newID)).Scan(&avatarID)
	if err == sql.ErrNoRows {
		return newID, nil
	} else if err != nil {
		return "", err
	} else {
		newID, err = GenerateAvatarID()
		return newID, err
	}
}

func GenerateSessionToken() (string, error) {
	newToken := GenerateRandomString(64)
	var userID string
	err := db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_sessions WHERE session_token = ?", tablePrefix), newToken).Scan(&userID)
	if err == sql.ErrNoRows {
		return newToken, nil
	} else if err != nil {
		logMessage(1, err.Error())
		return "", err
	} else {
		newToken, err = GenerateSessionToken()
		return newToken, err
	}
}

func GenerateResetToken() (string, error) {
	newToken := GenerateRandomString(32)

	var userID string
	err := db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_resets WHERE reset_token = ?", tablePrefix), newToken).Scan(&userID)
	if err == sql.ErrNoRows {
		return newToken, nil
	} else if err != nil {
		return "", err
	} else {
		newToken, err = GenerateResetToken()
		return newToken, err
	}
}

func GenerateMfaSessionToken() (string, error) {
	newToken := GenerateRandomString(32)

	var userID string
	err := db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_mfa WHERE mfa_session = ?", tablePrefix), newToken).Scan(&userID)
	if err == sql.ErrNoRows {
		return newToken, nil
	} else if err != nil {
		return "", err
	} else {
		newToken, err = GenerateMfaSessionToken()
		return newToken, err
	}
}

func GenerateEmailConfirmationToken() (string, error) {
	newToken := GenerateRandomString(32)

	var userID string
	err := db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_confirmations WHERE confirmation_token = ?", tablePrefix), newToken).Scan(&userID)
	if err == sql.ErrNoRows {
		return strings.ToLower(newToken), nil
	} else if err != nil {
		return "", err
	} else {
		newToken, err = GenerateEmailConfirmationToken()
		return strings.ToLower(newToken), err
	}
}

func CreateJWT(userId string) (string, error) {
	var (
		username       string
		email          string
		emailConfirmed bool
		avatarURL      string
	)
	err := db.QueryRow(fmt.Sprintf("SELECT username, email, email_confirmed, avatar_url FROM %s_accounts WHERE id = ?", tablePrefix), userId).Scan(&username, &email, &emailConfirmed, &avatarURL)
	if err != nil {
		return "", err
	}

	var header = map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	emailConfirmedString := "false"
	if emailConfirmed {
		emailConfirmedString = "true"
	}
	var payload = map[string]string{
		"iss":            "Gatehouse",
		"sub":            userId,
		"name":           username,
		"nickname":       username,
		"iat":            "now",
		"email":          email,
		"email_verified": emailConfirmedString,
		"picture":        avatarURL,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	headerString := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadString := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := CreateHMAC256(headerString+"."+payloadString, jwtSecret)
	return fmt.Sprintf("%s.%s.%s", headerString, payloadString, signature), nil
}

func CreateHMAC256(message, key string) string {
	keyBytes := []byte(key)
	messageBytes := []byte(message)
	h := hmac.New(sha256.New, keyBytes)
	h.Write(messageBytes)
	hashBytes := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(hashBytes)
}
