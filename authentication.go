package main

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"net/smtp"
	"regexp"
	"strings"
	"unicode"
)

func AuthenticateRequestor(response http.ResponseWriter, request *http.Request, userID string) {
	token := GenerateSessionToken()

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_sessions (session_token, user_id) VALUES (?, ?)", tablePrefix), token, userID)
	if err != nil {
		panic(err)
	}

	cookie := http.Cookie{Name: sessionCookieName, Value: token, SameSite: http.SameSiteStrictMode, Secure: false, Path: "/"}
	http.SetCookie(response, &cookie)
	http.Redirect(response, request, "/", http.StatusSeeOther)
}

func IsValidSession(sessionToken string) bool {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var userId string

	err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_sessions INNER JOIN %s_accounts ON id = user_id WHERE session_token = ? AND critical = 0", tablePrefix, tablePrefix), sessionToken).Scan(&userId)
	if err != nil && err == sql.ErrNoRows {
		return false
	} else if err != nil {
		panic(err)
	} else {
		return true
	}
}

func IsValidSessionWithInfo(sessionToken string) (bool, string, string) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var (
		userID    string
		userEmail string
	)
	err = db.QueryRow(fmt.Sprintf("SELECT user_id, email FROM %s_sessions INNER JOIN %s_accounts ON id = user_id WHERE session_token = ? AND critical = 0", tablePrefix, tablePrefix), sessionToken).Scan(&userID, &userEmail)
	if err != nil && err == sql.ErrNoRows {
		return false, "", ""
	} else if err != nil {
		panic(err)
	} else {
		return true, userID, userEmail
	}
}

func IsValidCriticalSession(sessionToken string) bool {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var userID string
	err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_sessions INNER JOIN %s_accounts ON id = user_id WHERE session_token = ? AND critical = 1 AND created > NOW() - INTERVAL 1 HOUR", tablePrefix, tablePrefix), sessionToken).Scan(&userID)
	if err != nil && err == sql.ErrNoRows {
		return false
	} else if err != nil {
		panic(err)
	} else {
		return true
	}
}

func PendingEmailApproval(sessionToken string) bool {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var emailConfirmed bool
	err = db.QueryRow(fmt.Sprintf("SELECT email_confirmed FROM %s_accounts INNER JOIN %s_sessions ON id = user_id WHERE session_token = ?", tablePrefix, tablePrefix), sessionToken).Scan(&emailConfirmed)
	if err != nil && err != sql.ErrNoRows {
		panic(err)
	} else if err == sql.ErrNoRows || emailConfirmed {
		return false
	} else {
		return true
	}
}

func ConfirmEmailCode(code string) bool {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()
	var isTokenUsed bool
	err = db.QueryRow(fmt.Sprintf("SELECT used FROM %s_confirmations WHERE confirmation_token = ?", tablePrefix), code).Scan(&isTokenUsed)
	if err == sql.ErrNoRows {
		return false
	} else if err != nil {
		panic(err)
	} else if isTokenUsed {
		return false
	} else {
		_, err := db.Exec(fmt.Sprintf("UPDATE %s_accounts INNER JOIN %s_confirmations ON user_id = id SET email_confirmed = 1, used = 1 WHERE confirmation_token = ?", tablePrefix, tablePrefix), code)
		if err != nil {
			panic(err)
		}
		return true
	}
}

func SendEmailConfirmationCode(userID string, email string, username string) {
	code := GenerateEmailConfirmationToken()
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()
	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_confirmations (confirmation_token, user_id) VALUES (?, ?)", tablePrefix), code, userID)
	if err != nil {
		panic(err)
	}

	var body bytes.Buffer
	err = emailTemplate.Execute(&body, struct {
		Title    string
		Username string
		Message  string
		HasLink  bool
		Link     string
		AppName  string
	}{
		Title:    "Confirm your email address",
		Username: username,
		Message:  fmt.Sprintf("Thank you for signing up to %s! Please confirm your email by clicking the link below:", appName),
		HasLink:  true,
		Link:     fmt.Sprintf("%s/%s/confirmcode?c=%s", webDomain, functionalPath, code),
		AppName:  appName,
	})
	if err != nil {
		panic(err)
	}

	// Email code
	err = sendMail(email, "Confirm your Email Address", body.String())
	if err != nil {
		fmt.Println(err)
		fmt.Println("Error sending email to " + email + ". Placing link below:")
		fmt.Println(webDomain + "/" + functionalPath + "/confirmcode?c=" + code)
	}
}

func sendMail(to string, subject string, body string) error {
	var client *smtp.Client
	var err error

	// Create a custom tls.Config with InsecureSkipVerify set to true
	if smtpTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: smtpTLSSkipVerify, /* #nosec G402 */
			ServerName:         smtpHost,
		}
		conn, err := tls.Dial("tcp", smtpHost+":"+smtpPort, tlsConfig)
		if err != nil {
			return err
		}
		client, err = smtp.NewClient(conn, smtpHost)
		if err != nil {
			return err
		}
	} else {
		// Don't use TLS encryption
		client, err = smtp.Dial(smtpHost + ":" + smtpPort)
		if err != nil {
			return err
		}
	}

	// Authenticate with the server if needed
	if smtpUser != "" && smtpPass != "" {
		auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
		err = client.Auth(auth)
		if err != nil {
			return err
		}
	}

	// Set the sender and recipient
	from := senderAddress

	// Compose the email message
	message := []byte("To: " + to + "\r\n" +
		"From: " + appName + " <" + from + ">\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-version: 1.0;\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\";\r\n" +
		"\r\n" +
		body + "\r\n")

	// Send the email message
	err = client.Mail(senderAddress)
	if err != nil {
		return err
	}

	err = client.Rcpt(to)
	if err != nil {
		return err
	}

	data, err := client.Data()
	if err != nil {
		return err
	}

	_, err = data.Write(message)
	if err != nil {
		return err
	}

	// Close the connection
	err = data.Close()
	if err != nil {
		return err
	}

	err = client.Quit()
	if err != nil {
		return err
	}

	return nil
}

func ResetPasswordRequest(email string) bool {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var userID string
	var username string
	err = db.QueryRow(fmt.Sprintf("SELECT id, username FROM %s_accounts WHERE email = ?", tablePrefix), strings.ToLower(email)).Scan(&userID, &username)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		} else {
			panic(err)
		}
	} else {
		// Reset password
		resetCode := GenerateResetToken()
		_, err = db.Exec(fmt.Sprintf("INSERT INTO %s_resets (user_id, reset_token) VALUES (?, ?)", tablePrefix), userID, resetCode)
		if err != nil {
			panic(err)
		}

		var body bytes.Buffer
		err = emailTemplate.Execute(&body, struct {
			Title    string
			Username string
			Message  string
			HasLink  bool
			Link     string
			AppName  string
		}{
			Title:    "Reset your password",
			Username: username,
			Message:  fmt.Sprintf("Click the link below to reset your %s password:", appName),
			HasLink:  true,
			Link:     fmt.Sprintf("%s/%s/resetpassword?c=%s", webDomain, functionalPath, resetCode),
			AppName:  appName,
		})
		if err != nil {
			panic(err)
		}

		err := sendMail(strings.ToLower(email), "Password Reset Request", body.String())
		if err != nil {
			fmt.Println(err)
			fmt.Println("Error sending email to " + email + ". Placing link below:")
			fmt.Println(webDomain + "/" + functionalPath + "/resetpassword?c=" + resetCode)
		}
		return true
	}
}

func IsValidResetCode(code string) bool {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var userID string
	err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_resets WHERE reset_token = ? AND used = 0", tablePrefix), code).Scan(&userID)
	if err == sql.ErrNoRows {
		return false
	} else if err != nil {
		panic(err)
	} else {
		return true
	}
}

func ResendConfirmationEmail(sessionToken string) bool {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var userID string
	var username string
	var email string
	err = db.QueryRow(fmt.Sprintf("SELECT user_id, email, username FROM %s_sessions INNER JOIN %s_accounts ON id = user_id WHERE session_token = ? AND email_resent = 0", tablePrefix, tablePrefix), sessionToken).Scan(&userID, &email, &username)
	if err == sql.ErrNoRows {
		return false
	} else if err != nil {
		panic(err)
	} else {
		SendEmailConfirmationCode(userID, email, username)
		_, err = db.Exec(fmt.Sprintf("UPDATE %s_accounts SET email_resent = 1 WHERE id = ?", tablePrefix), userID)
		if err != nil {
			panic(err)
		}
		return true
	}
}

func IsValidNewUsername(username string) bool {
	match, _ := regexp.MatchString("^[a-zA-Z0-9\\-_]{1,32}$", username)
	if !match {
		return false
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var userID string
		err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_accounts WHERE username = ?", tablePrefix), username).Scan(&userID)
		if err == sql.ErrNoRows {
			return true
		} else if err != nil {
			panic(err)
		} else {
			return false
		}
	}
}

func IsValidNewEmail(email string) bool {
	match, _ := regexp.MatchString(`^[\w!#$%&'*+/=?^_{|}~-]+(\.[\w!#$%&'*+/=?^_{|}~-]+)*@[a-zA-Z0-9]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,})$`, email)
	if !match {
		return false
	} else {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var userID string
		err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_accounts WHERE email = ?", tablePrefix), strings.ToLower(email)).Scan(&userID)
		if err == sql.ErrNoRows {
			return true
		} else if err != nil {
			panic(err)
		} else {
			return false
		}
	}
}

func IsValidPassword(password string) bool {
	// Check length
	if len(password) < 8 {
		return false
	}

	// Check for uppercase letter
	hasUppercase := false
	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUppercase = true
			break
		}
	}
	if !hasUppercase {
		return false
	}

	// Check for numeric digit
	hasDigit := false
	for _, char := range password {
		if unicode.IsDigit(char) {
			hasDigit = true
			break
		}
	}
	return hasDigit
}
