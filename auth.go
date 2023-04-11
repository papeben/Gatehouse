package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
)

func GenerateUserID() string {
	newID := GenerateRandomString(8)

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var userID string
	err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_accounts WHERE id = ?", tablePrefix), strings.ToLower(newID)).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return newID
		} else {
			panic(err)
		}
	} else {
		return GenerateUserID()
	}
}

func GenerateSessionToken() string {
	newToken := GenerateRandomString(64)

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var userID string
	err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_sessions WHERE session_token = ?", tablePrefix), newToken).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return newToken
		} else {
			panic(err)
		}
	} else {
		return GenerateSessionToken()
	}
}

func GenerateResetToken() string {
	newToken := GenerateRandomString(32)

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var userID string
	err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_resets WHERE reset_token = ?", tablePrefix), newToken).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return newToken
		} else {
			panic(err)
		}
	} else {
		return GenerateResetToken()
	}
}

func GenerateEmailConfirmationToken() string {
	newToken := GenerateRandomString(32)

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var userID string
	err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_confirmations WHERE confirmation_token = ?", tablePrefix), newToken).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return strings.ToLower(newToken)
		} else {
			panic(err)
		}
	} else {
		return GenerateEmailConfirmationToken()
	}
}

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

	cookie := http.Cookie{Name: sessionCookieName, Value: token, SameSite: http.SameSiteLaxMode, Secure: false, Path: "/"}
	http.SetCookie(response, &cookie)
	http.Redirect(response, request, "/", http.StatusSeeOther)
}

func IsValidSession(request *http.Request) bool {
	tokenCookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		return false
	} else {

		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var userID string
		var emailConfirmed int
		err = db.QueryRow(fmt.Sprintf("SELECT user_id, email_confirmed FROM %s_sessions INNER JOIN %s_accounts ON id = user_id WHERE session_token = ?", tablePrefix, tablePrefix), tokenCookie.Value).Scan(&userID, &emailConfirmed)
		if err != nil {
			if err == sql.ErrNoRows {
				return false
			} else {
				panic(err)
			}
		} else {
			if requireEmailConfirm == "TRUE" && emailConfirmed == 0 {
				return false
			} else {
				return true
			}
		}
	}
}

func PendingEmailApproval(request *http.Request) bool {
	tokenCookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		return false
	} else {

		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var emailConfirmed bool
		err = db.QueryRow(fmt.Sprintf("SELECT email_confirmed FROM %s_accounts INNER JOIN %s_sessions ON id = user_id WHERE session_token = ?", tablePrefix, tablePrefix), tokenCookie.Value).Scan(&emailConfirmed)
		if err != nil {
			if err == sql.ErrNoRows {
				return false
			} else {
				panic(err)
			}
		} else {
			if emailConfirmed {
				return false
			} else {
				return true
			}
		}
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
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		} else {
			panic(err)
		}
	} else {
		if isTokenUsed {
			return false
		} else {
			_, err := db.Exec(fmt.Sprintf("UPDATE %s_accounts INNER JOIN %s_confirmations ON user_id = id SET email_confirmed = 1, used = 1 WHERE confirmation_token = ?", tablePrefix, tablePrefix), code)
			if err != nil {
				panic(err)
			}
			return true
		}
	}
}

func SendEmailConfirmationCode(userID string, email string) {
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
	// Email code
	err = sendMail(email, "Confirm your Email Address", webDomain+"/"+functionalPath+"/confirmcode?c="+code)
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
	if smtpTLS == "TRUE" {
		// Use TLS encryption
		insecureSkipVerify := true
		if smtpTLSSkipVerify == "FALSE" {
			insecureSkipVerify = false
		}
		tlsConfig := &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
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
		"From: " + from + "\r\n" +
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
	err = db.QueryRow(fmt.Sprintf("SELECT id FROM %s_accounts WHERE email = ?", tablePrefix), strings.ToLower(email)).Scan(&userID)
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
		err := sendMail(strings.ToLower(email), "Password Reset Request", webDomain+"/"+functionalPath+"/resetpassword?c="+resetCode)
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
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		} else {
			panic(err)
		}
	} else {
		return true
	}
}

func ResetSubmission(request *http.Request) bool {
	code := request.URL.Query().Get("c")
	password := request.FormValue("password")
	passwordConfirm := request.FormValue("passwordConfirm")
	if code != "" && password != "" && password == passwordConfirm {
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var userID string
		err = db.QueryRow(fmt.Sprintf("SELECT user_id FROM %s_resets WHERE reset_token = ? AND used = 0", tablePrefix), code).Scan(&userID)
		if err != nil {
			if err == sql.ErrNoRows {
				return false
			} else {
				panic(err)
			}
		} else {
			_, err = db.Exec(fmt.Sprintf("UPDATE %s_resets INNER JOIN %s_accounts ON user_id = id SET password = ?, used = 1 WHERE reset_token = ?", tablePrefix, tablePrefix), HashPassword(password), code)
			if err != nil {
				panic(err)
			}
			return true
		}
	} else {
		return false
	}
}

func ResendConfirmationEmail(request *http.Request) bool {
	tokenCookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		return false
	} else {

		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			panic(err)
		}
		defer db.Close()

		var userID string
		var email string
		err = db.QueryRow(fmt.Sprintf("SELECT user_id, email FROM %s_sessions INNER JOIN %s_accounts ON id = user_id WHERE session_token = ? AND email_resent = 0", tablePrefix, tablePrefix), tokenCookie.Value).Scan(&userID, &email)
		if err != nil {
			if err == sql.ErrNoRows {
				return false
			} else {
				panic(err)
			}
		} else {
			SendEmailConfirmationCode(userID, email)
			_, err = db.Exec(fmt.Sprintf("UPDATE %s_accounts SET email_resent = 1 WHERE id = ?", tablePrefix), userID)
			if err != nil {
				panic(err)
			}
			return true
		}
	}
}
