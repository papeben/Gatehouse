package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// LOAD ENVIRONMENT VARIABLES

var (
	backendServerAddr     string = envWithDefault("BACKEND_SERVER", "127.0.0.1") // Load configuration from environment or set defaults
	backendServerPort     string = envWithDefault("BACKEND_PORT", "9000")
	listenPort            string = envWithDefault("LISTEN_PORT", "8080")
	functionalPath        string = envWithDefault("GATEHOUSE_PATH", "gatehouse")
	appName               string = envWithDefault("APP_NAME", "Gatehouse")
	mysqlHost             string = envWithDefault("MYSQL_HOST", "127.0.0.1")
	mysqlPort             string = envWithDefault("MYSQL_PORT", "3306")
	mysqlUser             string = envWithDefault("MYSQL_USER", "gatehouse")
	mysqlPassword         string = envWithDefault("MYSQL_PASS", "password")
	mysqlDatabase         string = envWithDefault("MYSQL_DATABASE", "gatehouse")
	tablePrefix           string = envWithDefault("TABLE_PREFIX", "gatehouse")
	sessionCookieName     string = envWithDefault("SESSION_COOKIE", "gatehouse-session")
	requireAuthentication string = envWithDefault("REQUIRE_AUTH", "TRUE")
	requireEmailConfirm   string = envWithDefault("REQUIRE_EMAIL_CONFIRM", "TRUE")
	smtpHost              string = envWithDefault("SMTP_HOST", "127.0.0.1")
	smtpPort              string = envWithDefault("SMTP_PORT", "25")
	smtpUser              string = envWithDefault("SMTP_USER", "")
	smtpPass              string = envWithDefault("SMTP_PASS", "")
	smtpTLS               string = envWithDefault("SMTP_TLS", "FALSE")
	senderAddress         string = envWithDefault("MAIL_ADDRESS", "Gatehouse <gatehouse@mydomain.local>")
	webDomain             string = envWithDefault("WEB_DOMAIN", "http://localhost:8080")
)

func main() {
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// INITALISE DATABASE

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/", mysqlUser, mysqlPassword, mysqlHost, mysqlPort))
	if err != nil {
		panic(err)
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	_, err = db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", mysqlDatabase))
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_accounts` (`id` VARCHAR(8) NOT NULL,`username` VARCHAR(32) NULL,`email` VARCHAR(255) NULL,`email_confirmed` TINYINT(1) NULL DEFAULT 0, `email_resent` TINYINT(1) NULL DEFAULT 0,`password` VARCHAR(64) NULL,`avatar` TEXT NULL,	`tos` TINYINT(1) NULL DEFAULT 0,`locked` TINYINT(1) NULL DEFAULT 0,	`tfa_secret` VARCHAR(16) NULL,	PRIMARY KEY (`id`))  ENGINE = InnoDB  DEFAULT CHARACTER SET = utf8  COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_sessions` (`session_token` VARCHAR(64) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`session_token`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_confirmations` (`confirmation_token` VARCHAR(32) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `used` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`confirmation_token`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_resets` (`reset_token` VARCHAR(32) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `used` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`reset_token`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
	if err != nil {
		panic(err)
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Configure functional URLs

	functionalURIs := map[string]map[string]string{
		"GET": {
			"/" + functionalPath + "/login":              "login",
			"/" + functionalPath + "/logout":             "logout",
			"/" + functionalPath + "/register":           "register",
			"/" + functionalPath + "/forgot":             "forgot",
			"/" + functionalPath + "/confirmemail":       "confirmemail",
			"/" + functionalPath + "/confirmcode":        "confirm_email_code",
			"/" + functionalPath + "/resetpassword":      "reset_password",
			"/" + functionalPath + "/resendconfirmation": "resend_confirmation",
		},
		"POST": {
			"/" + functionalPath + "/submit/register":     "sub_register",
			"/" + functionalPath + "/submit/login":        "sub_login",
			"/" + functionalPath + "/submit/resetrequest": "sub_reset_request",
			"/" + functionalPath + "/submit/reset":        "sub_reset",
		},
	}
	url, err := url.Parse("http://" + backendServerAddr + ":" + backendServerPort) // Validate backend URL
	if err != nil {
		panic(err)
	}
	db.Close()

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// ASSEMBLE FORM PAGES
	formTemplate, err := template.ParseFiles("template/form.html")
	if err != nil {
		panic(err)
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// MAIN REQUEST HANDLER
	proxy := httputil.NewSingleHostReverseProxy(url)
	staticFiles := http.StripPrefix("/"+functionalPath+"/static/", http.FileServer(http.Dir("./template/static/")))
	http.Handle("/"+functionalPath+"/static/", staticFiles)

	http.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) { // Create main listener function
		gateFunction := functionalURIs[request.Method][strings.ToLower(request.URL.Path)] // Load action associated with URI from functionalURIs map

		if gateFunction != "" { // If functional URL

			switch gateFunction { // Serve appropriate page
			case "login":
				formTemplate.Execute(response, loginPage)
			case "logout":
				http.SetCookie(response, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
				formTemplate.Execute(response, logoutPage)
			case "register":
				formTemplate.Execute(response, registrationPage)
			case "forgot":
				formTemplate.Execute(response, forgotPasswordPage)
			case "confirmemail":
				formTemplate.Execute(response, confirmEmailPage)
			case "sub_register":
				RegisterSubmission(response, request)
			case "sub_login":
				LoginSubmission(response, request)
			case "confirm_email_code":
				emailCode := request.URL.Query().Get("c")
				if ConfirmEmailCode(emailCode) {
					formTemplate.Execute(response, confirmedEmailPage)
				} else {
					formTemplate.Execute(response, linkExpired)
				}
			case "sub_reset_request":
				email := request.FormValue("email")
				if ResetPasswordRequest(email) {
					formTemplate.Execute(response, resetSentPage)
				} else {
					formTemplate.Execute(response, resetNotSentPage)
				}
			case "reset_password":
				resetCode := request.URL.Query().Get("c")
				if resetCode != "" && IsValidResetCode(resetCode) {
					customResetPage := resetPage
					customResetPage.FormAction += fmt.Sprintf("?c=%s", resetCode)
					formTemplate.Execute(response, customResetPage)
				} else {
					formTemplate.Execute(response, linkExpired)
				}
			case "sub_reset":
				if ResetSubmission(request) {
					formTemplate.Execute(response, resetSuccessPage)
				} else {
					response.WriteHeader(400)
					fmt.Fprint(response, `400 - Invalid request.`)
				}
			case "resend_confirmation":
				if !IsValidSession(request) && PendingEmailApproval(request) {
					if ResendConfirmationEmail(request) {
						formTemplate.Execute(response, resendConfirmationPage)
					} else {
						formTemplate.Execute(response, linkExpired)
					}

				} else {
					http.Redirect(response, request, "/", http.StatusSeeOther)
				}
			}

		} else {

			// For URLs not used by Gatehouse
			if requireAuthentication == "FALSE" {
				proxy.ServeHTTP(response, request)
			} else {
				validSession := IsValidSession(request)
				if validSession {
					proxy.ServeHTTP(response, request)
				} else if !validSession && requireEmailConfirm == "TRUE" && PendingEmailApproval(request) {
					http.Redirect(response, request, "/"+functionalPath+"/confirmemail", http.StatusSeeOther)
				} else {
					http.Redirect(response, request, "/"+functionalPath+"/login", http.StatusSeeOther)
				}
			}
		}
	})

	log.Fatal(http.ListenAndServe(":"+listenPort, nil))
}

////////////////////////////////////////////////////////////////////////////////////////////
// ENV WITH DEFAULT
// Used to pull environments variables and use a default value if not set
func envWithDefault(variableName, defaultString string) string {
	val := os.Getenv(variableName)
	if len(val) == 0 {
		return defaultString
	} else {
		return val
	}
}
