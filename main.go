package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
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
	mfaCookieName         string = envWithDefault("SESSION_COOKIE", "gatehouse-mfa")
	requireAuthentication bool   = envWithDefaultBool("REQUIRE_AUTH", true)
	requireEmailConfirm   bool   = envWithDefaultBool("REQUIRE_EMAIL_CONFIRM", true)
	mfaEnabled            bool   = envWithDefaultBool("MFA_ENABLED", true)
	smtpHost              string = envWithDefault("SMTP_HOST", "127.0.0.1")
	smtpPort              string = envWithDefault("SMTP_PORT", "25")
	smtpUser              string = envWithDefault("SMTP_USER", "")
	smtpPass              string = envWithDefault("SMTP_PASS", "")
	smtpTLS               bool   = envWithDefaultBool("SMTP_TLS", false)
	smtpTLSSkipVerify     bool   = envWithDefaultBool("SMTP_TLS_SKIP", false)
	senderAddress         string = envWithDefault("MAIL_ADDRESS", "gatehouse@mydomain.local")
	webDomain             string = envWithDefault("WEB_DOMAIN", "http://localhost:8080")
	formTemplate          *template.Template
	emailTemplate         *template.Template
)

func main() {
	InitDatabase()
	LoadTemplates()

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Configure functional URLs map [Method][Url] = func()
	functionalURIs := map[string]map[string]interface{}{
		"GET": {
			"/" + functionalPath + "/login":              HandleLogin,
			"/" + functionalPath + "/logout":             HandleLogout,
			"/" + functionalPath + "/register":           HandleRegister,
			"/" + functionalPath + "/forgot":             HandleForgotPassword,
			"/" + functionalPath + "/confirmemail":       HandleConfirmEmail,
			"/" + functionalPath + "/confirmcode":        HandleConfirmEmailCode,
			"/" + functionalPath + "/resetpassword":      HandlePasswordResetCode,
			"/" + functionalPath + "/resendconfirmation": HandleResendConfirmation,
			"/" + functionalPath + "/usernametaken":      HandleIsUsernameTaken,
			"/" + functionalPath + "/addmfa":             HandleAddMFA,
		},
		"POST": {
			"/" + functionalPath + "/submit/register":     HandleSubRegister,
			"/" + functionalPath + "/submit/login":        HandleSubLogin,
			"/" + functionalPath + "/submit/resetrequest": HandleSubResetRequest,
			"/" + functionalPath + "/submit/reset":        HandleSubReset,
			"/" + functionalPath + "/submit/mfa":          HandleSubOTP,
			"/" + functionalPath + "/submit/validatemfa":  HandleSubMFAValidate,
		},
	}

	url, err := url.Parse("http://" + backendServerAddr + ":" + backendServerPort) // Validate backend URL
	if err != nil {
		panic(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(url)
	staticFiles := http.StripPrefix("/"+functionalPath+"/static/", http.FileServer(http.Dir("./assets/static/")))
	http.Handle("/"+functionalPath+"/static/", staticFiles)

	http.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) { // Create main listener function
		handler := functionalURIs[request.Method][strings.ToLower(request.URL.Path)] // Load handler associated with URI from functionalURIs map
		tokenCookie, tokenError := request.Cookie(sessionCookieName)
		var validSession bool = false
		if tokenError == nil {
			validSession = IsValidSession(tokenCookie.Value)
		}
		if handler != nil {
			handler.(func(http.ResponseWriter, *http.Request))(response, request) // If handler function set, use it to handle http request
		} else if !validSession && requireAuthentication {
			http.Redirect(response, request, path.Join("/", functionalPath, "login"), http.StatusSeeOther)
		} else if requireEmailConfirm && validSession && PendingEmailApproval(tokenCookie.Value) {
			http.Redirect(response, request, "/"+functionalPath+"/confirmemail", http.StatusSeeOther)
		} else {
			proxy.ServeHTTP(response, request)
		}
	})

	server := &http.Server{
		Addr:              ":" + listenPort,
		ReadHeaderTimeout: 10 * time.Second,
	}
	err = server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func envWithDefault(variableName string, defaultString string) string {
	val := os.Getenv(variableName)
	if len(val) == 0 {
		return defaultString
	} else {
		return val
	}
}

func envWithDefaultBool(variableName string, defaultBool bool) bool {
	var (
		trueValues  []string = []string{"true", "yes", "on"}
		falseValues []string = []string{"false", "no", "off"}
	)
	val := os.Getenv(variableName)
	if len(val) == 0 {
		return defaultBool
	} else if listContains(trueValues, strings.ToLower(val)) {
		return true
	} else if listContains(falseValues, strings.ToLower(val)) {
		return false
	} else {
		fmt.Printf("Invalid true/false value set for %s\n", variableName)
		os.Exit(1)
		return false
	}
}

func listContains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func LoadTemplates() {
	var err error
	formTemplate, err = template.ParseFiles("assets/form.html") // Preload form page template into memory
	if err != nil {
		panic(err)
	}

	emailTemplate, err = template.ParseFiles("assets/email.html") // Preload email template into memory
	if err != nil {
		panic(err)
	}
}

func InitDatabase() {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/", mysqlUser, mysqlPassword, mysqlHost, mysqlPort))
	if err != nil {
		panic(err)
	}
	defer db.Close()
	db.SetConnMaxLifetime(time.Minute * 3)
	_, err = db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", mysqlDatabase))
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_accounts` (`id` VARCHAR(8) NOT NULL,`username` VARCHAR(32) NULL,`email` VARCHAR(255) NULL,`email_confirmed` TINYINT(1) NULL DEFAULT 0, `email_resent` TINYINT(1) NULL DEFAULT 0,`password` VARCHAR(64) NULL,`avatar` TEXT NULL,	`tos` TINYINT(1) NULL DEFAULT 0,`locked` TINYINT(1) NULL DEFAULT 0, `mfa_type` VARCHAR(8) NOT NULL DEFAULT 'email', `mfa_secret` VARCHAR(16) NULL,	PRIMARY KEY (`id`))  ENGINE = InnoDB  DEFAULT CHARACTER SET = utf8  COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
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
	_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_mfa` (`mfa_session` VARCHAR(32) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `type` VARCHAR(8) NOT NULL, `token` VARCHAR(6) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `used` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`mfa_session`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
	if err != nil {
		panic(err)
	}
}
