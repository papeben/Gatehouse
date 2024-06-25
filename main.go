package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// LOAD ENVIRONMENT VARIABLES

var (
	logVerbosity          int    = envWithDefaultInt("LOG_LEVEL", 4)
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
	mfaCookieName         string = envWithDefault("MFA_COOKIE", "gatehouse-mfa")
	criticalCookieName    string = envWithDefault("CRITICAL_COOKIE", "gatehouse-crit")
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
	dashTemplate          *template.Template
	functionalURIs        map[string]map[string]interface{}
	proxy                 *httputil.ReverseProxy
	elevatedRedirectPages        = []string{"removemfa", "changeemail", "deleteaccount"}
	sevMap                       = [6]string{"FATAL", "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
	gatehouseVersion      string = "%VERSION%"
)

func main() {
	fmt.Println("   _____       _       _                          ")
	fmt.Println("  / ____|     | |     | |                         ")
	fmt.Println(" | |  __  __ _| |_ ___| |__   ___  _   _ ___  ___ ")
	fmt.Println(" | | |_ |/ _\\ | __/ _ \\ _ \\  / _ \\| | | / __|/ _ \\")
	fmt.Println(" | |__| | (_| | ||  __/ | | | (_) | |_| \\__ \\  __/")
	fmt.Println("  \\_____|\\__,_|\\__\\___|_| |_|\\___/ \\__,_|___/\\___|")
	fmt.Println("                                                  ")
	fmt.Println("Version " + gatehouseVersion)
	InitDatabase(10)
	LoadTemplates()
	LoadFuncionalURIs()

	url, err := url.Parse("http://" + backendServerAddr + ":" + backendServerPort) // Validate backend URL
	if err != nil {
		log(0, fmt.Sprintf("Unable to start listening: %s", err.Error()))
		os.Exit(1)
	}
	proxy = httputil.NewSingleHostReverseProxy(url)
	staticFiles := http.StripPrefix("/"+functionalPath+"/static/", http.FileServer(http.Dir("./assets/static/")))
	http.Handle("/"+functionalPath+"/static/", staticFiles) // If /gatehouse/static, use static assets
	http.HandleFunc("/", HandleMain)

	server := &http.Server{
		Addr:              ":" + listenPort,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log(4, fmt.Sprintf("Listening for incoming requests on %s", server.Addr))
	err = server.ListenAndServe()
	if err != nil {
		log(0, fmt.Sprintf("Server error: %s", err.Error()))
	}
}

func envWithDefault(variableName string, defaultString string) string {
	val := os.Getenv(variableName)
	if len(val) == 0 {
		return defaultString
	} else {
		log(5, fmt.Sprintf("Loaded %s value '%s'", variableName, val))
		return val
	}
}

func envWithDefaultInt(variableName string, defaultInt int) int {
	val := os.Getenv(variableName)
	if len(val) == 0 {
		return defaultInt
	} else {
		i, err := strconv.Atoi(val)
		if err != nil {
			fmt.Printf("[CRITICAL] Integer parameter %s is not valid\n", val)
			os.Exit(1)
		}
		return i
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
		log(5, fmt.Sprintf("Loaded %s value 'true'", variableName))
		return true
	} else if listContains(falseValues, strings.ToLower(val)) {
		log(5, fmt.Sprintf("Loaded %s value 'false'", variableName))
		return false
	} else {
		log(3, fmt.Sprintf("Invalid true/false value set for %s\n", variableName))
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
		log(0, fmt.Sprintf("Unable to load HTML template from assets/form.html: %s", err.Error()))
		os.Exit(1)
	}

	emailTemplate, err = template.ParseFiles("assets/email.html") // Preload email template into memory
	if err != nil {
		log(0, fmt.Sprintf("Unable to load HTML template from assets/email.html: %s", err.Error()))
		os.Exit(1)
	}

	dashTemplate, err = template.ParseFiles("assets/dashboard.html") // Preload dashboard template into memory
	if err != nil {
		log(0, fmt.Sprintf("Unable to load HTML template from assets/dashboard.html: %s", err.Error()))
		os.Exit(1)
	}
}

func LoadFuncionalURIs() {
	functionalURIs = map[string]map[string]interface{}{
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
			"/" + functionalPath + "/removemfa":          HandleRemoveMFA,
			"/" + functionalPath + "/elevate":            HandleElevateSession,
			"/" + functionalPath + "/manage":             HandleManage,
			"/" + functionalPath + "/changeemail":        HandleChangeEmail,
			"/" + functionalPath + "/deleteaccount":      HandleDeleteAccount,
			"/" + functionalPath + "/recoverycode":       HandleRecoveryCode,
		},
		"POST": {
			"/" + functionalPath + "/submit/register":      HandleSubRegister,
			"/" + functionalPath + "/submit/login":         HandleSubLogin,
			"/" + functionalPath + "/submit/resetrequest":  HandleSubResetRequest,
			"/" + functionalPath + "/submit/reset":         HandleSubReset,
			"/" + functionalPath + "/submit/mfa":           HandleSubOTP,
			"/" + functionalPath + "/submit/validatemfa":   HandleSubMFAValidate,
			"/" + functionalPath + "/submit/elevate":       HandleSubElevate,
			"/" + functionalPath + "/submit/removemfa":     HandleSubRemoveMFA,
			"/" + functionalPath + "/submit/changeemail":   HandleSubEmailChange,
			"/" + functionalPath + "/submit/deleteaccount": HandleSubDeleteAccount,
			"/" + functionalPath + "/submit/recoverycode":  HandleSubRecoveryCode,
		},
	}
}

func InitDatabase(n int) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/", mysqlUser, mysqlPassword, mysqlHost, mysqlPort))
	if err != nil {
		log(0, fmt.Sprintf("Failed to connect to create database connection: %s", err.Error()))
		os.Exit(1)
	}
	defer db.Close()
	_, err = db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", mysqlDatabase))
	if err != nil {
		if n > 1 {
			log(2, "Failed to connect to database! Trying again in 5 seconds...")
			time.Sleep(5 * time.Second)
			InitDatabase(n - 1)
		} else {
			log(0, "Failed to connect to database. Exiting...")
			os.Exit(1)
		}
	} else {
		db.SetConnMaxLifetime(time.Minute * 3)
		log(4, "Creating database tables")
		_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_accounts` (`id` VARCHAR(8) NOT NULL,`username` VARCHAR(32) NULL,`email` VARCHAR(255) NOT NULL DEFAULT '',`email_confirmed` TINYINT(1) NULL DEFAULT 0, `email_resent` TINYINT(1) NULL DEFAULT 0,`password` VARCHAR(64) NULL,`avatar_url` TEXT NULL,	`tos` TINYINT(1) NULL DEFAULT 0,`locked` TINYINT(1) NULL DEFAULT 0, `mfa_type` VARCHAR(8) NOT NULL DEFAULT 'email', `mfa_secret` VARCHAR(16) NULL,	PRIMARY KEY (`id`))  ENGINE = InnoDB  DEFAULT CHARACTER SET = utf8  COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
		if err != nil {
			log(0, fmt.Sprintf("Failed to create required table: %s", err.Error()))
			os.Exit(1)
		}
		_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_sessions` (`session_token` VARCHAR(64) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `critical` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`session_token`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
		if err != nil {
			log(0, fmt.Sprintf("Failed to create required table: %s", err.Error()))
			os.Exit(1)
		}
		_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_confirmations` (`confirmation_token` VARCHAR(32) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `used` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`confirmation_token`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
		if err != nil {
			log(0, fmt.Sprintf("Failed to create required table: %s", err.Error()))
			os.Exit(1)
		}
		_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_resets` (`reset_token` VARCHAR(32) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `used` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`reset_token`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
		if err != nil {
			log(0, fmt.Sprintf("Failed to create required table: %s", err.Error()))
			os.Exit(1)
		}
		_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_mfa` (`mfa_session` VARCHAR(32) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `type` VARCHAR(8) NOT NULL, `token` VARCHAR(6) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `used` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`mfa_session`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
		if err != nil {
			log(0, fmt.Sprintf("Failed to create required table: %s", err.Error()))
			os.Exit(1)
		}
		_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_recovery` (`user_id` VARCHAR(8) NOT NULL, `code` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `used` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`user_id`, `code`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
		if err != nil {
			log(0, fmt.Sprintf("Failed to create required table: %s", err.Error()))
			os.Exit(1)
		}
	}
}
