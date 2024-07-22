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
	db                    *sql.DB
	elevatedRedirectPages          = []string{"removemfa", "changeemail", "deleteaccount", "changeusername"}
	sevMap                         = [6]string{"FATAL", "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
	gatehouseVersion      string   = "%VERSION%"
	allowRegistration     bool     = envWithDefaultBool("ALLOW_REGISTRATION", true)
	allowUsernameLogin    bool     = envWithDefaultBool("ALLOW_USERNAME_LOGIN", true)
	allowPasswordReset    bool     = envWithDefaultBool("ALLOW_PASSWORD_RESET", true)
	allowMobileMFA        bool     = envWithDefaultBool("ALLOW_MOBILE_MFA", true)
	allowUsernameChange   bool     = envWithDefaultBool("ALLOW_USERNAME_CHANGE", true)
	allowEmailChange      bool     = envWithDefaultBool("ALLOW_EMAIL_CHANGE", true)
	allowDeleteAccount    bool     = envWithDefaultBool("ALLOW_DELETE_ACCOUNT", true)
	allowSessionRevoke    bool     = envWithDefaultBool("ALLOW_SESSION_REVOKE", true)
	allowAvatarChange     bool     = envWithDefaultBool("ALLOW_AVATAR_CHANGE", true)
	enableLoginAlerts     bool     = envWithDefaultBool("ENABLE_LOGIN_ALERTS", true)
	enableMFAAlerts       bool     = envWithDefaultBool("ENABLE_MFA_ALERTS", true)
	publicPages           string   = envWithDefault("PUBLIC_PAGES", "")
	publicPageList        []string = strings.Split(publicPages, ",")
)

func main() {
	printBanner()
	InitDatabase(10)
	defer db.Close()
	LoadTemplates()
	LoadFuncionalURIs()

	url, err := url.Parse("http://" + backendServerAddr + ":" + backendServerPort) // Validate backend URL
	if err != nil {
		logMessage(0, fmt.Sprintf("Unable to start listening: %s", err.Error()))
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
	logMessage(4, fmt.Sprintf("Listening for incoming requests on %s", server.Addr))
	err = server.ListenAndServe()
	if err != nil {
		logMessage(0, fmt.Sprintf("Server error: %s", err.Error()))
	}
}

func printBanner() {
	fmt.Println("   _____       _       _                          ")
	fmt.Println("  / ____|     | |     | |                         ")
	fmt.Println(" | |  __  __ _| |_ ___| |__   ___  _   _ ___  ___ ")
	fmt.Println(" | | |_ |/ _\\ | __/ _ \\ _ \\  / _ \\| | | / __|/ _ \\")
	fmt.Println(" | |__| | (_| | ||  __/ | | | (_) | |_| \\__ \\  __/")
	fmt.Println("  \\_____|\\__,_|\\__\\___|_| |_|\\___/ \\__,_|___/\\___|")
	fmt.Println("                                                  ")
	fmt.Println("Version " + gatehouseVersion)
}

func envWithDefault(variableName string, defaultString string) string {
	val := os.Getenv(variableName)
	if len(val) == 0 {
		return defaultString
	} else {
		logMessage(5, fmt.Sprintf("Loaded %s value '%s'", variableName, val))
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
		logMessage(5, fmt.Sprintf("Loaded %s value 'true'", variableName))
		return true
	} else if listContains(falseValues, strings.ToLower(val)) {
		logMessage(5, fmt.Sprintf("Loaded %s value 'false'", variableName))
		return false
	} else {
		logMessage(3, fmt.Sprintf("Invalid true/false value set for %s\n", variableName))
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
		logMessage(0, fmt.Sprintf("Unable to load HTML template from assets/form.html: %s", err.Error()))
		os.Exit(1)
	}

	emailTemplate, err = template.ParseFiles("assets/email.html") // Preload email template into memory
	if err != nil {
		logMessage(0, fmt.Sprintf("Unable to load HTML template from assets/email.html: %s", err.Error()))
		os.Exit(1)
	}

	dashTemplate, err = template.ParseFiles("assets/dashboard.html") // Preload dashboard template into memory
	if err != nil {
		logMessage(0, fmt.Sprintf("Unable to load HTML template from assets/dashboard.html: %s", err.Error()))
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
			"/" + functionalPath + "/changeusername":     HandleChangeUsername,
			"/" + functionalPath + "/changeavatar":       HandleChangeAvatar,
			"/" + functionalPath + "/myavatar":           HandleMyAvatar,
			"/" + functionalPath + "/myusername":         HandleMyUsername,
			"/" + functionalPath + "/deleteaccount":      HandleDeleteAccount,
			"/" + functionalPath + "/recoverycode":       HandleRecoveryCode,
			"/" + functionalPath + "/revokesessions":     HandleSessionRevoke,
		},
		"POST": {
			"/" + functionalPath + "/submit/register":       HandleSubRegister,
			"/" + functionalPath + "/submit/login":          HandleSubLogin,
			"/" + functionalPath + "/submit/resetrequest":   HandleSubResetRequest,
			"/" + functionalPath + "/submit/reset":          HandleSubReset,
			"/" + functionalPath + "/submit/mfa":            HandleSubOTP,
			"/" + functionalPath + "/submit/validatemfa":    HandleSubMFAValidate,
			"/" + functionalPath + "/submit/elevate":        HandleSubElevate,
			"/" + functionalPath + "/submit/removemfa":      HandleSubRemoveMFA,
			"/" + functionalPath + "/submit/changeemail":    HandleSubEmailChange,
			"/" + functionalPath + "/submit/changeusername": HandleSubUsernameChange,
			"/" + functionalPath + "/submit/changeavatar":   HandleSubAvatarChange,
			"/" + functionalPath + "/submit/deleteaccount":  HandleSubDeleteAccount,
			"/" + functionalPath + "/submit/recoverycode":   HandleSubRecoveryCode,
			"/" + functionalPath + "/submit/revokesessions": HandleSubSessionRevoke,
		},
	}
}

func InitDatabase(n int) {
	var err error
	db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/", mysqlUser, mysqlPassword, mysqlHost, mysqlPort))
	if err != nil {
		logMessage(0, fmt.Sprintf("Failed to connect to create database connection: %s", err.Error()))
		os.Exit(1)
	}
	_, err = db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", mysqlDatabase))
	if err != nil {
		if n > 1 {
			logMessage(2, "Failed to connect to database! Trying again in 5 seconds...")
			err = db.Close()
			if err != nil {
				logMessage(4, fmt.Sprintf("Error closing connection: %s"+err.Error()))
			}
			time.Sleep(5 * time.Second)
			InitDatabase(n - 1)
		} else {
			logMessage(0, "Failed to connect to database. Exiting...")
			os.Exit(1)
		}
	} else {
		err = db.Close()
		if err != nil {
			logMessage(4, fmt.Sprintf("Error closing connection: %s"+err.Error()))
		}
		db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mysqlUser, mysqlPassword, mysqlHost, mysqlPort, mysqlDatabase))
		if err != nil {
			logMessage(0, "Failed to open newly created database. Exiting...")
			os.Exit(1)
		}
		logMessage(4, "Creating database tables")
		db.SetConnMaxIdleTime(10 * time.Second)

		CreateDatabaseTable(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_accounts` (`id` VARCHAR(8) NOT NULL,`username` VARCHAR(32) NULL,`email` VARCHAR(255) NOT NULL DEFAULT '',`email_confirmed` TINYINT(1) NULL DEFAULT 0, `email_resent` TINYINT(1) NULL DEFAULT 0,`password` VARCHAR(64) NULL,`avatar_url` VARCHAR(128) NOT NULL DEFAULT '/gatehouse/static/icons/user.png',	`tos` TINYINT(1) NULL DEFAULT 0,`locked` TINYINT(1) NULL DEFAULT 0, `mfa_type` VARCHAR(8) NOT NULL DEFAULT 'email', `mfa_secret` VARCHAR(16) NULL, `username_changed` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,	PRIMARY KEY (`id`))  ENGINE = InnoDB  DEFAULT CHARACTER SET = utf8  COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))

		CreateDatabaseTable(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_sessions` (`session_token` VARCHAR(64) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `critical` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`session_token`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))

		CreateDatabaseTable(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_confirmations` (`confirmation_token` VARCHAR(32) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `used` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`confirmation_token`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))

		CreateDatabaseTable(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_resets` (`reset_token` VARCHAR(32) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `used` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`reset_token`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))

		CreateDatabaseTable(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_mfa` (`mfa_session` VARCHAR(32) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `type` VARCHAR(8) NOT NULL, `token` VARCHAR(6) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `used` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`mfa_session`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))

		CreateDatabaseTable(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_recovery` (`user_id` VARCHAR(8) NOT NULL, `code` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `used` TINYINT(1) NOT NULL DEFAULT 0, PRIMARY KEY (`user_id`, `code`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))

		CreateDatabaseTable(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_avatars` (`avatar_id` VARCHAR(16) NOT NULL, `format` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, `data` LONGBLOB NOT NULL, PRIMARY KEY (`avatar_id`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
	}
}

func CreateDatabaseTable(tableSql string) {
	_, err := db.Exec(tableSql)
	if err != nil {
		logMessage(0, fmt.Sprintf("Failed to create required table: %s", err.Error()))
		os.Exit(1)
	}
}

func ServePage(response http.ResponseWriter, pageStruct GatehouseForm) {
	err := formTemplate.Execute(response, pageStruct)
	if err != nil {
		ServeErrorPage(response, err)
	}
}

func ServeErrorPage(response http.ResponseWriter, err error) {
	if err != nil {
		logMessage(1, fmt.Sprintf("An internal error occurred: %s", err.Error()))
	}
	var errorPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Error Occurred",
		"Error Occurred",
		"",
		"",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("We're currently experiencing issues. Please try again later."),
			FormCreateButtonLink("/", "Back to site"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}
	response.WriteHeader(500)
	err = formTemplate.Execute(response, errorPage)
	if err != nil {
		logMessage(1, fmt.Sprintf("Error rendering error page: %s", err.Error()))
		fmt.Fprint(response, `Internal Error.`)
	}
}
