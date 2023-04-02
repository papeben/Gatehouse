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
	backendServerAddr string = envWithDefault("BACKEND_SERVER", "127.0.0.1") // Load configuration from environment or set defaults
	backendServerPort string = envWithDefault("BACKEND_PORT", "9000")
	listenPort        string = envWithDefault("LISTEN_PORT", "8080")
	functionalPath    string = envWithDefault("GATEHOUSE_PATH", "gatehouse")
	appName           string = envWithDefault("APP_NAME", "Gatehouse")
	mysqlHost         string = envWithDefault("MYSQL_HOST", "127.0.0.1")
	mysqlPort         string = envWithDefault("MYSQL_PORT", "3306")
	mysqlUser         string = envWithDefault("MYSQL_USER", "gatehouse")
	mysqlPassword     string = envWithDefault("MYSQL_PASS", "password")
	mysqlDatabase     string = envWithDefault("MYSQL_DATABASE", "gatehouse")
	tablePrefix       string = envWithDefault("TABLE_PREFIX", "gatehouse")
	sessionCookieName string = envWithDefault("SESSION_COOKIE", "gatehouse-session")
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
	_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_accounts` (`id` VARCHAR(8) NOT NULL,`username` VARCHAR(32) NULL,`email` VARCHAR(255) NULL,`email_confirmed` TINYINT(1) NULL DEFAULT 0,`password` VARCHAR(64) NULL,`avatar` TEXT NULL,	`tos` TINYINT(1) NULL DEFAULT 0,`locked` TINYINT(1) NULL DEFAULT 0,	`tfa_secret` VARCHAR(16) NULL,	PRIMARY KEY (`id`))  ENGINE = InnoDB  DEFAULT CHARACTER SET = utf8  COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s_sessions` (`session_token` VARCHAR(64) NOT NULL, `user_id` VARCHAR(8) NOT NULL, `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`session_token`)) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8 COLLATE = utf8_bin; ", mysqlDatabase, tablePrefix))
	if err != nil {
		panic(err)
	}

	functionalURIs := map[string]map[string]string{
		"GET": {
			"/" + functionalPath + "/login":    "login",
			"/" + functionalPath + "/register": "register",
			"/" + functionalPath + "/forgot":   "forgot",
		},
		"POST": {
			"/" + functionalPath + "/submit/register": "sub_register",
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

	loginPage := GatehouseForm{ // Define login page
		appName + " - Sign in",
		"Sign In",
		"/" + functionalPath + "/submit/login",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateTextInput("username", "Username"),
			FormCreatePasswordInput("password", "Password"),
			FormCreateSmallLink("/"+functionalPath+"/forgot", "Forgot my password..."),
			FormCreateSubmitInput("signin", "Sign In"),
			FormCreateDivider(),
			FormCreateButtonLink("/"+functionalPath+"/register", "Create an Account"),
			FormCreateDivider(),
		},
		[]OIDCButton{
			{"Sign In with Google", "/" + functionalPath + "/static/icons/google.png", "#fff", "#000", "/" + functionalPath + "/auth/google"},
			{"Sign In with Microsoft Account", "/" + functionalPath + "/static/icons/microsoft.png", "#fff", "#000", "/" + functionalPath + "/auth/microsoft"},
			{"Sign In with Apple ID", "/" + functionalPath + "/static/icons/apple.png", "#fff", "#000", "/" + functionalPath + "/auth/apple"},
		},
	}

	registrationPage := GatehouseForm{ // Define registration page
		appName + " - Create Account",
		"Create an Account",
		"/" + functionalPath + "/submit/register",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateTextInput("newUsername", "Username"),
			FormCreateTextInput("email", "Email Address"),
			FormCreatePasswordInput("password", "Password"),
			FormCreatePasswordInput("passwordConfirm", "Confirm Password"),
			FormCreateSubmitInput("register", "Create Account"),
			FormCreateDivider(),
			FormCreateHint("Already have an account?"),
			FormCreateButtonLink("/"+functionalPath+"/login", "Sign In"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
	}

	forgotPasswordPage := GatehouseForm{ // Define forgot password page
		appName + " - Reset Password",
		"Reset Password",
		"/submit",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateTextInput("email", "Email Address"),
			FormCreateSubmitInput("register", "Send Reset Email"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
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
			case "register":
				formTemplate.Execute(response, registrationPage)
			case "forgot":
				formTemplate.Execute(response, forgotPasswordPage)
			case "sub_register":
				RegisterSubmission(response, request)
			}
		} else {
			proxy.ServeHTTP(response, request)
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
