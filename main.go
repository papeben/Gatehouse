package main

import (
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

func main() {
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// LOAD ENVIRONMENT VARIABLES
	backendServerAddr := envWithDefault("BACKEND_SERVER", "127.0.0.1") // Load configuration from environment or set defaults
	backendServerPort := envWithDefault("BACKEND_PORT", "9000")
	listenPort := envWithDefault("LISTEN_PORT", "8080")
	functionalPath := envWithDefault("GATEHOUSE_PATH", "gatehouse")
	appName := envWithDefault("APP_NAME", "Gatehouse")

	functionalURIs := map[string]map[string]string{
		"GET": {
			"/" + functionalPath + "/login":    "login",
			"/" + functionalPath + "/register": "register",
		},
	}
	url, err := url.Parse("http://" + backendServerAddr + ":" + backendServerPort) // Validate backend URL
	if err != nil {
		panic(err)
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// ASSEMBLE FORM PAGES
	formTemplate, err := template.ParseFiles("template/form.html")
	if err != nil {
		panic(err)
	}

	loginPage := GatehouseForm{ // Define login page
		appName + " - Sign in",
		"Sign In",
		"/submit",
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
		false,
		[]OIDCButton{},
	}

	registrationPage := GatehouseForm{ // Define login page
		appName + " - Create Account",
		"Create an Account",
		"/submit",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateTextInput("username", "Username"),
			FormCreateTextInput("email", "Email Address"),
			FormCreatePasswordInput("password", "Password"),
			FormCreatePasswordInput("passwordConfirm", "Confirm Password"),
			FormCreateSubmitInput("register", "Create Account"),
			FormCreateDivider(),
			FormCreateHint("Already have an account?"),
			FormCreateButtonLink("/"+functionalPath+"/login", "Sign In"),
			FormCreateDivider(),
		},
		false,
		[]OIDCButton{},
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// MAIN REQUEST HANDLER
	proxy := httputil.NewSingleHostReverseProxy(url)
	http.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) { // Create main listener function
		gateFunction := functionalURIs[request.Method][strings.ToLower(request.URL.Path)] // Load action associated with URI from functionalURIs map

		if gateFunction != "" { // If functional URL
			switch gateFunction { // Serve appropriate page
			case "login":
				formTemplate.Execute(response, loginPage)
			case "register":
				formTemplate.Execute(response, registrationPage)
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
