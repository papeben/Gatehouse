package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

func main() {
	// Load configuration from environment or set defaults
	backendServerAddr := envWithDefault("BACKEND_SERVER", "127.0.0.1")
	backendServerPort := envWithDefault("BACKEND_PORT", "9000")
	listenPort := envWithDefault("LISTEN_PORT", "8080")

	// Validate URL
	url, err := url.Parse("http://" + backendServerAddr + ":" + backendServerPort)
	if err != nil {
		panic(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(url)

	// Create main listener function
	http.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		fmt.Println(request.URL.Path)
		proxy.ServeHTTP(response, request)
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
