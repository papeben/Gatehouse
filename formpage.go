package main

type GatehouseForm struct {
	TabTitle     string
	FormTitle    string
	FormAction   string
	FormMethod   string
	FormElements []GatehouseFormElement
	OIDCOptions  []OIDCButton
}

type GatehouseFormElement struct {
	Class            string
	InnerText        string
	IsLink           bool
	LinkURI          string
	IsInput          bool
	InputType        string
	InputName        string
	InputPlaceholder string
}

type OIDCButton struct {
	Text            string
	ImageURI        string
	BackgroundColor string
	TextColor       string
	URI             string
}

func FormCreateTextInput(name string, placeholder string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_inp_text",
		"",
		false,
		"",
		true,
		"text",
		name,
		placeholder,
	}
}
func FormCreatePasswordInput(name string, placeholder string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_inp_text",
		"",
		false,
		"",
		true,
		"password",
		name,
		placeholder,
	}
}
func FormCreateSubmitInput(name string, text string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_inp_button",
		text,
		false,
		"",
		true,
		"submit",
		name,
		"",
	}
}
func FormCreateButtonLink(linkUrl string, text string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_a_button",
		text,
		true,
		linkUrl,
		false,
		"",
		"",
		"",
	}
}
func FormCreateSmallLink(linkUrl string, text string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_a_small",
		text,
		true,
		linkUrl,
		false,
		"",
		"",
		"",
	}
}
func FormCreateDivider() GatehouseFormElement {
	return GatehouseFormElement{
		"gh_div_divider",
		"",
		false,
		"",
		false,
		"",
		"",
		"",
	}
}
func FormCreateHint(text string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_div_hint",
		text,
		false,
		"",
		false,
		"",
		"",
		"",
	}
}

var (
	loginPage GatehouseForm = GatehouseForm{ // Define login page
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
			// {"Sign In with Google", "/" + functionalPath + "/static/icons/google.png", "#fff", "#000", "/" + functionalPath + "/auth/google"},
			// {"Sign In with Microsoft Account", "/" + functionalPath + "/static/icons/microsoft.png", "#fff", "#000", "/" + functionalPath + "/auth/microsoft"},
			// {"Sign In with Apple ID", "/" + functionalPath + "/static/icons/apple.png", "#fff", "#000", "/" + functionalPath + "/auth/apple"},
		},
	}

	logoutPage GatehouseForm = GatehouseForm{ // Define login page
		appName + " - Sign Out",
		"Goodbye",
		"/" + functionalPath + "/submit/logout",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("You have signed out."),
			FormCreateSmallLink("/", "Back to site"),
			FormCreateDivider(),
			FormCreateButtonLink("/"+functionalPath+"/login", "Sign In"),
			FormCreateButtonLink("/"+functionalPath+"/register", "Create an Account"),
		},
		[]OIDCButton{},
	}

	registrationPage GatehouseForm = GatehouseForm{ // Define registration page
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

	forgotPasswordPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Reset Password",
		"Reset Password",
		"/" + functionalPath + "/submit/reset",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateTextInput("email", "Email Address"),
			FormCreateSubmitInput("register", "Send Reset Email"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
	}

	confirmEmailPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Confirm Email Address",
		"Confirmation Required",
		"/submit",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("A confirmation email has been sent to your registered email address."),
			FormCreateDivider(),
			FormCreateHint("Didn't recieve an email?"),
			FormCreateButtonLink("/"+functionalPath+"/resendconfirmation", "Resend Confirmation Email"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
	}

	confirmedEmailPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Confirmed Email Address",
		"Email Confirmed",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Thank you for confirming your email address."),
			FormCreateSmallLink("/", "Back to site"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
	}

	linkExpired GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Expired",
		"Link Expired",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("This confirmation code is no longer valid."),
			FormCreateSmallLink("/", "Back to site"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
	}

	resetSentPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Reset Sent",
		"Reset Email Sent",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("A reset email has been sent to your email address."),
			FormCreateSmallLink("/", "Back to site"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
	}

	resetNotSentPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Reset Not Sent",
		"Account Not Found",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("There is no account registered with this email address."),
			FormCreateSmallLink("/", "Back to site"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
	}

	resetPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Reset Password",
		"Reset Password",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreatePasswordInput("password", "Password"),
			FormCreatePasswordInput("passwordConfirm", "Confirm Password"),
			FormCreateSubmitInput("submit", "Set Password"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
	}
)
