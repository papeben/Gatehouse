package main

type GatehouseForm struct {
	TabTitle       string
	FormTitle      string
	FormAction     string
	FormMethod     string
	FormElements   []GatehouseFormElement
	OIDCOptions    []OIDCButton
	FunctionalPath string
}

type GatehouseFormElement struct {
	Class            string
	InnerText        string
	IsLink           bool
	LinkURI          string
	IsInput          bool
	IsImage          bool
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

func FormCreateCheckboxInput(name string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_inp_checkbox",
		"",
		false,
		"",
		true,
		false,
		"checkbox",
		name,
		"",
	}
}
func FormCreateTextInput(name string, placeholder string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_inp_text",
		"",
		false,
		"",
		true,
		false,
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
		false,
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
		false,
		"submit",
		name,
		"",
	}
}
func FormCreateDangerSubmitInput(name string, text string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_a_danger_button gh_inp_button",
		text,
		false,
		"",
		true,
		false,
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
		false,
		"",
		"",
		"",
	}
}
func FormCreateDangerButtonLink(linkUrl string, text string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_a_danger_button gh_a_button",
		text,
		true,
		linkUrl,
		false,
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
		false,
		"",
		"",
		"",
	}
}
func FormCreateSmallHint(text string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_div_smallhint",
		text,
		false,
		"",
		false,
		false,
		"",
		"",
		"",
	}
}
func FormCreateQR(b64Data string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_img_qr",
		b64Data,
		false,
		"",
		false,
		true,
		"",
		"",
		"",
	}
}

func FormCreateUploadInput(name string, text string) GatehouseFormElement {
	return GatehouseFormElement{
		"gh_inp_upload",
		text,
		false,
		"",
		true,
		false,
		"file",
		name,
		"",
	}
}

var (
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
		functionalPath,
	}

	forgotPasswordPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Reset Password",
		"Reset Password",
		"/" + functionalPath + "/submit/resetrequest",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateTextInput("email", "Email Address"),
			FormCreateSubmitInput("register", "Send Reset Email"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
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
			FormCreateHint("Didn't receive an email?"),
			FormCreateButtonLink("/"+functionalPath+"/resendconfirmation", "Resend Confirmation Email"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
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
		functionalPath,
	}

	confirmedUsernameChangePage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Confirmed New Username",
		"Username Changed",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Username has been changed successfully."),
			FormCreateSmallLink("/"+functionalPath+"/manage", "Back to site"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	linkExpired GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Expired",
		"Link Expired",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("This link is no longer valid."),
			FormCreateSmallLink("/", "Back to site"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
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
		functionalPath,
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
		functionalPath,
	}

	resetPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Reset Password",
		"Reset Password",
		"/" + functionalPath + "/submit/reset",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreatePasswordInput("password", "Password"),
			FormCreatePasswordInput("passwordConfirm", "Confirm Password"),
			FormCreateSubmitInput("submit", "Set Password"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	resetSuccessPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Reset Success",
		"Reset Success",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Reset request successful."),
			FormCreateButtonLink("/"+functionalPath+"/login", "Sign In"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	resendConfirmationPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Second Confirmation Sent",
		"Second Confirmation Sent",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Second confirmation email sent. If the problem persists please contact your system administrator."),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	emailTakenPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Email Already Registered",
		"Email Already Registered",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("This email has already been registered."),
			FormCreateDivider(),
			FormCreateButtonLink("/"+functionalPath+"/login", "Sign In"),
			FormCreateHint("Forgotten your details?"),
			FormCreateButtonLink("/"+functionalPath+"/forgot", "Reset Password"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	emailChangePage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Change Your Email",
		"Change Your Email",
		"/" + functionalPath + "/submit/changeemail",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Enter your new email address:"),
			FormCreateTextInput("newemail", "name@example.com"),
			FormCreateSubmitInput("submit", "Change Email"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	usernameChangePage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Change Your Username",
		"Change Your Username",
		"/" + functionalPath + "/submit/changeusername",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Choose your new username:"),
			FormCreateTextInput("newUsername", "JohnSmith1234"),
			FormCreateCheckboxInput("confirmed"),
			FormCreateHint("I understand I can only change username once per 30 days."),
			FormCreateDangerSubmitInput("submit", "Change Username"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	usernameChangeBlockedPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Change Your Username",
		"Change Your Username",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("You have already changed your username recently."),
			FormCreateButtonLink("/"+functionalPath+"/manage", "Back"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	avatarChangePage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Change Your Avatar",
		"Change Your Avatar",
		"/" + functionalPath + "/submit/changeavatar",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Upload your new avatar:"),
			FormCreateUploadInput("avatarupload", "Select Image"),
			FormCreateSmallHint("JPG or PNG formats supported. Max 5MB"),
			FormCreateDivider(),
			FormCreateSubmitInput("submit", "Upload"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	avatarChangedPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Success",
		"Avatar changed",
		"",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Your avatar has been changed successfully."),
			FormCreateButtonLink("/"+functionalPath+"/manage", "Manage Account"),
			FormCreateDivider(),
			FormCreateButtonLink("/"+functionalPath+"/manage", "Back To Site"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	mfaEmailPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - MFA",
		"MFA Code Sent",
		"/" + functionalPath + "/submit/mfa",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("An MFA code has been sent to your email address."),
			FormCreateHint("Enter the code below:"),
			FormCreateTextInput("token", "000000"),
			FormCreateSubmitInput("submit", "Submit"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	mfaTokenPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - MFA",
		"Enter TOTP",
		"/" + functionalPath + "/submit/mfa",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("A timed-based one-time password is needed from your registered two-factor device."),
			FormCreateHint("Enter the code below:"),
			FormCreateTextInput("token", "000000"),
			FormCreateSubmitInput("submit", "Submit"),
			FormCreateDivider(),
			FormCreateHint("Can't access TOTP?"),
			FormCreateSmallLink("/gatehouse/recoverycode", "Use recovery code"),
		},
		[]OIDCButton{},
		functionalPath,
	}

	mfaRecoveryCodePage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - MFA",
		"Enter Recovery Code",
		"/" + functionalPath + "/submit/recoverycode",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Enter one of your saved recovery codes to sign in. The codes are single use and are deactivated once entered."),
			FormCreateHint("Enter the code below:"),
			FormCreateTextInput("token", "00000000"),
			FormCreateSubmitInput("submit", "Submit"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	elevateSessionPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Reauthenticate",
		"Confirm Password",
		"/" + functionalPath + "/submit/elevate",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("You must reauthenticate to perform this action."),
			FormCreatePasswordInput("password", "Password"),
			FormCreateSubmitInput("submit", "Submit"),
			FormCreateDivider(),
			FormCreateHint("Changed your mind?"),
			FormCreateButtonLink("/"+functionalPath+"/manage", "Cancel"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	mfaValidatedPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - MFA Validated",
		"Success",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Your OTP code was validated successfully! You are now able to sign in with your authenticator OTP in the future."),
			FormCreateButtonLink("/"+functionalPath+"/manage", "Back to Dashboard"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	mfaFailedPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - MFA Failed",
		"OTP Incorrect",
		"/" + functionalPath + "/addmfa",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Your OTP code was not valid, please try adding you MFA device again."),
			FormCreateButtonLink("/"+functionalPath+"/addmfa", "Try Again"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	mfaRemovePage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Remove MFA",
		"Remove MFA",
		"/" + functionalPath + "/submit/removemfa",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("This will remove your registered MFA device. Two-factor OTP codes will instead be sent by email."),
			FormCreateHint("Are you sure you wish to proceed?"),
			FormCreateSubmitInput("submit", "Yes"),
			FormCreateDivider(),
			FormCreateButtonLink("/"+functionalPath+"/manage", "No, take me back!"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	mfaRemovedPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - MFA Removed",
		"MFA Removed",
		"/" + functionalPath + "/manage",
		"GET",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("MFA device removed. Two-factor OTP codes will now be sent by email."),
			FormCreateButtonLink("/"+functionalPath+"/manage", "OK"),
		},
		[]OIDCButton{},
		functionalPath,
	}

	deleteAccountPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Delete Account",
		"Delete Account",
		"/" + functionalPath + "/submit/deleteaccount",
		"POST",
		[]GatehouseFormElement{
			FormCreateDivider(),
			FormCreateHint("Are you sure you wish to delete your account?"),
			FormCreateDivider(),
			FormCreateCheckboxInput("confirmed"),
			FormCreateHint("I understand this action is permanent and cannot be reversed."),
			FormCreateDangerSubmitInput("submit", "Delete Account"),
			FormCreateDivider(),
			FormCreateHint("Changed your mind?"),
			FormCreateButtonLink("/"+functionalPath+"/manage", "Cancel"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	deletedAccountPage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Account Deleted",
		"Account Deleted",
		"/",
		"GET",
		[]GatehouseFormElement{
			FormCreateHint("Your account has been deleted."),
			FormCreateButtonLink("/"+functionalPath+"/manage", "Back to Site"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}

	disabledFeaturePage GatehouseForm = GatehouseForm{ // Define forgot password page
		appName + " - Feature Disabled",
		"Feature Disabled",
		"",
		"",
		[]GatehouseFormElement{
			FormCreateHint("This feature is disabled."),
			FormCreateButtonLink("/", "Back to Site"),
			FormCreateDivider(),
		},
		[]OIDCButton{},
		functionalPath,
	}
)
