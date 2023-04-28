package main

import (
	"fmt"
	"net/http"
)

func HandleLogin(response http.ResponseWriter, request *http.Request) {
	err := formTemplate.Execute(response, loginPage)
	if err != nil {
		panic(err)
	}
}

func HandleLogout(response http.ResponseWriter, request *http.Request) {
	http.SetCookie(response, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	err := formTemplate.Execute(response, logoutPage)
	if err != nil {
		panic(err)
	}
}

func HandleForgotPassword(response http.ResponseWriter, request *http.Request) {
	err := formTemplate.Execute(response, forgotPasswordPage)
	if err != nil {
		panic(err)
	}
}

func HandleConfirmEmail(response http.ResponseWriter, request *http.Request) {
	err := formTemplate.Execute(response, confirmEmailPage)
	if err != nil {
		panic(err)
	}
}

func HandleRegister(response http.ResponseWriter, request *http.Request) {
	err := formTemplate.Execute(response, registrationPage)
	if err != nil {
		panic(err)
	}
}

func HandleConfirmEmailCode(response http.ResponseWriter, request *http.Request) {
	emailCode := request.URL.Query().Get("c")
	if ConfirmEmailCode(emailCode) {
		err := formTemplate.Execute(response, confirmedEmailPage)
		if err != nil {
			panic(err)
		}
	} else {
		err := formTemplate.Execute(response, linkExpired)
		if err != nil {
			panic(err)
		}
	}
}

func HandlePasswordResetCode(response http.ResponseWriter, request *http.Request) {
	resetCode := request.URL.Query().Get("c")
	if resetCode != "" && IsValidResetCode(resetCode) {
		customResetPage := resetPage
		customResetPage.FormAction += fmt.Sprintf("?c=%s", resetCode)
		err := formTemplate.Execute(response, customResetPage)
		if err != nil {
			panic(err)
		}
	} else {
		err := formTemplate.Execute(response, linkExpired)
		if err != nil {
			panic(err)
		}
	}
}

func HandleResendConfirmation(response http.ResponseWriter, request *http.Request) {
	if !IsValidSession(request) && PendingEmailApproval(request) {
		if ResendConfirmationEmail(request) {
			err := formTemplate.Execute(response, resendConfirmationPage)
			if err != nil {
				panic(err)
			}
		} else {
			err := formTemplate.Execute(response, linkExpired)
			if err != nil {
				panic(err)
			}
		}

	} else {
		http.Redirect(response, request, "/", http.StatusSeeOther)
	}
}

func HandleIsUsernameTaken(response http.ResponseWriter, request *http.Request) {
	if !IsValidNewUsername(request.URL.Query().Get("u")) {
		response.WriteHeader(400)
		fmt.Fprint(response, `Username taken.`)
	} else {
		response.WriteHeader(200)
		fmt.Fprint(response, `Username available.`)
	}
}

func HandleAddMFA(response http.ResponseWriter, request *http.Request) {
	MfaEnrol(response, request)
}

//////////////////////////////////////////////////////////////////////////////
// Form Submissions

func HandleSubLogin(response http.ResponseWriter, request *http.Request) {
	LoginSubmission(response, request)
}

func HandleSubRegister(response http.ResponseWriter, request *http.Request) {
	if IsValidNewEmail(request.FormValue("email")) {
		RegisterSubmission(response, request)
	} else {
		err := formTemplate.Execute(response, emailTakenPage)
		if err != nil {
			panic(err)
		}
	}
}

func HandleSubResetRequest(response http.ResponseWriter, request *http.Request) {
	email := request.FormValue("email")
	if ResetPasswordRequest(email) {
		err := formTemplate.Execute(response, resetSentPage)
		if err != nil {
			panic(err)
		}
	} else {
		err := formTemplate.Execute(response, resetNotSentPage)
		if err != nil {
			panic(err)
		}
	}
}

func HandleSubReset(response http.ResponseWriter, request *http.Request) {
	if ResetSubmission(request) {
		err := formTemplate.Execute(response, resetSuccessPage)
		if err != nil {
			panic(err)
		}
	} else {
		response.WriteHeader(400)
		fmt.Fprint(response, `400 - Invalid request.`)
	}
}

func HandleSubOTP(response http.ResponseWriter, request *http.Request) {
	MfaSubmission(response, request)
}

func HandleSubMFAValidate(response http.ResponseWriter, request *http.Request) {
	MfaValidate(response, request)
}
