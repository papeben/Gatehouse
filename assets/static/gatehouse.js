var containsUppercase = /[A-Z]+/
var containsLowercase = /[a-z]+/
var containsNumber = /[0-9]+/
var usernameCharacters = /^[A-Za-z0-9_]{1,32}$/
var testEmail = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/

function initGatehouse(){
    initPasswordConf()
    initNewUsername()
    initEmail()
    checkForError()
}

function initPasswordConf(){
    if (document.getElementsByName("passwordConfirm")[0] && document.getElementsByName("password")[0]){ // If password confirmation field, perform new password checks
        
        var passwordInput = document.getElementsByName("password")[0]
        var passwordConfirmInput = document.getElementsByName("passwordConfirm")[0]

        passwordInput.addEventListener("keyup", function(){ // Test password value on each keyup
            let password = passwordInput.value;
            let error = false
            if (!containsNumber.test(password)){
                error = "Password must contain at least one number"
            }
            else if (!containsUppercase.test(password)){
                error = "Password must contain at least one uppercase character"
            }
            else if (!containsLowercase.test(password)){
                error = "Password must contain at least one lowercase character"
            }
            else if (password.length < 8) {
                error = "Password must be at least 8 characters long"
            }

            if (error) {
                createInputError("password", error)
                passwordInput.style.border = `1px solid red`
            }
            else {
                removeInputError("password")
                passwordInput.style.border = `1px solid green`
            }
        })

        passwordConfirmInput.addEventListener("keyup", function(){ // Test passwords match on each change
            let password = passwordInput.value;
            let passwordConfirm = passwordConfirmInput.value;
            let error = false
            if (passwordConfirm != password){
                createInputError("passwordConfirm", "Passwords do not match")
                passwordConfirmInput.style.border = `1px solid red`
            }
            else {
                removeInputError("passwordConfirm")
                passwordConfirmInput.style.border = `1px solid green`
            }
        })
    }
}

function initNewUsername(){ // If new username field, validate it
    if (document.getElementsByName("newUsername")[0]){
        let usernameInput = document.getElementsByName("newUsername")[0]

        usernameInput.addEventListener("change", function(){
            let username = usernameInput.value
            if (!usernameCharacters.test(username)){
                createInputError("newUsername", "Usernames can only use numbers, letters, and underscores.")
                usernameInput.style.border = `1px solid red`
            }
            else {
                fetch(`/gatehouse/usernametaken?u=${username}`, {
                    method: 'GET',
                    headers: { 'Accept': 'text/html' }
                })
                .then(response => {
                    if (response.status === 200) {
                        removeInputError("newUsername")
                        usernameInput.style.border = `1px solid green`
                    } else if (response.status === 400) {
                        createInputError("newUsername", "Username is taken.")
                        usernameInput.style.border = `1px solid red`
                    } else {
                        throw new Error(`Unexpected response status: ${response.status}`);
                    }
                })
                .catch(error => {
                    console.error(`Error checking username availability: ${error}`);
                }); 
            }
        })

        usernameInput.addEventListener("keydown", function(){
            removeInputError("newUsername")
            usernameInput.style.border = null
        })

    }
}

function initEmail(){
    if (document.getElementsByName("email")[0]){
        var emailInput = document.getElementsByName("email")[0]
        emailInput.addEventListener("change", function(){
            let email = emailInput.value
            if (!testEmail.test(email)){
                createInputError("email", "Enter a valid email address")
                emailInput.style.border = `1px solid red`
            }
            else {
                removeInputError("email")
                emailInput.style.border = `1px solid green`
            }
        })
    }
}

function checkForError() {
    var urlParams = new URLSearchParams(window.location.search)
    var error = urlParams.get('error')
    var errorDesc = "An unknown error occurred."
    if (error) {
        switch (error) {
            case "invalid":
                errorDesc = "Invalid Credentials. Please try again."
                break
        } 

        var targetInput = document.getElementsByTagName("form")[0]
        let x = targetInput.getBoundingClientRect().left
        let y = targetInput.getBoundingClientRect().top
        let w = targetInput.getBoundingClientRect().width

        var errorMessage = document.createElement('div')
        errorMessage.innerText = errorDesc
        errorMessage.classList.add("gh_div_err_top")
        errorMessage.style.top = String(y - 100) + "px"
        errorMessage.style.left = String(x) + "px"
        errorMessage.style.width = String(w - 2) + "px"
        document.body.appendChild(errorMessage)
    }
  }

function createInputError(inputName, message, color="red"){
    if (document.getElementsByName(inputName)[0]){
        removeInputError(inputName)

        var targetForm = document.getElementsByTagName("form")[0]
        let tx = targetForm.getBoundingClientRect().left
        let ty = targetForm.getBoundingClientRect().top

        var targetInput = document.getElementsByName(inputName)[0]
        let x = targetInput.getBoundingClientRect().left + targetInput.getBoundingClientRect().width - tx
        let y = targetInput.getBoundingClientRect().top - ty
        let h = targetInput.getBoundingClientRect().height

        let msgFrame = document.createElement("div")
        msgFrame.classList.add("gh_div_err")
        msgFrame.id = `${inputName}-err`
        msgFrame.style.left = String(x + 21) + "px"
        msgFrame.style.top = String(y + 8) + "px"
        msgFrame.innerHTML = message

        targetForm.appendChild(msgFrame)

        let msgLeaderLine = document.createElement("div")
        msgLeaderLine.id = `${inputName}-err-leader`
        msgLeaderLine.style.left = String(x) + "px"
        msgLeaderLine.style.top = String(y + (h/2)) + "px"
        msgLeaderLine.classList.add("gh_div_err_leader")
        targetForm.appendChild(msgLeaderLine)
    }
}

function removeInputError(inputName){
    if (document.getElementById(`${inputName}-err`)){
        document.getElementById(`${inputName}-err`).remove()
    }
    if (document.getElementById(`${inputName}-err-leader`)){
        document.getElementById(`${inputName}-err-leader`).remove()
    }
}

function submitReady(){
    var numErrs = document.getElementsByClassName("gh_div_err").length
    if (numErrs > 0){
        return false
    }
    else {
        return true
    }
}

window.onload = initGatehouse;