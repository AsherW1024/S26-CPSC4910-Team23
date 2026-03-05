const orgInput = document.getElementById("orgInput")
if (orgInput) {
    orgInput.addEventListener("input", showOrgs)
}

const password = document.getElementById("password");
if (password) {
    password.addEventListener("input", checkPassword);
}

const newPassword = document.getElementById("newPassword");
if (newPassword) {
    newPassword.addEventListener("input", checkPassword);
}

function confirmUserDelete() {
    return confirm("Are you sure you want to delete this user?");
}

function confirmOrgDelete() {
    return confirm("Are you sure you want to delete this organization?");
}

function confirmUserRemove() {
    return confirm("Are you sure you want to remove this user?");
}

function promptUserAccept() {
    const message = prompt("Enter a reason for accepting this driver:");

    if (message === null) {return false;}

    if (message.trim() === "") {
        alert("You must enter a reason.");
        return false;
    }

    document.getElementById("acceptReason").value = message;
    return true;
}

function promptUserReject() {
    const message = prompt("Enter a reason for rejecting this driver:");

    if (message === null) {return false;}

    if (message.trim() === "") {
        alert("You must enter a reason.");
        return false;
    }

    document.getElementById("rejectReason").value = message;
    return true;
}

function showOrgs() {
    let input = document.getElementById("orgInput")
    if (input.value.length > 0) {
        input.setAttribute("list", "orgOptions")
    } else {
        input.removeAttribute("list")
    }
}

function checkPassword() {
    const pw = this.value

    const minLength = document.getElementById("minLength")
    const maxLength = document.getElementById("maxLength")
    const upper = document.getElementById("upper")
    const lower = document.getElementById("lower")
    const number = document.getElementById("number")
    const special = document.getElementById("special")

    if (pw.length >= 10) {
        minLength.classList.remove("invalid")
        minLength.classList.add("valid")
    } else {
        minLength.classList.remove("valid")
        minLength.classList.add("invalid")
    }

    if (pw.length > 128) {maxLength.hidden = false} 
    else {maxLength.hidden = true}

    if (/[A-Z]/.test(pw)) {
        upper.classList.remove("invalid")
        upper.classList.add("valid")
    } else {
        upper.classList.remove("valid")
        upper.classList.add("invalid")
    }

    if (/[a-z]/.test(pw)) {
        lower.classList.remove("invalid")
        lower.classList.add("valid")
    } else {
        lower.classList.remove("valid")
        lower.classList.add("invalid")
    }

    if (/[0-9]/.test(pw)) {
        number.classList.remove("invalid")
        number.classList.add("valid")
    } else {
        number.classList.remove("valid")
        number.classList.add("invalid")
    }

    if (/[^a-zA-Z0-9\s]/.test(pw)) {
        special.classList.remove("invalid")
        special.classList.add("valid")
    } else {
        special.classList.remove("valid")
        special.classList.add("invalid")
    }
}