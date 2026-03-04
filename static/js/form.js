document.getElementById("orgInput").addEventListener("input", showOrgs)

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