document.getElementById("orgInput").addEventListener("input", showOrgs)

function confirmUserDelete() {
    return confirm("Are you sure you want to delete this user?");
}

function confirmOrgDelete() {
    return confirm("Are you sure you want to delete this organization?");
}

function showOrgs() {
    let input = document.getElementById("orgInput")
    if (input.value.length > 0) {
        input.setAttribute("list", "orgOptions")
    } else {
        input.removeAttribute("list")
    }
}