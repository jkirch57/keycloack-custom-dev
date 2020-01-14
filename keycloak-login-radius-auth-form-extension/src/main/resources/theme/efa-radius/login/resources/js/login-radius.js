function togglePasscode(select) {
    if (select.value == "code") {
        document.getElementById("passcodeDiv").style.display = "block";
    } else {
        document.getElementById("passcodeDiv").style.display = "none";
    }
}