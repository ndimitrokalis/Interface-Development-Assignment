// My own custom Js

document.addEventListener("DOMContentLoaded", function () {
    const dateInput = document.getElementById("date");
    const eventSelect = document.getElementById("event");

    function toggleInputs() {
        if (dateInput.value) {
            eventSelect.disabled = true;
        } else {
            eventSelect.disabled = false;
        }

        if (eventSelect.value) {
            dateInput.disabled = true;
        } else {
            dateInput.disabled = false;
        }
    }

    dateInput.addEventListener("change", toggleInputs);
    eventSelect.addEventListener("change", toggleInputs);
});

document.addEventListener("DOMContentLoaded", function () {
    let currentUrl = window.location.pathname;
    let navLinks = document.querySelectorAll(".profile-nav a");

    navLinks.forEach(link => {
        if (link.getAttribute("href") === currentUrl) {
            link.classList.add("active");
        } else {
            link.classList.remove("active");
        }
    });
});
