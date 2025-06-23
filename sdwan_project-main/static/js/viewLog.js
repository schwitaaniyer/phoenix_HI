const menu_btn = document.querySelector(".menu-icon");
const menu_list = document.querySelector(".menu-list");


menu_btn.addEventListener("click", () => {
    menu_btn.classList.toggle("toggle")
    menu_list.classList.toggle("menu_list_toggle")
    
});


/**function sendLog(logType) {
    console.log("clicked");
    console.log(logType);
    
    // Use AJAX to send log_type value to Django view
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "{% url 'log' %}?log_type=" + logType, true);
    xhr.onreadystatechange = function () {
        if ( xhr.status == 200) {
            // Handle the response if needed
            console.log(xhr.responseText);
        } else {
            console.log("some error happening");
        }
    };
    xhr.send();
}
**/

//xhr.readyState == 4 &&