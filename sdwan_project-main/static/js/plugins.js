const menu_btn = document.querySelector(".menu-icon");
const menu_list = document.querySelector(".menu-list");
const nav_home_logo = document.querySelector(".nav-home-logo");
const toggle_btn = document.querySelector(".theme_button");
var theme_button = document.querySelector(".theme_button");


//this code is for toggling the menu list in left side
// menu_btn.addEventListener("click", () => {
//     menu_btn.classList.toggle("toggle")
//     menu_list.classList.toggle("menu_list_toggle")
// });


//this code is for on click on home button to redirect on the home page
nav_home_logo.addEventListener("click", ()=>{
    window.location.href = "http://221.171.85.50:8000/home";
})

//this code is for dark and light theme mode
const theme = localStorage.getItem('theme');
if (theme) {
    document.body.classList.add('dark-mode');
    theme_button.classList.add('theme_button_left');
}
toggle_btn.addEventListener("click", () => {
    theme_button.classList.toggle("theme_button_left");
    document.body.classList.toggle("dark-mode");
    if (document.body.classList.contains("dark-mode")){
        localStorage.setItem('theme', 'dark-mode');
    }else {
        localStorage.removeItem('theme');
    }
    
})