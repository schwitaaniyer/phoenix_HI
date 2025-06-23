const menu_btn = document.querySelector(".menu-icon");
const menu_list = document.querySelector(".menu-list");
console.log("hi")


menu_btn.addEventListener("click", () => {
    console.log("Hello")
    menu_btn.classList.toggle("toggle")
    menu_list.classList.toggle("menu_list_toggle")
});

