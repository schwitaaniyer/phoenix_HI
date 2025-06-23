console.log("line one")

const themeToggleBtn = document.getElementById('themeToggleBtn');


themeToggleBtn.addEventListener('click', function () {
    localStorage.setItem('theme', 'dark');
    document.body.classList.toggle('dark-mode');
    localStorage.setItem('theme', 'light');
    
});

function darkmode (){
    let getTheme = localStorage.getItem('theme');
    if (getTheme == 'dark'){
        document.body.classList.toggle('dark-mode');
    }
    
}

darkmode()