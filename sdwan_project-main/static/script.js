
function fetchFiles() {

    $.ajax({
        url: '/api/files/',
        type: 'GET',
        dataType: 'json',
        success: function(data) {
            console.log('Received data:', data); // Log the received data
            updateServiceDropdown(data.services);
            updateZoneDropdown(data.zones);
        },
        error: function(error) {
            console.error('Error fetching files:', error);
        }
    });
}

function updateServiceDropdown(files) {

    const dropdown = document.getElementById('serviceDropdown');
    updateDropdown(dropdown, files);
}

function updateZoneDropdown(directories) {

    const dropdown = document.getElementById('zoneDropdown');
    updateDropdown(dropdown, directories);
}

function updateDropdown(dropdown, items) {

    dropdown.innerHTML = '';


    items.forEach(item => {
        const optionElement = document.createElement('option');
        optionElement.value = item;
        optionElement.textContent = item;
        dropdown.appendChild(optionElement);
    });
}

fetchFiles();
