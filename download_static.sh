#!/bin/bash

# Create directories if they don't exist
mkdir -p static/css
mkdir -p static/js

# Download Bootstrap CSS
curl -o static/css/bootstrap.min.css https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css

# Download Font Awesome CSS
curl -o static/css/fontawesome.min.css https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css

# Download jQuery
curl -o static/js/jquery.min.js https://code.jquery.com/jquery-3.6.0.min.js

# Download Bootstrap Bundle JS
curl -o static/js/bootstrap.bundle.min.js https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js 