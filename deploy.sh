#!/bin/bash

# Build the WASM module
wasm-pack build --target web

# Copy the HTML file to the pkg directory
cp index.html pkg/

# Create a simple server configuration for GitHub Pages
echo '{
  "rewrites": [
    { "source": "**", "destination": "/index.html" }
  ]
}' > pkg/_redirects 