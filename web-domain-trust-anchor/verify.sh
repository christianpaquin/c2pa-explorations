#!/bin/bash

# Check if a file was provided as an argument
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <file>"
    exit 1
fi

# The file provided as an argument
FILE="$1"

# Get the manifest
c2patool "$FILE" > "${FILE}.manifest.json"

# Get the cert chain
c2patool --certs "$FILE" > "${FILE}.certs.pem"

# check origin
node check-origin.js --manifest "${FILE}.manifest.json" --certs "${FILE}.certs.pem"