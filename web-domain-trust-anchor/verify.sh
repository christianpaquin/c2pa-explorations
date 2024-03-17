#!/bin/bash

# Check if at least one argument was provided
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <file> [trustList]"
    exit 1
fi

# The file provided as the first argument
FILE="$1"

# Initialize TRUSTLIST variable
TRUSTLIST=""

# Check if a second argument (trustList) was provided
if [ "$#" -eq 2 ]; then
    TRUSTLIST_ARG="$2"
    TRUSTLIST="--trustlist ${TRUSTLIST_ARG}"
fi

# Get the manifest
c2patool "$FILE" > "${FILE}.manifest.json"

# Get the cert chain
c2patool --certs "$FILE" > "${FILE}.certs.pem"

# Check origin with optional trustList
node check-origin.js --manifest "${FILE}.manifest.json" --certs "${FILE}.certs.pem" $TRUSTLIST
