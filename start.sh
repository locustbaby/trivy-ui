#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Build frontend
cd "$SCRIPT_DIR/trivy-dashboard"
echo "Building Vue frontend..."
npm run build

# Start backend server
cd "$SCRIPT_DIR/go-server"
echo "Starting Go server..."
go run .