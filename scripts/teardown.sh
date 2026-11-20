#!/usr/bin/env bash
# Stop the lab and remove the images it pulled.
set -e
cd "$(dirname "$0")/.."
docker compose down
docker rmi node:22.14.0-bookworm-slim 2>/dev/null || true
echo "Lab torn down. (node:22-bookworm-slim kept — shared/patched base image.)"
