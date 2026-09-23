#!/bin/sh
set -eu

cd /app
storage="${STORAGE_DIR:-/data}"
mkdir -p "$storage"

if [ "$(id -u)" = "0" ]; then
  chown node:node "$storage"
  exec su-exec node node src/server.js
fi

exec node src/server.js
