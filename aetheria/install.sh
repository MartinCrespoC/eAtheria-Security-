#!/bin/bash
# Thin wrapper — full docs in start.sh
exec "$(dirname "$0")/start.sh" "${1:-prod}"
