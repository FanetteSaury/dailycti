#!/bin/bash
# DailyCTI -- scrape, compose, send
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$DIR")"

if [ ! -f "$DIR/.env" ]; then
    echo "ERROR: demo/.env not found"
    echo "  cp demo/.env.example demo/.env && nano demo/.env"
    exit 1
fi

[ -f "$ROOT/.venv/bin/activate" ] && source "$ROOT/.venv/bin/activate"

python "$DIR/scrape_feeds.py"
python "$DIR/compose_newsletter.py"
python "$DIR/send_newsletter.py"
