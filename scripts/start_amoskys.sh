#!/bin/bash
echo "��🛡️ Starting AMOSKYS Neural Security Platform..."
cd "$(dirname "$0")"
source venv/bin/activate
cd web
export FLASK_APP=app
export FLASK_ENV=development
python -m flask run --host=0.0.0.0 --port=5000
