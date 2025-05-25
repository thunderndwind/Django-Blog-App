#!/bin/bash
set -o errexit

# Load production environment variables
if [ "$DJANGO_PRODUCTION" = "true" ]; then
    set -a
    source .env.production
    set +a
fi

pip install -r requirements.txt

cd src

# Create static directory if it doesn't exist
mkdir -p static

# Run migrations
python manage.py makemigrations
python manage.py migrate --noinput

# Collect static files
python manage.py collectstatic --no-input

# Start Gunicorn
cd ..
gunicorn --config gunicorn_config.py --chdir src config.wsgi:application
