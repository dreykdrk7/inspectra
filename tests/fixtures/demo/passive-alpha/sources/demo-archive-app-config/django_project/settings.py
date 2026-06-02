from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DEBUG = True
SECRET_KEY = "super-secret-password"
ALLOWED_HOSTS = ["*"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "demo",
        "USER": "demo",
        "PASSWORD": "super-secret-password",
        "HOST": "db",
        "PORT": "5432",
    }
}

CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False

STATIC_URL = "/static/"
