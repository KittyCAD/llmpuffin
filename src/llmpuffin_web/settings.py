"""Django settings for llmpuffin."""

import os

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-insecure-key-change-in-prod")
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "llmpuffin",
    "llmpuffin_web",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "llmpuffin_web.urls"

_PG_CONNSTRING = os.environ.get("LLMPUFFIN_POSTGRES", "postgresql://localhost:5434/llmpuffin")

# Parse postgresql://host:port/dbname
_parts = _PG_CONNSTRING.replace("postgresql://", "").split("/")
_host_port = _parts[0] if _parts else "localhost:5434"
_dbname = _parts[1] if len(_parts) > 1 else "llmpuffin"
_host, _, _port = _host_port.partition(":")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": _dbname,
        "HOST": _host or "localhost",
        "PORT": _port or "5434",
    },
}

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
