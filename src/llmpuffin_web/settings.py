"""Django settings for llmpuffin — loaded from llmpuffin.toml."""

import os

from llmpuffin.config import Config

_config = Config.load()

SECRET_KEY = _config.web.secret_key
DEBUG = _config.web.debug
ALLOWED_HOSTS = _config.web.allowed_hosts

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
    "django.contrib.auth.middleware.LoginRequiredMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

LOGIN_URL = "/admin/login/"

ROOT_URLCONF = "llmpuffin_web.urls"

# Parse postgresql://host:port/dbname from config
_pg_url = os.environ.get("LLMPUFFIN_POSTGRES", _config.postgres.url)
_parts = _pg_url.replace("postgresql://", "").split("/")
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

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "loggers": {
        "llmpuffin": {
            "handlers": ["console"],
            "level": _config.logging.level,
        },
    },
}

# Expose for web management command (runserver port)
LLMPUFFIN_CONFIG = _config
