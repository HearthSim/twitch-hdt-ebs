"""
Django configuration

https://docs.djangoproject.com/en/2.0/topics/settings/
"""

import os

from hearthsim.instrumentation.ssm import get_secure_parameters


if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
	import raven
	from raven.transport import HTTPTransport

	DEBUG = False
	ALLOWED_HOSTS = [
		".twitch-ebs.hearthsim.net",
		".execute-api.{region}.amazonaws.com".format(
			region=os.environ.get("AWS_REGION", "us-east-1")
		),
	]
else:
	DEBUG = True
	ALLOWED_HOSTS = ["*"]
	raven = None


params = get_secure_parameters("twitch_ebs", debug=DEBUG)

SECRET_KEY = params.get("DJANGO_SECRET_KEY", "<local>")

WSGI_APPLICATION = "twitch_hdt_ebs.wsgi.application"
ROOT_URLCONF = "twitch_hdt_ebs.urls"
AUTH_USER_MODEL = "accounts.User"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_L10N = False
USE_TZ = True

INSTALLED_APPS = [
	"django.contrib.auth",
	"django.contrib.contenttypes",
	"django.contrib.sessions",
	"django.contrib.sites",
	"allauth.account",
	"allauth.socialaccount",
	"oauth2_provider",
	"rest_framework",
	"corsheaders",
	"hearthsim.identity.accounts",
	"hearthsim.identity.oauth2",
]

if raven:
	INSTALLED_APPS.append("raven.contrib.django.raven_compat")
	RAVEN_CONFIG = {
		"dsn": params.get("SENTRY_RAVEN_DSN", ""),
		"transport": HTTPTransport,
	}


MIDDLEWARE = [
	"django.middleware.security.SecurityMiddleware",
	"django.contrib.sessions.middleware.SessionMiddleware",
	"corsheaders.middleware.CorsMiddleware",
	"django.middleware.common.CommonMiddleware",
	"django.middleware.csrf.CsrfViewMiddleware",
	"django.contrib.auth.middleware.AuthenticationMiddleware",
	"django.contrib.messages.middleware.MessageMiddleware",
	"django.middleware.clickjacking.XFrameOptionsMiddleware",
]

DATABASES = {
	"default": {
		"ENGINE": "django.db.backends.postgresql",
		"NAME": params.get("DJANGO_DB_NAME", "hsreplaynet"),
		"USER": params.get("DJANGO_DB_USER", "postgres"),
		"PASSWORD": params.get("DJANGO_DB_PASSWORD", ""),
		"HOST": params.get("DJANGO_DB_HOST", "localhost"),
		"PORT": 5432,
	},
}

CACHE_READONLY = bool(int(params.get("REDIS_READONLY", 0)))
CACHES = {
	"default": {
		"BACKEND": "django_redis.cache.RedisCache",
		"LOCATION": params.get("REDIS_CACHE_URL", "redis://127.0.0.1:6379/1"),
		"OPTIONS": {
			"CLIENT_CLASS": "django_redis.client.DefaultClient",
			"COMPRESSOR": "django_redis.compressors.zlib.ZlibCompressor",
			"SERIALIZER": "django_redis.serializers.json.JSONSerializer",
			"SOCKET_CONNECT_TIMEOUT": 3,
			"SOCKET_TIMEOUT": 3,
		}
	}
}

TEMPLATES: list = []
AUTH_PASSWORD_VALIDATORS: list = []


# Disable DRF browsable API (it requires templates to be setup)
REST_FRAMEWORK = {
	"DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer", ),
	"EXCEPTION_HANDLER": "twitch_hdt_ebs.views.exception_handler",
}

# DRF CORS handling
CORS_ALLOW_METHODS = ("OPTIONS", "GET", "POST", "PUT")
CORS_ORIGIN_REGEX_WHITELIST = (r"^https://(\w+)\.ext-twitch\.tv$", )
CORS_ALLOW_HEADERS = (
	"accept",
	"accept-encoding",
	"authorization",
	"content-type",
	"dnt",
	"origin",
	"user-agent",
	"x-requested-with",
	"x-twitch-client-id",
	"x-twitch-extension-version",
	"x-twitch-user-id",
)

OAUTH2_PROVIDER_APPLICATION_MODEL = "oauth2.Application"


# Should this be moved to the db?
EBS_APPLICATIONS = {
	params.get("HDT_TWITCH_CLIENT_ID", ""): {
		"secret": params.get("HDT_TWITCH_SECRET_KEY", ""),
		"owner_id": params.get("HDT_TWITCH_OWNER_ID", ""),
		"ebs_client_id": params.get("HDT_EBS_CLIENT_ID", ""),
	}
}
EBS_JWT_ALGORITHMS = ["HS256"]
EBS_JWT_TTL_SECONDS = 120
EBS_JWT_VERIFY = not DEBUG


INFLUX_ENABLED = not DEBUG
INFLUX_DATABASES = {
	"default": {
		"database": params.get("INFLUX_DB_NAME"),
		"host": params.get("INFLUX_DB_HOST", "localhost"),
		"port": int(params.get("INFLUX_DB_PORT", "8086")),
		"username": params.get("INFLUX_DB_USER"),
		"password": params.get("INFLUX_DB_PASSWORD"),
		"timeout": 2,
		"ssl": True,
		"verify_ssl": True,
	}
}
