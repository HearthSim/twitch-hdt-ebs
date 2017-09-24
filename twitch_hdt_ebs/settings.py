"""
Django configuration

https://docs.djangoproject.com/en/1.11/topics/settings/
"""


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
	"hearthsim_identity.accounts",
	"hearthsim_identity.api",
	"hearthsim_identity.oauth2",
]

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

TEMPLATES = []
AUTH_PASSWORD_VALIDATORS = []

WSGI_APPLICATION = "twitch_hdt_ebs.wsgi.application"
ROOT_URLCONF = "twitch_hdt_ebs.urls"

AUTH_USER_MODEL = "accounts.User"


LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_L10N = False
USE_TZ = True


# Disable DRF browsable API (it requires templates to be setup)
REST_FRAMEWORK = {
	"DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer", ),
}

OAUTH2_PROVIDER_APPLICATION_MODEL = "oauth2.Application"


# Fill in local_settings.py
EBS_APPLICATIONS = {}
EBS_JWT_TTL_SECONDS = 120


try:
	from twitch_hdt_ebs.local_settings import *  # noqa
except ImportError as e:
	# Make sure you have a `local_settings.py` file in the same directory as `settings.py`.
	# We raise a verbose error because the file is *required* in production.
	raise RuntimeError("A `local_settings.py` file could not be found or imported. (%s)" % e)
