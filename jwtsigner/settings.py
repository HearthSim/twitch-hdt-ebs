"""
Django settings for jwtsigner project.
"""


INSTALLED_APPS = [
	"django.contrib.auth",
	"django.contrib.contenttypes",
	"django.contrib.sessions",
	"rest_framework",
	"hearthsim_identity.accounts",
	"hearthsim_identity.api",
]

MIDDLEWARE = [
	"django.middleware.security.SecurityMiddleware",
	"django.contrib.sessions.middleware.SessionMiddleware",
	"django.middleware.common.CommonMiddleware",
	"django.middleware.csrf.CsrfViewMiddleware",
	"django.contrib.auth.middleware.AuthenticationMiddleware",
	"django.contrib.messages.middleware.MessageMiddleware",
	"django.middleware.clickjacking.XFrameOptionsMiddleware",
]

TEMPLATES = []
AUTH_PASSWORD_VALIDATORS = []

WSGI_APPLICATION = "jwtsigner.wsgi.application"
ROOT_URLCONF = "jwtsigner.urls"

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


# Fill in local_settings.py
JWTSIGNER_APPLICATIONS = {}
JWTSIGNER_JWT_TTL_SECONDS = 120


try:
	from jwtsigner.local_settings import *  # noqa
except ImportError as e:
	# Make sure you have a `local_settings.py` file in the same directory as `settings.py`.
	# We raise a verbose error because the file is *required* in production.
	raise RuntimeError("A `local_settings.py` file could not be found or imported. (%s)" % e)
