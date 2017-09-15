from jwtsigner.settings import *  # noqa


SECRET_KEY = "hunter2"
DEBUG = True

DEFAULT_FILE_STORAGE = "django.core.files.storage.FileSystemStorage"
STATICFILES_STORAGE = "django.contrib.staticfiles.storage.StaticFilesStorage"


DATABASES = {
	"default": {
		"ENGINE": "django.db.backends.postgresql",
		"NAME": "hsreplaynet",
		"USER": "postgres",
		"PASSWORD": "",
		"HOST": "localhost",
		"PORT": "",
	},
}
