import os

from twitch_hdt_ebs.settings import *  # noqa


SECRET_KEY = "hunter2"
DEBUG = True

DEFAULT_FILE_STORAGE = "django.core.files.storage.FileSystemStorage"
STATICFILES_STORAGE = "django.contrib.staticfiles.storage.StaticFilesStorage"
CHAT_BOT_API_SECRET_KEY = "A123B123C123D123E123"

DATABASES = {
	"default": {
		"ENGINE": "django.db.backends.postgresql",
		"NAME": "postgres",
		"USER": "postgres",
		"PASSWORD": "",
		"HOST": "localhost",
		"PORT": os.environ.get("PGPORT", 5432),
	},
}

DJANGO_REDIS_CONNECTION_FACTORY = "tests.utils.FakeConnectionFactory"

CACHES = {
	"default": {
		"BACKEND": "django_redis.cache.RedisCache",
		"LOCATION": "redis://localhost:6379/0",
		"OPTIONS": {
			"REDIS_CLIENT_CLASS": "fakeredis.FakeStrictRedis",
		}
	}
}
