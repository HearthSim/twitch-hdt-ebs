import os
from twitch_hdt_ebs.settings import *  # noqa


SECRET_KEY = "hunter2"
DEBUG = True

DEFAULT_FILE_STORAGE = "django.core.files.storage.FileSystemStorage"
STATICFILES_STORAGE = "django.contrib.staticfiles.storage.StaticFilesStorage"


DATABASES = {
	"default": {
		"ENGINE": "django.db.backends.postgresql",
		"NAME": "test_hdt_ebs",
		"USER": "postgres",
		"PASSWORD": "",
		"HOST": "localhost",
		"PORT": os.environ.get("PGPORT", 5432),
	},
}

DJANGO_REDIS_CONNECTION_FACTORY = "tests.utils.FakeConnectionFactory"

CACHES = {
	"default": {
		"BACKEND": "django.core.cache.backends.locmem.LocMemCache"
	},
	"live_stats": {
		"BACKEND": "django_redis.cache.RedisCache",
		"LOCATION": "redis://localhost:6379/0",
		"OPTIONS": {
			"REDIS_CLIENT_CLASS": "fakeredis.FakeStrictRedis",
		}
	}
}
