import logging
from datetime import datetime

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from influxdb.client import InfluxDBClient


INFLUX_ENABLED = getattr(settings, "INFLUX_ENABLED", False)
_clients = {}


def get_client(name: str="default") -> InfluxDBClient:
	if name not in _clients:
		if not getattr(settings, "INFLUX_DATABASES", None):
			raise ImproperlyConfigured("INFLUX_DATABASES is not configured.")

		if name not in settings.INFLUX_DATABASES:
			raise ValueError("Unknown database: {}".format(name))

		_clients[name] = InfluxDBClient(**settings.INFLUX_DATABASES[name])

	return _clients[name]


def write_point(measurement: str, fields, influx_database: str="default", **tags) -> bool:
	# Set tags to None if it's an empty dict

	if not INFLUX_ENABLED:
		return False

	client = get_client(influx_database)
	tags = tags or None

	payload = {
		"measurement": measurement,
		"tags": tags,
		"fields": fields,
		"time": datetime.now().isoformat(),
	}

	try:
		client.write_points([payload])
	except Exception:
		logging.exception("An exception happened while writing points to InfluxDB.")
		return False

	return True
