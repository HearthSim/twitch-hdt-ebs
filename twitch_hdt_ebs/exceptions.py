import logging

import requests
from hearthsim.instrumentation.django_influxdb import write_point
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.views import exception_handler


class TwitchAPITimeout(APIException):
	status_code = status.HTTP_504_GATEWAY_TIMEOUT
	default_detail = "The Twitch API timed out."
	default_code = "twitch_api_timeout"


class BadGateway(APIException):
	# We'd prefer to return a 502 here, but unfortunately Cloudflare will replace
	# any response with that status code with it's own error page. So we simply fall
	# back to a less specific 500 here.
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "Bad Gateway"
	default_code = "bad_gateway"


class BadTwitchResponse(BadGateway):
	default_detail = "Twitch returned an invalid response."
	default_code = "bad_twitch_response"


def untapped_django_exception_handler(exc, context):
	"""A Django REST Framework "custom exception handler" for translating additional types.

	This implementation attempts to convert upstream exception types corresponding to HTTP
	502 (Bad gateway) and HTTP 504 (Gateway timeout) before delegating to the default
	exception handler implementation.

	See also
	https://www.django-rest-framework.org/api-guide/exceptions/#custom-exception-handling

	:param exc:
	:param context:
	"""

	if isinstance(exc, requests.Timeout):
		effective_exc = TwitchAPITimeout()
	elif (
		isinstance(exc, requests.ConnectionError) or
		isinstance(exc, requests.HTTPError)
	):
		effective_exc = BadGateway()
	else:
		effective_exc = exc

	detail = getattr(exc, "detail", {})

	logger = logging.getLogger("twitch_hdt_ebs")
	logger.error("Got exception %r, detail=%r", exc, detail)

	if detail and isinstance(detail, dict):
		write_point("api_error", {"count": 1}, error=detail.get("error", "unknown"))

	return exception_handler(effective_exc, context)
