from rest_framework import status
from rest_framework.exceptions import APIException


class TwitchAPITimeout(APIException):
	status_code = status.HTTP_504_GATEWAY_TIMEOUT
	default_detail = "The Twitch API timed out."
	default_code = "twitch_api_timeout"
