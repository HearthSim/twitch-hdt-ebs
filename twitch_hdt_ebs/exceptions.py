from rest_framework import status
from rest_framework.exceptions import APIException


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
