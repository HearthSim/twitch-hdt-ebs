import requests
from django.core.cache import caches

from twitch_hdt_ebs import serializers, settings
from twitch_hdt_ebs.exceptions import BadTwitchResponse


TWITCH_API_TOKEN_CACHE_KEY = "twitch_api_oauth_access_token"


def get_twitch_app_access_token() -> str:
	cache = caches["default"]

	cached_key = cache.get(TWITCH_API_TOKEN_CACHE_KEY)

	if cached_key is not None:
		return cached_key

	response = requests.post(
		"https://id.twitch.tv/oauth2/token",
		params={
			"client_id": list(settings.EBS_APPLICATIONS.keys())[0],
			"client_secret": settings.HDT_TWITCH_API_CLIENT_SECRET,
			"grant_type": "client_credentials",
		},
		headers={
			"User-Agent": settings.TWITCH_USER_AGENT,
		}
	)

	if not response.ok:
		raise BadTwitchResponse()

	payload = response.json()
	serializer = serializers.TwitchOAuthTokenResponseSerializer(data=payload)
	if not serializer.is_valid():
		raise BadTwitchResponse()

	if serializer.validated_data["token_type"] != "bearer":
		raise BadTwitchResponse()

	access_token = serializer.validated_data["access_token"]
	expires_in = serializer.validated_data["expires_in"]
	ttl = max(expires_in - 30, 0)  # allow for up to 30 seconds drift
	cache.set(TWITCH_API_TOKEN_CACHE_KEY, access_token, timeout=ttl)

	return access_token
