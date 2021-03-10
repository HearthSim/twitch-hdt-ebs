import base64
import json
import logging

import jwt
from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from django.core.cache import caches
from django.http import HttpResponse
from django.views.generic import View
from hearthsim.instrumentation.django_influxdb import write_point
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from oauth2_provider.models import AccessToken
from requests import Timeout
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import (
	AuthenticationFailed, PermissionDenied, ValidationError
)
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from sentry_sdk import set_user

from .exceptions import TwitchAPITimeout
from .serializers import ConfigSerializer, PubSubMessageSerializer
from .twitch import TwitchClient


def _extract_twitch_client_id(request) -> str:
	client_id = request.META.get("HTTP_X_TWITCH_CLIENT_ID", "")
	if not client_id:
		raise ValidationError({"detail": "Missing X-Twitch-Client-Id header"})

	if client_id not in settings.EBS_APPLICATIONS:
		raise ValidationError({"detail": f"Invalid Twitch Client ID: {client_id}"})

	return client_id


class TwitchJWTAuthentication(BaseAuthentication):
	def authenticate(self, request):
		auth_header = request.META.get("HTTP_AUTHORIZATION", "")
		if not auth_header.startswith("Bearer "):
			raise AuthenticationFailed({
				"error": "invalid_authorization",
				"detail": "Invalid Authorization header (Bearer required).",
			})
		token = auth_header[len("Bearer "):].encode("utf-8")

		twitch_client_id = _extract_twitch_client_id(request)
		secret = settings.EBS_APPLICATIONS[twitch_client_id]["secret"]
		decoded_secret = base64.b64decode(secret)

		try:
			payload = jwt.decode(
				token,
				decoded_secret,
				algorithms=settings.EBS_JWT_ALGORITHMS,
				options={
					"require_exp": True,
					"verify_exp": True
				}
			)
		except jwt.exceptions.DecodeError as e:
			raise AuthenticationFailed({"error": "invalid_jwt", "detail": str(e)})
		except jwt.exceptions.ExpiredSignatureError as e:
			raise AuthenticationFailed({"error": "expired_signature", "detail": str(e)})

		expected_keys = ("user_id", "channel_id", "role")
		for k in expected_keys:
			if k not in payload:
				raise AuthenticationFailed({"error": "missing_payload_key", "detail": k})

		if payload["role"] != "broadcaster":
			raise AuthenticationFailed({"error": "unauthorized_role", "detail": payload["role"]})

		try:
			twitch_account = SocialAccount.objects.get(provider="twitch", uid=payload["user_id"])
		except SocialAccount.DoesNotExist:
			raise AuthenticationFailed({"error": "account_not_linked", "detail": payload["user_id"]})

		return twitch_account.user, twitch_account


class HasValidTwitchClientId(BasePermission):
	def has_permission(self, request, view):
		request.twitch_client_id = _extract_twitch_client_id(request)
		return True


class CanPublishToTwitchChannel(BasePermission):
	def has_permission(self, request, view):
		user_id = request.META.get("HTTP_X_TWITCH_USER_ID", "")
		if not user_id:
			raise ValidationError({"detail": "Missing X-Twitch-User-Id header"})

		request.available_channels = list(SocialAccount.objects.filter(
			user=request.user, provider="twitch"
		).values_list("uid", flat=True))

		if user_id not in request.available_channels:
			raise PermissionDenied({
				"error": "channel_not_allowed",
				"detail": user_id,
				"available_channels": request.available_channels,
			})
			return False

		request.twitch_user_id = user_id
		return True


class BaseTwitchAPIView(APIView):
	authentication_classes = (OAuth2Authentication, )
	permission_classes = (
		IsAuthenticated, CanPublishToTwitchChannel, HasValidTwitchClientId,
	)

	def get_twitch_client(self) -> TwitchClient:
		config = settings.EBS_APPLICATIONS[self.request.twitch_client_id]
		return TwitchClient(
			self.request.twitch_client_id, config["secret"], config["owner_id"],
			jwt_ttl=settings.EBS_JWT_TTL_SECONDS
		)

	def get_ebs_client_id(self) -> str:
		config = settings.EBS_APPLICATIONS[self.request.twitch_client_id]
		return config["ebs_client_id"]

	def initial(self, request, *args, **kwargs):
		super().initial(request, *args, **kwargs)

		if request.user.is_authenticated:
			set_user({
				"id": request.user.id,
				"username": request.user.username,
			})


class PubSubSendView(BaseTwitchAPIView):
	serializer_class = PubSubMessageSerializer

	def post(self, request, format=None) -> Response:
		twitch_client = self.get_twitch_client()
		serializer = self.serializer_class(data=request.data)
		serializer.is_valid(raise_exception=True)

		data = serializer.validated_data["data"]
		if serializer.validated_data["type"] == "game_start":
			self.cache_deck_data(data, serializer.validated_data["version"])

		config = ConfigSerializer(instance=request.user.settings.get("twitch_ebs", {}))

		pubsub_data = {
			"type": serializer.validated_data["type"],
			"data": serializer.validated_data["data"],
			"config": config.data,
		}
		try:
			resp = twitch_client.send_pubsub_message(self.request.twitch_user_id, pubsub_data)
		except Timeout:
			raise TwitchAPITimeout()

		write_point(
			"pubsub_message",
			{"count": 1},
			channel_id=self.request.twitch_user_id,
			status_code=resp.status_code,
			message_type=serializer.validated_data["type"]
		)

		return Response(
			status=200 if resp.status_code in (200, 204) else 502,
			data={
				"status": resp.status_code,
				"content_type": resp.headers.get("content-type"),
				"content": resp.content,
			}
		)

	def cache_deck_data(self, data, version: int, timeout: int = 1200) -> bool:
		if version < 3:
			# Discard old HDT versions
			return False

		if settings.CACHE_READONLY:
			# Refuse to write in read-only mode
			return False

		deck_data = data.get("deck", {})

		cards_list = []

		for dbf_id, current, initial in deck_data.get("cards", []):
			for i in range(initial):
				cards_list.append(dbf_id)

		cards_list.sort()

		cache_key = f"twitch_{self.request.twitch_user_id}"
		caches["default"].set(cache_key, {
			"deck": cards_list,
			"hero": deck_data.get("hero"),
			"format": deck_data.get("format"),
			"rank": data.get("rank"),
			"legend_rank": data.get("legend_rank", 0),
			"game_type": data.get("game_type", 0),
			"twitch_user_id": self.request.twitch_user_id,
		}, timeout=timeout)

		return True


class ExtensionSetupView(BaseTwitchAPIView):
	authentication_classes = (TwitchJWTAuthentication, )

	def post(self, request, format=None) -> Response:
		twitch_client = self.get_twitch_client()

		version = request.META.get("HTTP_X_TWITCH_EXTENSION_VERSION", "")
		if not version:
			raise ValidationError({"detail": "Missing X-Twitch-Extension-Version header"})

		authorized_apps = AccessToken.objects.filter(
			user=self.request.user, application__client_id=self.get_ebs_client_id(),
		)
		if not authorized_apps.count():
			raise PermissionDenied({"error": "upstream_client_not_found"})

		value = "COMPLETE"

		try:
			resp = twitch_client.set_extension_required_configuration(
				version=version, value=value, channel_id=self.request.twitch_user_id
			)
		except Timeout:
			raise TwitchAPITimeout()

		if resp.status_code > 299:
			try:
				twitch_data = resp.json()
			except json.JSONDecodeError:
				twitch_data = None

			return Response(
				status=502,
				data={
					"error": "bad_upstream",
					"detail": "Unexpected response from Twitch API.",
					"upstream_data": twitch_data,
					"upstream_status_code": resp.status_code,
				}
			)

		return Response({"required_configuration": value})


class SetConfigView(BaseTwitchAPIView):
	authentication_classes = (TwitchJWTAuthentication, )
	serializer_class = ConfigSerializer
	settings_key = "twitch_ebs"

	def get(self, request, format=None):
		user_settings = request.user.settings.get(self.settings_key, {})
		serializer = self.serializer_class(data=user_settings)
		serializer.is_valid(raise_exception=True)
		return Response(serializer.data)

	def put(self, request, format=None):
		serializer = self.serializer_class(data=request.data)
		if not serializer.is_valid():
			raise ValidationError(serializer.errors)

		request.user.settings[self.settings_key] = serializer.validated_data
		request.user.save()

		return Response(serializer.validated_data)


class PingView(View):
	def get(self, request):
		return HttpResponse("OK", content_type="text/plain")


def exception_handler(exc, context):
	from rest_framework.views import exception_handler as original_handler

	response = original_handler(exc, context)
	detail = getattr(exc, "detail", {})

	logger = logging.getLogger("twitch_hdt_ebs")
	logger.error("Got exception %r, detail=%r", exc, detail)

	if detail and isinstance(detail, dict):
		write_point("api_error", {"count": 1}, error=detail.get("error", "unknown"))

	return response
