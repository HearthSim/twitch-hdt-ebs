import base64
import hashlib
import json
import logging
import string
from typing import Any, Dict, List

import jwt
from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from django.core.cache import caches
from django.db import transaction
from django.http import HttpResponse
from django.views.generic import View
from django_hearthstone.cards.models import Card
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
from shortuuid.main import int_to_string

from .exceptions import TwitchAPITimeout
from .permissions import HasApiSecretKey
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
	authentication_classes = [OAuth2Authentication]
	permission_classes = [
		IsAuthenticated, CanPublishToTwitchChannel, HasValidTwitchClientId,
	]

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
		else:
			self.heartbeat_deck_data()

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

	def cache_deck_data(self, data, version: int) -> bool:
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

		cache_key = f"twitch_hdt_live_id_{self.request.twitch_user_id}"
		caches["default"].set(cache_key, {
			"deck": cards_list,
			"hero": deck_data.get("hero"),
			"format": deck_data.get("format"),
			"rank": data.get("rank"),
			"legend_rank": data.get("legend_rank", 0),
			"game_type": data.get("game_type", 0),
			"twitch_user_id": self.request.twitch_user_id,
		}, timeout=120)

		return True

	def heartbeat_deck_data(self):
		if settings.CACHE_READONLY:
			# Refuse to write in read-only mode
			return False

		cache_key = f"twitch_hdt_live_id_{self.request.twitch_user_id}"
		caches["default"].touch(cache_key, timeout=120)


class ExtensionSetupView(BaseTwitchAPIView):
	authentication_classes = [TwitchJWTAuthentication]

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
	authentication_classes = [TwitchJWTAuthentication]
	serializer_class = ConfigSerializer
	settings_key = "twitch_ebs"

	def get(self, request, format=None):
		user_settings = request.user.settings.get(self.settings_key, {})
		serializer = self.serializer_class(instance=user_settings)
		return Response(serializer.data)

	def put(self, request, format=None):
		serializer = self.serializer_class(data=request.data)
		serializer.is_valid(raise_exception=True)

		with transaction.atomic():
			request.user.refresh_from_db()
			request.user.settings[self.settings_key] = serializer.validated_data
			request.user.save()

		return self.get(request)


class ActiveChannelsView(APIView):
	authentication_classes: List[Any] = []
	permission_classes = [HasApiSecretKey]

	ALPHABET = string.ascii_letters + string.digits
	CARDS_MAP_CACHE: Dict[int, str] = {}

	def generate_digest_from_deck_list(self, id_list: List[str]) -> str:
		sorted_cards = sorted(id_list)
		m = hashlib.md5()
		m.update(",".join(sorted_cards).encode("utf-8"))
		return m.hexdigest()

	def get_shortid_from_digest(self, digest: str) -> str:
		return int_to_string(int(digest, 16), ActiveChannelsView.ALPHABET)

	def get_shortid_from_deck_list(self, cards: List[int]) -> str:
		card_list: List[str] = []
		for dbf_id in cards:
			card_id = self.CARDS_MAP_CACHE.get(dbf_id)
			if not card_id:
				card = Card.objects.get(dbf_id=dbf_id)
				card_id = card.card_id
				self.CARDS_MAP_CACHE[dbf_id] = card.card_id
			card_list.append(str(card_id))
		digest = self.generate_digest_from_deck_list(card_list)
		return self.get_shortid_from_digest(digest)

	def to_deck_url(self, card_list: List[int], channel_login) -> str:
		deck_key = ",".join(sorted([str(dbfid) for dbfid in card_list]))

		short_id = caches["default"].get(deck_key)
		if not short_id:
			short_id = self.get_shortid_from_deck_list(card_list)
			caches["default"].set(deck_key, short_id, timeout=1200)

		utm_params = f"utm_source=twitch&utm_medium=chatbot&utm_content={channel_login}"
		return f"https://hsreplay.net/decks/{short_id}/?{utm_params}"

	def get_twitch_client(self) -> TwitchClient:
		client_id = settings.HDT_TWITCH_CLIENT_ID
		config = settings.EBS_APPLICATIONS[client_id]
		return TwitchClient(
			client_id, config["secret"], config["owner_id"],
			jwt_ttl=settings.EBS_JWT_TTL_SECONDS
		)

	def get(self, request):
		cache = caches["default"]
		twitch_client = self.get_twitch_client()

		# Need direct client access for keys list
		client = cache.client.get_client()
		data = []

		all_details = []
		for k in client.keys(":*:twitch_hdt_live_id_*"):
			details = cache.get(k.decode()[3:])

			if details and "twitch_user_id" in details:
				all_details.append(details)

		twitch_user_ids = []
		for details in all_details:
			twitch_user_ids.append(details["twitch_user_id"])

		# Fetch all the channel names from Twitch API
		users = twitch_client.get_users(ids=twitch_user_ids)

		# Pivot the user list
		users_by_id = {
			str(user["id"]): user for user in users
			if "id" in user
		}

		for details in all_details:
			twitch_user_id = details["twitch_user_id"]

			twitch_account = users_by_id.get(str(twitch_user_id))

			if not twitch_account or not twitch_account.get("login"):
				# Maybe it was deleted since or something
				continue

			channel_login = twitch_account["login"]
			deck_cards = details.get("deck")
			deck_url = self.to_deck_url(deck_cards, channel_login) if deck_cards else None

			data.append({
				"channel_login": channel_login,
				"deck_url": deck_url
			})

		return Response(status=200, data=data)


class LiveCheckView(BaseTwitchAPIView):
	serializer_class = PubSubMessageSerializer

	def get(self, request, user_id) -> Response:
		twitch_client = self.get_twitch_client()

		try:
			resp = twitch_client.get_user_stream(user_id)
		except Timeout:
			raise TwitchAPITimeout()

		write_point(
			"live_check_request",
			{"count": 1},
			user_id=user_id,
			status_code=resp.status_code
		)

		data = {
			"is_live": False
		}
		if resp.status_code == 200:
			json = resp.json()
			data["is_live"] = len(json.get("data", [])) > 0

		return Response(
			status=resp.status_code,
			headers=resp.headers,
			data=data
		)


class CurrentVodView(BaseTwitchAPIView):
	serializer_class = PubSubMessageSerializer

	def get(self, request, user_id) -> Response:
		twitch_client = self.get_twitch_client()

		try:
			resp = twitch_client.get_user_videos(user_id)
		except Timeout:
			raise TwitchAPITimeout()

		write_point(
			"get_videos_request",
			{"count": 1},
			user_id=user_id,
			status_code=resp.status_code
		)

		data = resp.content
		if resp.status_code == 200:
			json = resp.json()
			if len(json.get("data", [])) > 0:
				video = json["data"][0]
				data = {
					"id": video["id"],
					"url": video["url"],
					"language": video["language"],
					"created_at": video["created_at"],
					"date": resp.headers.get("date")
				}

		return Response(
			status=resp.status_code,
			headers=resp.headers,
			data=data
		)


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
