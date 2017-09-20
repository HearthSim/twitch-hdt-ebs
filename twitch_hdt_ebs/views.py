from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import CharField, DictField, Serializer
from rest_framework.views import APIView

from .twitch import TwitchClient


class HasValidTwitchClientId(BasePermission):
	def has_permission(self, request, view):
		client_id = request.META.get("HTTP_X_TWITCH_CLIENT_ID", "")
		if not client_id:
			raise ValidationError({"detail": "Missing X-Twitch-Client-Id header"})

		if client_id not in settings.EBS_APPLICATIONS:
			raise ValidationError({"detail": "Invalid Twitch Client ID: {}".format(client_id)})

		request.twitch_client_id = client_id
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
				"code": "channel_not_allowed",
				"detail": "No permission for channel {user_id}".format(user_id=repr(user_id)),
				"available_channels": request.available_channels,
			})
			return False

		request.twitch_user_id = user_id
		return True


class PubSubMessageSerializer(Serializer):
	type = CharField()
	data = DictField()


class BaseTwitchAPIView(APIView):
	authentication_classes = (OAuth2Authentication, )
	permission_classes = (
		IsAuthenticated, CanPublishToTwitchChannel, HasValidTwitchClientId,
	)

	def get_twitch_client(self):
		config = settings.EBS_APPLICATIONS[self.request.twitch_client_id]
		return TwitchClient(
			self.request.twitch_client_id, config["secret"], config["owner_id"],
			jwt_ttl=settings.EBS_JWT_TTL_SECONDS
		)


class PubSubSendView(BaseTwitchAPIView):
	serializer_class = PubSubMessageSerializer

	def post(self, request, format=None):
		twitch_client = self.get_twitch_client()
		serializer = self.serializer_class(data=request.data)
		serializer.is_valid(raise_exception=True)

		data = {
			"type": serializer.validated_data["type"],
			"data": serializer.validated_data["data"],
		}
		resp = twitch_client.send_pubsub_message(self.request.twitch_user_id, data)

		return Response({
			"status": resp.status_code,
			"content_type": resp.headers.get("content-type"),
			"content": resp.content,
		})


class ExtensionSetupView(BaseTwitchAPIView):
	def post(self, request, format=None):
		twitch_client = self.get_twitch_client()

		version = request.META.get("HTTP_X_TWITCH_EXTENSION_VERSION", "")
		if not version:
			raise ValidationError({"detail": "Missing X-Twitch-Extension-Version header"})

		value = "COMPLETE"

		resp = twitch_client.set_extension_required_configuration(
			version=version, value=value, channel_id=self.request.twitch_user_id
		)

		if resp.status_code > 299:
			return Response(resp.json(), status=resp.status_code)

		return Response({"required_configuration": value})
