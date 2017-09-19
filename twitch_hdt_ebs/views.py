from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from django.utils.timezone import now
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import CharField, Serializer
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED
from rest_framework.views import APIView

from .twitch import TwitchClient


class JWTSignInputSerializer(Serializer):
	client_id = CharField()
	user_id = CharField()

	def validate_client_id(self, data):
		if data not in settings.EBS_APPLICATIONS:
			raise ValidationError("No such application")
		return data


class JWTSignView(APIView):
	authentication_classes = (OAuth2Authentication, )
	permission_classes = (IsAuthenticated, )

	def get_expiry(self):
		return int(now().timestamp()) + settings.EBS_JWT_TTL_SECONDS

	def post(self, request, format=None):
		serializer = JWTSignInputSerializer(data=request.data)
		if serializer.is_valid():
			client_id = serializer.validated_data["client_id"]
			secret = settings.EBS_APPLICATIONS[client_id]
			assert secret
		else:
			return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

		user_id = serializer.validated_data["user_id"]

		available_channels = SocialAccount.objects.filter(
			user=request.user, provider="twitch"
		).values_list("uid", flat=True)

		if user_id not in available_channels:
			error = {
				"error": "Not authorized to publish to channel id %r" % (user_id),
				"available_channels": available_channels,
			}
			return Response([error], status=HTTP_401_UNAUTHORIZED)

		client = TwitchClient(client_id, secret)

		return Response(client.sign_jwt(self.get_expiry(), user_id))