from django.conf import settings
from django.utils.timezone import now
from jwt import encode as jwt_encode
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.serializers import CharField, Serializer
from rest_framework.status import HTTP_400_BAD_REQUEST
from rest_framework.views import APIView


class JWTSignInputSerializer(Serializer):
	client_id = CharField()

	def validate_client_id(self, data):
		if data not in settings.JWTSIGNER_APPLICATIONS:
			raise ValidationError("No such application")
		return data


class JWTSignView(APIView):
	def get_user_id(self):
		return "NotImplemented"

	def get_expiry(self):
		return int(now().timestamp()) + settings.JWTSIGNER_JWT_TTL_SECONDS

	def post(self, request, format=None):
		serializer = JWTSignInputSerializer(data=request.data)
		if serializer.is_valid():
			client_id = serializer.validated_data["client_id"]
			secret = settings.JWTSIGNER_APPLICATIONS[client_id]
			assert secret
		else:
			return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

		payload = {
			"exp": self.get_expiry(),
			"user_id": self.get_user_id(),
			"role": "external",
		}

		encoded_jwt = jwt_encode(payload, secret, algorithm="HS256")

		return Response({"jwt": encoded_jwt, "payload": payload})
