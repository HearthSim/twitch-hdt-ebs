from django.conf import settings
from rest_framework.permissions import BasePermission


class HasApiSecretKey(BasePermission):
    """
    Allows access only to requests with API secret key.
    """

    def has_permission(self, request, view):
        secret_key = request.META.get("HTTP_X_CHAT_BOT_SECRET_KEY")
        return secret_key == settings.CHAT_BOT_API_SECRET_KEY
