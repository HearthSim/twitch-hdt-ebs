"""
URL Configuration
"""
from django.urls import path
from django.views.generic import RedirectView

from . import views


urlpatterns = [
	path("", RedirectView.as_view(
		url="https://github.com/hearthsim/twitch-hdt-ebs", permanent=False
	)),
	path("config/", views.SetConfigView.as_view(), name="ebs_config"),
	path("setup/", views.ExtensionSetupView.as_view(), name="ebs_setup"),
	path("send/", views.PubSubSendView.as_view(), name="ebs_pubsub_send"),
	path("ping/", views.PingView.as_view()),
]
