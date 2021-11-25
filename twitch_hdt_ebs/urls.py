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
	path("live-check/<int:user_id>", views.LiveCheckView.as_view(), name="ebs_live_check"),
	path("current-vod/<int:user_id>", views.CurrentVodView.as_view(), name="ebs_current_vod"),
	path("ping/", views.PingView.as_view()),

	# Kept for compatibility, drop after update HDT
	path("current_vod/<int:user_id>", views.CurrentVodView.as_view(), name="ebs_vod_url"),
]
