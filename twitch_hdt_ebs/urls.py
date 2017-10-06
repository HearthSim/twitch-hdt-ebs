"""
URL Configuration
"""

from django.conf.urls import url

from . import views


urlpatterns = [
	url(r"^config/$", views.SetConfigView.as_view(), name="ebs_config"),
	url(r"^setup/$", views.ExtensionSetupView.as_view(), name="ebs_setup"),
	url(r"^send/$", views.PubSubSendView.as_view(), name="ebs_pubsub_send"),
]
