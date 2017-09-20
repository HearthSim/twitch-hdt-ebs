"""
URL Configuration
"""

from django.conf.urls import url

from . import views


urlpatterns = [
	url(r"^setup/$", views.ExtensionSetupView.as_view(), name="ebs_setup"),
]
