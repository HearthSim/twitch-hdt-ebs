"""
jwtsigner URL Configuration
"""

from django.conf.urls import url

from . import views


urlpatterns = [
	url("^sign/$", views.JWTSignView.as_view(), name="jwt_sign"),
]
