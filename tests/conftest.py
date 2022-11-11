import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient


@pytest.fixture(scope="function")
def api_client():
	return APIClient()


@pytest.yield_fixture(scope="function")
def user(db):
	return get_user_model().objects.create_user("Test#1234", email="test_user@example.com")
