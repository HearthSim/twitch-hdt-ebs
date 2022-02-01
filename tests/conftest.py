import pytest
from django.contrib.auth import get_user_model


@pytest.yield_fixture(scope="function")
def user(db):
	return get_user_model().objects.create_user("Test#1234", email="test_user@example.com")
