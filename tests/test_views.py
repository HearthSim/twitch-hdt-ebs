from unittest.mock import patch

from django.core.cache import caches
from django.test import override_settings

from twitch_hdt_ebs.twitch import TwitchClient


def test_config_view(client):
	response = client.post("/config/")

	assert response.status_code == 403


def test_setup_view(client):
	response = client.post("/setup/")

	assert response.status_code == 403


def test_send_view(client):
	response = client.post("/send/")

	assert response.status_code == 401


def mock_authentication(mocker):
	def set_user_id(request, view):
		request.twitch_user_id = "1"
		return True
	mocker.patch(
		"twitch_hdt_ebs.views.CanPublishToTwitchChannel.has_permission",
		side_effect=set_user_id
	)

	def set_client_id(request, view):
		request.twitch_client_id = "1a"
		return True
	mocker.patch(
		"twitch_hdt_ebs.views.HasValidTwitchClientId.has_permission",
		side_effect=set_client_id
	)

	class MockUser:
		is_authenticated = True
		settings = {}
		id = 1
		username = "MockUser"
	mocker.patch(
		"oauth2_provider.contrib.rest_framework.authentication.OAuth2Authentication.authenticate",
		side_effect=lambda x: (MockUser, "xxx")
	)


@override_settings(
	EBS_APPLICATIONS={
		"1a": {
			"secret": "eA==",
			"owner_id": "1",
			"ebs_client_id": "y",
		}
	},
	CACHES={
		"default": {
			"BACKEND": "django.core.cache.backends.locmem.LocMemCache"
		}
	},
	CACHE_READONLY=False,
)
def test_game_start(requests_mock, mocker, client):
	TWITCH_USER_ID = 1

	DECK_LIST = [
		[268, 2, 2], [306, 1, 1], [459, 2, 2], [559, 1, 1], [667, 1, 1], [724, 2, 2],
		[757, 2, 2], [1117, 2, 2], [41217, 2, 2], [41247, 1, 1], [41323, 2, 2], [41418, 1, 1],
		[42442, 2, 2], [45265, 2, 2], [45707, 2, 2], [46461, 1, 1], [47014, 2, 2],
		[48158, 1, 1], [48487, 1, 1],
	]

	DECK_LIST_FLAT = [
		268, 268, 306, 459, 459, 559, 667, 724, 724, 757, 757, 1117, 1117, 41217, 41217, 41247,
		41323, 41323, 41418, 42442, 42442, 45265, 45265, 45707, 45707, 46461, 47014, 47014,
		48158, 48487
	]

	requests_mock.post(TwitchClient.EBS_SEND_MESSAGE, status_code=204)

	mock_authentication(mocker)

	response = client.post(
		"/send/",
		{
			"type": "game_start",
			"data": {
				"deck": {
					"hero": 930,
					"format": 1,
					"cards": DECK_LIST,
				},
				"game_type": 2,
				"rank": None,
				"legend_rank": 1337,
			},
			"version": 3
		},
		content_type="application/json",
		HTTP_CONTENT_TYPE="application/json",
		HTTP_AUTHORIZATION="Bearer xxx",
		HTTP_X_TWITCH_USER_ID=TWITCH_USER_ID,
		HTTP_X_TWITCH_CLIENT_ID=1,
	)

	assert response.status_code == 200

	body = response.json()
	assert body["status"] == 204

	stored = caches["default"].get(f"twitch_hdt_live_id_{TWITCH_USER_ID}")
	assert stored
	assert stored["hero"] == 930
	assert stored["format"] == 1
	assert stored["game_type"] == 2
	assert stored["rank"] is None
	assert stored["legend_rank"] == 1337
	assert stored["deck"] == DECK_LIST_FLAT


@override_settings(
	EBS_APPLICATIONS={
		"1a": {
			"secret": "eA==",
			"owner_id": "1",
			"ebs_client_id": "y",
		}
	},
	CACHES={
		"default": {
			"BACKEND": "django.core.cache.backends.locmem.LocMemCache"
		},
		"live_stats": {
			"BACKEND": "django_redis.cache.RedisCache",
			"LOCATION": "redis://redis:6379/0",
			"OPTIONS": {
				"REDIS_CLIENT_CLASS": "fakeredis.FakeStrictRedis"
			}
		}
	},
	CACHE_READONLY=False,
)
def test_get_active_channels(client, requests_mock, mocker):
	mock_authentication(mocker)
	cache = caches["live_stats"]

	client = cache.client.get_client()
	client.set("a", "b")
	r = client.get("a")

	cache.set("twitch_hdt_live_id_123", {
		"deck": [],
		"hero": "foo",
		"format": 1,
		"rank": "bar",
		"legend_rank": 0,
		"game_type": 1,
		"twitch_user_id": 123,
	}, timeout=1200)
	cache.set("twitch_hdt_live_id_456", {
		"deck": [],
		"hero": "foo",
		"format": "bar",
		"rank": "bronze",
		"legend_rank": 0,
		"game_type": 1,
		"twitch_user_id": 456,
	}, timeout=1200)

	response = client.get("/active-channels/")

	assert response.status_code == 200
	assert response.json() == [
		{
			"is_live": True
		}
	]


@override_settings(
	EBS_APPLICATIONS={
		"1a": {
			"secret": "eA==",
			"owner_id": "1",
			"ebs_client_id": "y",
		}
	},
	CACHES={
		"default": {
			"BACKEND": "django.core.cache.backends.locmem.LocMemCache"
		}
	},
	CACHE_READONLY=False,
)
def test_live_check_on_active_user(client, requests_mock, mocker):
	mock_authentication(mocker)

	stream_data = {
		"id": "41375541868",
		"user_id": "459331509",
		"user_login": "auronplay",
		"user_name": "auronplay",
		"game_id": "494131",
		"game_name": "Little Nightmares",
		"type": "live",
		"title": "hablamos y le damos a Little Nightmares 1",
		"viewer_count": 78365,
		"started_at": "2021-03-10T15:04:21Z",
		"language": "es",
		"thumbnail_url": "https://static-cdn.jtvnw.net/previews-ttv/live_user_auronplay-{width}x{height}.jpg",
		"tag_ids": [
			"d4bb9c58-2141-4881-bcdc-3fe0505457d1"
		],
		"is_mature": False
	}
	requests_mock.get(
		"https://api.twitch.tv/helix/streams?user_id=13579",
		json={
			"data": [stream_data],
			"pagination": {}
		},
		headers={"date": "2018-11-14T21:30:00Z"}
	)

	response = client.get("/live-check/13579")

	assert response.status_code == 200
	assert response.json() == {
		"is_live": True
	}


@override_settings(
	EBS_APPLICATIONS={
		"1a": {
			"secret": "eA==",
			"owner_id": "1",
			"ebs_client_id": "y",
		}
	},
	CACHES={
		"default": {
			"BACKEND": "django.core.cache.backends.locmem.LocMemCache"
		}
	},
	CACHE_READONLY=False,
)
def test_live_check_on_inactive_user(client, requests_mock, mocker):
	mock_authentication(mocker)

	requests_mock.get(
		"https://api.twitch.tv/helix/streams?user_id=13579",
		json={
			"data": [],
			"pagination": {}
		},
		headers={"date": "2018-11-14T21:30:00Z"}
	)

	response = client.get("/live-check/13579")

	assert response.status_code == 200
	assert response.json() == {
		"is_live": False
	}


@override_settings(
	EBS_APPLICATIONS={
		"1a": {
			"secret": "eA==",
			"owner_id": "1",
			"ebs_client_id": "y",
		}
	},
	CACHES={
		"default": {
			"BACKEND": "django.core.cache.backends.locmem.LocMemCache"
		}
	},
	CACHE_READONLY=False,
)
def test_get_vod_url(client, requests_mock, mocker):
	mock_authentication(mocker)

	vod_data = {
		"id": "335921245",
		"title": "Twitch Developers 101",
		"created_at": "2018-11-14T21:30:18Z",
		"url": "https://www.twitch.tv/videos/335921245",
		"viewable": "public",
		"view_count": 1863062,
		"language": "en",
		"duration": "3m21s"
	}
	requests_mock.get(
		"https://api.twitch.tv/helix/videos?user_id=13579",
		json={
			"data": [vod_data],
			"pagination": {}
		},
		headers={"date": "2018-11-14T21:30:00Z"}
	)

	response = client.get("/current-vod/13579")

	assert response.status_code == 200
	assert response.json() == {
		"id": "335921245",
		"url": "https://www.twitch.tv/videos/335921245",
		"language": "en",
		"created_at": "2018-11-14T21:30:18Z",
		"date": "2018-11-14T21:30:00Z"
	}


def test_ping_view(client):
	response = client.get("/ping/")

	assert response.status_code == 200
	assert response.content == b"OK"
