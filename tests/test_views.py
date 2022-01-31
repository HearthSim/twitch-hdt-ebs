import pytest
from allauth.socialaccount.models import SocialAccount
from django.core.cache import caches
from django.test import override_settings
from django_hearthstone.cards.models import Card

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


@pytest.mark.django_db
@override_settings(
	EBS_APPLICATIONS={
		"1a": {
			"secret": "eA==",
			"owner_id": "1",
			"ebs_client_id": "y",
		}
	},
	CACHE_READONLY=False,
)
def test_get_active_channels(client, mocker, user):
	mock_authentication(mocker)
	cache = caches["default"]
	ls_cache = caches["live_stats"]

	def create_card(dbf_id, card_id, name):
		Card.objects.create(
			card_id=card_id,
			dbf_id=dbf_id,
			name=name,
			description="",
			flavortext="",
			how_to_earn="",
			how_to_earn_golden="",
			artist="",
		)

	create_card(58794, "SCH_305", "Secret Passage")
	create_card(59556, "SCH_350", "Wand Thief")
	create_card(61159, "DMF_515", "Swindle")
	create_card(61171, "DMF_519", "Prize Plunderer")
	create_card(62890, "BAR_319", "Wicked Stab (Rank 1)")
	create_card(64033, "SW_412", "SI:7 Extortion")
	create_card(64673, "SW_050", "Maestra of the Masquerade")
	create_card(65597, "DED_004", "Blackwater Cutlass")
	create_card(65599, "DED_006", "Mr. Smite")
	create_card(65645, "DED_510", "Edwin, Defias Kingpin")
	create_card(66939, "AV_203", "Shadowcrafter Scabbs")
	create_card(69622, "CORE_EX1_144", "Shadowstep")
	create_card(69623, "CORE_EX1_145", "Preparation")
	create_card(69742, "CORE_KAR_069", "Swashburglar")
	create_card(70202, "AV_710", "Reconnaissance")
	create_card(70203, "AV_711", "Double Agent")
	create_card(70395, "AV_298", "Wildpaw Gnoll")

	SocialAccount.objects.create(
		uid=123,
		user=user,
		provider="twitch",
		extra_data={"login": "foo_bar"}
	)

	ls_cache.set("twitch_hdt_live_id_123", {
		"deck": {
			"hero": 930,
			"format": 2,
			"cards": [
				[69623, 2, 2],
				[69622, 2, 2],
				[65597, 2, 2],
				[61171, 2, 2],
				[58794, 2, 2],
				[64033, 2, 2],
				[69742, 2, 2],
				[59556, 2, 2],
				[64673, 1, 1],
				[70202, 2, 2],
				[61159, 2, 2],
				[62890, 2, 2],
				[70203, 2, 2],
				[65645, 1, 1],
				[70395, 2, 2],
				[65599, 1, 1],
				[66939, 1, 1]
			]
		},
		"hero": 930,
		"format": 2,
		"rank": "foo",
		"legend_rank": 0,
		"game_type": 1,
		"twitch_user_id": 123,
	})

	response = client.get("/active-channels/")

	deck_url = "https://hsreplay.net/decks/T9ZCF12FeCfBPTe14Jsb0d/"
	assert response.status_code == 200
	assert response.json() == [
		{
			"channel_login": "foo_bar",
			"deck_url": deck_url
		}
	]

	deck_key = "58794_2,59556_2,61159_2,61171_2,62890_2,64033_2,64673_1,65597_2," \
		"65599_1,65645_1,66939_1,69622_2,69623_2,69742_2,70202_2,70203_2,70395_2"
	assert cache.get(deck_key) == deck_url


@pytest.mark.django_db
@override_settings(
	EBS_APPLICATIONS={
		"1a": {
			"secret": "eA==",
			"owner_id": "1",
			"ebs_client_id": "y",
		}
	},
	CACHE_READONLY=False,
)
def test_get_active_channels_with_cached_deck(client, mocker, user):
	mock_get_shortid_from_deck_list = mocker.patch(
		"twitch_hdt_ebs.views.ActiveChannelsView.get_shortid_from_deck_list"
	)
	mock_authentication(mocker)
	cache = caches["default"]
	ls_cache = caches["live_stats"]

	SocialAccount.objects.create(
		uid=123,
		user=user,
		provider="twitch",
		extra_data={"login": "foo_bar"}
	)

	ls_cache.set("twitch_hdt_live_id_123", {
		"deck": {
			"hero": 930,
			"format": 2,
			"cards": [
				[69623, 2, 2],
				[69622, 2, 2],
				[65597, 2, 2],
				[61171, 2, 2],
				[58794, 2, 2],
				[64033, 2, 2],
				[69742, 2, 2],
				[59556, 2, 2],
				[64673, 1, 1],
				[70202, 2, 2],
				[61159, 2, 2],
				[62890, 2, 2],
				[70203, 2, 2],
				[65645, 1, 1],
				[70395, 2, 2],
				[65599, 1, 1],
				[66939, 1, 1]
			]
		},
		"hero": 930,
		"format": 2,
		"rank": "foo",
		"legend_rank": 0,
		"game_type": 1,
		"twitch_user_id": 123,
	})

	deck_url = "https://hsreplay.net/decks/T9ZCF12FeCfBPTe14Jsb0d/"
	deck_key = "58794_2,59556_2,61159_2,61171_2,62890_2,64033_2,64673_1,65597_2," \
		"65599_1,65645_1,66939_1,69622_2,69623_2,69742_2,70202_2,70203_2,70395_2"
	cache.set(deck_key, deck_url)

	response = client.get("/active-channels/")

	assert response.status_code == 200
	assert response.json() == [
		{
			"channel_login": "foo_bar",
			"deck_url": deck_url
		}
	]
	mock_get_shortid_from_deck_list.assert_not_called()


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
