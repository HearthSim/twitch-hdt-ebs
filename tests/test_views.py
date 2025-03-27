import pytest
from django.core.cache import caches
from django.test import override_settings
from django_hearthstone.cards.models import Card
from shortuuid.main import int_to_string
from tests import settings

from twitch_hdt_ebs.twitch import TwitchClient
from twitch_hdt_ebs.views import ActiveChannelsView


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


class TestActiveChannelView:

	def test_generate_digest_from_deck_list(self):
		view = ActiveChannelsView()

		assert view.generate_digest_from_deck_list(["CS2_005", "CS2_012"]) == \
			"b17757abcc45e8c5d6b12650725263a6"

	def test_generate_digest_from_deck_list_with_sideboard(self):
		view = ActiveChannelsView()

		assert view.generate_digest_from_deck_list(
			["CS2_005", "CS2_012"],
			sideboard={"ETC_080": ["OG_042", "OG_133", "BOT_424"]}
		) == "897160eabea1d92662e629942f65cfa0"

	@pytest.mark.django_db
	def test_get_shortid_from_deck_list(self):
		create_card(1050, "CS2_005", "Claw")
		create_card(64, "CS2_012", "Swipe")

		view = ActiveChannelsView()

		assert view.get_shortid_from_deck_list([1050, 64]) == int_to_string(
			int("b17757abcc45e8c5d6b12650725263a6", 16),
			ActiveChannelsView.ALPHABET
		)

	@pytest.mark.django_db
	def test_get_shortid_from_deck_list_with_sideboard(self):
		create_card(1050, "CS2_005", "Claw")
		create_card(64, "CS2_012", "Swipe")
		create_card(90749, "ETC_080", "E.T.C., Band Manager")
		create_card(38312, "OG_042", "Y'Shaarj, Rage Unbound")
		create_card(38496, "OG_133", "N'Zoth, the Corruptor")
		create_card(48625, "BOT_424", "Mecha'thun")

		view = ActiveChannelsView()

		assert view.get_shortid_from_deck_list(
			[1050, 64],
			sideboard={90749: [38312, 38496, 48625]}
		) == int_to_string(
			int("897160eabea1d92662e629942f65cfa0", 16),
			ActiveChannelsView.ALPHABET
		)

	@pytest.mark.django_db
	def test_to_deck_url(self):
		create_card(1050, "CS2_005", "Claw")
		create_card(64, "CS2_012", "Swipe")

		view = ActiveChannelsView()

		assert view.to_deck_url([1050, 64], "test-channel-login") == (
			"https://hsreplay.net/decks/WzWNuLVn9DWW7D6bZpl2yf/?utm_source=twitch&"
			"utm_medium=chatbot&utm_content=test-channel-login"
		)

	@pytest.mark.django_db
	def test_to_deck_url_with_sideboard(self):
		create_card(1050, "CS2_005", "Claw")
		create_card(64, "CS2_012", "Swipe")
		create_card(90749, "ETC_080", "E.T.C., Band Manager")
		create_card(38312, "OG_042", "Y'Shaarj, Rage Unbound")
		create_card(38496, "OG_133", "N'Zoth, the Corruptor")
		create_card(48625, "BOT_424", "Mecha'thun")

		view = ActiveChannelsView()

		assert view.to_deck_url(
			[1050, 64],
			"test-channel-login",
			sideboard={90749: [38312, 38496, 48625]}
		) == (
			"https://hsreplay.net/decks/8cUM263xrSr1uiLrXsVvle/?utm_source=twitch&"
			"utm_medium=chatbot&utm_content=test-channel-login"
		)


class TestConfigView:
	def test_unauthenticated_post(self, api_client):
		response = api_client.post("/config/")
		assert response.status_code == 403

	def test_get(self, api_client, user, mocker):
		api_client.force_authenticate(user)
		mock_authentication(mocker)

		user.settings["twitch_ebs"] = {
			"deck_position": "topright",
			"game_offset_horizontal": "",
		}
		user.save()

		response = api_client.get("/config/")

		assert response.status_code == 200
		assert response.json() == {
			"deck_position": "topright",
			"game_offset_horizontal": "0.0",
			"hidden": "0",
			"when_to_show_bobs_buddy": "all",
			"promote_on_hsreplaynet": True,
		}

	def test_put(self, api_client, user, mocker):
		api_client.force_authenticate(user)
		mock_authentication(mocker)

		user.settings["twitch_ebs"] = {}
		user.save()

		response = api_client.put(
			"/config/",
			data={
				"deck_position": "topright",
				"game_offset_horizontal": "-25.5",
			}
		)

		expected = {
			"deck_position": "topright",
			"game_offset_horizontal": "-25.5",
			"hidden": "0",
			"when_to_show_bobs_buddy": "all",
			"promote_on_hsreplaynet": True,
		}

		assert response.status_code == 200
		assert response.json() == expected

		user.refresh_from_db()
		assert user.settings["twitch_ebs"] == expected

	def test_put_invalid(self, api_client, user, mocker):
		api_client.force_authenticate(user)
		mock_authentication(mocker)

		user.settings["twitch_ebs"] = {}
		user.save()

		response = api_client.put(
			"/config/",
			data={
				"game_offset_horizontal": "",
			}
		)

		expected = {
			"deck_position": "topleft",
			"game_offset_horizontal": "0.0",
			"hidden": "0",
			"when_to_show_bobs_buddy": "all",
			"promote_on_hsreplaynet": True,
		}

		assert response.status_code == 200
		assert response.json() == expected

		user.refresh_from_db()
		assert user.settings["twitch_ebs"] == expected


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
	HDT_TWITCH_CLIENT_ID="1a",
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
	HDT_TWITCH_CLIENT_ID="1a",
	CACHE_READONLY=False,
)
def test_get_active_channels(client, mocker, requests_mock):
	mock_authentication(mocker)
	cache = caches["default"]

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

	mocker.patch("twitch_hdt_ebs.twitch.get_twitch_app_access_token", lambda: "xyz")
	requests_mock.get(
		"https://api.twitch.tv/helix/users?id=123",
		json={
			"data": [{
				"id": "123",
				"login": "foo_bar",
			}],
		},
		headers={"date": "2018-11-14T21:30:00Z"}
	)

	cache.set("twitch_hdt_live_id_123", {
		"deck": [
			69623, 69623, 69622, 69622, 65597, 65597, 61171, 61171, 58794, 58794,
			64033, 64033, 69742, 69742, 59556, 59556, 64673, 70202, 70202, 61159,
			61159, 62890, 62890, 70203, 70203, 65645, 70395, 70395, 65599, 66939
		],
		"hero": 930,
		"format": 2,
		"rank": "foo",
		"legend_rank": 0,
		"game_type": 1,
		"twitch_user_id": 123,
	})

	response = client.get(
		"/active-channels/",
		HTTP_X_CHAT_BOT_SECRET_KEY=settings.CHAT_BOT_API_SECRET_KEY
	)

	short_id = "T9ZCF12FeCfBPTe14Jsb0d"
	deck_url = f"https://hsreplay.net/decks/{short_id}/?utm_source=twitch&utm_medium=chatbot&utm_content=foo_bar"
	assert response.status_code == 200
	assert response.json() == [
		{
			"channel_login": "foo_bar",
			"deck_url": deck_url,
			"affiliate_utm": None,
		}
	]

	deck_key = (
		"twitch_ebs:ActiveChannelsView:to_deck_url:"
		"58794,58794,59556,59556,61159,61159,61171,61171,62890,62890,64033,64033,64673,65597,65597,"
		"65599,65645,66939,69622,69622,69623,69623,69742,69742,70202,70202,70203,70203,70395,70395"
	)
	assert cache.get(deck_key) == short_id


@pytest.mark.django_db
@override_settings(
	EBS_APPLICATIONS={
		"1a": {
			"secret": "eA==",
			"owner_id": "1",
			"ebs_client_id": "y",
		}
	},
	HDT_TWITCH_CLIENT_ID="1a",
	CACHE_READONLY=False,
)
def test_get_active_channels_with_cached_deck(client, mocker, requests_mock):
	mock_get_shortid_from_deck_list = mocker.patch(
		"twitch_hdt_ebs.views.ActiveChannelsView.get_shortid_from_deck_list"
	)
	mock_authentication(mocker)
	cache = caches["default"]

	mocker.patch("twitch_hdt_ebs.twitch.get_twitch_app_access_token", lambda: "xyz")
	requests_mock.get(
		"https://api.twitch.tv/helix/users?id=123",
		json={
			"data": [{
				"id": "123",
				"login": "foo_bar",
			}],
		},
		headers={"date": "2018-11-14T21:30:00Z"}
	)

	cache.set("twitch_hdt_live_id_123", {
		"deck": [
			69623, 69623, 69622, 69622, 65597, 65597, 61171, 61171, 58794, 58794,
			64033, 64033, 69742, 69742, 59556, 59556, 64673, 70202, 70202, 61159,
			61159, 62890, 62890, 70203, 70203, 65645, 70395, 70395, 65599, 66939,
		],
		"hero": 930,
		"format": 2,
		"rank": "foo",
		"legend_rank": 0,
		"game_type": 1,
		"twitch_user_id": 123,
	})

	short_id = "T9ZCF12FeCfBPTe14Jsb0d"
	deck_url = f"https://hsreplay.net/decks/{short_id}/?utm_source=twitch&utm_medium=chatbot&utm_content=foo_bar"
	deck_key = "58794,58794,59556,59556,61159,61159,61171,61171,62890,62890,64033,64033,64673,65597,65597," \
		"65599,65645,66939,69622,69622,69623,69623,69742,69742,70202,70202,70203,70203,70395,70395"
	cache.set(deck_key, short_id)

	response = client.get(
		"/active-channels/",
		HTTP_X_CHAT_BOT_SECRET_KEY=settings.CHAT_BOT_API_SECRET_KEY
	)

	assert response.status_code == 200
	assert response.json() == [
		{
			"channel_login": "foo_bar",
			"deck_url": deck_url,
			"affiliate_utm": None,
		}
	]
	mock_get_shortid_from_deck_list.assert_not_called()


@pytest.mark.django_db
@override_settings(
	EBS_APPLICATIONS={
		"1a": {
			"secret": "eA==",
			"owner_id": "1",
			"ebs_client_id": "y",
		}
	},
	HDT_TWITCH_CLIENT_ID="1a",
	CACHE_READONLY=False,
)
def test_get_active_channels_for_bgs_game(client, mocker, requests_mock):
	mock_authentication(mocker)
	cache = caches["default"]

	mocker.patch("twitch_hdt_ebs.twitch.get_twitch_app_access_token", lambda: "xyz")
	requests_mock.get(
		"https://api.twitch.tv/helix/users?id=123",
		json={
			"data": [{
				"id": "123",
				"login": "foo_bar",
			}],
		},
		headers={"date": "2018-11-14T21:30:00Z"}
	)

	cache.set("twitch_hdt_live_id_123", {
		"deck": [],
		"hero": 0,
		"format": 0,
		"rank": "foo",
		"legend_rank": 0,
		"game_type": 2,
		"twitch_user_id": 123,
	})

	response = client.get(
		"/active-channels/",
		HTTP_X_CHAT_BOT_SECRET_KEY=settings.CHAT_BOT_API_SECRET_KEY
	)

	assert response.status_code == 200
	assert response.json() == [
		{
			"channel_login": "foo_bar",
			"deck_url": None,
			"affiliate_utm": None,
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
	HDT_TWITCH_CLIENT_ID="1a",
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
