from django.test import override_settings

from twitch_hdt_ebs.twitch import TwitchClient


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
def test_get_user_videos(requests_mock):
	data = {
		"data": [
			{
				"id": "335921245",
				"title": "Twitch Developers 101",
				"created_at": "2018-11-14T21:30:18Z",
				"url": "https://www.twitch.tv/videos/335921245",
				"viewable": "public",
				"view_count": 1863062,
				"language": "en",
				"duration": "3m21s"
			}
		],
		"pagination": {}
	}
	requests_mock.post(
		"https://id.twitch.tv/oauth2/token",
		status_code=200,
		json={
			"access_token": "a123b456",
			"expires_in": 123,
			"token_type": "bearer"
		}
	)

	requests_mock.get(
		"https://api.twitch.tv/helix/videos?user_id=13579",
		json=data
	)

	client = TwitchClient("y", "eA==", "1")
	response = client.get_user_videos("13579")

	assert response.status_code == 200
	assert response.json() == data
