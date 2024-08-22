import base64
import datetime
import json
from typing import Dict, List

import jwt
import requests

from twitch_hdt_ebs.utils import get_twitch_app_access_token


DEFAULT_TIMEOUT = 60
DEFAULT_PUBSUB_TIMEOUT = 5


class TwitchClient:
	API_ROOT = "https://api.twitch.tv/helix"
	API_EXTENSION_REQUIRED_CONFIGURATION = (
		API_ROOT + "/extensions/required_configuration"
	)
	API_EXTENSION_CONFIGURATIONS = (
		API_ROOT + "/extensions/configurations"
	)
	API_GET_STREAMS = API_ROOT + "/streams"
	API_GET_USERS = API_ROOT + "/users"
	API_GET_VIDEOS = API_ROOT + "/videos"
	EBS_SEND_MESSAGE = API_ROOT + "/extensions/pubsub"

	USER_AGENT = "HearthSim.TwitchClient/0.0"

	def __init__(
		self, client_id: str, client_secret: str, owner_user_id: str, jwt_ttl: int = 120
	) -> None:
		self.client_id = client_id
		self.client_secret = base64.b64decode(client_secret)
		self.owner_user_id = owner_user_id
		self.jwt_ttl = jwt_ttl
		self.jwt_algorithm = "HS256"
		self.pubsub_perms = {"send": ["broadcast"]}

	def sign_jwt(self, exp: int, channel_id: str, role: str = "external") -> bytes:
		payload = {
			"exp": exp,
			"user_id": self.owner_user_id,
			"role": role,
			"channel_id": channel_id,
		}
		if self.pubsub_perms:
			payload["pubsub_perms"] = self.pubsub_perms

		return jwt.encode(payload, self.client_secret, self.jwt_algorithm)

	def get_ebs_authorization(self, channel_id) -> str:
		exp = int(datetime.datetime.now().timestamp()) + self.jwt_ttl
		signed_jwt = self.sign_jwt(exp, channel_id).decode("utf-8")

		return f"Bearer {signed_jwt}"

	def send_pubsub_message(
		self, channel_id: str, message: dict, timeout: int = DEFAULT_PUBSUB_TIMEOUT
	):
		endpoint = self.EBS_SEND_MESSAGE
		authorization = self.get_ebs_authorization(channel_id)

		data = {
			"message": json.dumps(message),
			"broadcaster_id": channel_id,
			"target": ["broadcast"],
		}

		return self.post(endpoint, data, authorization=authorization, timeout=timeout)

	def set_extension_required_configuration(
		self, version: str, channel_id: str, value: str
	) -> requests.Response:
		endpoint = self.API_EXTENSION_REQUIRED_CONFIGURATION
		params = {"broadcaster_id": channel_id}
		data = {
			"required_configuration": value,
			"extension_id": self.client_id,
			"extension_version": version
		}
		authorization = self.get_ebs_authorization(channel_id)

		return self.put(endpoint, data=data, params=params, authorization=authorization)

	def set_extension_configuration_segment(
		self, channel_id: str, segment: str, version: str,
	) -> requests.Response:
		endpoint = self.API_EXTENSION_CONFIGURATIONS
		data = {
			"broadcaster_id": channel_id,
			"extension_id": self.client_id,
			"segment": segment,
			"version": str(version),
		}
		authorization = self.get_ebs_authorization(channel_id)

		return self.put(
			endpoint, data=data, authorization=authorization,
			content_type="application/json",
		)

	def get_user_stream(self, user_id: str):
		endpoint = self.API_GET_STREAMS
		authorization = f"Bearer {get_twitch_app_access_token()}"
		params = {
			"user_id": user_id,
			"first": 1,
		}

		return self.get(endpoint, params=params, authorization=authorization)

	def get_users(self, ids: List[str]) -> List[Dict]:
		endpoint = self.API_GET_USERS
		authorization = f"Bearer {get_twitch_app_access_token()}"

		users: List[Dict] = []

		MAX_USERS_PER_REQUEST = 100
		for start in range(0, len(ids), MAX_USERS_PER_REQUEST):
			params = {
				"id": ids[start:start + MAX_USERS_PER_REQUEST],
			}
			response = self.get(endpoint, params=params, authorization=authorization)
			response.raise_for_status()
			json = response.json()
			users = users + json["data"]

		return users

	def get_user_videos(self, user_id: str):
		endpoint = self.API_GET_VIDEOS
		authorization = f"Bearer {get_twitch_app_access_token()}"
		params = {
			"user_id": user_id,
			"first": 1,
			"period": "day",
			"sort": "time"
		}

		return self.get(endpoint, params=params, authorization=authorization)

	def get_headers(self, authorization: str) -> dict:
		headers = {
			"Client-Id": self.client_id,
			"User-Agent": self.USER_AGENT,
		}

		if authorization:
			headers["Authorization"] = authorization

		return headers

	def get(
		self, url: str, params: dict = None,
		authorization: str = "", timeout: int = DEFAULT_TIMEOUT
	) -> requests.Response:
		headers = self.get_headers(authorization)
		return requests.get(url, params=params, headers=headers, timeout=timeout)

	def post(
		self, url: str, data: dict, params: dict = None,
		authorization: str = "", timeout: int = DEFAULT_TIMEOUT
	) -> requests.Response:
		headers = self.get_headers(authorization)
		return requests.post(url, params=params, headers=headers, json=data, timeout=timeout)

	def put(
		self, url: str, data: dict, params: dict = None,
		authorization: str = "", timeout: int = DEFAULT_TIMEOUT,
		content_type=None,
	) -> requests.Response:
		headers = self.get_headers(authorization)
		if content_type is not None:
			headers["Content-Type"] = content_type
		return requests.put(url, params=params, headers=headers, json=data, timeout=timeout)
