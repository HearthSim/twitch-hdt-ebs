import base64
import datetime
import json

import jwt
import requests


DEFAULT_TIMEOUT = 60
DEFAULT_PUBSUB_TIMEOUT = 5


class TwitchClient:
	API_ROOT = "https://api.twitch.tv"
	API_EBS_ROOT = API_ROOT + "/extensions"
	API_EXTENSION_REQUIRED_CONFIGURATION = (
		API_EBS_ROOT + "/{client_id}/{version}/required_configuration"
	)
	EBS_SEND_MESSAGE = API_EBS_ROOT + "/message/{channel_id}"

	USER_AGENT = "HearthSim.TwitchClient/0.0"

	def __init__(
		self, client_id: str, client_secret: str, owner_user_id: str, jwt_ttl: int = 120
	) -> None:
		self.client_id = client_id
		self.client_secret = base64.b64decode(client_secret)
		self.owner_user_id = owner_user_id
		self.jwt_ttl = jwt_ttl
		self.jwt_algorithm = "HS256"
		self.pubsub_perms = {"send": ["*"]}

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
		endpoint = self.EBS_SEND_MESSAGE.format(channel_id=channel_id)
		authorization = self.get_ebs_authorization(channel_id)

		data = {
			"content_type": "application/json",
			"message": json.dumps(message),
			"targets": ["broadcast"],
		}

		return self.post(endpoint, data, authorization=authorization, timeout=timeout)

	def set_extension_required_configuration(
		self, version: str, channel_id: str, value: str
	) -> requests.Response:
		endpoint = self.API_EXTENSION_REQUIRED_CONFIGURATION.format(
			client_id=self.client_id, version=version
		)
		params = {"channel_id": channel_id}
		data = {"required_configuration": value}
		authorization = self.get_ebs_authorization(channel_id)

		return self.put(endpoint, data=data, params=params, authorization=authorization)

	def get_headers(self, authorization: str) -> dict:
		headers = {
			"Client-Id": self.client_id,
			"User-Agent": self.USER_AGENT,
		}

		if authorization:
			headers["Authorization"] = authorization

		return headers

	def post(
		self, url: str, data: dict, params: dict = None,
		authorization: str = "", timeout: int = DEFAULT_TIMEOUT
	) -> requests.Response:
		headers = self.get_headers(authorization)
		return requests.post(url, params=params, headers=headers, json=data, timeout=timeout)

	def put(
		self, url: str, data: dict, params: dict = None,
		authorization: str = "", timeout: int = DEFAULT_TIMEOUT
	) -> requests.Response:
		headers = self.get_headers(authorization)
		return requests.put(url, params=params, headers=headers, json=data, timeout=timeout)
