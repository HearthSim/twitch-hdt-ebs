import datetime
import json

import jwt
import requests


class TwitchClient:
	API_ROOT = "https://api.twitch.tv"
	API_EBS_ROOT = API_ROOT + "/extensions"
	EBS_SEND_MESSAGE = API_EBS_ROOT + "/message/{channel_id}"

	USER_AGENT = "HearthSim.TwitchClient/0.0"

	def __init__(self, client_id, client_secret, jwt_ttl=120):
		self.client_id = client_id
		self.client_secret = client_secret
		self.jwt_ttl = jwt_ttl
		self.jwt_algorithm = "HS256"

	def sign_jwt(self, exp, user_id, role="external"):
		payload = {"exp": exp, "user_id": user_id, "role": role}
		return jwt.encode(payload, self.client_secret, self.jwt_algorithm)

	def get_ebs_authorization(self, channel_id):
		exp = int(datetime.datetime.now().timestamp()) + self.jwt_ttl
		encoded_jwt = self.sign_jwt(exp, channel_id)
		return "Bearer {jwt}".format(jwt=encoded_jwt.decode("utf-8"))

	def send_pubsub_message(self, channel_id, message):
		endpoint = self.EBS_SEND_MESSAGE.format(channel_id=channel_id)
		authorization = self.get_ebs_authorization(channel_id)

		data = {
			"content_type": "application/json",
			"message": json.dumps(message),
			"targets": ["broadcast"],
		}

		return self.post(endpoint, data, authorization)

	def post(self, url, data, authorization=None):
		headers = {
			"Client-Id": self.client_id,
			"User-Agent": self.USER_AGENT,
		}

		if authorization:
			headers["Authorization"] = authorization

		return requests.post(url, json=data, headers=headers)
