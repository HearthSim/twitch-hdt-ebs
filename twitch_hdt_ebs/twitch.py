import jwt


class TwitchClient:
	def __init__(self, client_id, client_secret):
		self.client_id = client_id
		self.client_secret = client_secret
		self.jwt_algorithm = "HS256"

	def sign_jwt(self, exp, user_id, role="external"):
		payload = {"exp": exp, "user_id": user_id, "role": role}
		return jwt.encode(payload, self.client_secret, self.jwt_algorithm)
