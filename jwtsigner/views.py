from django.conf import settings
from django.http import Http404, HttpResponse
from django.utils.decorators import method_decorator
from django.utils.timezone import now
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from jwt import encode as jwt_encode


@method_decorator(csrf_exempt, name="dispatch")
class JWTSignView(View):
	def get_user_id(self):
		return "NotImplemented"

	def get_expiry(self):
		return int(now().timestamp()) + settings.JWTSIGNER_JWT_TTL_SECONDS

	def post(self, request, application):
		app = settings.JWTSIGNER_APPLICATIONS.get(application)
		if not app:
			raise Http404("No such application: %r" % (application))

		payload = {
			"exp": self.get_expiry(),
			"user_id": self.get_user_id(),
			"role": "external",
		}
		secret = app["secret"]
		assert secret

		encoded_jwt = jwt_encode(payload, secret, algorithm="HS256")

		return HttpResponse(encoded_jwt)
