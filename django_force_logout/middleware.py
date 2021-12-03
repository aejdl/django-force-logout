import datetime

from django.contrib import auth
from django.utils.deprecation import MiddlewareMixin

from . import app_settings
from .utils import from_dotted_path

class ForceLogoutMiddleware(MiddlewareMixin):
    SESSION_KEY = 'force-logout:last-login'

    def __init__(self, get_response=None):
        self.fn = app_settings.CALLBACK

        if not callable(self.fn):
            self.fn = from_dotted_path(app_settings.CALLBACK)

        self.get_response = get_response

    def process_request(self, request):
        if not request.user.is_authenticated:
            return

        user_timestamp = self.fn(request.user)
        if user_timestamp is None:
            return

        if request.user.last_login > user_timestamp:
            return

        auth.logout(request)
