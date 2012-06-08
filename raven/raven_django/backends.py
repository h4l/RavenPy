# Copyright (c) 2012 Hal Blackburn <hwtb2@caret.cam.ac.uk> and 
#                    CARET, University of Cambridge http://www.caret.cam.ac.uk/
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from django.contrib.auth import backends
from django.contrib.auth.models import User
from django.utils.crypto import constant_time_compare
import raven
from raven.raven_django import settings
import logging

LOG = logging.getLogger(__name__)

class RavenBackend(backends.ModelBackend):
    """A Django Authentication backend which uses Raven auth responses to
    authenticate users.
    """

    def _get_validator(self, keys, expected_url):
        if not keys:
            keys = settings.RAVEN_KEYS
        return raven.Validator(keys, expected_post_login_url=expected_url)

    def authenticate(self, raven_response=None, expected_data=None,
            expected_url="", keys_override=None):
        """Gets the user authenticated by a Raven auth response string.
        
        Args:
            raven_response: A Raven auth response string as provided by the
                client in the WLS-Response URL query param.
            expected_data: The authentication will only succeed if the data in 
                the signed response is equal to this value. This can be used to
                protect against "login CSRF" attacks by ensuring a Raven auth 
                response was in response to one originating from the Django app.
            expected_url: If provided, the authentication will only succeed if
                the URL in the auth response matches this argument. Can safely
                be ignored.
            keys_override: A dict of name -> public key mappings to pass to the
                raven.Validator. If not provided the RAVEN_KEYS settings value
                is used. If that has no value then raven.RAVEN_KEYS is used.
        Returns:
            None if the auth response was invalid, or didn't represent a 
            successful authentication, otherwise a User object representing the
            authenticated user.
        Raises:
            ValueError: If raven_response is provided (indicating the auth() 
                request is intended for this method) but no expected_data is
                provided.
        """
        # If no raven_response is set then this authenticate() call must not
        # be meant for us
        if raven_response is None:
            LOG.debug("authenticate() called without raven_response - ignoring")
            return False
        if expected_data is None:
            raise ValueError("No expected_data value provided.")

        validator = self._get_validator(keys_override, expected_url)
        try:
            authresponse = validator.validate(raven_response)
            username = authresponse.get_authenticated_identity()
        except raven.NotAuthenticatedException:
            LOG.warn("Authentication rejected: "
                    "response was valid but did not have success status")
            return None
        except raven.InvalidityException:
            LOG.warn("Authentication rejected: "
                    "response was invalid in some way")
            return None

        # Ensure response data matches expected_data. In order not to leak 
        # information on how much of a string matched, a comparison method is
        # used which takes the same time to determine string equality, 
        # regardless of how much of a string matched.
        if not constant_time_compare(expected_data, authresponse.request_data):
            LOG.warn("Got valid raven response, but the response's data did not"
                    " match the user's per-session secret. This could indicate "
                    "a login CSRF attempt. expected: %s but got: %s" % (
                            expected_data, authresponse.request_data))
            return None

        user, _ = User.objects.get_or_create(username=username)
        LOG.info("Authentication successful. user: %s, raven_response: %s" % (
                user.username, raven_response))
        return user
