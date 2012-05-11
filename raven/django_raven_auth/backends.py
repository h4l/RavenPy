from django.contrib.auth import backends
from django.contrib.auth.models import User
import raven
from raven.django_raven_auth import getsetting

class RavenBackend(backends.ModelBackend):
    """A Django Authentication backend which uses Raven auth responses to
    authenticate users.
    """

    def _get_validator(self, keys, expected_url):
        if not keys:
            keys = getsetting("RAVEN_KEYS", raven.RAVEN_KEYS)
        return raven.Validator(keys, expected_post_login_url=expected_url)

    validator = RavenBackend.validator_from_settings()

    def authenticate(self, raven_response=None, expected_url="",
            keys_override=None):
        """Gets the user authenticated by a Raven auth response string.
        
        Args:
            raven_response: A Raven auth response string as provided by the
                client in the WLS-Response URL query param.
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
        """
        validator = self._get_validator(keys_override, expected_url)
        username = validator.get_authenticated_user(raven_response)
        if not username:
            return None

        user, _ = User.objects.get_or_create(username=username)
        return user
