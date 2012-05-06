import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import datetime
import pytz
import urllib
import urlparse

def login_url(post_login_url,
        authservice_url="https://raven.cam.ac.uk/auth/authenticate.html",
        resource_name=None, acceptable_auth_types=["pwd"], message=None,
        reauthenticate=None, data=None):
    """Constructs a login URL for a Ucam-webauth auth service.
    
    Args:
        post_login_url: The URL the auth service should redirect to once the
            user has logged in.
        raven_url: The URL of the auth service which the returned login
            url should point to.
        protocol_version: The version number of the Ucam-webauth protocol to 
            use.
        resource_name: The name of the page or resource which is initiating the
            login request. This is shown to the user as part of their login
            prompt.
        acceptable_auth_types: A list of authentication methods understood by
            the server that are deemed to be acceptable methods of
            authenticating the client.
        message: A message shown to the user as part of their login prompt.
        reauthenticate: Require a re-authentication exchange with the auth
            service if not None. A value of "interactive" requires the user to
            re-authenticate with the auth service (e.g. login). A value of
            "noninteractive" requires the auth service validate the user's
            identity without prompting them to login in any way. If this is not
            possible, the authentication does not succeed.
        data: A string of data which will be included in the authentication
            response passed to the post_login_url. Note that this data is under
            the control of the user.
    Returns:
        A URL which will initiate an authentication exchange when requested by
        a web browser. Typically a website user is redirected to such a URL in
        order to initiate a Raven login.
        
    For more detailed information, see:
        http://raven.cam.ac.uk/project/waa2wls-protocol.txt  
    """
    auth_url = urlparse.urlparse(authservice_url)
    url_params = urlparse.parse_qsl(auth_url.query)

    # Required parameters
    url_params.append(("ver", 2))
    url_params.append(("url", post_login_url))

    # Optional parameters
    if resource_name:
        url_params.append(("desc", resource_name))
    if message:
        url_params.append(("msg", message))
    if acceptable_auth_types and len(acceptable_auth_types) > 0:
        url_params.append(("aauth", ",".join(acceptable_auth_types)))
    if reauthenticate:
        if not reauthenticate in ["interactive", "noninteractive"]:
            raise ValueError(
                    "Unknown reauthenticate type: {0}".format(reauthenticate))
        url_params.append(
                ("iact", "yes" if reauthenticate == "interactive" else "no"))
    if data:
        url_params.append(("params", data))

    return urlparse.urlunparse(
            _replace_query(auth_url, urllib.urlencode(url_params)))

def _replace_query(parsed_url, querystring):
    pieces = list(parsed_url)
    pieces[4] = querystring
    return pieces

class AuthenticationResponseValidator(object):

    def __init__(self, keys, acceptable_auth_types=["pwd"],
            max_timestamp_delta_seconds=datetime.timedelta(seconds=60)):
        self._keys = keys
        self._max_timestamp_delta = max_timestamp_delta_seconds
        self._acceptable_auth_types = set(acceptable_auth_types)

    def _get_signature_verifier(self, response):
        key = self._keys.get(response.key_id)
        if not key:
            raise SignatureInvalidityException("no public key available for "
                    "key_id: {0}".format(response.key_id), response)
        return PKCS1_v1_5.new(key)

    def _verify_response_signature(self, response):
        verifier = self._get_signature_verifier(response)
        response_hash = SHA.new(response.signed_portion)
        if not verifier.verify(response_hash, response.signature):
            raise SignatureInvalidityException(
                    "Response signature was not valid", response)

    def validate(self, response_str, now=None, ignore_signature=False):
        """Validates a WLS-Response string.
        
        This is achieved by verifying the response's cryptographic signature
        
        Args:
            response_str: A WLS-Response string.
            now: A datetime object which if present will be used instead of the
                current time when checking the age of a response. 
        Returns:
            
        """
        response = AuthenticationResponse(response_str)
        # AuthenticationResponse ensures that a successful auth always has a
        # signature. Signatures are optional for unsuccessful responses.
        if response.signature and not ignore_signature:
            self._verify_response_signature(response)

        self._validate_timestamp(response.timestamp,
                now or datetime.datetime.utcnow())
        self._validate_authtypes(response)

        return response

    def _validate_authtypes(self, response):
        if response.auth_type:
            if response.auth_type not in self._acceptable_auth_types:
                raise InvalidityException("Response was authenticated with "
                        "unacceptable auth_type: {0}, acceptable types: {1}"
                        .format(response.auth_type,
                            self._acceptable_auth_types))
        else:
            assert response.origional_auth_types
            previous_types = set(response.origional_auth_types)
            # Fail if any auth types used to validate previously are not 
            # acceptable.
            if not previous_types <= self._acceptable_auth_types:
                raise InvalidityException("One or more authentication methods "
                        "used previously by the client to authenticate are not "
                        "accepted. Previously used methods: {0}, acceptable "
                        "methods: {1}"
                        .format(previous_types, self._acceptable_auth_types))

    def _validate_timestamp(self, timestamp, now):
        "Raises an InvalidityException if timestamp is too far from now."
        delta = max(now, timestamp) - min(now, timestamp)
        if delta > self._max_timestamp_delta:
            raise InvalidityException("timestamp was too far from current time."
                    " delta: {0}, permitted delta: {1}"
                    .format(delta, self._max_timestamp_delta))

class InvalidityException(ValueError):
    pass

class SignatureInvalidityException(InvalidityException):
    pass

class AuthenticationResponse(object):
    "Represents the values contained in a Raven authentication response."

    def __init__(self, responsestr):
        raw_parts = responsestr.split("!")
        if not len(raw_parts) == 13:
            raise InvalidityException("response did not have 13 values split "
                    "by '!'.")

        # The data signed by the RSA signature is the first 11 fields
        self.signed_portion = "!".join(raw_parts[0:11])

        # Values have % and ! characters escaped...
        fields = map(self._raven_unescape, raw_parts)

        self.version = fields.pop(0)
        try:
            status = fields.pop(0)
            self.status = int(status)
        except ValueError:
            raise InvalidityException("Status was not an integer: {0}"
                                      .format(status))
        self.status_description = fields.pop(0)
        self.timestamp = self._parse_raven_date(fields.pop(0))
        self.id = fields.pop(0)
        self.response_url = fields.pop(0)
        self.identity = fields.pop(0)
        self.auth_type = fields.pop(0)
        self.origional_auth_types = self._split_ignore_empty(fields.pop(0), ",")
        self.expiry_timestamp = self._expiry_timestamp(
                self.timestamp, fields.pop(0))
        self.request_data = fields.pop(0)
        self.key_id = fields.pop(0)

        base64sig = self._raven_unescape_b64(fields.pop(0))
        self.signature = base64.b64decode(base64sig)

        self._validate()

    def _split_ignore_empty(self, string, separator):
        "Split string by separator, returning an empty list if string is empty."
        if not string:
            return []
        return string.split(separator)

    def _validate(self):
        """Checks various postconditions to ensure data consistency."""
        if not self.version in ["1", "2"]:
            raise InvalidityException("Unsupported version: {0}"
                    .format(self.version))
        if not self.id:
            raise InvalidityException("No ID present in response")
        if not self.response_url:
            raise InvalidityException("No response_url present in response")
        if self.status == 200:
            if not self.identity:
                raise InvalidityException(
                        "identity WASN'T present with 200 status")
            if not self.signature:
                raise InvalidityException(
                        "no signature was present with 200 status")
            if not (self.auth_type or self.origional_auth_types):
                raise InvalidityException("At least one of auth_type and "
                        "origional_auth_types must be present with a successful"
                        " authentication")
        if self.status != 200:
            if self.identity:
                raise InvalidityException(
                        "identity WAS present with non 200 status")
            if self.auth_type:
                raise InvalidityException(
                        "auth_type WAS present with non 200 status")
        if self.signature and not self.key_id:
            raise InvalidityException(
                    "no key_id present with signature present")

    @staticmethod
    def _raven_unescape_b64(b64string):
        return b64string.replace("-", "+").replace(".", "/").replace("_", "=")

    @staticmethod
    def _raven_unescape(string):
        return string.replace("%25", "%").replace("%21", "!")

    @staticmethod
    def _parse_raven_date(datestr):
        try:
            return datetime.datetime.strptime(datestr, "%Y%m%dT%H%M%SZ")
        except ValueError:
            raise InvalidityException(
                    "Unrecognised date value: {0}".format(datestr))

    @staticmethod
    def _expiry_timestamp(fromdate, seconds):
        if seconds == "":
            return None
        return fromdate + datetime.timedelta(seconds=int(seconds))
