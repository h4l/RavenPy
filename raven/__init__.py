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
"""
This module provides support for authenticating users with the University of 
Cambridge Raven Authentication Service.

In the lingo of the Raven spec, this module implements a Python "Web application
agent" (WAA) capable of interacting with any given "Web login service" (WLS).
The Raven service is one such WLS. See the WAA->WLS communication protocol spec
for more details: http://raven.cam.ac.uk/project/waa2wls-protocol.txt

Raven 101
=========

In order to use this module to authenticate users, you need to have a high level
understanding of how Raven works.

Unlike many other authentication systems, a web server authenticating users 
never contacts the Raven service directly. Instead, all communication is 
directed via the user who is authenticating. A typical authentication works like
this:

1. A user requests a page on your web server which requires authentication.
   Rather than serve them the page, you redirect them to the Raven login page.
2. The user logs in at the Raven login page (your website never sees any 
   passwords).
3. Assuming the login was successful, the Raven server redirects the user back
   to your website. Raven embeds authentication information in the URL pointing
   to your website it redirects the user to.
4. Your website verifies that the authentication information in the URL used by
   the client is valid and considers them to be logged in if it is.

There are two parts of this process which your server handles: redirecting users
to Raven (step 1) and validating Raven's response (step 4). This module helps
with both.

Redirecting Users to Raven
--------------------------

The raven.login_url() function is used to generate a Raven login URL. Send an
HTTP 303 response with the URL returned as the value of the Location header.

Validating Raven's Response
---------------------------
The HTTP request your server receives from a client who's completed a Raven
login will include a URL query parameter named "WLS-Response". The parameter's
value is a Raven auth response string which needs validating. Public key
cryptography is used to check that the response was not changed after Raven
generated it.

To validate a response, create a Validator object, then call its
get_authenticated_user() or validate() methods, passing in the response string.

When creating a Validator you need to provide a dict containing one or more key
names mapped to RSA public keys. For convenience, Raven's current public key is
available from this module as raven.RAVEN_PUB_KEY_2, or even more conveniently
as raven.RAVEN_KEYS which is a dict ready to use when creating an Validator.
"""

import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import datetime
import urllib
import urlparse

RAVEN_PUB_KEY_2 = RSA.importKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC/9qcAW1"
        "XCSk0RfAfiulvTouMZKD4jm99rXtMIcO2bn+3ExQpObbwWugiO8DNEffS7bzSxZqGp7U6b"
        "Pdi4xfX76wgWGQ6qWi55OXJV0oSiqrd3aOEspKmJKuupKXONo2efAt6JkdHVH0O6O8k5LV"
        "ap6w4y1W/T/ry4QH7khRxWtQ==")

RAVEN_KEYS = {"2": RAVEN_PUB_KEY_2}

RAVEN_URL = "https://raven.cam.ac.uk/auth/authenticate.html"
DEFAULT_AUTH_TYPES = ["pwd"]

def login_url(post_login_url,
        authservice_url=RAVEN_URL,
        resource_name=None, acceptable_auth_types=DEFAULT_AUTH_TYPES,
        message=None, reauthenticate=None, data=None):
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
        url_params.append(("desc", _html_escape(resource_name)))
    if message:
        url_params.append(("msg", _html_escape(message)))
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

def _html_escape(string):
    """HTML escapes non ASCII printable chars in string.
    
    Values outside the range [0x20, 0x7e] are replaced by the string "&#x___;"
    where ___ is the hexidecimal encoding of unicode codepoint of the
    character.
    
    Args:
        string: A python string. This should be a unicode object if chars with
            codepoints outside the ascii range are used. 
    """
    if not string:
        return string
    head, tail = string[0], string[1:]
    if ord(head) < 0x20 or ord(head) > 0x7e or head == "&":
        head = "&#" + hex(ord(head))[1:] + ";"
    return head + _html_escape(tail)

def _replace_query(parsed_url, querystring):
    pieces = list(parsed_url)
    pieces[4] = querystring
    return pieces

class Validator(object):
    """A configurable validator of authentication responses. 
    
    Validator maintain a set of trusted keys, acceptable
    methods of authentication, allowable time delta between authentication and
    verification and verification of URl that the auth server expected the auth
    response to go to.
    
    Auth responses are checked to ensure they meet these criteria by calling the
    validate(response) method.
    
    The get_authenticated_user(response) method provides a shortcut to just get
    the username if the response is valid, or else raise an exception. 
    """

    def __init__(self, keys, acceptable_auth_types=["pwd"],
            max_timestamp_delta_seconds=datetime.timedelta(seconds=60),
            expected_post_login_url=""):
        self._keys = keys
        self._max_timestamp_delta = max_timestamp_delta_seconds
        self._acceptable_auth_types = set(acceptable_auth_types)

        if isinstance(expected_post_login_url, basestring):
            expected_post_login_url = urlparse.urlparse(expected_post_login_url)
        if len(expected_post_login_url) != 6:
            raise ValueError("expected_post_login_url should be tuple of length"
                    " 6 or similar, was: {0}".format(expected_post_login_url))
        self._expected_post_login_url = expected_post_login_url

    def _verify_post_login_url(self, url):
        """Checks that url provided in the response matches the expected URL.
        
        In practice, validating the URL is fairly pointless, as:
            - The value of the url is under the client's control
            - Raven doesn't restrict authentication based on destination website  
        
        This can be overridden in a subclass if more specific URL matching is
        required."""
        parts = urlparse.urlparse(url)
        for expected, actual in zip(self._expected_post_login_url, parts):
            if expected and expected != actual:
                raise InvalidityException("Response url did not match expected."
                        " Expected: {0}, actual: {1}"
                        .format(self._expected_post_login_url, parts))

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

    def _validate_authtypes(self, response):
        # auth types are only applicable to successful auth responses
        if not response.represents_successful_authentication():
            return

        if response.auth_type:
            if response.auth_type not in self._acceptable_auth_types:
                raise InvalidityException("Response was authenticated with "
                        "unacceptable auth_type: {0}, acceptable types: {1}"
                        .format(response.auth_type,
                            self._acceptable_auth_types))
        else:
            # AuthResponse._validate() ensures that at least one of auth_type, 
            # origional_auth_types are present on successful auths.
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

    def validate(self, response, now=None, ignore_signature=False):
        """Validates a WLS-Response.
        
        This is achieved by verifying the response's cryptographic signature,
        timestamp, authentication method and URL (if the expected_post_login_url
        param was provided when creating this validator). 
        
        Args:
            response_str: A WLS-Response string or AuthResponse 
                object.
            now: A datetime object which if present will be used instead of the
                current time when checking the age of a response.
            ignore_signature: If True then the response is not checked to see if
                it matches the signature. This is used in testing and should not
                normally be set to True. Default is False. 
        Returns:
            A validated AuthResponse object. A value is only returned
            if the input was validated as being safe to use.
        Raises:
            InvalidityException: If the signature of the response did not match
                the content of the object, or the signature was not signed by
                a key trusted by this validator. Also if the message was
                authenticated, but the timestamp was not near enough to the
                current time, or the method used for authentication was not
                trusted, or the URL specified in the response does not match
                that recognised by this validator.
        """
        # We accept either AuthResponse objects, or strings which
        # will be interpreted as AuthResponse objects.
        if not isinstance(response, AuthResponse):
            response = AuthResponse(response)

        # AuthResponse ensures that a successful auth always has a
        # signature. Signatures are optional for unsuccessful responses.
        if response.signature and not ignore_signature:
            self._verify_response_signature(response)

        self._validate_timestamp(response.timestamp,
                now or datetime.datetime.utcnow())
        self._validate_authtypes(response)
        self._verify_post_login_url(response.response_url)

        return response

    def get_authenticated_user(self, response, **kwargs):
        """Validates a WLS-Response, returning the username if all is well.
        
        Args:
            response: The value of the WLS-Response query parameter provided
                by the remote auth server (via the client's request), either as
                a raw string, or as a AuthResponse object.
            kwargs: any keyword args accepted by validate()
        Returns:
            The username of the user whose login created the response if it 
            represents a successful login. None is returned if the response was
            invalid, or did not represent a successful login.
        """
        try:
            return (self.validate(response, **kwargs)
                    .get_authenticated_identity())
        except InvalidityException:
            return None


class InvalidityException(ValueError):
    pass


class SignatureInvalidityException(InvalidityException):
    pass


class NotAuthenticatedException(Exception):
    pass


class AuthResponse(object):
    """Represents the values contained in a Raven authentication response.
    
    Upon construction, the combination of values present is validated for
    consistency. For example that an identity must be present with a status of
    200.
    
    The AuthResponse itself is not responsible for validating aspects
    other than the format of the string itself. In particular, the 
    cryptographic signature is not checked, neither is the timestamp or auth
    type. These are all checked by the 
    Validator.validate(responsestr) method which returns
    a fully validated AuthResponse object. As such, 
    AuthResponse should not normally be constructed directly, the
    aforementioned validate() method should be used in most cases.
    """

    def __init__(self, responsestr):
        """Parses a response string into its values.
        
        Warning: does not validate cryptographic signatures, use 
        Validator.validate() unless you really don't
        want to fully validate the response.
        
        Args:
            responsestr: The value of the WLS-Response query parameter provided
                by the auth service (via the user's request).
        Raises:
            InvalidityException: If the string itself, or the combination of
                its values are not acceptable.
        """
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

    def represents_successful_authentication(self):
        "Returns True if the response is marked as successful (status 200)."
        return self.status == 200

    def get_authenticated_identity(self):
        """Gets the authenticated identity (e.g. username) of the remote user.
        
        Returns:
            The username of the user whose successful login this response 
            represents. If this function returns a value, it's guaranteed to be
            an authenticated username.
        Raises:
            A NotAuthenticatedException is raised if the response does not 
            represent a successful login.
        """
        if self.represents_successful_authentication():
            return self.identity
        raise NotAuthenticatedException

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
            if self.origional_auth_types:
                raise InvalidityException(
                        "origional_auth_types WAS present with non 200 status")
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
