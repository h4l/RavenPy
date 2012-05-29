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
from django.conf import settings
import raven

# The key which Raven uses to provide its auth response value in the query
# portion of the URI which the client is redirected to following a login.
_RAVEN_AUTH_RESPONSE_QUERY_KEY = "WLS-Response"

def getsetting(name, default=None):
    """Gets a django setting value by name, or the default if no value is set.
    """
    try:
        # For some reason there is no sensible way to check if a setting is 
        # defined...
        return settings.__getattr__(name)
    except AttributeError:
        return default

# The URL of the Ucam-webauth service login page. By default the login page
# of raven.cam.ac.uk is used. 
RAVEN_URL = getsetting("RAVEN_URL", raven.RAVEN_URL)

# A name/description of the website asking for users to log in. Raven displays
# this string to users as part of the login prompt. 
RAVEN_RESOURCE_NAME = getsetting("RAVEN_RESOURCE_NAME", None)

# A message which Raven will display to users when logging in. It's intended to
# explain why the user is being asked to login.
RAVEN_MESSAGE = getsetting("RAVEN_MESSAGE", None)

# A list of strings, Each string is the name of a method of authenticating users
# that the remote Ucam-webauth service knows about, and that are trusted by
# the website initiating the authentication. Default: password authentication.
RAVEN_AUTH_TYPES = getsetting("RAVEN_AUTH_TYPES",
        raven.DEFAULT_AUTH_TYPES)

# The key which the Ucam-webauth service uses to provide its auth response value
# in the query portion of the URI which the client is redirected to following a
# login. Default: WLS-Response (as used by Raven).
RAVEN_AUTH_RESPONSE_QUERY_KEY = getsetting("RAVEN_AUTH_RESPONSE_QUERY_KEY",
        _RAVEN_AUTH_RESPONSE_QUERY_KEY)

# The salt value used when hashing the user's session ID before inclusion in
# a login request to a remote Ucam-webauth service. Additionally, the 
# deployment's settings.SECRET_KEY is used when generating the HMAC, so this
# value need not be changed.
RAVEN_ANTI_CSRF_HMAC_SALT = getsetting("RAVEN_ANTI_CSRF_HMAC_SALT",
        "ucam-raven-secret")


RAVEN_LOGIN_REDIRECT_URL_QUERY_KEY = getsetting(
        "RAVEN_LOGIN_REDIRECT_URL_QUERY_KEY", "next")

# A dict mapping string key names to PyCrypto public key objects. Auth responses
# mark themselves as being signed by a named key which must be found in this 
# dict for a response to be valid.
RAVEN_KEYS = getsetting("RAVEN_KEYS", raven.RAVEN_KEYS)
