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
import unittest
import urlparse
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from HTMLParser import HTMLParser

from base64 import b64decode
from urllib import unquote
from datetime import datetime, timedelta

# Import _raven directly to access all hidden members
import raven._raven as raven

class LoginUrlConstructionTest(unittest.TestCase):

    @staticmethod
    def replace(target, index, newvalue):
        if index < 0 or index >= len(target):
            raise IndexError(index)
        return target[:index] + (newvalue,) + target[index + 1:]

    def test_generated_url_matches_authservice_url_ignoring_query(self):
        # given
        auth_url = ("http", "example.com", "/some/place/auth", "", "", "")
        post_login_url = "https://example.com/foo/bar/baz?wee=pop&whiz=bang"

        # when
        result_url = raven.login_url(post_login_url,
                authservice_url=urlparse.urlunparse(auth_url))

        # then
        result = urlparse.urlparse(result_url)
        self.assertEqual(auth_url, self.replace(result, 4, ""),
                         "Input and output urls are the same (ignoring query)")

    def test_html_escape(self):
        # Some strings containing various odd unicode characters
        odd_strings = [
            u"This is a test of a fancy login message with odd characters such "
            u"as: \u03a9 \u2248 \xe7 \u2211 \u02da \u2206 \u03c0 \xf8 .",
            "foo",
            u"\xe6\xdf\xe5\u2202\u0192\u221a^\xb4\xa9\u0192\u02d9\u2206\u02da"
            u"\xdf\u2202\u0192\xdf\xac\u2202\xe7~\u222b\u221a~\xb5\u2248\xa8^"
            u"\xf8\u2211\xb4\xa9\u02d9\xdf\u2206"
        ]

        for strange_string in odd_strings:
            escaped = raven._html_escape(strange_string)
            # Check that the input string equals the unescaped version of the 
            # escaped string.
            self.assertEqual(strange_string, HTMLParser().unescape(escaped))

    def test_provided_params_end_where_expected(self):
        # given
        post_login_url = "https://example.com/tasty-pies?abc=def"
        resource_name = "Tasty Pies"
        acceptable_auth_types = "authtype1,authtype2"
        message = "Pies are super secret and must be protected by authentication"
        data = "{'thisis':'jsondata'}"

        # when
        result = urlparse.urlparse(raven.login_url(post_login_url,
                resource_name=resource_name,
                acceptable_auth_types=acceptable_auth_types.split(","),
                message=message, data=data))
        query_list = urlparse.parse_qsl(result.query)
        query = dict(query_list)

        # then
        self.assertEqual(6, len(query_list))
        self.assertEqual(6, len(query))
        self.assertEqual("2", query["ver"])
        self.assertEqual(post_login_url, query["url"])
        self.assertEqual(resource_name, query["desc"])
        self.assertEqual(acceptable_auth_types, query["aauth"])
        self.assertEqual(message, query["msg"])
        self.assertEqual(data, query["params"])

    def test_login_url_without_reauthentication(self):
        # Create login url without requesting special reauthentication
        result = urlparse.urlparse(raven.login_url("http://ignorethis/url"))
        query = dict(urlparse.parse_qsl(result.query))

        self.assertTrue(not query.has_key("iact"),
                        "No reauthentication should be requested")

    def test_login_url_with_interactive_reauthentication(self):
        # Create login url with interactive reauthentication
        result = urlparse.urlparse(raven.login_url("http://ignorethis/url",
                reauthenticate="interactive"))
        query = dict(urlparse.parse_qsl(result.query))

        self.assertEqual("yes", query["iact"])

    def test_login_url_with_noninteractive_reauthentication(self):
        # Create login url with noninteractive reauthentication
        result = urlparse.urlparse(raven.login_url("http://ignorethis/url",
                reauthenticate="noninteractive"))
        query = dict(urlparse.parse_qsl(result.query))

        self.assertEqual("no", query["iact"])

    def test_login_url_with_unknown_reauthenticate_value_raises_value_error(self):
        # Create login url with bad value for reauthenticate
        try:
            raven.login_url("http://ignorethis/url",
                            reauthenticate="ilikeauthentication")
            self.fail("The call to login_url should have raised a ValueError")
        except ValueError:
            pass


class ValidationTest(unittest.TestCase):

    VALID_RAVEN_RESPONSE = ("1!200!!20120504T220258Z!1336168978-26673-6!https:/"
            "/textmonster.caret.cam.ac.uk/!hwtb2!pwd!!36000!foo%21bar%21baz!2!q"
            "-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewO"
            "XuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3"
            "aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    @staticmethod
    def unescape_signature(sig):
        return b64decode(sig.replace("-", "+").replace(".", "/")
                            .replace("_", "="))

    def test_sanity_check_response_signature_verification(self):
        """A sanity check, very that pycrypto is working as expected.
        
        Also serves to demonstrate the basics of verifying the signa
        """
        bits = self.VALID_RAVEN_RESPONSE.split("!")
        response = "!".join(bits[0:11])

        binary_signature = self.unescape_signature(bits[-1])
        self.assertEqual(128, len(binary_signature))

        response_hash = SHA.new(response)

        verifier = PKCS1_v1_5.new(raven.RAVEN_PUB_KEY_2)
        self.assertTrue(verifier.verify(response_hash, binary_signature))

    def test_parsed_response_contains_expected_data(self):
        response = raven.AuthResponse(self.VALID_RAVEN_RESPONSE)
        self.assertEqual("1", response.version)
        self.assertEqual(200, response.status)
        self.assertEqual("", response.status_description)
        self.assertEqual("20120504T220258Z",
                         response.timestamp.strftime("%Y%m%dT%H%M%SZ"))
        self.assertEqual("1336168978-26673-6", response.id)
        self.assertEqual("https://textmonster.caret.cam.ac.uk/",
                         response.response_url)
        self.assertEqual("hwtb2", response.identity)
        self.assertEqual("pwd", response.auth_type)
        self.assertEqual([], response.origional_auth_types)
        self.assertEqual(36000, (response.expiry_timestamp - response.timestamp).seconds)
        self.assertEqual("foo!bar!baz", response.request_data)
        self.assertEqual("2", response.key_id)
        self.assertEqual(self.unescape_signature("q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8"
                "iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8"
                "cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0"
                "On.A9sDwv6kGqsZJYA_"), response.signature)
        self.assertEqual(128, len(response.signature))

    def test_valid_response_validates(self):
        keys = raven.RAVEN_KEYS
        validator = raven.Validator(keys)
        validator.validate(self.VALID_RAVEN_RESPONSE,
                           now=datetime(2012, 5, 4, 22, 2, 58))

    def test_valid_response_validates_with_url_check(self):
        keys = raven.RAVEN_KEYS
        validator = raven.Validator(keys,
                expected_post_login_url="https://textmonster.caret.cam.ac.uk/")
        validator.validate(self.VALID_RAVEN_RESPONSE,
                           now=datetime(2012, 5, 4, 22, 2, 58))

    def test_valid_response_validates_with_url_check2(self):
        keys = raven.RAVEN_KEYS
        validator = raven.Validator(keys,
                expected_post_login_url=("https", "textmonster.caret.cam.ac.uk",
                        "/", "", "", ""))
        validator.validate(self.VALID_RAVEN_RESPONSE,
                           now=datetime(2012, 5, 4, 22, 2, 58))

    def test_validator_ctor_fails_if_url_param_is_tuple_but_not_len_6(self):
        try:
            raven.Validator({},
                    expected_post_login_url=("", "", "", "", "", "", ""))
            self.fail("A ValueError should have been raised.")
        except ValueError:
            pass
        try:
            raven.Validator({},
                    expected_post_login_url=("", "", "", "", ""))
            self.fail("A ValueError should have been raised.")
        except ValueError:
            pass

    def test_valid_response_with_bad_url_invalidates_response(self):
        keys = raven.RAVEN_KEYS
        validator = raven.Validator(keys,
                expected_post_login_url=("https", "someotherhostname.com",
                        "/", "", "", ""))
        try:
            validator.validate(self.VALID_RAVEN_RESPONSE,
                    now=datetime(2012, 5, 4, 22, 2, 58))
            self.fail("URLs shouldn't match.")
        except raven.InvalidityException:
            pass

    def test_response_manipulation_invalidates_response(self):
        keys = raven.RAVEN_KEYS
        validator = raven.Validator(keys)
        # Try to spoof the username of the response
        manipulated_response = self.VALID_RAVEN_RESPONSE.replace("hwtb2",
                                                                 "spoofuser")
        try:
            validator.validate(manipulated_response,
                    now=datetime(2012, 5, 4, 22, 2, 58))
            self.fail("An SignatureInvalidityException should have be raised")
        except raven.SignatureInvalidityException:
            pass

    def test_get_authenticated_user_returns_valid_user_for_valid_response(self):
        keys = raven.RAVEN_KEYS
        validator = raven.Validator(keys)
        self.assertEqual("hwtb2", validator.get_authenticated_user(
                self.VALID_RAVEN_RESPONSE, now=datetime(2012, 5, 4, 22, 2, 58)))

    def test_get_authenticated_user_returns_none_on_manipulated_input(self):
        keys = raven.RAVEN_KEYS
        validator = raven.Validator(keys)
        # Try to spoof the username of the response
        manipulated_response = self.VALID_RAVEN_RESPONSE.replace("hwtb2",
                                                                 "spoofuser")
        self.assertEqual(None, validator.get_authenticated_user(
                manipulated_response, now=datetime(2012, 5, 4, 22, 2, 58)))

    def test_responses_older_than_one_min_are_invalid(self):
        keys = raven.RAVEN_KEYS
        validator = raven.Validator(keys)

        # Set now to be the auth time plus just over 1 min
        now = datetime(2012, 5, 4, 22, 2, 58) + timedelta(seconds=61)
        try:
            validator.validate(self.VALID_RAVEN_RESPONSE, now=now)
            self.fail("An InvalidityException should have be raised")
        except raven.InvalidityException:
            pass

    def test_responses_newer_than_one_min_are_invalid(self):
        keys = raven.RAVEN_KEYS
        validator = raven.Validator(keys)

        # Set now to be the auth time minus just over 1 min
        now = datetime(2012, 5, 4, 22, 2, 58) - timedelta(seconds=61)
        try:
            validator.validate(self.VALID_RAVEN_RESPONSE, now=now)
            self.fail("An InvalidityException should have be raised")
        except raven.InvalidityException:
            pass

    def test_responses_referencing_missing_keys_are_invalid(self):
        keys = {"responseDoesn'tKnowAboutThisKey": raven.RAVEN_PUB_KEY_2}
        validator = raven.Validator(keys)
        now = datetime(2012, 5, 4, 22, 2, 58)
        try:
            validator.validate(self.VALID_RAVEN_RESPONSE, now=now)
            self.fail("An InvalidityException should have be raised")
        except raven.InvalidityException:
            pass

    def test_responses_with_unacceptable_auth_types_are_invalid(self):
        keys = raven.RAVEN_KEYS
        validator = raven.Validator(keys,
                acceptable_auth_types=["foo"])
        now = datetime(2012, 5, 4, 22, 2, 58)
        try:
            validator.validate(self.VALID_RAVEN_RESPONSE, now=now,
                               ignore_signature=True)
            self.fail("An InvalidityException should have be raised")
        except raven.InvalidityException:
            pass

    def test_responses_with_unacceptable_origional_auth_types_are_invalid(self):
        keys = raven.RAVEN_KEYS
        validator = raven.Validator(keys,
                acceptable_auth_types=["foo", "bar"])
        now = datetime(2012, 5, 4, 22, 2, 58)
        response = "1!200!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!hwtb2!!foo,bar,baz!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_"
        try:
            validator.validate(response, now=now, ignore_signature=True)
            self.fail("An InvalidityException should have be raised")
        except raven.InvalidityException:
            pass

    def test_too_many_values_invalidates_response(self):
        response = self.VALID_RAVEN_RESPONSE + "!foo"
        try:
            raven.AuthResponse(response)
            self.fail("An InvalidityException should have be raised")
        except raven.InvalidityException:
            pass

    def test_too_few_values_invalidates_response(self):
        try:
            raven.AuthResponse("wee!pop!ping")
            self.fail("An InvalidityException should have be raised")
        except raven.InvalidityException:
            pass

    def test_response_with_non_200_status_has_no_authenticated_entity(self):
        response = raven.AuthResponse("1!500!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!!!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")
        try:
            response.get_authenticated_identity()
            self.fail("An InvalidityException should have be raised")
        except raven.NotAuthenticatedException:
            pass

    def expect_invalid_response(self, response):
        try:
            raven.AuthResponse(response)
            self.fail("An InvalidityException should have be raised")
        except raven.InvalidityException:
            pass

    def expect_valid_response(self, response):
        raven.AuthResponse(response)

    def test_missing_version_invalidates_response(self):
        self.expect_invalid_response("!200!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!hwtb2!pwd!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    def test_missing_status_invalidates_response(self):
        self.expect_invalid_response("1!!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!hwtb2!pwd!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    def test_missing_timestamp_invalidates_response(self):
        self.expect_invalid_response("1!200!!!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!hwtb2!pwd!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    def test_missing_id_invalidates_response(self):
        self.expect_invalid_response("1!200!!20120504T220258Z!!https://textmonster.caret.cam.ac.uk/!hwtb2!pwd!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    def test_missing_url_invalidates_response(self):
        self.expect_invalid_response("1!200!!20120504T220258Z!1336168978-26673-6!!hwtb2!pwd!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    def test_missing_identify_with_200_status_invalidates_response(self):
        self.expect_invalid_response("1!200!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!!pwd!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    def test_identity_with_non_200_status_invalidates_response(self):
        # Response is fine with 410 status and no identity...
        self.expect_valid_response("1!410!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!!!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")
        # But not with 410 status and an identity present
        self.expect_invalid_response("1!410!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!hwtb2!!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    def test_auth_type_with_non_200_status_invalidates_response(self):
        # Response is fine with 410 status and no identity...
        self.expect_valid_response("1!410!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!!!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")
        # And also fails with auth_type present
        self.expect_invalid_response("1!410!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!!pwd!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    def test_absent_signature_invalidates_successful_response(self):
        self.expect_invalid_response("1!200!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!hwtb2!pwd!!36000!foo%21bar%21baz!2!")

    def test_absent_key_id_invalidates_successful_response(self):
        self.expect_invalid_response("1!200!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!hwtb2!pwd!!36000!foo%21bar%21baz!!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    def test_origional_auth_types_can_be_present_alongside_auth_type(self):
        self.expect_valid_response("1!200!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!hwtb2!pwd!pwd,pwd,pwd!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    def test_origional_auth_types_and_auth_type_cant_both_be_absent_on_success(self):
        self.expect_invalid_response("1!200!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!hwtb2!!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    def test_origional_auth_types_and_auth_type_cant_be_present_on_failure(self):
        self.expect_invalid_response("1!410!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!!pwd!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")
        self.expect_valid_response("1!410!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!!!!36000!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")

    def test_successful_response_with_no_lifetime_has_no_expiry(self):
        response = raven.AuthResponse("1!200!!20120504T220258Z!1336168978-26673-6!https://textmonster.caret.cam.ac.uk/!hwtb2!pwd!!!foo%21bar%21baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd.qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_")
        self.assertEqual(None, response.expiry_timestamp)

if __name__ == "__main__":
    unittest.main()
