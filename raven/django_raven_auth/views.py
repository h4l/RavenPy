from django.conf import settings as djangosettings
from django.contrib.auth import authenticate, login
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.shortcuts import redirect
from django.utils.crypto import salted_hmac
from django.views.decorators.http import require_GET
from raven.django_raven_auth import settings
import raven
import urlparse
import urllib

assert settings.RAVEN_ANTI_CSRF_HMAC_SALT, ("RAVEN_ANTI_CSRF_HMAC_SALT setting "
        "cannot be empty.")

@require_GET
def raven_login(request):
    # If the user is already logged in then just send them on their way...
    if request.user.is_authenticated():
        return redirect(_get_next_url(request))

    # Otherwise login with Raven. Raven auth responses come back here too, so
    # we need to check if we're finishing or starting a login exchange.
    if settings.RAVEN_AUTH_RESPONSE_QUERY_KEY in request.GET:
        return _authenticate_user(request)
    else:
        return _initiate_raven_login(request)

def _authenticate_user(request):
    if not request.session.test_cookie_worked():
        # Try to set the test cookie again, even though the client doesn't seem
        # to accept cookies. This allows a login to work if the client gets the
        # message asking them to enable cookies, enables them, then refreshes
        # the page.
        request.session.set_test_cookie()
        return HttpResponse(status=400, content="Your browser doesn't seem to "
                "be accepting cookies. Please enable them before trying to log"
                " in.")
    request.session.delete_test_cookie()


    auth_response = request.GET[settings.RAVEN_AUTH_RESPONSE_QUERY_KEY]

    user = authenticate(raven_response=auth_response,
            expected_data=_get_per_session_raven_secret(request))

    if user is not None and user.is_active:
        # Associate the user with the active client's session
        login(request, user)
        return redirect(_get_next_url(request))

    # User was not authenticated.
    # Re-set test cookie so that the check at the top is not triggered if the
    # client refreshes this page. FIXME: Should create a login failure page
    # and redirect to that rather than displaying an error here to avoid the
    # need to keep setting test cookies. Or use our own session state instead...
    request.session.set_test_cookie()
    return HttpResponse(status=403, content="<h1>Not authenticated</h1>"
            "<p>The authentication information received from Raven was not "
            "accepted for some reason.</p>")

def _initiate_raven_login(request):
    # Set a test cookie so that we can detect if the client does not have
    # cookies enabled when they get redirected back to us after login. This also
    # ensures that the current session is persisted on the client which is 
    # required as we use the session ID to link auth responses to requests.
    request.session.set_test_cookie()

    # Create an absolute URL pointing to this page which the remote server will
    # redirect the user back to once they've logged in.
    post_login_url = (request.build_absolute_uri(reverse(raven_login)))
    if settings.RAVEN_LOGIN_REDIRECT_URL_QUERY_KEY in request.GET:
        post_login_url += "?" + urllib.urlencode(
                {settings.RAVEN_LOGIN_REDIRECT_URL_QUERY_KEY:
                 request.GET[settings.RAVEN_LOGIN_REDIRECT_URL_QUERY_KEY]})

    login_url = raven.login_url(post_login_url,
            authservice_url=settings.RAVEN_URL,
            resource_name=settings.RAVEN_RESOURCE_NAME,
            acceptable_auth_types=settings.RAVEN_AUTH_TYPES,
            message=settings.RAVEN_MESSAGE,
            # Tag the request with a secret value known only to us, the client
            # and raven which allows us to associate a response message with a
            # session. Doing to prevents 3rd parties redirecting people to the
            # login URL with a valid raven response for a different account.
            # In other words, a login CSRF attack.
            data=_get_per_session_raven_secret(request))

    return redirect(login_url)

def _get_per_session_raven_secret(request):
    """Gets a pseudorandom string which is always the same for a given session,
    but does not leak any information about the session (e.g. the actual session
    id). 
    """
    session_key = request.session.session_key
    assert session_key, "session_key must not be empty"
    hmac = salted_hmac(settings.RAVEN_ANTI_CSRF_HMAC_SALT, session_key)
    return hmac.hexdigest()

def _get_next_url(request):
    # Get the location to redirect to after login
    next_url = request.GET.get(settings.RAVEN_LOGIN_REDIRECT_URL_QUERY_KEY,
            djangosettings.LOGIN_REDIRECT_URL)
    # Don't allow redirecting to a host other than our own
    netloc = urlparse.urlparse(next_url).netloc
    if netloc and netloc != request.get_host():
        next_url = djangosettings.LOGIN_REDIRECT_URL
    return next_url
