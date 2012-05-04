from urlparse import urlparse, urlunparse, parse_qsl
from urllib import urlencode

def login_url(post_login_url,
              authservice_url="https://raven.cam.ac.uk/auth/authenticate.html",
              resource_name=None,
              acceptable_auth_types=["pwd"],
              message=None,
              reauthenticate=None, # interactively, noninteractively
              data=None):
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
    auth_url = urlparse(authservice_url)
    url_params = parse_qsl(auth_url.query)

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
            raise ValueError("Unknown reauthenticate type: {0}"
                             .format(reauthenticate))
        url_params.append(("iact", "yes" if reauthenticate == "reauthenticate"
                                         else "no"))
    if data:
        url_params.append(("data", data))

    return urlunparse(_replace_query(auth_url, urlencode(url_params)))

def _replace_query(parsed_url, querystring):
    pieces = list(parsed_url)
    pieces[4] = querystring
    return pieces
