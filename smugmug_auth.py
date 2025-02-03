# Copyright (c) 2014 SmugMug, Inc. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY SMUGMUG, INC. ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL SMUGMUG, INC. BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES;LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import json
from rauth import OAuth1Service, OAuth1Session
import sys
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

OAUTH_ORIGIN = 'https://secure.smugmug.com'
REQUEST_TOKEN_URL = OAUTH_ORIGIN + '/services/oauth/1.0a/getRequestToken'
ACCESS_TOKEN_URL = OAUTH_ORIGIN + '/services/oauth/1.0a/getAccessToken'
AUTHORIZE_URL = OAUTH_ORIGIN + '/services/oauth/1.0a/authorize'

API_ORIGIN = 'https://api.smugmug.com'

SERVICE = None


def get_service(config):
    global SERVICE
    if SERVICE is None:
        if type(config) is not dict \
                or 'key' not in config \
                or 'secret' not in config \
                or type(config['key']) is not str \
                or type(config['secret']) is not str:
            print('====================================================')
            print('Invalid config.json!')
            print('The expected format is demonstrated in example.json.')
            print('====================================================')
            sys.exit(1)
        SERVICE = OAuth1Service(
            name='smugmug-oauth-web-demo',
            consumer_key=config['key'],
            consumer_secret=config['secret'],
            request_token_url=REQUEST_TOKEN_URL,
            access_token_url=ACCESS_TOKEN_URL,
            authorize_url=AUTHORIZE_URL,
            base_url=API_ORIGIN + '/api/v2')
    return SERVICE


def add_auth_params(auth_url, access=None, permissions=None):
    if access is None and permissions is None:
        return auth_url
    parts = urlsplit(auth_url)
    query = parse_qsl(parts.query, True)
    if access is not None:
        query.append(('Access', access))
    if permissions is not None:
        query.append(('Permissions', permissions))
    return urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path,
        urlencode(query, True),
        parts.fragment))

def auth(config, tokenfn):

    if tokenfn.exists():
        with open(tokenfn, 'r') as openfile:
            token = json.load(openfile)
            session = OAuth1Session(
                config["key"],
                config["secret"],
                access_token=token["token"],
                access_token_secret=token["secret"])
            return session

    """This example interacts with its user through the console, but it is
    similar in principle to the way any non-web-based application can obtain an
    OAuth authorization from a user."""
    service = get_service(config)

    # First, we need a request token and secret, which SmugMug will give us.
    # We are specifying "oob" (out-of-band) as the callback because we don't
    # have a website for SmugMug to call back to.
    rt, rts = service.get_request_token(params={'oauth_callback': 'oob'})

    # Second, we need to give the user the web URL where they can authorize our
    # application.
    auth_url = add_auth_params(
        service.get_authorize_url(rt), access='Full', permissions='Modify')
    print('Go to %s in a web browser.' % auth_url)

    # Once the user has authorized our application, they will be given a
    # six-digit verifier code. Our third step is to ask the user to enter that
    # code:
    sys.stdout.write('Enter the six-digit code: ')
    sys.stdout.flush()
    verifier = sys.stdin.readline().strip()

    # Finally, we can use the verifier code, along with the request token and
    # secret, to sign a request for an access token.
    at, ats = service.get_access_token(rt, rts, params={'oauth_verifier': verifier})

    # The access token we have received is valid forever, unless the user
    # revokes it.  Let's make one example API request to show that the access
    # token works.
    print('Access token: %s' % at)
    print('Access token secret: %s' % ats)
    print('Consumer key: %s' % service.consumer_key)
    print('Consumer secret: %s' % service.consumer_secret)
    session = OAuth1Session(
        service.consumer_key,
        service.consumer_secret,
        access_token=at,
        access_token_secret=ats)
    with open(tokenfn, "w") as outfile:
        json.dump({
            "token": at,
            "secret": ats,
        }, outfile)
    return session