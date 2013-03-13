#!/usr/bin/env python

# Copyright 2010 University of Chicago
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Login to www.globusonline.org and extract the saml cookie.

When run as a script, takes username as first and only argument, and prompts
for password. The cookie is printed to stdout.
"""

import sys
import urlparse
import getpass
from collections import namedtuple
import json
import base64

from globusonline.transfer.api_client.verified_https \
    import VerifiedHTTPSConnection

HOST = "nexus.api.globusonline.org"
GOAUTH_PATH = "/goauth/token?grant_type=client_credentials"
PORT = 443

GOAuthResult = namedtuple("GOAuthResult", "username password token")


class GOAuthError(Exception):
    pass


class GOCredentialsError(GOAuthError):
    def __init__(self):
        GOAuthError.__init__(self, "Wrong username or password")


def get_access_token(username=None, password=None, ca_certs=None):
    """Get a goauth access token from nexus.

    Uses basic auth with the user's username and password to authenticate
    to nexus. If the username or password are not passed, they are prompted
    for on stdin.

    @param username: Globus Online username to authenticate as, or None
                     to prompt on stdin.
    @param password: Globus Online password to authenticate with, or None
                     to prompt on stdin (with echo disabled for security).
    @param ca_certs: Path to a ca certificate to verify nexus, or None
                     to use the default CA included in the package.

    @return: GOAuthResult object. Most applications will only care about the
             token field, but username/password may be useful for caching
             authentication information when using the prompt.
    """
    if ca_certs is None:
        from globusonline.transfer.api_client import get_ca
        ca_certs = get_ca(HOST)
    if username is None:
        print "Globus Online Username: ",
        sys.stdout.flush()
        username = sys.stdin.readline().strip()
    if password is None:
        password = getpass.getpass("Globus Online Password: ")

    basic_auth = base64.b64encode("%s:%s" % (username, password))
    headers = { "Content-type": "application/json; charset=UTF-8",
                "Hostname": HOST,
                "Accept": "application/json; charset=UTF-8",
                "Authorization": "Basic %s" % basic_auth }
    c = VerifiedHTTPSConnection(HOST, PORT, ca_certs=ca_certs)
    c.request("GET", GOAUTH_PATH, headers=headers)
    response = c.getresponse()
    if response.status == 403:
        raise GOCredentialsError()
    elif response.status > 299 or response.status < 200:
        raise GOAuthError("error response: %d %s"
                         % (response.status, response.reason))
    data = json.loads(response.read())
    token = data.get("access_token")
    if token is None:
        raise GOAuthError("no token in response")

    return GOAuthResult(username, password, token)


def _get_host_port(url):
    o = urlparse(url)
    netloc_parts = o.netloc.split(":")
    if len(netloc_parts) == 2:
        host = netloc_parts[0]
        port = int(netloc_parts[1])
    else:
        host = o.netloc
        if o.scheme == "https":
            port = 443
        else:
            port = 80
    return (host, port)


def process_args(args=None, parser=None):
    from optparse import OptionParser

    if not parser:
        usage = "usage: %prog [username]"
        parser = OptionParser(usage=usage)

    parser.add_option("-C", "--server-ca-file", dest="server_ca_file",
                      help="ca file for validating server",
                      metavar="SERVER_CA_FILE")

    options, args = parser.parse_args(args)

    return options, args


if __name__ == '__main__':
    options, args = process_args()

    if len(args):
        username = args[0]
    else:
        username = None

    try:
        result = get_access_token(ca_certs=options.server_ca_file,
                                  username=username)
        print result.token
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        sys.exit(2)
