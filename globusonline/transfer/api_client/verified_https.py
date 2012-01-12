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
As of Python 2.6, httlib doesn't validate the server certificate.
However the ssl module does support validation, so it's fairly easy to
extend the stardant classes to support validation.

See http://www.muchtooscrawled.com/2010/03/https-certificate-verification-in-python-with-urllib2/
"""
import socket
import ssl
import os
from httplib import HTTPSConnection
from urlparse import urlsplit


__all__ = ["VerifiedHTTPSConnection"]


def get_proxy():
    """
    Return (host, port) if environment variable HTTPS_PROXY or
    https_proxy is found.  Otherwise return ().  Proxy variable value
    is assumed to be in the form of a URL like http://host[:port]/.
    If port is not given it defaults to 443.
    """
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not proxy: return ()
    proxy = urlsplit(proxy).netloc.split(":")
    if len(proxy) == 1:
        return (proxy, 443)
    return (proxy[0], int(proxy[1]))


class VerifiedHTTPSConnection(HTTPSConnection):
    """
    Extension of Python's standard library HTTPSConnection which
    verifies the server certificate.
    """
    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 ca_certs=None):
        """
        Adds the ca_certs argument.

        @param ca_certs: File containing a concatination of x509
                         CA certificates that are trusted for verifying
                         the certificate of the remote server.
        """
        proxy = get_proxy()
        if proxy:
            real_host, real_port = host, port
            host, port = proxy

        HTTPSConnection.__init__(self, host, port, key_file, cert_file,
                                 strict, timeout)
        if proxy:
            if hasattr(self, "set_tunnel"):     # Python 2.7+
                self.set_tunnel(real_host, real_port)
            elif hasattr(self, "_set_tunnel"):  # Python 2.6.6 (private)
                self._set_tunnel(real_host, real_port)

        self.ca_certs = ca_certs

    def connect(self):
        """
        Identical to the standard library version except for the addition
        of the cert_reqs and ca_certs arguments to ssl.wrap_socket.
        """
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if hasattr(self, "_tunnel_host") and self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock,
                                    self.key_file,
                                    self.cert_file,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ca_certs=self.ca_certs)


if __name__ == '__main__':
    import sys
    import urlparse
    def exit_usage():
        sys.exit("Usage: %s CA_CERTS_FILE HTTPS_URL" % sys.argv[0])

    if len(sys.argv) != 3:
        exit_usage()

    ca_certs_file = sys.argv[1]
    url = sys.argv[2]
    if not url.startswith("https://"):
        exit_usage()

    url = url[8:]
    slash_index = url.find("/")
    if slash_index == -1:
        host = url
        path = "/"
    else:
        host = url[:slash_index]
        path = url[slash_index:]

    colon_index = host.find(":")
    if colon_index == -1:
        port = 443
    else:
        port = int(host[colon_index+1:])
        host = host[:colon_index]

    c = VerifiedHTTPSConnection(host=host, port=port, timeout=.5,
                                ca_certs=ca_certs_file)
    try:
        c.request("GET", path)
        r = c.getresponse()
    except ssl.SSLError as e:
        # Timeout comes in with errno None and a single value in args.
        if e.errno is None \
        and e.args and e.args[0] == "The read operation timed out":
            sys.exit("Timout!")
        else:
            raise
    print r.status, r.reason
    for h in r.getheaders():
        print "%s: %s" % h
    print r.read(),
