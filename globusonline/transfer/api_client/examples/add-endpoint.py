#!/usr/bin/env python

# Copyright 2012 University of Chicago
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
Add an endpoint to the user's account. Prompts for username and password to
authenticate.

Example usage:

    add-endpoint.py myep \
      --hostname=myep.mydomain.example.net \
      --myproxy-server=myproxy.mydomain.example.net \
      --public

Hostname is required unless --is-globus-connect is passed to create a
GC endpoint.

For a full list of options, run with -h.
"""
import sys
import inspect
from optparse import OptionParser

from globusonline.transfer.api_client import TransferAPIClient
from globusonline.transfer.api_client.goauth import get_access_token


def main():
    # Derive command line options from the method args, making
    # the endpoint name positional and the rest options.
    argspec = inspect.getargspec(TransferAPIClient.endpoint_create)
    fargs = [arg.replace("_", "-") for arg in argspec.args
             if arg not in ("self", "endpoint_name")]
    parser = OptionParser(usage="Usage: %prog [options] endpoint_name")
    for i, arg in enumerate(fargs):
        default = argspec.defaults[i]
        action = "store"
        type_ = "string"
        if arg in "public is-globus-connect".split():
            action = "store_true"
            type_ = None
        elif arg == "port":
            type_ = "int"

        if default not in (None, ""):
            doc = "[DEFAULT: %s]" % default
        else:
            doc = None
        parser.add_option("--%s" % arg, action=action, type=type_,
                          default=default, help=doc)
    options, args = parser.parse_args(sys.argv)
    if len(args) != 2:
        parser.error("requires one positional argument with endpoint name")

    # Convert options object into a keyword dict we can pass to the method
    kw = {}
    for arg in fargs:
        name = arg.replace("-", "_")
        value = getattr(options, name)
        if value is not None:
            kw[name] = value

    # will prompt for username and password
    auth_result = get_access_token()

    api = TransferAPIClient(username=auth_result.username,
                            goauth=auth_result.token)

    _, _, data = api.endpoint_create(args[1], **kw)
    setup_key = data.get("globus_connect_setup_key")
    if setup_key:
        print "GC Setup Key: %s" % setup_key
    print "Endpoint Name: %s" % data["canonical_name"]
    print data["message"]


if __name__ == '__main__':
    main()
