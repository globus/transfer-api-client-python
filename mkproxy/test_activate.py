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
Test a proxy chain created with mkproxy or some other external method
by using it to activate an endpoint. Real applications should use the provided
API instead - see
globusonline/transfer/api_client/examples/delegate_proxy_activate.py.

Usage:

 # Create proxy with 10 hour lifetime. server.pubkey must contain the PEM
 # from the public_key activation_requirement.
 cat server.pubkey /path/to/activation/credential \
    | mkproxy 10 > /tmp/proxy_chain
 test_activate.py USERNAME 'ENDPOINT_NAME' /tmp/proxy_chain \
    -k /path/to/auth/key -c /path/to/auth/cert

The endpoint name may contain a # which is a shell comment, so be sure to
quote the endpoint name.
"""

import sys
import subprocess

from globusonline.transfer.api_client import create_client_from_args

if __name__ == '__main__':
    api, args = create_client_from_args()
    if len(args) < 2:
        sys.stderr.write(
            "username, endpoint, proxy_chain_file arguments are required")
        sys.exit(1)

    ep = args[0]
    proxy_chain_file = args[1]

    _, _, reqs = api.endpoint_activation_requirements(ep,
                                                      type="delegate_proxy")
    with open(proxy_chain_file) as f:
        proxy_chain = f.read()
    print proxy_chain
    reqs.set_requirement_value("delegate_proxy", "proxy_chain", proxy_chain)

    result = api.endpoint_activate(ep, reqs)
    print result
