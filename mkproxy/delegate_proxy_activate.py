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
Demonstrate how to use the delegate_proxy activation method. This version takes
a proxy chain created externally (e.g. using mkproxy).

Usage:

 delegate_proxy_activate.py USERNAME 'ENDPOINT_NAME' /path/to/proxy_chain \
    -k /path/to/auth/key -c /path/to/auth/cert -C ca/gd-bundle_ca.cert

The endpoint name may contain a # which is a shell comment, so be sure to
quote the endpoint name.
"""

import sys
import subprocess

from globusonline.transfer.api_client import create_client_from_args
from globusonline.transfer.api_client import create_proxy_from_file

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
