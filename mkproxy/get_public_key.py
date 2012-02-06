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
Script to get the public key for delegate_proxy activation. Uses 'go#ep1'
by default; currently all endpoints use the same key anyway. This is useful
for testing mkproxy - see test_activate.py.
"""

import sys
import subprocess

from globusonline.transfer.api_client import create_client_from_args

if __name__ == '__main__':
    api, args = create_client_from_args()
    endpoint = "go#ep1"
    if len(args) == 1:
        endpoint = args[0]
    elif len(args) != 0:
        sys.stderr.write(
            "Usage: %s username [endpoint] [options]" % sys.argv[0])
        sys.exit(1)

    _, _, reqs = api.endpoint_activation_requirements(endpoint,
                                                      type="delegate_proxy")
    print reqs.get_requirement_value("delegate_proxy", "public_key"),
