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
Create a proxy with a specific public key, using the helper function from
transfer_api meant for delegate_proxy activation. This can be useful
for testing.
"""

import sys

from globusonline.transfer.api_client import create_proxy_from_file

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print "usage: %s proxy_file pubkey_file lifetime_hours" % sys.argv[0]
        sys.exit(1)

    proxy_file, pubkey_file = sys.argv[1:3]
    lifetime = int(sys.argv[3]) * 3600

    with open(pubkey_file) as f:
        public_key = f.read()

    proxy_pem = create_proxy_from_file(proxy_file, public_key, lifetime)
    print proxy_pem
