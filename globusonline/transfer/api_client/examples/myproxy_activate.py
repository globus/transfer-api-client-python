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
Demonstrate how to use the myproxy activation method. This method can be used
when the endpoint's identity provider runs a myproxy server.

Usage:

 myproxy_activate.py USERNAME 'ENDPOINT_NAME' [auth options]

The endpoint name may contain a # which is a shell comment, so be sure to
quote the endpoint name.
"""

import sys
from getpass import getpass

from globusonline.transfer.api_client import create_client_from_args, APIError


def input_default(field_name, default, private=False):
    if default:
        prompt = "%s [default '%s']: " % (field_name, default)
    else:
        prompt = field_name + ": "

    value = None
    while not value:
        if private:
            value = getpass(prompt)
        else:
            value = raw_input(prompt).strip()
        if not value:
            if default:
                value = default
            else:
                print "Error: %s is required, please enter a value" \
                    % field_name
    return value


def prompt_requirement(reqs, req_name, private=False):
    """Prompt the user for an activation requirement, using the current
    value as default, and update the passed requirements with the value
    they enter."""
    default = reqs.get_requirement_value("myproxy", req_name)
    value = input_default(req_name, default, private)
    reqs.set_requirement_value("myproxy", req_name, value)


if __name__ == '__main__':
    api, args = create_client_from_args()
    if len(args) < 1:
        sys.stderr.write(
            "username and endpoint arguments are required")
        sys.exit(1)

    ep = args[0]

    _, _, reqs = api.endpoint_activation_requirements(ep,
                                                      type="myproxy")

    for f in "hostname username passphrase".split():
        private = (f == "passphrase")
        prompt_requirement(reqs, f, private)

    try:
        _, _, result = api.endpoint_activate(ep, reqs)
        print "Activation successful"
        print "Subject:", result["subject"]
        print "Expires:", result["expire_time"]
    except APIError as e:
        print "Error: %s" % e.message
