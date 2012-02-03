#!/usr/bin/env python -i

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
Script for using the client in an interactive interpreter, e.g.

 python -i -m globusonline.transfer.api_client.main USERNAME -p

It creates a TransferAPIClient instance called "api" with the credentials
passed on the command line, which you can use to make requests.

 >>> import readline # This gives you command history.
 >>> print dir(api) # See a list of available methods.
 >>> code, reason, data = api.tasksummary() # Test out tasksummary.
 >>> api.set_debug_print(True, True) # Print raw request/responses.
 >>> code, reason, data = api.tasksummary() # Run again with debugging enabled.

"""

import globusonline.transfer.api_client

if __name__ == '__main__':
    try:
        import readline
    except ImportError:
        pass
    api, _ = globusonline.transfer.api_client.create_client_from_args()
