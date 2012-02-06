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
Library for creating proxy certificates. Two implementations are provided -
one that uses M2Crypto, and another that uses a custom C program built against
openssl.
"""
from globusonline.transfer.api_client.x509_proxy import mkproxy

__all__ = ["create_proxy", "create_proxy_from_file"]

# Favor the C program implementation if available.
if mkproxy.get_mkproxy_path():
    from globusonline.transfer.api_client.x509_proxy.mkproxy \
                                                import create_proxy_from_file
    implementation = "mkproxy"
else:
    # raises ImportError if M2Crypto is not available
    from globusonline.transfer.api_client.x509_proxy.m2 \
                                                import create_proxy_from_file
    implementation = "m2"
