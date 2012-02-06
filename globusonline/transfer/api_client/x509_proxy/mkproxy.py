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
Implementation using mkproxy C program. Requires that the executable be
installed in the directory containing this module (the x509_proxy directory).

If linked against a non-standard openssl library, make sure that
LD_LIBRARY_PATH is set accordingly in the environment.
"""
import os.path
import subprocess

from globusonline.transfer.api_client import InterfaceError

NOT_SET = object()
_path = NOT_SET


def get_mkproxy_path():
    global _path
    if _path is NOT_SET:
        _path = "mkproxy"
        try:
            import pkg_resources
            _path = pkg_resources.resource_filename(__name__, _path)
        except ImportError:
            pkg_path = os.path.dirname(__file__)
            _path = os.path.join(pkg_path, _path)
        if not os.path.isfile(_path):
            _path = None
    return _path


def create_proxy_from_file(issuer_cred_file, public_key, lifetime_hours=1):
    with open(issuer_cred_file) as f:
        issuer_cred = f.read()

    p = subprocess.Popen([get_mkproxy_path(), str(lifetime_hours)],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

    output, err = p.communicate(public_key + issuer_cred)
    if p.returncode != os.EX_OK:
        raise InterfaceError("mkproxy failed with code %d: %s"
                             % (p.returncode, err.strip()))
    return output
