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
Library for using the Globus Transfer API. Tested with python 2.6;
will likely also work with 2.7, but not with earlier releases or 3.x.

Can also be run with python -i or ipython and used as an interactive shell
for experimenting with the API:

ipython -- transfer_api.py USERNAME -k ~/.globus/userkey.pem \
           -c ~/.globus/usercert.pem \

OR

python -i transfer_api.py ...

It creates an TransferAPIClient instance called "api" with the credentials
passed on the command line, which you can use to make requests:

> print dir(api) # See a list of available methods.
> code, reason, data = api.tasksummary() # Test out tasksummary.

See https://transfer.api.globusonline.org for API documentation.
"""
from __future__ import print_function
import os.path
import os
import sys
import platform
import socket
import json
import urllib
import time
import ssl
try:
  from urlparse import urlparse
except:
  from urllib.parse import urlparse
try:
  from httplib import BadStatusLine
except:
  from http.client import BadStatusLine
from datetime import datetime, timedelta

from globusonline.transfer.api_client.verified_https \
    import VerifiedHTTPSConnection
from globusonline.transfer.api_client.goauth import get_access_token

API_VERSION = "v0.10"
DEFAULT_BASE_URL = "https://transfer.api.globusonline.org/" + API_VERSION
RETRY_WAIT_SECONDS=30

CA_FILE = "ca/all-ca.pem"

__all__ = ["TransferAPIClient", "TransferAPIError", "InterfaceError",
           "APIError", "ClientError", "ServerError", "ExternalError",
           "ServiceUnavailable", "Transfer", "Delete"]

# client version
__version__ = "0.10.17"


class TransferAPIClient(object):
    """
    Maintains a connection to the server as a specific user. Not thread
    safe. Uses the JSON representations.

    Convenience api methods return a triple:
      (status_code, status_message, data)

    data is either the JSON response loaded as a python dictionary,
    or None if the reponse was empty, or a conveninience wrapper around
    the JSON data if the data itself is hard to use directly.

    Endpoint names can be full canonical names of the form
    ausername#epname, or simply epname, in which case the API looks at
    the logged in user's endpoints.
    """

    def __init__(self, username, server_ca_file=None,
                 cert_file=None, key_file=None,
                 base_url=DEFAULT_BASE_URL,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 httplib_debuglevel=0, max_attempts=1,
                 goauth=None):
        """
        Initialize a client with the client credential and optional alternate
        base URL.

        For authentication, use either x509 or goauth.

        x509 requires configuring your Globus Online account with the x509
        certificate and having the private key available. Requires @cert_file
        and @key_file, or just one if both are in the same file.

        goauth requires fetching an access token from nexus, which supports
        several authentication methods including basic auth - see the
        goauth module and the nexus documentation.

        @param username: username to connect to the service with.
        @param server_ca_file: path to file containing one or more x509
                               certificates, used to verify the server
                               certificate. If not specified tries to choose
                               the appropriate CA based on the hostname in
                               base_url.
        @param cert_file: path to file containing the x509 client certificate
                          for authentication.
        @param key_file: path to file containg the RSA key for client
                         authentication. If blank and cert_file passed,
                         uses cert_file.
        @param goauth: goauth access token retrieved from nexus.
        @param base_url: optionally specify an alternate base url, if testing
                         out an unreleased or alternatively hosted version of
                         the API.
        @param timeout: timeout to set on the underlying TCP socket.
        @param max_attempts: Retry every API call on network
                             errors and ServiceUnavailable up to this many
                             times. Sleeps for 30 seconds between each attempt.
                             Note that a socket timeout will be treated as
                             a network error and retried. When max_attempts
                             is exceeded, the exception from the last attempt
                             will be raised. max_attempts=1 implies no
                             retrying.
        """
        if server_ca_file is None:
            server_ca_file = get_ca(base_url)
            if server_ca_file is None:
                raise InterfaceError("no CA found for base URL '%s'"
                                     % base_url)
        if not os.path.isfile(server_ca_file):
            raise InterfaceError("server_ca_file not found: '%s'"
                                 % server_ca_file)

        self.headers = {}

        if goauth:
            if cert_file or key_file:
                raise InterfaceError("pass only one auth method")
        elif cert_file or key_file:
            if not key_file:
                key_file = cert_file
            if not cert_file:
                cert_file = key_file
            if not os.path.isfile(cert_file):
                raise InterfaceError("cert_file not found: %s" % cert_file)
            if not os.path.isfile(key_file):
                raise InterfaceError("key_file not found: %s" % key_file)
            self.headers["X-Transfer-API-X509-User"] = username
        else:
            raise InterfaceError("pass one auth method")

        if max_attempts is not None:
            max_attempts = int(max_attempts)
            if max_attempts < 1:
                raise InterfaceError(
                    "max_attempts must be None or a positive integer")
        self.max_attempts = max_attempts

        self.goauth = goauth
        self.cert_file = cert_file
        self.key_file = key_file

        self.username = username
        self.server_ca_file = server_ca_file
        self.httplib_debuglevel = httplib_debuglevel

        self.base_url = base_url
        self.host, self.port = _get_host_port(base_url)
        self.timeout = timeout

        self.print_request = False
        self.print_response = False
        self.c = None

        self.user_agent = "Python-httplib/%s (%s)" \
                          % (platform.python_version(), platform.system())
        self.client_info = "globusonline.transfer.api_client/%s" % __version__

    def connect(self):
        """
        Create an HTTPS connection to the server. Run automatically by
        request methods.
        """
        kwargs = dict(ca_certs=self.server_ca_file, strict=False,
                      timeout=self.timeout)
        if self.cert_file:
            kwargs["cert_file"] = self.cert_file
            kwargs["key_file"] = self.key_file
        self.c = VerifiedHTTPSConnection(self.host, self.port, **kwargs)

        self.c.set_debuglevel(self.httplib_debuglevel)

    def set_http_connection_debug(self, value):
        """
        Turn debugging of the underlying VerifiedHTTPSConnection on or
        off. Note: this may print sensative information, like auth tokens,
        to standard out.
        """
        if value:
            level = 1
        else:
            level = 0
        self.httplib_debuglevel = level
        if self.c:
            self.c.set_debuglevel(level)

    def set_debug_print(self, print_request, print_response):
        self.print_request = print_request
        self.print_response = print_response

    def close(self):
        """
        Close the wrapped VerifiedHTTPSConnection.
        """
        if self.c:
            self.c.close()
        self.c = None

    def _request(self, method, path, body=None, content_type=None):
        if not path.startswith("/"):
            path = "/" + path
        url = self.base_url + path

        headers = self.headers.copy()
        if content_type:
            headers["Content-Type"] = content_type

        if self.print_request:
            print("")
            print(">>>REQUEST>>>:")
            print("%s %s" % (method, url))
            for h in headers.iteritems():
                print("%s: %s" % h)
            print("")
            if body:
                print(body)

        if self.goauth:
            headers["Authorization"] = "Globus-Goauthtoken %s" % self.goauth

        headers["User-Agent"] = self.user_agent
        headers["X-Transfer-API-Client"] = self.client_info

        def do_request():
            if self.c is None:
                self.connect()
            self.c.request(method, url, body=body, headers=headers)
            r = self.c.getresponse()
            response_body = r.read()
            return r, response_body

        for attempt in range(self.max_attempts):
            r = None
            try:
                try:
                    r, response_body = do_request()
                except BadStatusLine:
                    # This happens when the connection is closed by the server
                    # in between request, which is very likely when using
                    # interactively, in a client that waits for user input
                    # between requests, or after a retry wait. This does not
                    # count as an attempt - it just means the old connection
                    # has gone stale and we need a new one.
                    # TODO: find a more elegant way to re-use the connection
                    #       on closely spaced requests. Can we tell that the
                    #       connection is dead without making a request?
                    self.close()
                    r, response_body = do_request()
            except ssl.SSLError:
                # This probably has to do with failed authentication, so
                # retrying is not useful.
                self.close()
                raise
            except socket.error:
                # Network error. If the last attempt failed, raise,
                # otherwise do nothing and go on to next attempt.
                self.close()
                if attempt == self.max_attempts - 1:
                    raise

            # Check for 503 ServiceUnavailable, which is treated just like
            # network errors.
            if (r is not None and r.status == 503
            and attempt < self.max_attempts - 1):
                # Force sleep below and continue loop, unless we are on
                # the last attempt in which case skip this and return
                # the 503 error.
                self.close()
                r = None

            if r is not None:
                break
            else:
                time.sleep(RETRY_WAIT_SECONDS)

        if self.print_response:
            print("")
            print("<<<RESPONSE<<<:")
            print(r.status, r.reason)
            for h in r.getheaders():
                print("%s: %s" % h)
            print("")
            print(response_body)

        return r, response_body

    def _request_json(self, method, path, body=None, content_type=None):
        """
        Make a request and load the response body as JSON, if the response
        is not empty.
        """
        r, response_body = self._request(method, path, body, content_type)
        response_content_type = r.getheader("content-type")
        assert response_content_type == "application/json" or r.status != 200
        if response_body and response_content_type == "application/json":
            try:
                data = json.loads(response_body)
            except Exception as e:
                raise InterfaceError(
                    ("Unable to parse JSON in response: err='%s', "
                     +"body len='%d', status='%d %s'")
                    % (e, len(response_body), r.status, r.reason))
        else:
            data = None
            parts = response_content_type.split(';')
            if parts[0].strip() == "text/html":
                data = response_body
        return api_result(r, data)

    # Generic API methods:
    def get(self, path):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self._request_json("GET", path)

    def put(self, path, body):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self._request_json("PUT", path, body, "application/json")

    def post(self, path, body):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self._request_json("POST", path, body, "application/json")

    def _delete(self, path):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError

        TODO: this conflicts with the method for submitting delete
              jobs, so it's named inconsistently from the other HTTP method
              functions. Maybe they should all be _ prefixed?
        """
        return self._request_json("DELETE", path)

    # Convenience API methods:
    def tasksummary(self, **kw):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.get("/tasksummary" + encode_qs(kw))

    def task_list(self, **kw):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.get("/task_list" + encode_qs(kw))

    def task(self, task_id, **kw):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.get("/task/%s" % task_id + encode_qs(kw))

    def task_update(self, task_id, task_data, **kw):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.post("/task/%s" % task_id + encode_qs(kw))

    def task_cancel(self, task_id, **kw):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.post("/task/%s/cancel" % task_id + encode_qs(kw),
                         body=None)

    def task_successful_transfers(self, task_id, **kw):
        """
        Get a list of source and destination paths for files successful
        transferred in a transfer task. Raises an error if task_id is not
        a transfer task.

        @param marker: start from specified marker, copied from the
                       next_marker field of the previous page

        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.get("/task/%s/successful_transfers" % task_id
                        + encode_qs(kw))

    def subtask_list(self, parent_task_id, **kw):
        """
        DEPRECATED, see task_successful_transfers

        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.get("/task/%s/subtask_list"
                        % parent_task_id + encode_qs(kw))

    def subtask(self, task_id, **kw):
        """
        DEPRECATED, see task_successful_transfers

        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.get("/subtask/%s" % task_id + encode_qs(kw))

    def task_event_list(self, parent_task_id, **kw):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.get("/task/%s/event_list" % parent_task_id + encode_qs(kw))

    def endpoint_list(self, **kw):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.get("/endpoint_list" + encode_qs(kw))

    def endpoint(self, endpoint_name, **kw):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.get(_endpoint_path(endpoint_name) + encode_qs(kw))

    def endpoint_activation_requirements(self, endpoint_name, **kw):
        """
        @return: (code, reason, data), where data is an
                 ActivationRequirements instance instead of a plain
                 dictionary.
        @raise TransferAPIError
        """
        code, reason, data = self.get(_endpoint_path(endpoint_name,
                                                 "/activation_requirements")
                                      + encode_qs(kw))
        if code == 200 and data:
            data = ActivationRequirementList(data)
        return code, reason, data

    def endpoint_activate(self, endpoint_name, filled_requirements,
                          if_expires_in="", timeout=30):
        """
        @param endpoint_name: partial or canonical name of endpoint to
                              activate.
        @param filled_requirements: ActivationRequirementList instance with
                                    required values set for one activation
                                    type.
        @type filled_requirements: ActivationRequirementList
        @param if_expires_in: don't re-activate endpoint if it doesn't expire
                              for this many minutes. If not passed, always
                              activate, even if already activated.
        @param timeout: timeout in seconds to attempt contacting external
                        servers to get the credential.
        @return: (code, reason, data), where data is an ActivationRequirements
                 instance.
        @raise TransferAPIError
        """
        if filled_requirements:
            body = json.dumps(filled_requirements.json_data)
        else:
            raise InterfaceError("Use autoactivate instead; using activate "
                "with an empty request body to auto activate is "
                "deprecated.")
        # Note: blank query parameters are ignored, so we can pass blank
        # values to use the default behavior.
        qs = encode_qs(dict(if_expires_in=str(if_expires_in),
                            timeout=str(timeout)))
        code, reason, data = self.post(
            _endpoint_path(endpoint_name, "/activate" + qs), body=body)
        if code == 200 and data:
            data = ActivationRequirementList(data)
        return code, reason, data

    def endpoint_autoactivate(self, endpoint_name, if_expires_in="",
                              timeout=30):
        """
        @param endpoint_name: partial or canonical name of endpoint to
                              activate.
        @param if_expires_in: don't re-activate endpoint if it doesn't expire
                              for this many minutes. If not passed, always
                              activate, even if already activated.
        @param timeout: timeout in seconds to attempt contacting external
                        servers to get the credential.
        @return: (code, reason, data), where data is an ActivationRequirements
                 instance.
        @raise TransferAPIError
        """
        # Note: blank query parameters are ignored, so we can pass blank
        # values to use the default behavior.
        qs = encode_qs(dict(if_expires_in=str(if_expires_in),
                            timeout=str(timeout)))
        code, reason, data = self.post(
            _endpoint_path(endpoint_name, "/autoactivate" + qs), body=None)
        if code == 200 and data:
            data = ActivationRequirementList(data)
        return code, reason, data

    def endpoint_deactivate(self, endpoint_name, **kw):
        """
        @param endpoint_name: partial or canonical name of endpoint to
                              activate.
        @return: (code, reason, data)
        @raise TransferAPIError
        """
        # Note: blank query parameters are ignored, so we can pass blank
        # values to use the default behavior.
        code, reason, data = self.post(
            _endpoint_path(endpoint_name, "/deactivate") + encode_qs(kw),
            body=None)
        return code, reason, data

    def endpoint_ls(self, endpoint_name, path="", **kw):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        kw["path"] = path
        return self.get(_endpoint_path(endpoint_name, "/ls")
                        + encode_qs(kw))

    def endpoint_mkdir(self, endpoint_name, path, **kw):
        data = dict(path=path, DATA_TYPE="mkdir")
        return self.post(_endpoint_path(endpoint_name, "/mkdir")
                         + encode_qs(kw), json.dumps(data))

    def endpoint_create(self, endpoint_name, hostname=None, description="",
                        scheme="gsiftp", port=2811, subject=None,
                        myproxy_server=None, myproxy_dn=None,
                        public=False, is_globus_connect=False,
                        default_directory=None, oauth_server=None):
        """
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        data = { "DATA_TYPE": "endpoint",
                 "myproxy_server": myproxy_server,
                 "myproxy_dn": myproxy_dn,
                 "description": description,
                 "canonical_name": endpoint_name,
                 "public": public,
                 "is_globus_connect": is_globus_connect,
                 "default_directory": default_directory,
                 "oauth_server": oauth_server, }
        if not is_globus_connect:
            data["DATA"] = [dict(DATA_TYPE="server",
                                 hostname=hostname,
                                 scheme=scheme,
                                 port=port,
                                 subject=subject)]

        return self.post("/endpoint", json.dumps(data))

    def endpoint_update(self, endpoint_name, endpoint_data):
        """
        Update top level endpoint fields. Using this method to add or remove
        server is deprecated, use endpoint_server_add and
        endpoint_server_delete instead.

        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.put(_endpoint_path(endpoint_name),
                        json.dumps(endpoint_data))

    def endpoint_rename(self, endpoint_name, new_endpoint_name):
        _, _, endpoint_data = self.endpoint(endpoint_name)
        endpoint_data["canonical_name"] = new_endpoint_name
        del endpoint_data["name"]
        return self.endpoint_update(endpoint_name, endpoint_data)

    def endpoint_delete(self, endpoint_name):
        """
        Delete the specified endpoint. Existing transfers using the endpoint
        will continue to work, but you will not be able to use the endpoint
        in any new operations, and it will be gone from the endpoint_list.

        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self._delete(_endpoint_path(endpoint_name))

    def endpoint_server_list(self, endpoint_name, **kw):
        return self.get(_endpoint_path(endpoint_name, "/server_list")
                        + encode_qs(kw))

    def endpoint_server(self, endpoint_name, server_id, **kw):
        return self.get(_endpoint_path(endpoint_name, "/server/")
                        + urllib.quote(str(server_id)) + encode_qs(kw))

    def endpoint_server_delete(self, endpoint_name, server_id, **kw):
        return self._delete(_endpoint_path(endpoint_name, "/server/")
                            + urllib.quote(str(server_id)) + encode_qs(kw))

    def endpoint_server_add(self, endpoint_name, server_data):
        return self.post(_endpoint_path(endpoint_name, "/server"),
                         json.dumps(server_data))

    def shared_endpoint_create(self, endpoint_name, host_endpoint,
                               host_path):
        """
        [ALPHA] This API is alpha and may change between minor server releases.
        It is provided for testing and development only.

        Create a shared endpoint on the specified host. Raises an error if
        the host endpoint does not support sharing, if the user is not licensed
        to use sharing, or if the specified path is not allowed for sharing.

        @param endpoint_name: name of the new shared endpoint to create
        @param host_endpoint: endpoint that hosts the actual data for the
          shared endpoint. Must be running a newer GridFTP server with sharing
          enabled.
        @param host_path: a path on the host_endpoint to use as the root of
          the new shared endpoint.

        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        data = { "DATA_TYPE": "shared_endpoint",
                 "name": endpoint_name,
                 "host_endpoint": host_endpoint,
                 "host_path": host_path, }
        return self.post("/shared_endpoint", json.dumps(data))

    def submission_id(self):
        """
        @return: (status_code, status_reason, data)
        @raise: TransferAPIError
        """
        return self.get("/submission_id")

    # backward compatibility
    transfer_submission_id = submission_id

    def transfer(self, transfer):
        """
        @type transfer: Transfer object
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.post("/transfer", transfer.as_json())

    def delete(self, delete):
        """
        @type delete: Delete object
        @return: (status_code, status_reason, data)
        @raise TransferAPIError
        """
        return self.post("/delete", delete.as_json())


class Transfer(object):
    """
    Class for constructing a transfer request, which is a collections of items
    containing the source and destination paths, along with flags.
    A transfer can only invovle one source and one destination endpoint, so
    they are set in the constructor.

    @param **kw: support additional top level options without having to
                 add them to the client API. New options should use this.
                 Example options are encrypt_data and verify_checksum,
                 both of which are boolean and default to False if not
                 specified.
    """
    def __init__(self, submission_id, source_endpoint, destination_endpoint,
                 deadline=None, sync_level=None, label=None, **kw):
        self.submission_id = submission_id
        self.source_endpoint = source_endpoint
        self.destination_endpoint = destination_endpoint
        self.deadline = deadline
        self.sync_level = sync_level
        self.kw = kw
        self.label = label
        self.items = []

    def add_item(self, source_path, destination_path, recursive=False,
                 verify_size=None):
        item = dict(source_path=source_path,
                    destination_path=destination_path,
                    recursive=recursive,
                    verify_size=verify_size,
                    DATA_TYPE="transfer_item")
        self.items.append(item)

    def as_data(self):
        if self.deadline is None:
            deadline = None
        else:
            deadline = str(self.deadline)
        data = { "DATA_TYPE": "transfer",
                 "length": len(self.items),
                 "submission_id": self.submission_id,
                 "source_endpoint": self.source_endpoint,
                 "destination_endpoint": self.destination_endpoint,
                 "deadline": deadline,
                 "sync_level": self.sync_level,
                 "label": self.label,
                 "DATA": self.items }
        if self.kw:
            data.update(self.kw)
        return data

    def as_json(self):
        return json.dumps(self.as_data())

# For backward compatibility; new code should just use Transfer.
SimpleTransfer = Transfer


class Delete(object):
    """
    Class for constructing a delete request, which contains an endpoint and a
    collections of items containing the paths to delete on that endpoint. To
    delete directories, the recursive option must be set.
    """
    def __init__(self, submission_id, endpoint, deadline=None, recursive=False,
                 ignore_missing=True, label=None, interpret_globs=False):
        self.submission_id = submission_id
        self.endpoint = endpoint
        self.deadline = deadline
        self.recursive = recursive
        self.ignore_missing = ignore_missing
        self.interpret_globs = interpret_globs
        self.label = label
        self.items = []

    def add_item(self, path):
        item = dict(path=path, DATA_TYPE="delete_item")
        self.items.append(item)

    def as_data(self):
        if self.deadline is None:
            # TODO: there is a bug in the API that doesn't allow null
            # deadline for delete. Change this once it's fixed.
            #deadline = None
            deadline = str(datetime.utcnow() + timedelta(seconds=3600 * 24))
        else:
            deadline = str(self.deadline)
        return { "DATA_TYPE": "delete",
                 "length": len(self.items),
                 "submission_id": self.submission_id,
                 "endpoint": self.endpoint,
                 "deadline": deadline,
                 "recursive": self.recursive,
                 "ignore_missing": self.ignore_missing,
                 "interpret_globs": self.interpret_globs,
                 "label": self.label,
                 "DATA": self.items }

    def as_json(self):
        return json.dumps(self.as_data())


class ActivationRequirementList(object):
    """
    Wrapper around the activation requirement list data which makes it easier
    to set specific values. The json data itself uses a list to preserve
    order for display in a UI, but that is not so convenient for programmatic
    access.
    """
    fields = []

    def __init__(self, json_data):
        if json_data["DATA_TYPE"] not in ("activation_requirements",
                                          "activation_result"):
            raise InterfaceError("Expected activation_requirements or "
                             "activation_result data, got "
                             "'%s'" % json_data["DATA_TYPE"])
        self.json_data = json_data

        # The req_list contains references to activation_requirement
        # data dictionaries in self.json_data.
        self.req_list = []

        self.types = []
        self.type_reqs = {}
        self.index_map = {}

        subdocuments = json_data.get("DATA", ())
        for r in subdocuments:
            if r["DATA_TYPE"] != "activation_requirement":
                continue
            type_ = r["type"]
            name = r["name"]
            if type_ not in self.types:
                self.types.append(type_)
            key = type_ + "." + name
            self.req_list.append(r)
            self.index_map[key] = len(self.req_list) - 1

    def __getitem__(self, key):
        return self.json_data[key]

    def _get_requirement(self, key):
        """
        Keys should be "type.name"
        """
        return self.req_list[self.index_map[key]]

    def set_requirement_value(self, type, name, value):
        """
        @raise KeyError: if requirement not found.
        """
        key = type + "." + name
        self._get_requirement(key)["value"] = value

    def get_requirement_value(self, type, name):
        """
        @raise KeyError: if requirement not found.
        """
        key = type + "." + name
        return self._get_requirement(key)["value"]

    def is_required(self, type, name):
        """
        @raise KeyError: if requirement not found.
        """
        key = type + "." + name
        return self._get_requirement(key)["required"]

    def is_private(self, type, name):
        """
        @raise KeyError: if requirement not found.
        """
        key = type + "." + name
        return self._get_requirement(key)["private"]

    def get_requirements_list(self, type):
        """
        If no requirements were found with matching type, that type is not
        supported and we return None.
        """
        reqs = [req for req in self.req_list if req["type"] == type]
        if reqs:
            return reqs
        return None

    def set_submit_type(self, type):
        """
        Removes requirements of other types; this is needed when submitting,
        to indicate what type of activation is actually desired.
        """
        self.req_list = [req for req in self.req_list if req["type"] == type]
        # remap
        keys = [r["type"] + "." + r["name"] for r in self.req_list]
        self.index_map = dict(zip(keys, range(len(keys))))

    def as_json(self):
        return json.dumps(self.json_data)

    def supported_types(self):
        return self.types

    def __str__(self):
        return str(self.json_data)

    def __repr__(self):
        return str(self.json_data)


def _get_host_port(url):
    o = urlparse(url)
    netloc_parts = o.netloc.split(":")
    if len(netloc_parts) == 2:
        host = netloc_parts[0]
        port = int(netloc_parts[1])
    else:
        host = o.netloc
        if o.scheme == "https":
            port = 443
        else:
            port = 80
    return (host, port)


class TransferAPIError(Exception):
    """
    Superclass for API errors.
    """
    pass


class InterfaceError(TransferAPIError):
    """
    Error generated by the python interface.
    """
    pass


class APIError(TransferAPIError):
    """
    Wrapper around an error returned by the transfer API.
    """
    def __init__(self, error_code, status_code, status_message, error_data):
        self.status_code = status_code
        self.status_message = status_message
        self.code = error_code
        # error_data not set unless reply is from the api itself
        self.read_error_data(error_code, error_data)

        Exception.__init__(self, status_message)

    def read_error_data(self, error_code, error_data):
        if error_code:
            # API error message
            self.resource = error_data["resource"]
            self._message = error_data["message"]
            self.request_id = error_data["request_id"]
        else:
            # Possibly web server error message, assume plaintext
            # response body
            self._message = error_data

    @property
    def message(self):
        return self._message

    @property
    def status(self):
        return "%s %s" % (self.status_code, self.status_message)

    def __str__(self):
        return "%s (%s): %s" % (self.code, self.status, self.message)


class ClientError(APIError):
    """
    DEPRECATED, use APIError instead

    Used for 400 errors.
    """
    pass


class ServerError(APIError):
    """
    DEPRECATED, use APIError instead

    Used for 500 error only. Indicates bug in the server.
    """
    pass


class ExternalError(APIError):
    """
    DEPRECATED, use APIError instead

    Used for 502 Bad Gateway and 504 Gateway Timeout.
    Inticates problem contacting external resources, like gridftp
    endpoints and myproxy servers.
    """
    pass


class ServiceUnavailable(APIError):
    """
    DEPRECATED, use APIError instead

    Used for 503 Service Unavailable.
    """
    pass


def _endpoint_path(endpoint_name, trailing_path=None):
    """
    endpoint_name must be percent encoded, because it may contain
    '#' (used to separate username from endpoint name).
    """
    p = "/endpoint/%s" % urllib.quote(endpoint_name)
    if trailing_path:
        p += trailing_path
    return p


def api_result(response, data):
    status_code = response.status
    status_message = response.reason
    error_code = response.getheader("X-Transfer-API-Error", None)

    if error_code or (status_code >= 400 and status_code < 600):
        _raise_error(error_code, status_code, status_message, data)
    elif status_code >= 200 and status_code < 400:
        return (status_code, status_message, data)
    else:
        raise InterfaceError("Unexpected status code in response: %d"
                             % status_code)


def _raise_error(error_code, status_code, status_message, error_data):
    """
    Raise an APIError based on the HTTP status code and API error code
    and error data.

    For backward compatibility, use APIError subclasses when possible. New
    code should still except APIError and check the code, as the subclasses
    are deprecated.
    """
    if status_code >= 200 and status_code < 400:
        raise InterfaceError("status code %d is not an error"
                             % status_code)

    # error_code not set means the request never made it all the way to the
    # go application, typically caused by a bad base_url.
    if not error_code and status_code >= 400 and status_code < 500:
        raise ClientError(error_code, status_code, status_message, error_data)

    if status_code in (400, 403, 404, 405, 406, 409):
        raise ClientError(error_code, status_code, status_message, error_data)
    elif status_code in (502, 504):
        raise ExternalError(error_code, status_code, status_message,
                             error_data)
    elif status_code == 503:
        raise ServiceUnavailable(error_code, status_code, status_message,
                                 error_data)
    elif status_code == 500:
        raise ServerError(error_code, status_code, status_message,
                          error_data)

    raise APIError(error_code, status_code, status_message, error_data)


def encode_qs(kwargs=None, **kw):
    if kwargs is None:
        kwargs = kw
    else:
        kwargs.update(kw)

    if kwargs:
        return "?" + urllib.urlencode(kwargs)
    else:
        return ""


def get_ca(base_url_or_hostname):
    # Note: use the same CA file for all servers. This is simpler and
    # facilitates the transition from GoDaddy to InCommon for the api servers.
    try:
        import pkg_resources
        path = pkg_resources.resource_filename(__name__, CA_FILE)
    except ImportError:
        pkg_path = os.path.dirname(__file__)
        path = os.path.join(pkg_path, CA_FILE)
    return path


def process_args(args=None, parser=None):
    from optparse import OptionParser

    if not parser:
        usage = "usage: %prog username [options]"
        parser = OptionParser(usage=usage)

    parser.add_option("-C", "--server-ca-file", dest="server_ca_file",
                      help="ca file for validating server",
                      metavar="SERVER_CA_FILE")
    parser.add_option("-c", "--cert", dest="cert_file",
                      help="client cert file", metavar="CERT_FILE")
    parser.add_option("-k", "--key", dest="key_file",
                      help="client key file", metavar="KEY_FILE")
    parser.add_option("-p", "--password-prompt", dest="password_prompt",
                      action="store_true", default=False,
                      help="prompt for GO password for authentication")
    parser.add_option("-b", "--base-url", dest="base_url",
                      help="alternate base URL", metavar="URL")
    parser.add_option("-t", "--socket-timeout", dest="timeout", type="int",
                      help="timeout in seconds for underlying TCP socket",
                      metavar="TIMEOUT_SECONDS")
    parser.add_option("-a", "--max-attempts", dest="max_attempts", type="int",
                      help="retry up to this many times on connection errors",
                      metavar="ATTEMPTS")
    parser.add_option("-g", "--goauth", dest="goauth",
                      help="Use goauth authentication",
                      metavar="TOKEN", type="str")
    parser.set_defaults(base_url=DEFAULT_BASE_URL,
                        max_attempts=1,
                        timeout=socket._GLOBAL_DEFAULT_TIMEOUT)

    options, args = parser.parse_args(args)
    if len(args) < 1:
        parser.error("username arguments is required")

    auth_method_error = ("use only one authentication method:"
                         + " -p, -k/-c, or -g")
    if options.password_prompt:
        if options.goauth or options.key_file or options.cert_file:
            parser.error(auth_method_error)
        username = args[0]
        success = False
        for i in range(5):
            try:
                result = get_access_token(username=username)
                args[0] = result.username
                options.goauth = result.token
                success = True
                break
            except InterfaceError:
                sys.stderr.write("authentication to GO failed")
                if i < 4:
                    sys.stderr.write(", please try again")
                sys.stderr.write("\n")
                username = None
        if not success:
            sys.stderr.write("too many failed attempts, exiting\n")
            sys.exit(2)
    elif options.goauth:
        if options.key_file or options.cert_file:
            parser.error(auth_method_error)
    else:
        # If only one of -k/-c is specified, assume both the key and cert are
        # in the same file.
        if not options.key_file:
            if not options.cert_file:
                parser.error(auth_method_error)
            options.key_file = options.cert_file
        if not options.cert_file:
            options.cert_file = options.key_file

    return options, args


def create_client_from_args(args=None):
    """
    Create a client instance according to options in command line
    arguments.

    @param args: if passed, use these arguments instead of sys.argv

    @return: (api_client_instance, extra_args)
    """
    options, args = process_args(args)
    api = TransferAPIClient(args[0], server_ca_file=options.server_ca_file,
                            cert_file=options.cert_file,
                            key_file=options.key_file,
                            base_url=options.base_url,
                            goauth=options.goauth,
                            timeout=options.timeout,
                            max_attempts=options.max_attempts)
    return api, args[1:]
