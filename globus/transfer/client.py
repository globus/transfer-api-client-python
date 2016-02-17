from __future__ import print_function

import requests
import urllib


STACKS = {
    "prod": ("transfer.api.globusonline.org",
             "nexus.api.globusonline.org"),
    "staging": ("transfer.qa.api.globusonline.org",
                "graph.api.staging.globuscs.info"),
    "test": ("transfer.test.api.globusonline.org",
             "graph.api.test.globuscs.info"),
    "sandbox": ("transfer.sandbox.api.globusonline.org",
               "graph.api.go.sandbox.globuscs.info"),
    "beta": ("transfer.api.beta.globus.org",
             "nexus.api.beta.globus.org"),
}

TOKEN_PATH = "/goauth/token?grant_type=client_credentials"


class TransferClient(object):
    def __init__(self, stack="prod", custom_hosts=None, custom_verify=True):
        if stack == "custom":
            self._hosts = custom_hosts
            self._verify = custom_verify
        else:
            self._hosts = STACKS.get(stack)
            self._verify = True
            if self._hosts is None:
                raise ValueError("Unknown stack '%s'" % stack)
        self._token = None
        self._s = requests.Session()

    def get_goauth_token(self, username, password):
        url = "https://%s%s" % (self._hosts[1], path)
        headers = dict(Accepts="application/json")
        r = requests.get(url, auth=(username, password),
                         headers=headers, verifyf=self._verify)
        data = r.json()
        return data["access_token"]

    def get(self, path, path_args=None, params=None):
        return self._request("GET", path, path_args, params=params)

    def post(self, path, path_args=None, body=None):
        if body is not None and not isinstance(body, basestring):
            body = json.dumps(body)
        return self._request("POST", path, path_args, data=body)

    def delete(self, path, path_args=None):
        return self._request("DELETE", path, path_args)

    def put(self, path, path_args=None, body=None):
        if body is not None and not isinstance(body, basestring):
            body = json.dumps(body)
        return self._request("PUT", path, path_args, data=body)

    def _request(self, method, path, path_args=None, **kw):
        if path_args is not None:
            path_args = tuple(urllib.quote(arg) for arg in path_args)
            path = path % path_args
        if "headers" not in kw:
            kw["headers"] = {}
        kw["headers"]["Accepts"] = "application/json"
        kw["headers"]["Authorization"] = "Bearer %s" % self._token
        kw["verify"] = self._verify
        url = "https://%s/v0.10%s" % (self._hosts[0], path)
        r = self._s.request(method, url, **kw)
        content_type = r.headers["Content-Type"]
        if 200 <= r.status_code < 300 and content_type == "application/json":
            return r.json()
        raise TransferAPIError(r)

    def set_auth_token(self, token):
        self._token = token


class TransferAPIError(Exception):
    def __init__(self, r):
        if r.headers["Content-Type"] == "application/json":
            data = r.json()
            self.code = data["code"]
            self.message = data["message"]
            self.request_id = data["request_id"]
        else:
            self.code = "BadRequest"
            self.message = "Requested URL is not an API resource"
            self.request_id = ""
        super(TransferAPIError, self).__init__(self.code, self.message,
                                               self.request_id)


def _main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: %s token_file [stack]" % sys.argv[0])
        sys.exit(1)

    with open(sys.argv[1]) as f:
        token = f.read().strip()

    if len(sys.argv) > 2:
        stack = sys.argv[2]
    else:
        stack = "prod"

    api = TransferClient(stack)
    api.set_auth_token(token)
    return api


if __name__ == '__main__':
    api = _main()
