This package contains a client library for the Globus Online Transfer API.

    from globusonline.transfer import api_client

    api = api_client.TransferAPIClient(username="myusername",
                                    server_ca_file="/path/to/godaddy_ca.pem",
                                    cert_file="/path/to/client/credential",
                                    key_file="/path/to/client/credential")
    status_code, status_message, data = api.task_list()

One of the best ways to learn the library is to run an interactive interpreter
with an instance of the client. The module provides a shortcut for doing this:

    python -i -m globusonline.transfer.api_client.main USERNAME -p \
      -C ca/gd-bundle_ca.cert
    >>> status_code, status_message, data = api.task_list()
    >>> dir(api) # get a list of all available methods

replace USERNAME with your Globus Online username, and you will be prompted
for your password. This form of authentication should not be used in production
systems, but is useful for development and testing.

For detailed documentation of the Transfer API, see
[https://transfer.api.globusonline.org](https://transfer.api.globusonline.org)
