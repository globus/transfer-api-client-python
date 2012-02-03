This package contains a client library for the Globus Online Transfer API.

For detailed documentation of the Transfer API, see
[https://transfer.api.globusonline.org](https://transfer.api.globusonline.org)


Installation
============

If you downloaded the source from github, simply run:

    python setup.py install

There is also a package on PyPI with the latest stable version; it can be
installed with `easy_install` or `pip`:

    easy_install globusonline-transfer-api-client


Usage
=====

Basic usage:

    from globusonline.transfer import api_client

    api = api_client.TransferAPIClient(username="myusername",
                                    cert_file="/path/to/client/credential",
                                    key_file="/path/to/client/credential")
    status_code, status_message, data = api.task_list()

See the `globusonline/transfer/api_client/examples` directory for more complete
examples. If you installed from PyPI, this will be somewhere in your Python
path:

    python -c "from globusonline.transfer import api_client; print api_client.__path__"

One of the best ways to learn the library is to run an interactive interpreter
with an instance of the client. The module provides a shortcut for doing this:

    python -i -m globusonline.transfer.api_client.main USERNAME -p
    >>> status_code, status_message, data = api.task_list()
    >>> dir(api) # get a list of all available methods

replace USERNAME with your Globus Online username, and you will be prompted
for your password. This form of authentication should not be used in production
systems, but is useful for development and testing.


Changlog
========

0.10.10
-------
* Include CAs in the package; the `server_ca_file` parameter (and the -C
  command line arg) is no longer required.
* Alternate `delegate_proxy` activation implementation using a custom C
  program called `mkproxy` instead of M2Crypto. See `mkproxy/README.markdown`
  for details. `mkproxy` is the preferred implementations, so if both the
  executable and M2Crypto are installed, `mkproxy` is used.
* Moved examples to package data, so they are included in the PyPI package.

0.10.9
------

* Add https proxy support, using the `HTTPS_PROXY` environment variable.
  This has been tested in 2.6.6 and 2.7, and does not work in 2.6.1
  (because the tunnel features was added in the middle of the 2.6.X
  cycle). Other versions > 2.6.1 may also work, but this has not been
  tested. Thanks to Brett Viren for this feature!
* If you have both your key and certificate in the same file, you
  don't have to pass it to both -c and -k when running the examples and
  interactive client. Just pass one of them, and it will assume the
  file contains both.
* Added some basic usage docs to `examples/delegate_proxy_activate.py`
* Fix example.py breakage when printing GC endpoints.
* Import readline in main.py, for more convenient interactive testing.
