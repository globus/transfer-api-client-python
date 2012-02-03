Overview
========

This program creates a proxy from a given credential and public key, without
requiring a CSR. It can be used instead of M2Crypto to create a proxy for use
with `delegate_proxy` activation.

Installation
============

First make sure the client library version 0.10.10 or later is installed in
your python path:

    python -c "from globusonline.transfer import api_client; print api_client.__version__"

Then build and install mkproxy to the correct location:

    make install

It requires only gcc and the openssl library and headers. If your openssl is in
a nonstandard location, you'll need to edit the Makefile and add -I and -L
options to the gcc line, pointing at the include directory and lib directory
respectively.

The install script copies mkproxy to the directory containing the
`globusonline.transfer.api_client.x509_proxy` package. Once the executable is
in place, it will be used instead of M2Crypto. This can be verified by checking
that `globusonline.transfer.api_client.x509_proxy.implementation` is "mkproxy"
instead of "m2".
