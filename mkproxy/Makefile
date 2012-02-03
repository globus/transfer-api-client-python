PYTHON_PACKAGE=$(shell python -c "import os.path; from globusonline.transfer import api_client; print os.path.dirname(api_client.__file__)")

mkproxy: mkproxy.c
	gcc -o mkproxy mkproxy.c -lcrypto

install: mkproxy
	cp mkproxy "$(PYTHON_PACKAGE)/x509_proxy/"

.PHONY: clean

clean:
	-rm -f mkproxy
