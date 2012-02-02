#!/bin/bash

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 /path/to/proxy"
    exit 2
fi

cd $(dirname $0)

# create a key pair
if [ ! -f server.pubkey ]; then
    openssl genrsa -out server.key 1024
    openssl rsa -in server.key -pubout -out server.pubkey
fi

# build mkproxy
make

# run
cat server.pubkey "$1" | ./mkproxy 1
#| openssl x509 -noout -text
