#!/bin/sh

# Copyright contributors to the IBM Security Verify Directory project

# This script is used to create the secret which holds the license
# key.

if [ $# -ne 1 ] ; then
    echo "usage: $0 [license-key]"
    exit 1
fi

tlspath=`dirname $0`/../certs

kubectl create secret generic isvd-secret --from-literal=license-key=$1 \
        --from-literal=admin_password=passw0rd1 \
        --from-literal=replication_password=passw0rd2 \
        --from-literal=server_key="`cat $tlspath/tls.crt $tlspath/tls.key`" \
        --from-literal=server_cert="`cat $tlspath/tls.crt`"

