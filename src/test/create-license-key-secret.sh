#!/bin/sh

# Copyright contributors to the IBM Security Verify Directory project

# This script is used to create the secret which holds the license
# key.

if [ $# -ne 1 ] ; then
    echo "usage: $0 [license-key]"
    exit 1
fi

kubectl create secret generic isvd-secret --from-literal=license-key=$1 \
        --from-literal=admin-password=passw0rd1

