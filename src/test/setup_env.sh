#!/bin/sh

# Copyright contributors to the IBM Security Verify Directory project

# This script is used to initialise or clean-up the Kubernetes environment
# so that it can run the verify directory test operator, and more specifically
# the custom resource found at 
#      src/config/samples/ibm_v1_ibmsecurityverifydirectory.yaml

set -e

usage()
{
    echo "usage: $0 [init <license-key>|clean]"
    exit 1
}

yaml_files="env-configmap.yaml \
    env-secret.yaml \
    proxy-configmap.yaml \
    proxy-service.yaml \
    server-configmap.yaml \
    service-account.yaml"

root=`dirname $0`

if [ -z "$PVCS" ] ; then
    PVCS="replica-1 replica-2 replica-3 proxy"
fi

if [ "$1" = "clean" ] ; then

    # Check the command line.
    if [ $# != 1 ] ; then
        usage
    fi

    # Process each of the YAML files.
    for yaml in $yaml_files; do
        echo "Processing $yaml..."
        kubectl delete -f $root/$yaml
    done

    # Remove license key secret.
    echo "Deleting the license key secret..."
    kubectl delete secret isvd-secret

    # Remove the PVCs.
    echo "Deleting the PVCs..."
    for pvc in $PVCS; do
        $root/create-nfs-pvc.sh remove $pvc
    done

    # Remove the NFS server.
    echo "Deleting the NFS server..."
    kubectl delete -f $root/nfs-server.yaml

elif [ "$1" = "init" ] ; then

    # Check the command line.
    if [ $# != 2 ] ; then
        usage
    fi

    # Create the NFS server.
    echo "Creating the NFS server..."
    kubectl apply -f $root/nfs-server.yaml

    kubectl wait deployment nfs-server --for condition=Available=True \
                --timeout=90s

    # Create the PVCs.
    echo "Creating the PVCs..."
    for pvc in $PVCS; do
        $root/create-nfs-pvc.sh add $pvc
    done

    # Create the license key secret.
    echo "Creating the license key secret..."
    $root/create-license-key-secret.sh $2

    # Process each of the YAML files.
    for yaml in $yaml_files; do
        echo "Processing $yaml..."
        kubectl apply -f $root/$yaml
    done

else
    usage
fi



