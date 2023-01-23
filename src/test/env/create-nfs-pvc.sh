#!/bin/sh

# Copyright contributors to the IBM Security Verify Directory project

# This script is used to create a new NFS based PVC.  The NFS server should
# first be created by calling:
#  kubectl create -f nfs-server.yaml

set -e

if [ $# -ne 2 ] ; then
    echo "usage: $0 [add|remove] [pvc-name]"
    exit 1
fi

pvc=$2

if [ $1 = "remove" ] ; then

    kubectl delete pvc $pvc
    kubectl delete pv $pvc

    kubectl exec deploy/nfs-server -- rm -rf /exports/$pvc
elif [ $1 = "add" ] ; then

    # Work out the IP address of the NFS service.
    ip=`kubectl get service nfs-service -o jsonpath='{.spec.clusterIP}'`

    # Create the directory on the NFS server.
    kubectl exec deploy/nfs-server -- mkdir -p /exports/$pvc
    kubectl exec deploy/nfs-server -- chmod 777 /exports/$pvc

    # Now we can create the PVC.
    cat <<EOF | kubectl create -f -
apiVersion: v1
kind: PersistentVolume
metadata:
  name: $pvc
  labels:
    app: $pvc
spec:
  capacity:
    storage: 200Mi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  nfs:
    server: "$ip"
    path: "/exports/$pvc" 

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: ""
  resources:
    requests:
      storage: 200Mi
  selector:
    matchLabels:
      app: $pvc
EOF

else
    echo "usage: $0 [add|remove] [pvc-name]"
    exit 1
fi



