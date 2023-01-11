#!/bin/sh

# Copyright contributors to the IBM Security Verify Directory project

# This script is used to create a new NFS based PVC.  The NFS server should
# first be created by calling:
#  kubectl create -f nfs-server.yaml

set -e

if [ $# -ne 1 ] ; then
    echo "usage: $0 [pvc-name]"
    exit 1
fi

# Work out the IP address of the NFS service.
ip=`kubectl get service nfs-service -o jsonpath='{.spec.clusterIP}'`

# Now we can create the PVC.
cat <<EOF | kubectl create -f -
apiVersion: v1
kind: PersistentVolume
metadata:
  name: $1
  labels:
    app: $1
spec:
  capacity:
    storage: 200Mi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Recycle
  nfs:
    server: "$ip"
    path: "/exports/$1" 

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $1
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: ""
  resources:
    requests:
      storage: 200Mi
  selector:
    matchLabels:
      app: $1
EOF

