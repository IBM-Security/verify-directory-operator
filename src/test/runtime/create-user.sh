#!/bin/sh

##############################################################################
# Copyright contributors to the IBM Security Verify Directory project.
##############################################################################

#
# This script is used to create a new user on the specified replica.
#

set -e

port=9636
extra_args="-Z -K /home/idsldap/idsslapd-idsldap/etc/server.kdb"
admin_dn=cn=root
suffix=o=sample
admin_pwd=`kubectl get secrets/isvd-secret --template={{.data.admin_password}} | base64 -D`

ldif=/tmp/a.ldif

trap "rm -f $ldif" EXIT

#
# The following function is used to create the user on the specified pod.
#

create_user()
{
cat <<EOF > $ldif
dn: cn=$1,$suffix
changetype: add
objectClass: inetOrgPerson
cn: $1
sn: $1
EOF

    echo "Creating $1 on $2...."

    kubectl cp $ldif $2:$ldif

    kubectl exec -it $2 -- ldapadd -h 127.0.0.1 \
        -p $port $extra_args -D $admin_dn -w $admin_pwd -f $ldif
}

#
# Check the command line options.
#

if [ $# -ne 2 ] ; then
    echo "usage: $0 [user] [pvc]|all"
    exit 1
fi

#
# Create the user.
#

if [ $2 = "all" ] ; then
    pods=`kubectl get pods -l app.kubernetes.io/part-of=verify-directory --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}'`

    for pod in $pods; do
        create_user $1_$pod $pod
    done

else 
    pod=`kubectl get pods --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}' | grep $2`

    create_user $1 $pod
fi

