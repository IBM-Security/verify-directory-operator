#!/bin/sh

##############################################################################
# Copyright contributors to the IBM Security Verify Directory project.
##############################################################################

#
# This script is used to validate the current environment.  This will involve:
#    - Querying the status of the proxy to ensure that all servers are
#      active and available.
#    - Querying the suffix of each individual LDAP server to ensure that all
#      inetOrgPerson entries are the same.
#    - Querying the suffix of the proxy to ensure that all inetOrgPerson
#      entries are the same.
#

set -e

port=9389
replica_port=9636
replica_args="-Z -K /home/idsldap/idsslapd-idsldap/etc/server.kdb"
admin_dn=cn=root
suffix=o=sample
admin_pwd=`kubectl get secrets/isvd-secret --template={{.data.admin_password}} | base64 -D`

#
# Check the command line options.
#

if [ $# != 0 -a $# != 1 ] ; then
    echo "Usage: $0 [-verbose]"

    exit 1
fi

verbose="$1"

if [ ! -z $verbose ] ; then
    if [ "$verbose" != "-verbose" -a "$verbose" != "-v" ] ; then
        echo "Usage: $0 [-verbose]"

        exit 1
    fi
fi

#
# Query the status of the proxy.
#

echo "Checking the status of the replicas within the proxy...."

tempfile=/tmp/search.txt

trap "rm -f $tempfile" EXIT

proxy=`kubectl get pods --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}' | grep proxy`

kubectl exec -it $proxy -- idsldapsearch -h 127.0.0.1 \
        -p $port -D $admin_dn -w $admin_pwd \
        -b "cn=partitions,cn=proxy,cn=monitor" \
        -s base "(objectclass=*)" > $tempfile

if [ ! -z "$verbose" ] ; then
    echo "Search result:"
    cat $tempfile
fi

set +e
grep "ibm-slapdServerStatus" $tempfile | grep -qv "=active"
rc=$?
set -e

if [ $rc -ne 1 ] ; then
    echo "Error> some servers are inactive!"
    cat $tempfile

    exit 1
fi

echo "    All of the replicas are active."

#
# Work out the list of servers which are known to the proxy.
#

servers=`cat $tempfile | grep "ibm-slapdProxyBackendServerName" \
            | cut -f 2 -d '=' | cut -f 1 -d ',' | cut -f 1 -d '+' | sort | uniq`

#
# Query each of the pods, ensuring that the suffix is the same for each
# pod.
#

echo "Checking the $suffix suffix of each individual server...."

baseline=`kubectl exec -it $proxy -- idsldapsearch -h 127.0.0.1 \
        -p $port -D $admin_dn -w $admin_pwd \
        -b $suffix \
        "(objectclass=inetOrgPerson)" dn | tr -d '\r' | awk 'NF'`

if [ ! -z "$verbose" ] ; then
    echo "Baseline:"
    printf "%s\n" $baseline
fi

for server in $servers; do
    echo "    Checking $server"

    data=`kubectl exec -it $server -- idsldapsearch -h 127.0.0.1 \
        -p $replica_port $replica_args -D $admin_dn -w $admin_pwd \
        -b $suffix \
        "(objectclass=inetOrgPerson)" dn | tr -d '\r' | awk 'NF'`

    if [ "$baseline" != "$data" ]; then
        echo "        Failed - the server data differs to the baseline data!"
        printf "%s\n" $data

        exit 1
    fi

    if [ ! -z "$verbose" ] ; then
        echo "Suffix:"
        printf "%s\n" $data
    fi

    echo "        OK."
done

#
# If we get this far we know that everything is OK.
#

echo "Successful."

exit 0

