# IBM Security Verify Directory Operator
  * [Overview](#overview)
  * [Installation](#installation)
    + [RedHat OpenShift Environment](#redhat-openshift-environment)
    + [Standard Kubernetes Environment](#standard-kubernetes-environment)
      - [OperatorHub.io and the Operator Lifecycle Manager](#operatorhubio-and-the-operator-lifecycle-manager)
        * [Installing](#installing)
      - [Manual Installation](#manual-installation)
  * [Usage](#usage)
    + [Configuration](#Configuration)
    + [Persistent Volumes](#persistent-volumes)
    + [Deploying a Directory Server](#deploying-a-directory-server)
    + [Custom Resource Definition](#custom-resource-definition)
    + [Creating a Service](#creating-a-service)

## Overview

IBM Security Verify Directory is a scalable, standards-based identity directory that helps simplify identity and directory management. Verify Directory helps consolidate identity silos into a single identity source. Verify Directory is purpose-built to provide a directory foundation that can help provide a trusted identity data infrastructure that assists in enabling mission-critical security and authentication. It is designed to deliver a reliable, scalable, standards-based identity data platform that interoperates with a broad range of operating systems and applications. Verify Directory supports Lightweight Directory Access Protocol (LDAP) V3, offering a flexible and highly scalable LDAP infrastructure.

For a detailed description of IBM Security Verify Directory refer to the [offical documentation](https://www.ibm.com/docs/en/svd).

The IBM Security Verify Directory operator provides lifecycle management of a scalable directory server environment.

The operator will manage the deployment of the replicated directory server containers, the initialisation of the replicated data, and will also manage the directory proxy which acts as a front-end to the environment.  The environment is depicted in the following figure.

![Overview](src/images/Overview.png)

At a high level, the operator will complete the steps depicted in the following figure when adding a new replica into the environment:

![Steps](src/images/Steps.png)

**Note:**

* The ‘principal’ term is used to describe the initial replica in the environment.
* There is no down-time in the environment after the initial replica has been configured.
* Each server is a complete replica.



## Installation

### RedHat OpenShift Environment

The IBM Security Verify Access Operator is available from the RedHat community operator catalog.  Information on how to install a community operator in OpenShift can be obtained from the official RedHat OpenShift documentation.

### Standard Kubernetes Environment

In a standard (i.e. non-OpenShift) Kubernetes environment the operator can be installed and managed manually, or it can be installed and managed using the [Operator Lifecycle Manager](https://github.com/operator-framework/operator-lifecycle-manager) and [OperatorHub.io](https://operatorhub.io/). 

#### OperatorHub.io and the Operator Lifecycle Manager

Kubernetes operators are very useful tools that provide lifecycle management capabilities for many varying custom objects in Kubernetes. [OperatorHub.io](https://operatorhub.io/) provides a single place where Kubernetes administrators or developers can go to find existing operators that may provide the functionality that they require. 

The information provided by [OperatorHub.io](https://operatorhub.io/) allows the Operator Lifecycle Manager (OLM) to manage the operator throughout its complete lifecycle. This includes the initial installation and subscription to OperatorHub.io such that updates to the operator can be performed automatically.

##### Installing

To install the IBM Security Verify Access operator from OperatorHub.io:

1. Access the [IBM Security Verify Directory operator page on OperatorHub.io](https://operatorhub.io/operator/ibm-security-verify-directory-operator) in a browser.

2. Click the Install button on the page and follow the installation instructions.

3. Ensure that the IBM Security Verify Directory operator has been created by the Operator Lifecycle Manager. The phase should be set to "Succeeded". Note that this may take a few minutes.

```shell
kubectl get csv -n operators

NAME                                DISPLAY                                  VERSION   REPLACES  PHASE
verify-directory-operator.v23.3.0   IBM Security Verify Directory Operator   23.3.0              Succeeded
``` 

At this point the Operator Lifecycle Manager has been installed into the Kubernetes cluster, the IBM Security Verify Directory operator has been deployed and a subscription has been created that will monitor for any updates to the operator on OperatorHub.io. The IBM Security Verify Directory operator is now operational and any subsequent custom resources of the kind "IBMSecurityVerifyDirectory" will result in the operator being invoked to create the deployment.

#### Manual Installation

The IBM Security Verify Directory operator in essence is made up of 2 components:

1. The custom resource definition
2. The controller application

Each of these needs to be deployed into the Kubernetes environment before the operator can function.  The definitions for these resources are published with the IBM Security Verify Directory Operator GitHub release in a single `bundle.yaml` file.  

To see a list of available releases refer to the releases page in GitHub: [https://github.com/IBM-Security/verify-directory-operator/releases](https://github.com/IBM-Security/verify-directory-operator/releases).

The following command can be used to deploy the operator directly from the definition published to GitHub:

```shell
kubectl create -f https://github.com/ibm-security/verify-directory-operator/releases/download/v22.3.0/bundle.yaml
```
After executing this command the operator will be deployed to a newly created namespace: `verify-directory-operator-system`.  The following command can be used to validate that the operator has been deployed correctly.  The available field should be set to "1". Note that this may take a few minutes.

```shell
kubectl get deployment -n verify-directory-operator-system
NAME                                           READY   UP-TO-DATE   AVAILABLE   AGE
verify-directory-operator-controller-manager   1/1     1            1           21s
```
At this point the IBM Security Verify Directory operator has been deployed and is operational.  Any subsequent custom resources of the kind "IBMSecurityVerifyDirectory" will result in the operator being invoked to create the deployment.


## Usage

### Configuration

Each directory server deployment requires two ConfigMaps, one to contain the configuration of the directory server, and another to contain the base configuration of the proxy.  

#### Server Configuration

Documentation for the server configuration can be located in the YAML specification, which is available in the official documentation: [https://www.ibm.com/docs/en/svd?topic=specification-verify-directory-server]().

The server configuration must be stored in a Kubernetes ConfigMap.  The following example (isvd-server-config.yaml) shows the configuration of a directory server:

```
apiVersion: v1 
kind: ConfigMap 
metadata: 
  name: isvd-server-config 
data: 
  config.yaml: | 
    general: 
      license:
        accept: limited
        key: --license-key--

      key-stash: "B64:GAAAAHM1Q2lqMCtLYVppZUhOemprZi9XSGc9PThOcHIiXmA9RlB0Rji/nsd3MpTYvRzUn5joE804v57HdzKU2L0c1J+Y6BPNnceUEUr3I0I4v57HdzKU2L0c1J+Y6BPNnceUEUr3I0I/+VsYL0fIEQ=="

      admin: 
        dn: cn=root
        pwd: passw0rd1

    server:
      replication:
        admin:
          dn: cn=replcred
          pwd: passw0rd2

      suffixes:
        - dn: o=sample
          object-classes:
          - organization
```

The following command can be used to create the ConfigMap from this file:

```shell
kubectl apply -f isvd-server-config.yaml
```

#### Proxy Configuration

Documentation for the proxy configuration can be located in the YAML specification, which is available in the official documentation: [https://www.ibm.com/docs/en/svd?topic=specification-verify-directory-proxy]().

The proxy configuration must be stored in a Kubernetes ConfigMap, and should contain the general proxy configuration, excluding the proxy.server-groups and proxy.suffixes entries.  These entries will be automatically added by the operator based on the current replica configuration.  The following example (isvd-proxy-config.yaml) shows the configuration of the proxy:

```
apiVersion: v1 
kind: ConfigMap 
metadata: 
  name: isvd-proxy-config
  namespace: default 
data: 
  config.yaml: | 
    general: 
      id: isvd-proxy

      license:
        accept: limited
        key: --license-key--

      key-stash: "B64:GAAAAHM1Q2lqMCtLYVppZUhOemprZi9XSGc9PThOcHIiXmA9RlB0Rji/nsd3MpTYvRzUn5joE804v57HdzKU2L0c1J+Y6BPNnceUEUr3I0I4v57HdzKU2L0c1J+Y6BPNnceUEUr3I0I/+VsYL0fIEQ=="

      admin: 
        dn: cn=root
        pwd: passw0rd1
```

**NB**: The `key-stash` entry should be given the same value in both the server and proxy configurations.

The following command can be used to create the ConfigMap from this file:

```shell
kubectl apply -f isvd-proxy-config.yaml
```

### Persistent Volumes

A PersistentVolume (PV) is a piece of storage in the cluster that has been provisioned by an administrator or dynamically provisioned using Storage Classes. It is a resource in the cluster just like a node is a cluster resource. PVs are volume plugins like Volumes, but have a lifecycle independent of any individual Pod that uses the PV. This API object captures the details of the implementation of the storage, be that NFS, iSCSI, or a cloud-provider-specific storage system.

A PersistentVolumeClaim (PVC) is a request for storage by a user. It is similar to a Pod. Pods consume node resources and PVCs consume PV resources. Pods can request specific levels of resources (CPU and Memory). Claims can request specific size and access modes (e.g., they can be mounted ReadWriteOnce, ReadOnlyMany or ReadWriteMany, see AccessModes).

The directory data which is managed by a replica must be stored in a PVC, and each replica requires its own unique PVC.  So, a separate PVC must be created for each replica prior to the creation of the replica by the operator.

The PVC definition will be different based on the storage class which is being used, and each Kubernetes environment will provide their own storage classes.  Refer to your Kubernetes environment documentation for instructions on creating a PVC.

The following example (pvc.yaml) depicts a PVC which is created to use NFS storage:

```
apiVersion: v1
kind: PersistentVolume
metadata:
  name: isvd-server-1-pv
  labels:
    app: isvd-server-1-pv
spec:
  capacity:
    storage: 200Mi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Recycle
  nfs:
    server: "172.21.233.1"
    path: "/exports/isvd-server-1" 

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: isvd-server-1-pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: ""
  resources:
    requests:
      storage: 10Gi
  selector:
    matchLabels:
      app: isvd-server-1-pv
```

The following command can be used to create the PVC from this file:

```shell
kubectl apply -f pvc.yaml
```
 

### Deploying a Directory Server

In order to deploy a directory server using the operator a new `IBMSecurityVerifyDirectory` custom resource must be created in the environment. 

The following example (isvd.yaml) shows the custom resource for a new replicated server, which contains two replicas:

```yaml
apiVersion: ibm.com/v1
kind: IBMSecurityVerifyDirectory

metadata:
  # The name which will be give to the deployment.
  name: isvd-server

spec:
  # Details associated with each directory server replica.  The id will 
  # be used as the server and pod identifier, and the pvc refers to the
  # pre-created Persistent Volume Claim which will be used to store the
  # directory data for the replica.
  replicas:
  - id:  replica-1
    pvc: replica-1-pvc
  - id:  replica-2
    pvc: replica-2-pvc
    
  # Details associated with the pods which will be created by the
  # operator.
  pods:
  
    # The name of the ServiceAccount to use to run the managed pod.
    # serviceAccountName: "default"

    # Details associated with the directory images which will be used.
    # This includes the repository which is used to store the server, seed
    # and proxy images, along with the label of the images.
    image: 
      repo:    icr.io/isvd
      label:   10.0.0.0
      
    # The names of the ConfigMaps which store the server and proxy
    # configuration.
    configMap:
      proxy:   isvd-proxy-config
      server:  isvd-server-config
```

The following command can be used to create the deployment from this file:

```shell
kubectl apply -f isvd.yaml
```

#### Custom Resource Definition

The `IBMSecurityVerifyDirectory` custom resource definition contains the following elements:

|Entry|Description|Default|Required?
|-----|-----------|-------|---------
|spec.replicas[].id|The unique identifier for the replica.  This will be used as the pod name, and server identity.| |Yes
|spec.replicas[].pvc|The name of the persistent volume claim which will be used by the replica.  Each replica must have its own PVC, and the PVC must be pre-created.| |Yes
|spec.pods.image.repo|The repository which is used to store the Verify Directory images.|icr.io/isvd|No
|spec.pods.image.label|The label of the Verify Directory images to be used. |latest|No
|spec.pods.image.imagePullPolicy|The pull policy for the images.|'Always' if the latest label is specified, otherwise 'IfNotPresent'.|No
|spec.pods.image.imagePullSecrets[]|A list of secrets which contain the credentials, used to access the images.| |No
|spec.pods.configMap.proxy|The initial configuration data for the proxy.  This should include everything but the proxy.server-groups and proxy.suffixes entries.| |Yes
|spec.pods.configMap.server|The configuration data for the server which is being managed/replicated.| |Yes
|spec.pods.resources|The compute resources required by each pod.  Further information can be found at [https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/]().| |No
|spec.pods.envFrom[]|A list of sources to populate environment variables in the container.  Further information can be found at [https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/]().| |No
|spec.pods.env[]|A list of environment variables to be added to the pods.  Further information can be found at [https://kubernetes.io/docs/tasks/inject-data-application/define-environment-variable-container/]().| |No
|spec.pods.serviceAccountName|The Kubernetes account which the pods will run as.|default|No




### Creating a Service

When creating a service for the environment the selector for the service must match the selector for the proxy deployment, achieved by specifying the `app` label.  

An example NodePort service definition is provided below:

```
apiVersion: v1
kind: Service
metadata:
  name: isvd-server
spec:
  ports:
    - port: 9443
      name: isvd-server
      protocol: TCP
      nodePort: 30443
  selector:
    app: isvd-server
  type: NodePort
```
