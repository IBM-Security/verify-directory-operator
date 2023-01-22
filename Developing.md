# Building

A container image has been created which encapsulates the required build environment for the operator.  For further information on how to create and use the build container refer to the [build/README.md]() file.

# Testing

## Pre-Requisites

In order to test a development version of the operator the following pre-requisites must be met:

1. You first need to ensure that you have access to a Kubernetes environment and the kubectl context has been set for this environment.  
2. The `operator-sdk` must be installed.  Information on how to install the `operator-sdk` is available at: [ https://sdk.operatorframework.io/docs/installation/]().
3. The operator lifecycle management (OLM) tool must be installed into the Kubernetes cluster which is being used for testing.  This can be achieved by executing the following operator-sdk command:

	```
	operator-sdk olm install
	```

## Install the Operator

You must first set the following environment variables:

|Name|Description
|----|-----------
|IMAGE\_TAG\_BASE|This is the image repository name of the operator.  The operator which is automatically published from GitHub is: `icr.io/isvd/verify-directory-operator`.
|VERSION|The version/label of the operator image which is to be used.  Non-release builds are published by GitHub to ICR with a label of `0.0.0`.

You can then install the operator with the following command:

```
operator-sdk run bundle ${IMAGE_TAG_BASE}-bundle:${VERSION}
```

After this command has completed you should see that the operator has been installed into the environment and the operator controller pod is running.

## Cleanup

To uninstall the operator issue the following command:

```
operator-sdk cleanup ibm-security-verify-directory-operator
```

To remove the OLM environment from your Kubernetes cluster issue the following command:

```
operator-sdk olm uninstall
```

