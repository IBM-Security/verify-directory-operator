# Introduction

This directory contains files which can be used when testing the operator.
In particular:

|File/Directory|Description|
|--------------|-----------|
|catalog.yaml|Contains a template definition for a catalog which can be used in an OpenShift environment.
|certs|Contains a test certificate/key which is used by the build environment, and the test environment.
|env|Contains files which can be used to set up a test environment.  This test environment is designed to work with the `src/config/samples/ibm_v1_ibmsecurityverifydirectory.yaml` file.  The setup\_env.sh script can be used to initialise the test environment, and clean-up the test environment.
|runtime|This directory contains scripts which can be used to test/validate the runtime environment (i.e. to test the ISVD server which is being managed by the operator).
